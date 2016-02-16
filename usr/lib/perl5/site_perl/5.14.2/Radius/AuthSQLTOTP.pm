# AuthSQLTOTP.pm
#
# Object for handling Authentication of TOTP tokens (draft-mraihi-totp-timebased-06.txt)
# from an SQL database
#
# Suports optional PIN/static password
# brute force attack detection, 
# replay attack detection,
# optional active/inactive flag etc.
# Works by default with sample database schema in goodies/totp.sql
#
# Requires Digest::HMAC_SHA1
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2009 Open System Consultants
# $Id: AuthSQLTOTP.pm,v 1.9 2014/11/13 20:31:27 hvn Exp $

package Radius::AuthSQLTOTP;
@ISA = qw(Radius::AuthGeneric Radius::SqlDb);
use Radius::AuthGeneric;
use Radius::SqlDb;
use Radius::TOTP;
use strict;

%Radius::AuthSQLTOTP::ConfigKeywords = 
('AuthSelect'            => 
 ['string', 'SQL query that will be used to fetch TOTP data from the database. Special characters are permitted, and %0 is replaced with the quoted user name. %1 is replaced with the token ID. ', 0],
 'UpdateQuery'           => 
 ['string', 'SQL query that will be used to store TOTP token data back to the database after authentication. ', 0],
 'Require2Factor'           => 
 ['flag', 'SQL query that will be used to store TOTP token data back to the database after authentication.Indicates that the user is required to enter their static password as a prefix to their TOTP one time password. Requires appropriate configuration of AuthSelect', 0],
 'DefaultDigits' =>
 ['integer', 'If AuthSelect does not provide the number of digits expected in the users TOTP code, this value will be used. Defaults to 6.', 1],
 'MaxBadLogins' =>
 ['integer', 'MaxBadLogins specifies how many consecutive bad PINs or bad TOTP codes will be tolerated in the last BadLoginWindow seconds. If more than MaxBadLogins bad authentication attempts (according to field 5  from AuthSelect occurs and if the last one is  within the last BadLoginWindow seconds (according to field 6 from AuthSelect), the authentication attempt will be rejected. The user must wait at least BadLoginWindow seconds before attempting to authenticate again.', 1],
 'BadLoginWindow' =>
 ['integer', 'If more than MaxBadLogins consecutive authentication failures occurs, the user must wait at least this number of seconds before a successful authentication can be performed.', 1],
 'DelayWindow' =>
 ['integer', 'Maximum number of delay timesteps that will be tolerated. Defaults to 1, the value recommended by the TOTP RFC', 1],
 'TimeStep' =>
 ['integer', 'Size of the time step to be used, in seconds. Defaults to 30, the value recommended by the TOTP RFC', 2],
 'TimeStepOrigin' =>
 ['integer', 'The Unix time from which to start counting time steps. Defaults to 0, the value recommended by the TOTP RFC', 2],

 );

# RCS version number of this module
$Radius::AuthSQLTOTP::VERSION = '$Revision: 1.9 $';

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    $self->Radius::AuthGeneric::check_config();
    $self->Radius::SqlDb::check_config();
    return;
}

#####################################################################
# Do per-instance default initialization
# This is called by Configurable during Configurable::new before
# the config file is parsed. Its a good place initialize instance 
# variables
# that might get overridden when the config file is parsed.
# Do per-instance default initialization. This is called after
# construction is complete
sub initialize
{
    my ($self) = @_;

    $self->Radius::AuthGeneric::initialize();
    $self->Radius::SqlDb::initialize();
    $self->{NoDefault}         = 1;
    $self->{AuthSelect}        = 'select secret, active, pin, digits, bad_logins, unix_timestamp(accessed), last_timestep from totpkeys where username=%0';
    $self->{UpdateQuery}       = 'update totpkeys set accessed=now(), bad_logins=%0, last_timestep=%2 where username=%1';
    $self->{DefaultDigits}     = 6;
    $self->{MaxBadLogins}      = 10; # For detection of bruteforce attacks
    $self->{BadLoginWindow}    = 10; # seconds
    $self->{DelayWindow}       = 1; 
    $self->{TimeStep}          = 30; 
    $self->{TimeStepOrigin}    = 0; 
}

#####################################################################
# This is a bogus findUser that basically does nothing but does not
# fail
sub findUser
{
    return Radius::User->new();
}

#####################################################################
# We subclass this to do nothing: there are no check items
# except the password, and only if its not an EAP
sub checkUserAttributes
{
    my ($self, $user, $p) = @_;
    
    # Short circuit authentication in EAP requests ?
    return ($main::ACCEPT) 
      if $p->getAttrByNum($Radius::Radius::EAP_MESSAGE);

    my $user_name = $p->getUserName;
    $user_name =~ s/@[^@]*$//
	if $self->{UsernameMatchesWithoutRealm};
    my $submitted_pw = $p->decodedPassword();
    my ($result, $reason) = 
	$self->check_response($user_name, $submitted_pw, undef, $p);
    $p->{Handler}->logPassword($user_name, $submitted_pw, 'TOTP', 
			       $result == $main::ACCEPT, $p)
	if $p->{Handler};

    return ($result, $reason);
}

#####################################################################
# $submitted_pw is the response being authenticated
# $pw is the correct password if known
# $user is the user name to be authenticated
sub check_response
{
    my ($self, $user, $submitted_pw, $pw, $p, $encrypted) = @_;

    return ($main::ACCEPT) if $self->{NoCheckPassword};

    if (defined $p->getAttrByNum($Radius::Radius::CHAP_PASSWORD)
	|| defined $p->get_attr('MS-CHAP-Response')
	|| defined $p->get_attr('MS-CHAP-Challenge')
	|| defined $p->get_attr('MS-CHAP2-Response')
	|| defined $p->get_attr('MS-CHAP-Challenge'))
    {
	return ($main::REJECT, "Authentication type not supported. Only RADIUS PAP, EAP-OPT and EAP-GTC is supported by TOTP");
    }

    if ($submitted_pw eq '')
    {
	my $prompt = "Enter OTP";
	$p->{rp}->addAttrByNum($Radius::Radius::STATE, "TOTP=$prompt");
	$p->{rp}->addAttrByNum($Radius::Radius::REPLY_MESSAGE, $prompt);
	return ($main::CHALLENGE, "OTP Required");
    }
    return $self->checkTOTP($user, $submitted_pw, $p);
}

#####################################################################
# $submitted_pw is the response being authenticated
# $user is the user name to be authenticated
# return (result, reason)
sub checkTOTP
{
    my ($self, $user, $submitted_pw, $p) = @_;

    # Get data for this user from the database
    my $qname = $self->quote($user);
    my $q = &Radius::Util::format_special($self->{AuthSelect}, $p, $self, $qname);
    my $sth = $self->prepareAndExecute($q);
    return ($main::IGNORE, 'Database failure')
	unless $sth;
    
    my ($secret, $active, $pin, $digits, $bad_logins, $last_access_time, $last_timestep, $algorithm, $timestep, $timestep_origin) = $self->getOneRow($sth);
    return ($main::REJECT, "TOTP secret not found in database")
	unless defined $secret;

    return ($main::REJECT, "TOTP is not active")
	if defined $active && not $active;

    $last_timestep += 0; # In case database has NULL
    $algorithm = 'SHA1' unless $algorithm; # In case database has NULL or empty

    # Digits field is optional
    $digits = $self->{DefaultDigits} unless defined $digits;

    # The token code should be the last $digits characters. Anything before that
    # is a PIN/password
    my $code = substr($submitted_pw, -$digits);
    my $password = substr($submitted_pw, 0, length($submitted_pw) - length($code));

    return ($main::REJECT, "TOTP Brute Force attack on $user throttled")
	if (defined $last_access_time
	    && $bad_logins > $self->{MaxBadLogins} 
	    && $last_access_time > (time - $self->{BadLoginWindow}));

    my ($result, $reason) = ($main::ACCEPT);
    # REVISIT: detect brute force attacks
    if (defined $password || $self->{Require2Factor})
    {
	($result, $reason) = ($main::REJECT, "Bad PIN"), goto save
	    unless $password eq $pin;
    }

    # Try each permitted delay_counter
    # That allows us to auth even if there is a delay between the client and authenticator
    my ($delay_counter, $found);
    my $recv_time = $p->{RecvTime};

    # TEST case from draft-mraihi-totp-timebased-06.txt
    # test like this:
    # mysql -Dradius -umikem -pfred <goodies/totp.sql
    # perl radpwtst -noacct -user mikem -password 731029 
    # perl radpwtst -noacct -user mikem -password 081804    
    #$recv_time = 1111111109;

    # Configure TOTP options:
    $Radius::TOTP::X = $timestep ? $timestep : $self->{TimeStep};
    $Radius::TOTP::T0 = defined $timestep_origin ? $timestep_origin : $self->{TimeStepOrigin};
    my $T;
    for ($delay_counter = -$self->{DelayWindow}; $delay_counter <= $self->{DelayWindow}; $delay_counter++)
    {
	$T = Radius::TOTP::totp_timestep($recv_time, $delay_counter);
	my $totp;
	$totp = Radius::TOTP::totp_compute_sha256(pack('H*', $secret), $T, $digits) if $algorithm eq 'SHA256';
	$totp = Radius::TOTP::totp_compute_sha512(pack('H*', $secret), $T, $digits) if $algorithm eq 'SHA512';
	$totp = Radius::TOTP::totp_compute_sha1(pack('H*', $secret), $T, $digits) unless $totp; # Default to SHA1
	if ($totp eq $code)
	{
	    $found++;
	    last;
	}
    }

    if (!$found)
    {
	($result, $reason) =  ($main::REJECT, "Bad TOTP password")
    }
    # Look for attempted reuse of an earlier timestep
    elsif ($T <= $last_timestep)
    {
	($result, $reason) =  ($main::REJECT, "Replay attack detected");
	$found = undef;
    }
    else
    {
	$last_timestep = $T;
	$bad_logins = 0;
    }

    # Update the database
  save:
    # Computer new bad_logins
    $bad_logins = ($result == $main::ACCEPT) ? 0 : $bad_logins+1;

    $q = Radius::Util::format_special($self->{UpdateQuery}, $p, $self, $bad_logins, $qname, $last_timestep);
    return ($main::IGNORE, "Database update failed")
	unless $self->do($q);
	
    # Update the database with the new counter and timestamps
    return ($result, $reason);
}

#####################################################################
# This is also called by the EAP_5 OTP code
sub otp_challenge
{
    my ($self, $user, $p, $context) = @_;

    return "Enter your TOTP";
}

#####################################################################
# This is also called by the EAP_5 OTP code
# Return 1 if OK else 0
sub otp_verify
{
    my ($self, $user, $submitted_pw, $p, $context) = @_;

    my ($result, $reason) = $self->checkTOTP($user, $submitted_pw, $p);
    if ($result == $main::ACCEPT)
    {
	$p->{Handler}->logPassword($user, $submitted_pw, 'TOTP', 1, $p);
	return 1;
    }
    else
    {
	$self->log($main::LOG_INFO, "TOTP EAP-OTP authentication failed for $user: $reason");
	$p->{Handler}->logPassword($user, $submitted_pw, 'TOTP', 0, $p);
	return;
    }
}

#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_start
{
    my ($self, $context, $user, $p) = @_;

    return (2, "Enter your TOTP");
}

#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_continue
{
    my ($self, $context, $user, $submitted_pw, $p) = @_;

    my ($result, $reason) = $self->checkTOTP($user, $submitted_pw, $p);
    if ($result == $main::ACCEPT)
    {
	$p->{Handler}->logPassword($user, $submitted_pw, 'TOTP', 1, $p);
	return (1);
    }
    else
    {
	$self->log($main::LOG_INFO, "TOTP EAP-OTP authentication failed for $user: $reason");
	$p->{Handler}->logPassword($user, $submitted_pw, 'TOTP', 0, $p);
	return (0, $reason);
    }
}

#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_end
{
    my ($self, $context, $user) = @_;
}


1;

