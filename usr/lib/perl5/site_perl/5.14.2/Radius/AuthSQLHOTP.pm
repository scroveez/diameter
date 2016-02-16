# AuthSQLHOTP.pm
#
# Object for handling Authentication of HOTP tokens (RFC 4226)
# from an SQL database
#
# Suports optional PIN/static password, counter resynchronisation,
# brute force attack detection, 
# optional active/inactive flag etc.
# Works by default with sample database schema in goodies/hotp.sql
#
# Requires Digest::HMAC_SHA1
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2009 Open System Consultants
# $Id: AuthSQLHOTP.pm,v 1.9 2013/12/10 21:20:14 hvn Exp $

package Radius::AuthSQLHOTP;
@ISA = qw(Radius::AuthGeneric Radius::SqlDb);
use Radius::AuthGeneric;
use Radius::SqlDb;
use Radius::HOTP;
use strict;

%Radius::AuthSQLHOTP::ConfigKeywords = 
('AuthSelect'            => 
 ['string', 'SQL query that will be used to fetch HOTP data from the database. Special characters are permitted, and %0 is replaced with the quoted user name. %1 is replaced with the token ID. ', 0],
 'UpdateQuery'           => 
 ['string', 'SQL query that will be used to store HOTP token data back to the database after authentication. ', 0],
 'Require2Factor'           => 
 ['flag', 'SQL query that will be used to store HOTP token data back to the database after authentication.Indicates that the user is required to enter their static password as a prefix to their HOTP one time password. Requires appropriate configuration of AuthSelect', 0],
 'DefaultDigits' =>
 ['integer', 'If AuthSelect does not provide the number of digits expected in the users HOTP code, this value will be sued. Defaults to 6.', 1],
 'MaxBadLogins' =>
 ['integer', 'MaxBadLogins specifies how many consecutive bad PINs or bad HOTP codes will be tolerated in the last BadLoginWindow seconds. If more than MaxBadLogins bad authentication attempts (according to field 5  from AuthSelect occurs and if the last one is  within the last BadLoginWindow seconds (according to field 6 from AuthSelect), the authentication attempt will be rejected. The user must wait at least BadLoginWindow seconds before attempting to authenticate again.', 1],
 'BadLoginWindow' =>
 ['integer', 'If more than MaxBadLogins consecutive authentication failures occurs, the user must wait at least this number of seconds before a successful authentication can be performed.', 1],
 'ResyncWindow' =>
 ['integer', 'Maximum number of missing authentications that will be tolerated for counter resynchronisation', 1],

 );

# RCS version number of this module
$Radius::AuthSQLHOTP::VERSION = '$Revision: 1.9 $';

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
    $self->{AuthSelect}        = 'select secret, counter_high, counter_low, active, pin, digits, bad_logins, unix_timestamp(accessed) from hotpkeys where username=%0';
    $self->{UpdateQuery}       = 'update hotpkeys set accessed=now(), counter_high=%0, counter_low=%1, bad_logins=%2 where username=%3';
    $self->{DefaultDigits} = 6;
    $self->{MaxBadLogins} = 10; # For detection of bruteforce attacks
    $self->{BadLoginWindow} = 10; # seconds
    $self->{ResyncWindow}  = 20; 
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
    $p->{Handler}->logPassword($user_name, $submitted_pw, 'HOTP', 
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
	return ($main::REJECT, "Authentication type not supported. Only RADIUS PAP, EAP-OPT and EAP-GTC is supported by HOTP");
    }

    return $self->checkHOTP($user, $submitted_pw, $p);
}

#####################################################################
# Increment the counter, overflowing from low to high
sub increment_counter
{
    my ($h, $l) = @_;

    # Increment the counter, which prevents replay attacks
    $l++;
    if ($l > 0xffffffff)
    {
	$l = 0;
	$h++;
    }
    return ($h, $l);
}

#####################################################################
# $submitted_pw is the response being authenticated
# $user is the user name to be authenticated
# return (result, reason)
sub checkHOTP
{
    my ($self, $user, $submitted_pw, $p) = @_;

    # Get data for this user from the database
    my $qname = $self->quote($user);
    my $q = &Radius::Util::format_special($self->{AuthSelect}, $p, $self, $qname);
    my $sth = $self->prepareAndExecute($q);
    return ($main::IGNORE, 'Database failure')
	unless $sth;
    
    my ($secret, $counter_high, $counter_low, $active, $pin, $digits, $bad_logins, $last_access_time) = $self->getOneRow($sth);
    return ($main::REJECT, "HOTP secret not found in database")
	unless defined $secret;

    return ($main::REJECT, "HOTP is not active")
	if defined $active && not $active;

    # Digits field is optional
    $digits = $self->{DefaultDigits} unless defined $digits;

    # The token code should be the last $digits characters. Anything before that
    # is a PIN/password
    my $code = substr($submitted_pw, -$digits);
    my $password = substr($submitted_pw, 0, length($submitted_pw) - length($code));

    return ($main::REJECT, "HOTP Brute Force attack on $user throttled")
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

    # Try each incremented coutner value until ResyncWindow is exhausted
    # That allows us to auth even if some counter uses have been lost
    # Allowing us to resync the counters
    my ($resync_counter, $found);
    my ($temp_high, $temp_low) = ($counter_high, $counter_low);
    for ($resync_counter = 0; $resync_counter < $self->{ResyncWindow}; $resync_counter++)
    {
	my $counter = pack('NN', $temp_high, $temp_low);
	($temp_high, $temp_low) = &increment_counter($temp_high, $temp_low);
	my $hotp = Radius::HOTP::hotp_sha1(pack('H*', $secret), $counter, $digits);
	if ($hotp == $code)
	{
	    $found++;
	    $bad_logins = 0;
	    ($counter_high, $counter_low) = ($temp_high, $temp_low);
	    last;
	}
	
    }
    ($result, $reason) =  ($main::REJECT, "Bad HOTP password")
	unless $found;

    # Update the database
  save:
    # Computer new bad_logins
    $bad_logins = ($result == $main::ACCEPT) ? 0 : $bad_logins+1;

    my $q = &Radius::Util::format_special($self->{UpdateQuery}, $p, $self, $counter_high, $counter_low, $bad_logins, $qname);
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

    return "Enter your HOTP";
}

#####################################################################
# This is also called by the EAP_5 OTP code
# Return 1 if OK else 0
sub otp_verify
{
    my ($self, $user, $submitted_pw, $p, $context) = @_;

    my ($result, $reason) = $self->checkHOTP($user, $submitted_pw, $p);
    if ($result == $main::ACCEPT)
    {
	$p->{Handler}->logPassword($user, $submitted_pw, 'HOTP', 1, $p);
	return 1;
    }
    else
    {
	$self->log($main::LOG_INFO, "HOTP EAP-OTP authentication failed for $user: $reason");
	$p->{Handler}->logPassword($user, $submitted_pw, 'HOTP', 0, $p);
	return;
    }
}

#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_start
{
    my ($self, $context, $user, $p) = @_;

    return (2, "Enter your HOTP");
}

#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_continue
{
    my ($self, $context, $user, $submitted_pw, $p) = @_;

    my ($result, $reason) = $self->checkHOTP($user, $submitted_pw, $p);
    if ($result == $main::ACCEPT)
    {
	$p->{Handler}->logPassword($user, $submitted_pw, 'HOTP', 1, $p);
	return (1);
    }
    else
    {
	$self->log($main::LOG_INFO, "HOTP EAP-OTP authentication failed for $user: $reason");
	$p->{Handler}->logPassword($user, $submitted_pw, 'HOTP', 0, $p);
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

