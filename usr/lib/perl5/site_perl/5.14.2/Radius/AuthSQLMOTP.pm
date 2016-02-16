# AuthSQLMOTP.pm
#
# Object for handling Authentication of mobile-otp tokens (motp.sourceforge.net)
# from an SQL database
#
# Caution: replay attack detection, per-client time offset, bad-password count not supported
#
# Author: Jerome Fleury (jerome@fleury.net), based on AuthBy SQLYUBIKEY.
# Copyright (C) Open System Consultants

package Radius::AuthSQLMOTP;
@ISA = qw(Radius::AuthGeneric Radius::SqlDb);
use Radius::AuthGeneric;
use Radius::SqlDb;
use MIME::Base64;
use strict;

%Radius::AuthSQLMOTP::ConfigKeywords = 
('AuthSelect'            => 
 ['string', 'SQL query that will be used to fetch mobile-OTP data from the database. Special characters are permitted, and %0 is replaced with the quoted user name.', 0],
'WindowSize'            => 
 ['integer', 'Number of minutes either side of the current time to search for. This limits how far out of sync the client and the Radius server can be. Defaults to 3 minutes.', 0],
 );

# RCS version number of this module
$Radius::AuthSQLMOTP::VERSION = '$Revision: 1.6 $';

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

    $self->SUPER::initialize;
    $self->Radius::SqlDb::initialize();
    $self->{NoDefault}         = 1;
    $self->{AuthSelect}        = 'select secret, active, userId, pin from mobileotp where userId=%0';
    $self->{WindowSize}        = 3;
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
    $p->{Handler}->logPassword($user_name, $submitted_pw, 'MOTP', 
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
        return ($main::REJECT, "Authentication type not supported. Only RADIUS PAP, EAP-OPT and EAP-GTC is supported by MOTP");
    }

    return $self->checkMOTP($user, $submitted_pw, $p);
}


#####################################################################
# $submitted_pw is the response being authenticated
# $user is the user name to be authenticated
# return (result, reason)
sub checkMOTP
{
    my ($self, $user, $submitted_pw, $p) = @_;

    my ($otp) = $submitted_pw =~ /^([0-9a-fA-F]{6})$/;
    $otp = lc($otp); 

    return ($main::REJECT, "Bad mobile OTP password format")
        unless (defined $otp);
        
    # Get data for this user or token from the database
    my $qname = $self->quote($user);
    my $q = &Radius::Util::format_special($self->{AuthSelect}, $p, $self, $qname);
    my $sth = $self->prepareAndExecute($q);
    return ($main::IGNORE, 'Database failure')
        unless $sth;
    
    my ($secret, $active, $userId, $pin) = $self->getOneRow($sth);
    return ($main::REJECT, "secret not found in database")
        unless defined $secret;

    return ($main::REJECT, "User is not active")
        if defined $active && not $active;

    my $otp_ok;
    my $windowsize = $self->{WindowSize} * 6; # Seconds / 10
    my $time = time; # get UTC epoch time in seconds
    chop($time); # with last digit dropped
    my $i;
    for ($i = $time - $windowsize; $i <= $time + $windowsize; $i++)
    {
       my $md5 = substr(Digest::MD5::md5_hex($i . $secret . $pin), 0, 6);

       if ($otp eq $md5) 
       {
	   $otp_ok = 1; 
	   last;
       }
    }

    return ($main::REJECT, "Bad mobile OTP password")
        unless $otp_ok;

    return ($main::ACCEPT);
}

#####################################################################
# This is also called by the EAP_5 OTP code
sub otp_challenge
{
    my ($self, $user, $p, $context) = @_;

    return "Enter your OTP";
}

#####################################################################
# This is also called by the EAP_5 OTP code
# Return 1 if OK else 0
sub otp_verify
{
    my ($self, $user, $submitted_pw, $p, $context) = @_;

    my ($result, $reason) = $self->checkMOTP($user, $submitted_pw, $p);
    if ($result == $main::ACCEPT)
    {
        $p->{Handler}->logPassword($user, $submitted_pw, 'MOTP', 1, $p);
        return 1;
    }
    else
    {
        $self->log($main::LOG_INFO, "mobile-OTP EAP-OTP authentication failed for $user: $reason");
        $p->{Handler}->logPassword($user, $submitted_pw, 'MOTP', 0, $p);
        return;
    }
}

#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_start
{
    my ($self, $context, $user, $p) = @_;

    return (2, "Enter your mobile OTP");
}

#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_continue
{
    my ($self, $context, $user, $submitted_pw, $p) = @_;

    my ($result, $reason) = $self->checkMOTP($user, $submitted_pw, $p);
    if ($result == $main::ACCEPT)
    {
        $p->{Handler}->logPassword($user, $submitted_pw, 'MOTP', 1, $p);
        return (1);
    }
    else
    {
        $self->log($main::LOG_INFO, "mobile-OTP EAP-OTP authentication failed for $user: $reason");
        $p->{Handler}->logPassword($user, $submitted_pw, 'MOTP', 0, $p);
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
