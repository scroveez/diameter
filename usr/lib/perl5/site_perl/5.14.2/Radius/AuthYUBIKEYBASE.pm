# AuthYUBIKEYBASE.pm
#
# Object for basic handling of Yubikey token authentication
# (yubico.com). Requires the child class to implement token checks
# using the chosen database or validation server.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001-2010 Open System Consultants
# $Id: AuthYUBIKEYBASE.pm,v 1.1 2014/03/25 21:57:47 hvn Exp $

package Radius::AuthYUBIKEYBASE;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use strict;

# RCS version number of this module
$Radius::AuthYUBIKEYBASE::VERSION = '$Revision: 1.1 $';

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    $self->SUPER::check_config();
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
    $self->{NoDefault}         = 1;
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
    $p->{Handler}->logPassword($user_name, $submitted_pw, 'YUBIKEY',
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
	return ($main::REJECT, "Authentication type not supported. Only RADIUS PAP, EAP-OPT and EAP-GTC is supported by Yubikey");
    }

    return $self->checkYubikey($user, $submitted_pw, $p);
}

#####################################################################
# $submitted_pw is the response being authenticated
# $user is the user name to be authenticated
# return (result, reason)
sub checkYubikey
{
    my ($self, $user, $submitted_pw, $p) = @_;

    my $msg = 'Someone forgot to override AuthYUBIKEYBASE::checkYubikey';
    $self->log($main::LOG_ERR, $msg);

    return ($main::REJECT, $msg);
}

#####################################################################
# This is also called by the EAP_5 OTP code
sub otp_challenge
{
    my ($self, $user, $p, $context) = @_;

    return "Insert your Yubikey and press the button";
}

#####################################################################
# This is also called by the EAP_5 OTP code
# Return 1 if OK else 0
sub otp_verify
{
    my ($self, $user, $submitted_pw, $p, $context) = @_;

    my ($result, $reason) = $self->checkYubikey($user, $submitted_pw, $p);
    if ($result == $main::ACCEPT)
    {
	$p->{Handler}->logPassword($user, $submitted_pw, 'YUBIKEY', 1, $p);
	return 1;
    }
    else
    {
	$self->log($main::LOG_INFO, "Yubikey EAP-OTP authentication failed for $user: $reason");
	$p->{Handler}->logPassword($user, $submitted_pw, 'YUBIKEY', 0, $p);
	return;
    }
}

#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_start
{
    my ($self, $context, $user, $p) = @_;

    return (2, "Insert your Yubikey and press the button");
}

#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_continue
{
    my ($self, $context, $user, $submitted_pw, $p) = @_;

    my ($result, $reason) = $self->checkYubikey($user, $submitted_pw, $p);
    if ($result == $main::ACCEPT)
    {
	$p->{Handler}->logPassword($user, $submitted_pw, 'YUBIKEY', 1, $p);
	return (1);
    }
    else
    {
	$self->log($main::LOG_INFO, "Yubikey EAP-OTP authentication failed for $user: $reason");
	$p->{Handler}->logPassword($user, $submitted_pw, 'YUBIKEY', 0, $p);
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
