# AuthOPIE.pm
#
# Object for handling Authentication via OPIE.
#
# Requires opie-2.4 or better from http://www.inner.net/opie 
# and Authen-OPIE-1.00 or better from CPAN
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001-2004 Open System Consultants
# $Id: AuthOPIE.pm,v 1.12 2012/05/22 22:03:41 mikem Exp $

package Radius::AuthOPIE;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Authen::OPIE;
use strict;

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
    $self->{NoDefault} = 1;
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

    return $self->check_plain_password($p->getUserName(), $p->decodedPassword(), undef, $p);
}

#####################################################################
# $submitted_pw is the password being authenticated
# $pw is the correct password if known
# $user is the user name to be authenticated
sub check_plain_password
{
    my ($self, $user, $submitted_pw, $pw, $p, $encrypted) = @_;

    return ($main::ACCEPT) if $self->{NoCheckPassword};

    if ($submitted_pw eq '')
    {
	# First time, issue a challenge containing the OPIE
	# challenge string
	my $challenge = $self->otp_challenge($user);
	return ($main::REJECT, "OPIE challenge failed. Is OPIE set up properly?")
	    unless defined $challenge;
	
	$p->{rp}->addAttrByNum($Radius::Radius::REPLY_MESSAGE,
			  "OPIE Challenge: $challenge");
	return ($main::CHALLENGE);
    }
    else
    {
	my $result = $self->otp_verify($user, $submitted_pw);
	return ($main::REJECT, "OPIE Authentication failed. Is OPIE set up properly?")
	    unless defined $result;
	
	if ($result) 
	{
	    $p->{Handler}->logPassword($user, $submitted_pw, 'OPIE', 1, $p) if $p->{Handler};
	    return ($main::ACCEPT);
	}
	else
	{
	    # Caution: this can happen if you are not running 
	    # as root.
	    $p->{Handler}->logPassword($user, $submitted_pw, 'OPIE', 0, $p) if $p->{Handler};
	    return ($main::REJECT, "OPIE Authentication failed: ($result)");
	}
    }
}

#####################################################################
# This is also called by the EAP_4 OTP code
sub otp_challenge
{
    my ($self, $user) = @_;

    return Authen::OPIE::opie_challenge($user);
}

#####################################################################
# This is also called by the EAP_4 OTP code
sub otp_verify
{
    my ($self, $user, $submitted_pw) = @_;

    my $result = Authen::OPIE::opie_verify($user, $submitted_pw);
    return unless defined $result;
    return !$result;
}

#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_start
{
    my ($self, $context, $user) = @_;

    my $result = Authen::OPIE::opie_challenge($user);
    return (0, 'Error') unless defined $result;
    return (2, "CHALLENGE=Enter OPIE one-time-password.\r\nOPIE challenge is $result");
}

#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_continue
{
    my ($self, $context, $user, $data) = @_;

    my $result = Authen::OPIE::opie_verify($user, $data);
    
    return (0, 'Error') unless defined $result;
    return (1) if $result == 0;
    return (0, 'Bad password');
}

#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_end
{
    my ($self, $context, $user) = @_;
}

1;
