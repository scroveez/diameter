# AuthOTP.pm
#
# Object for handling Authentication via One-Time-Passwords
# This module handles generic OTP authentication for either dialup 
# EAP-OTP or EAP-GTC
#
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001 Open System Consultants
# $Id: AuthOTP.pm,v 1.10 2012/05/22 22:03:41 mikem Exp $

package Radius::AuthOTP;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Radius::Context;
use strict;

%Radius::AuthOTP::ConfigKeywords =
('ChallengeHook'        => 
 ['hook', 'ChallengeHook is a fragment of perl code that is expected to generate a OTP (if necessary) save the OTP (in $context is sometimes convenient) and send the OTP to the user by a back channel (if necessary). It should return a challenge string that will be presented to the user by the client, informing them of how to get or generate their password.', 1],

 'VerifyHook'           => 
 ['hook', 'VerifyHook is a fragment of perl code that is expected to validate a OTP and return 1 on success. You will need to specify your own VerifyHook if you require an external program to verify the correct OTP.', 1],

 'PasswordPattern'      => 
 ['string', 'This optional parameter specifies a character pattern that will be used to generate random passwords by generate_password() and the default ChallengeHook.', 1],

 'ContextTimeout'       => 
 ['integer', 'This optional parameter specifies how long (in seconds) the context passed to ChallengeHook for a user will be kept. It defaults to 120 seconds, which is expected to be enough time for most users to receive and enter their correct OTP. You should not need to change this.', 1],

 );

# RCS version number of this module
$Radius::AuthOTP::VERSION = '$Revision: 1.10 $';

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
    $self->{'ChallengeHook.compiled'} = \&default_otp_challenge;
    $self->{'VerifyHook.compiled'}    = \&default_otp_verify;
    $self->{PasswordPattern} = 'cvcvcvc99';
    $self->{ContextTimeout} = 120; # seconds
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

    my $context = &Radius::Context::get("otp:$user", $self->{ContextTimeout});
    if ($submitted_pw eq '')
    {
	# First time, issue a challenge containing the OTP
	# challenge string
	my $challenge = $self->otp_challenge($user, $p, $context);
	return ($main::REJECT, "OTP challenge failed. Is OTP set up properly?")
	    unless defined $challenge;
	
	$p->{rp}->addAttrByNum($Radius::Radius::REPLY_MESSAGE,
			  "OTP Challenge: $challenge");
	return ($main::CHALLENGE);
    }
    else
    {
	my $result = $self->otp_verify($user, $submitted_pw, $p, $context);
	return ($main::REJECT, "OTP Authentication failed. Is OTP set up properly?")
	    unless defined $result;
	
	if ($result) 
	{
	    $p->{Handler}->logPassword($user, $submitted_pw, 'OTP', 1, $p) if $p->{Handler};
	    return ($main::ACCEPT);
	}
	else
	{
	    # Caution: this can happen if you are not running 
	    # as root.
	    $p->{Handler}->logPassword($user, $submitted_pw, 'OTP', 0, $p) if $p->{Handler};
	    return ($main::REJECT, "OTP Authentication failed: ($result)");
	}
    }
}

#####################################################################
# This is also called by the EAP_5 OTP code
# It has to do whatever is required to possibly generate a OTP, possibly send it to the
# user and return a challenge string that may be helpful to the user
# in determining or fetching their OTP
# ChallengeHook is expected to return ("challenge string")
sub otp_challenge
{
    my ($self, $user, $p, $context) = @_;

    my @result = $self->runHook('ChallengeHook', $p, $self, $user, $p, $context);
    return $result[0]; # The challenge
}

#####################################################################
# Default code for generating a new password. Uses the PasswordPattern
# Can be overridden. Returns the new password, or undef on failure
sub generate_password
{
    my ($self) = @_;

    my ($type, $pw);
    foreach $type (split(//, $self->{PasswordPattern}))
    {
	if ($type eq 'a')
	{
	    $pw .= &selectRandomChar('abcdefghijklmnopqrstuvwxyz0123456789');
	}
	elsif ($type eq 'A')
	{
	    $pw .= &selectRandomChar('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789');
	}
	elsif ($type eq 'c')
	{
	    $pw .= &selectRandomChar('bcdfghjklmnpqrstvwxyz');
	}
	elsif ($type eq 'C')
	{
	    $pw .= &selectRandomChar('BCDFGHJKLMNPQRSTVWXYZ');
	}
	elsif ($type eq 'v')
	{
	    $pw .= &selectRandomChar('aeiou');
	}
	elsif ($type eq 'V')
	{
	    $pw .= &selectRandomChar('AEIOU');
	}
	elsif ($type eq '9')
	{
	    $pw .= &selectRandomChar('0123456789');
	}
	else
	{
	    $pw .= $type;
	}
    }
    return $pw;
}
sub selectRandomChar
{
    my ($string) = @_;

    return substr($string, (int rand(32767)) % length($string), 1);
}

#####################################################################
# This is the default ChallengeHook
sub default_otp_challenge
{
    my ($self, $user, $p, $context) = @_;

    $context->{otp_password} = $self->generate_password();
    return "DEMO ONLY!. Your password is $context->{otp_password}";
}

#####################################################################
# This is also called by the EAP_5 OTP code
# VerifyHook is expected to return (1) on success and (0) on failure
sub otp_verify
{
    my ($self, $user, $submitted_pw, $p, $context) = @_;

    my @result = $self->runHook('VerifyHook', $p, $self, $user, $submitted_pw, $p, $context);
    return $result[0]; # The challenge
}

#####################################################################
# This is the default VerifyHook
# VerifyHook is expected to return (1) on success and (0) on failure
sub default_otp_verify
{
    my ($self, $user, $submitted_pw, $p, $context) = @_;

    return $submitted_pw eq $context->{otp_password};
}

#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_start
{
    my ($self, $context, $user, $p) = @_;

    my $result = $self->otp_challenge($user, $p, $context);
    return (0, 'Error') unless defined $result;
    return (2, "CHALLENGE=Enter One-Time-Password.\r\n$result");
}

#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_continue
{
    my ($self, $context, $user, $data, $p) = @_;

    my $result = $self->otp_verify($user, $data, $p, $context);

    return (0, 'Error') unless defined $result;
    return (1) if $result == 1;
    return (0, 'Bad password');
}

#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_end
{
    my ($self, $context, $user, $p) = @_;
}

1;
