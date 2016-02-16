# EAP_5.pm
#
# Module for  handling Authentication via EAP type 5 
# (one-time-password)
#
# See RFCs 2869 2284 1994
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001 Open System Consultants
# $Id: EAP_5.pm,v 1.10 2012/06/27 23:27:18 mikem Exp $

package Radius::EAP_5;
use strict;

# RCS version number of this module
$Radius::EAP_5::VERSION = '$Revision: 1.10 $';

#####################################################################
# Called by EAP.pm when the caller wants to know the EAP type name this class supports
sub type_name
{
    my ($classname) = @_;

    return 'OTP';
}

#####################################################################
# request
# Called by EAP.pm when a request is received for this protocol type
sub request
{
    my ($classname, $self, $context, $p, $data) = @_;

    return $self->eap_error('Unexpected EAP request');
}

#####################################################################
# Called by EAP.pm when an EAP Response/Identity is received
sub response_identity
{
    my ($classname, $self, $context, $p) = @_;

    my $challenge = $self->otp_challenge($context->{identity}, $p, $context);
    $self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_OTP, $challenge);
    return ($main::CHALLENGE, 'EAP OTP Challenge');
}

#####################################################################
# Called by EAP.pm when an EAP Response (other than Identity)
# is received
sub response
{
    my ($classname, $self, $context, $p, $type, $typedata) = @_;

    # OTP per RFC 1938
    # This should be a response to a request for a
    # one time password. Call this classes check_plain_password 
    # function
    if ($self->otp_verify($context->{identity}, $typedata, $p, $context))
    {
	$self->eap_success($p->{rp}, $context);
	$self->adjustReply($p);
	return ($main::ACCEPT);
    }
    else
    {
	$self->eap_failure($p->{rp}, $context);
	return ($main::REJECT, 'EAP OTP failed');
    }
}

1;
