# EAP_16776957_4244372217.pm
#
# Radiator module for handling Authentication via EAP extended type
# vendor 16776957, type 4244372217
# which is a test type used by wpa_supplicant
# Requires CONFIG_EAP_VENDOR_TEST=y in the wpa_supplicant .config file
# and eap=VENDOR-TEST in the wpa_supplicant config file
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2011 Open System Consultants
# $Id: EAP_16776957_4244372217.pm,v 1.1 2011/11/19 00:02:45 mikem Exp $

package Radius::EAP_16776957_4244372217;

use strict;

# RCS version number of this module
$Radius::EAP_16776957_4244372217::VERSION = '$Revision: 1.1 $';

#####################################################################
# Called by EAP.pm when the caller wants to know the EAP type name this class supports
sub type_name
{
    my ($classname) = @_;

    return 'WPA-SUPPLICANT-VENDOR-TEST';
}

#####################################################################
# Called by EAP.pm when an EAP Response/Identity is received
sub response_identity
{
    my ($classname, $self, $context, $p) = @_;

    $self->eap_request_expanded($p->{rp}, $context, 0xfcfbfaf9, 0xfffefd, pack('C', 1));
    return ($main::CHALLENGE, 'VENDOR-TEST Challenge 1');
}

#####################################################################
# Called by EAP.pm when an EAP Response (other than Identity)
# is received. 
# wpa_supplicant VENDOR-TEST just has a simple 4 way handshake with hardwired keys
sub response
{
    my ($classname, $self, $context, $p, $type, $typedata) = @_;

    if ($typedata eq pack('C', 2))
    {
	$self->eap_request_expanded($p->{rp}, $context, 0xfcfbfaf9, 0xfffefd, pack('C', 3));
	return ($main::CHALLENGE, 'VENDOR-TEST Challenge 3');
    }
    elsif ($typedata eq pack('C', 4))
    {
	# Handshake finished, make fake keys that wpa_supplicant expects
	$p->{rp}->change_attr('MS-MPPE-Send-Key', pack('C', 0x11) x 32);
	$p->{rp}->change_attr('MS-MPPE-Recv-Key', pack('C', 0x11) x 32);
	$self->eap_success($p->{rp}, $context);
	return ($main::ACCEPT); # Success, all done
    }
    else
    {
	return ($main::REJECT, 'VENDOR-TEST unknown handshake');
    }
}

1;
