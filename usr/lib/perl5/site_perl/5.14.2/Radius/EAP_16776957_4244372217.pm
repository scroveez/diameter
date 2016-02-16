# EAP_16776957_4244372217.pm
#
# Radiator module for handling Authentication via EAP extended type
# vendor 16776957, type 4244372217
# which is a test type used by wpa_supplicant
# Requires CONFIG_EAP_VENDOR_TEST=y in the wpa_supplicant .config file
# and eap=VENDOR-TEST in the wpa_supplicant config file
#
# Note: this module does not implement the full handshake. See below
# for more information.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2011 Open System Consultants
# $Id: EAP_16776957_4244372217.pm,v 1.2 2014/12/02 21:23:40 hvn Exp $

package Radius::EAP_16776957_4244372217;

use strict;

# RCS version number of this module
$Radius::EAP_16776957_4244372217::VERSION = '$Revision: 1.2 $';

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

    return ($main::REJECT, 'VENDOR-TEST not supported. See Radius/EAP_16776957_4244372217.pm');
}

#####################################################################
# Called by EAP.pm when an EAP Response (other than Identity)
# is received. 
# wpa_supplicant VENDOR-TEST just has a simple 4 way handshake with hardwired keys
# Since this module does no authentication, the handshake is disabled in this file.
# The full example comes with Radiator. See goodies/example-code/EAP_16776957_4244372217.pm
sub response
{
    my ($classname, $self, $context, $p, $type, $typedata) = @_;

    return ($main::REJECT, 'VENDOR-TEST not supported. See Radius/EAP_16776957_4244372217.pm');
}

1;
