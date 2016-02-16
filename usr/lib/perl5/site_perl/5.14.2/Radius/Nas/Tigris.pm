# Tigris.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: Tigris.pm,v 1.3 2012/09/24 22:06:06 mikem Exp $

package Radius::Nas::Tigris;
use Radius::SNMP;
use strict;

# RCS version number of this module
$Radius::Nas::Tigris::VERSION = '$Revision: 1.3 $';

# The ACC Tigris SNMP MIP
# As at 2012, some SNMP tools dont ship with MIBs
#$Radius::Nas::AccMIB = '.iso.org.dod.internet.private.enterprises.5';
$Radius::Nas::AccMIB = '.1.3.6.1.4.1.5';

#####################################################################
# ACC's Tigris Terminal Server.  --  rob@rpi.net.au 20/4/1999
#
# This is -only- for Tigris Terminal servers running OS Software LATER OR
# EQUAL TO version 11.4.1.14 - Before this, you had to do horrible things
# to find out if a user was online or not.
#
# This version does a simple SNMP query of the MIB:
# .1.3.6.1.4.1.5.1.1.54.3.1.22.[portnum]
# This returns the username logged into that port.
sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;

    return 1 unless &Radius::SNMP::snmpgetprogExists();

    my $result = &Radius::SNMP::snmpget($nas_id,
			 $client->{SNMPCommunity},
			 "$Radius::Nas::AccMIB.1.1.54.3.1.22.$nas_port");

    if ($result =~ /^.*\"([^"]+)".*$/)
    {			
	return $1 eq $name;
    }
    return 0;
}

1;
