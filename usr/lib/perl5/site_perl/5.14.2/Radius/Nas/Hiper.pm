# Hiper.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: Hiper.pm,v 1.3 2012/09/24 22:06:06 mikem Exp $

package Radius::Nas::Hiper;
use Radius::SNMP;
use strict;

# RCS version number of this module
$Radius::Nas::Hiper::VERSION = '$Revision: 1.3 $';

# The HiPer ARC SNMP MIB
# As at 2012, some SNMP tools dont ship with MIBs
#$Radius::Nas::HiperMIB = '.iso.org.dod.internet.private.enterprises.429';
$Radius::Nas::HiperMIB = '.1.3.6.1.4.1.429';

#####################################################################
sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;

    return 1 unless &Radius::SNMP::snmpgetprogExists();
    # Adjust the port number, as described by 
    # jesus.diaz@telia-iberia.com
    my $usr_if_ix = $nas_port + 1256;
    my $result = &Radius::SNMP::snmpget($nas_id,
			 $client->{SNMPCommunity},
			 "$Radius::Nas::HiperMIB.4.10.1.1.18.$usr_if_ix");
    if ($result =~ /^.*\"([^"]+)".*$/)
    {			
	return $1 eq $name;
    }
    return 0;
}

1;
