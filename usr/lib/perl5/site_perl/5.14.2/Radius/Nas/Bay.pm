# Bay.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: Bay.pm,v 1.3 2012/09/24 22:06:06 mikem Exp $

package Radius::Nas::Bay;
use Radius::SNMP;
use strict;

# RCS version number of this module
$Radius::Nas::Bay::VERSION = '$Revision: 1.3 $';

# The Bay networks SNMP MIB
# As at 2012, some SNMP tools dont ship with MIBs
#$Radius::Nas::BayMIB = '.iso.org.dod.internet.private.enterprises.15';
$Radius::Nas::BayMIB = '.1.3.6.1.4.1.15';

#####################################################################
sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;

    return 1 unless &Radius::SNMP::snmpgetprogExists();

    my $result = &Radius::SNMP::snmpget($nas_id,
			 $client->{SNMPCommunity},
			 "$Radius::Nas::BayMIB.2.16.1.2.1.3.1.$nas_port");
    if ($result =~ /^.*\"([^"]+)".*$/)
    {			
	return $1 eq $name;
    }
    return 0;
}

1;
