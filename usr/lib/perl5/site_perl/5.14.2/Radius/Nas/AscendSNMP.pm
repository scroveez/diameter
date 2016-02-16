# AscendSNMP.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: AscendSNMP.pm,v 1.4 2012/09/24 22:06:06 mikem Exp $

package Radius::Nas::AscendSNMP;
use Radius::SNMP;
use strict;

# RCS version number of this module
$Radius::Nas::AscendSNMP::VERSION = '$Revision: 1.4 $';

# The Ascend SNMP MIB
# As at 2012, some SNMP tools dont ship with MIBs
#$Radius::Nas::AscendMIB = '.iso.org.dod.internet.private.enterprises.529';
$Radius::Nas::AscendMIB = '.1.3.6.1.4.1.529';

#####################################################################
sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;

    return 1 unless &Radius::SNMP::snmpgetprogExists();

    my $result = &Radius::SNMP::snmpget($nas_id,
			 $client->{SNMPCommunity},
			 "$Radius::Nas::AscendMIB.12.2.1.3.$nas_port");
    # Some people have better results with this:
    #                    "$Radius::Nas::AscendMIB.12.3.1.4.$session_id");
    # 'cause the MAX6000 (TAOS 8.0.1+) returns session id in decimal not
    # octal. Reported by Pavel A Crasotin <pavel@ctk.ru>

    # Some people have better results with this:
    # "$Radius::Nas::AscendMIB.12.3.1.4." . oct("0x$session_id"));

    if ($result =~ /^.*\"([^"]+)".*$/)
    {			
	return $1 eq $name;
    }
    return 0;
}

1;
