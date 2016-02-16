# TotalControlSNMP.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: TotalControlSNMP.pm,v 1.3 2012/09/24 22:06:06 mikem Exp $

package Radius::Nas::TotalControlSNMP;
use Radius::SNMP;
use strict;

# RCS version number of this module
$Radius::Nas::TotalControlSNMP::VERSION = '$Revision: 1.3 $';

# The 3com TotalControl SNMP MIB
# As at 2012, some SNMP tools dont ship with MIBs
#$Radius::Nas::TCMIB = '.iso.org.dod.internet.private.enterprises.429';
$Radius::Nas::TCMIB = '.1.3.6.1.4.1.429';

#####################################################################
# Check Total Control by using SNMP
# Contributed by Stephen Roderick <steve@proaxis.com>
sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;

    return 1 unless &Radius::SNMP::snmpgetprogExists();

    # Adjusted algorithm contributed by Aaron Nabil <nabil@spiritone.com>
    my $oid = length $session_id;
    my $x;
    foreach $x (unpack('C*', $session_id)) 
    {
        $oid .= ".$x";
    }

    my $result = &Radius::SNMP::snmpget
	($nas_id, $client->{SNMPCommunity},
	 "$Radius::Nas::TCMIB.4.2.1.140.1.2.$oid");

    return ($result =~ /^.*\"([^"]+)".*$/ && $1 eq $name);
}

1;
