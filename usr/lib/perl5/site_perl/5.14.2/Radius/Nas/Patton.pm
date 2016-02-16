# Patton.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: Patton.pm,v 1.3 2012/12/13 20:19:47 mikem Exp $

package Radius::Nas::Patton;
use Radius::SNMP;
use strict;

# RCS version number of this module
$Radius::Nas::Patton::VERSION = '$Revision: 1.3 $';

# Patton
$Radius::Nas::PattonMIB = '.1.3.6.1.4.1.1768.5.100.1.40';

#####################################################################
sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client, $framed_ip_address) = @_;

    return 1 unless &Radius::SNMP::snmpgetprogExists();

    # This just checks if the session is still active, not who
    # owns the session
    my $result = &Radius::SNMP::snmpget($nas_id,
			 $client->{SNMPCommunity},
			 "$Radius::Nas::PattonMIB.$session_id");
    return $result ? 1 : 0;
}

1;
