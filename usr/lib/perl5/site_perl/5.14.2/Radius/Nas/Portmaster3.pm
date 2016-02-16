# Portmaster3.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: Portmaster3.pm,v 1.4 2012/12/13 20:19:47 mikem Exp $

package Radius::Nas::Portmaster3;
use Radius::SNMP;
use strict;

# RCS version number of this module
$Radius::Nas::Portmaster3::VERSION = '$Revision: 1.4 $';

#####################################################################
# Modified by GH3 on 9/6/01
sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;

    return 1 unless &Radius::SNMP::snmpgetprogExists();

    my $portidx = $nas_port + 2;

    $portidx -= $client->{LivingstonHole}
    if ($nas_port > $client->{LivingstonOffs});

    my $result = &Radius::SNMP::snmpget
	($nas_id,
	 $client->{SNMPCommunity},
	 "$main::config->{LivingstonMIB}.3.2.1.1.1.5.$portidx");
#    print "------got $result\n";
    my ($id) = ($result =~ /^.*\"([^"]+)".*$/);

    return ($id eq $session_id);
}

1;
