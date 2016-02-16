# Livingston.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: Livingston.pm,v 1.3 2012/09/24 22:06:06 mikem Exp $

package Radius::Nas::Livingston;
use Radius::SNMP;
use strict;

# RCS version number of this module
$Radius::Nas::Livingston::VERSION = '$Revision: 1.3 $';

# The Livingston SNMP MIB
# Not used, see ServerConfig instead
# As at 2012, some SNMP tools dont ship with MIBs
#$Radius::Nas::LivingstonMIB = '.iso.org.dod.internet.private.enterprises.307'
$Radius::Nas::LivingstonMIB = '.1.3.6.1.4.1.307'
    unless defined $Radius::Nas::LivingstonMIB;

#####################################################################
# Uses SNMP, and can be slow
# Returns 1 if the user is still online with the given session id
# $LivingstonOffs is where the last S port is before one or two
#  ports are skipped (22 or 29, for US or Europe)
#  $LivingstonHole is the size of the hole (1 or 2, for US or Europe).
# These global defaults can be changed globally or per-client
# in the configuration file.
sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;

    return 1 unless &Radius::SNMP::snmpgetprogExists();

    # First find out the offset (ugly!!). Also, if the portno
    # is greater than 29, substract 2 (S30 and S31 don't exist).
    # You might need to change this to 23 and 1 for the USA.
    my $result = &Radius::SNMP::snmpget($nas_id,
			 $client->{SNMPCommunity},
			 "$main::config->{LivingstonMIB}.3.2.1.1.1.2.5");
    my ($xport) = ($result =~ /^.*\"S([0-9]+)\".*$/);
    $xport += 0;
    my $portidx = $nas_port + (5 - $xport);
    $portidx -= $client->{LivingstonHole}
	if ($nas_port > $client->{LivingstonOffs});

    $result = &Radius::SNMP::snmpget($nas_id,
		      $client->{SNMPCommunity},
		      "$main::config->{LivingstonMIB}.3.2.1.1.1.5.$portidx");
#    print "------got $result\n";
    my ($id) = ($result =~ /^.*\"([^"]+)".*$/);

    return ($id eq $session_id);
}

1;
