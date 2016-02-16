# Cyclades.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: Cyclades.pm,v 1.3 2012/09/24 22:06:06 mikem Exp $

package Radius::Nas::Cyclades;
use Radius::SNMP;
use strict;

# RCS version number of this module
$Radius::Nas::Cyclades::VERSION = '$Revision: 1.3 $';

# The Cyclades SNMP MIB
# As at 2012, some SNMP tools dont ship with MIBs
#$Radius::Nas::CycladesMIB = '.iso.org.dod.internet.private.enterprises.2925'
$Radius::Nas::CycladesMIB = '.1.3.6.1.4.1.2925'
    unless defined $Radius::Nas::CycladesMIB;

#####################################################################
# Uses SNMP, and can be slow
# Returns 1 if the user is still online on the given port
sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;

    return 1 unless &Radius::SNMP::snmpgetprogExists();

# based on email from nei@cyclades.com, 2000.12.08
    my $cyport = $nas_port % 100;
    $cyport += ( $nas_port > 300 ) ? 17 : 9;
    $cyport += ( $nas_port > 300 ) ? 22 : 8 if ( $nas_port % 100 > 8 );

    &main::log($main::LOG_DEBUG,"--- Checking nas_port = $nas_port, oid = $cyport");

    my $result = &Radius::SNMP::snmpget($nas_id,
		      $client->{SNMPCommunity},
		      "$Radius::Nas::CycladesMIB.3.3.6.1.1.2.$cyport");

    &main::log($main::LOG_DEBUG, "--- Result $result =? $name");

    return ($result eq $name);
}

1;
