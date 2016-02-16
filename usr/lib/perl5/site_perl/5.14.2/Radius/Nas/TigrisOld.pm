# TigrisOld.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: TigrisOld.pm,v 1.3 2012/09/24 22:06:06 mikem Exp $

package Radius::Nas::TigrisOld;
use Radius::SNMP;
use strict;

# RCS version number of this module
$Radius::Nas::TigrisOld::VERSION = '$Revision: 1.3 $';

# The ACC Tigris SNMP MIP
# As at 2012, some SNMP tools dont ship with MIBs
#$Radius::Nas::AccMIB = '.iso.org.dod.internet.private.enterprises.5';
$Radius::Nas::AccMIB = '.1.3.6.1.4.1.5';

#####################################################################
# ACC's Tigris Terminal Server.  --  rob@rpi.net.au 19/4/1999
#
# This is -only- for Tigris Terminal servers running OS Software PRIOR
# to version 11.4.1.14 - After this, there is a much better way to do it.
# 
# Oh, god, this thing is an abomination to get info from.
# We have -two- different mibs to look -through-.  There's no direct
# port->username mapping in there at all. We start with the username mib,
# enterprise.5.1.1.31.12.1.2.200 through to 300, looking for the
# username. When we find it, we then take the number we found it on,
# and look at 5.1.1.31.12.1.3.[number] which will then give us the port
# number that user is on.  Sensible, isn't it. *sigh*
#
# rewritten by ragnar@uninet.ee 25/11/1999
# use snmpwalk to get id->user map and get id->post map.
# put them together and make port->user map.
# scanning with snmpget is probably slower than snmpwalk.
# ranges (200..300) differs from host to host. mine is (0..100).
sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;
  
    &Radius::SNMP::snmpwalkprogExists()
 	|| return 1;
    
    &main::log($main::LOG_NOTICE, "TigrisOld: Checking $nas_id:$nas_port:$name" );
 
    my $list;
 
    # make id->user map
    $list = &Radius::SNMP::snmpwalk
	(
	 $nas_id,
	 $client->{SNMPCommunity},
	 "$Radius::Nas::AccMIB.1.1.31.12.1.2"
	 );
    my %users = map {
	/^[a-z0-9\.]+\.(\d+)\s*=\s*"([^"]+)"/o ?
 		($1=>$2) :
 		()
 	} split "\n", $list;
 
 	# make id->port map
 	$list = &Radius::SNMP::snmpwalk(
 		$nas_id,
 		$client->{SNMPCommunity},
 		"$Radius::Nas::AccMIB.1.1.31.12.1.3"
 	);
 	my %ports = map {
 		/^[a-z0-9\.]+\.(\d+)\s*=\s*(\d+)/o ?
 		($1=>$2) :
 		()
 	} split "\n", $list;
 
 	# create port->user map
 	my %port_user = map {
 		$ports{$_} => $users{$_}
 	} keys %ports;
 
 	my $p = \$port_user{$nas_port};
 	return ( (defined $$p && $$p eq $name) ? 1 : 0 );

}

1;
