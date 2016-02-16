# Colubris.pm
#
# Created by Vangelis Kyriakakis (vkyriak@forthnet.gr)
# Copyright (C) Open System Consultants
#
# Implement Radiator routines for communicating with a given type of NAS
#

package Radius::Nas::Colubris;
use Radius::SNMP;
use strict;

# RCS version number of this module
$Radius::Nas::Colubris::VERSION = '$Revision: 1.3 $';

# The Colubris SNMP MIB
# As at 2012, some SNMP tools dont ship with MIBs
#$Radius::Nas::Colubris = '.iso.org.dod.internet.private.enterprises.8744';
$Radius::Nas::Colubris = '.1.3.6.1.4.1.8744';

sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;

    return 1 unless &Radius::SNMP::snmpgetprogExists();
    
    &main::log($main::LOG_DEBUG, "Colubris: Checking $session_id-> $nas_id:$nas_port:$name" );
    
    my $result = &Radius::SNMP::snmpget
	($nas_id,
	 $client->{SNMPCommunity},
	 "$Radius::Nas::Colubris.5.1.1.3.6.1.6.$nas_port");
    
    return 1 if (!$result || $result =~ /no response/i); # Could not SNMP. Assume still there
    return uc($1) eq uc($name)
	if ($result =~ /^.*\"([^"]+)".*$/);
			      
    return 0; # not there
}

1;
