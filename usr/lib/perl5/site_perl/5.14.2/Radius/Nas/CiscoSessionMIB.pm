# CiscoSessionMIB.pm
#
# Contributed by Vangelis Kyriakakis <vkyriak@forthnet.gr>
#
# Uses the new Session MIB available in Cisco IOS 12.2.15T.
# See http://www.cisco.com/univercd/cc/td/doc/product/software/ios121/121newft/121t/121t3/dt_asmib.htm for more details.
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: CiscoSessionMIB.pm,v 1.6 2012/09/24 22:06:06 mikem Exp $
package Radius::Nas::CiscoSessionMIB;
use Radius::SNMP;
use strict;

# RCS version number of this module
$Radius::Nas::CiscoSessionMIB::VERSION = '$Revision: 1.6 $';

# The Cisco SNMP MIB
# As at 2012, some SNMP tools dont ship with MIBs
#$Radius::Nas::CiscoMIB = '.iso.org.dod.internet.private.enterprises.9';
$Radius::Nas::CiscoMIB = '.1.3.6.1.4.1.9';

sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;
    
    return 1 unless &Radius::SNMP::snmpgetprogExists();
    
    &main::log($main::LOG_DEBUG, "CiscoSessionMIB: Checking $session_id->$nas_id:$nas_port:$name" );
    
    # The Session MIB requires the session ID in decimal, but Radius
    # generally receives it in hex, perhaps with spaces and other trash. Sigh.
    # Typical example is 0/0/0/334_000AA9D8
    ($session_id) = $session_id =~ /([0-9a-fA-F]+$)/;
    $session_id = hex($session_id);
    my $result = &Radius::SNMP::snmpget
	($nas_id,
	 $client->{SNMPCommunity},
	 "$Radius::Nas::CiscoMIB.9.150.1.1.3.1.2.$session_id");
    
    return 1 if (!$result || $result =~ /no response/i); # Could not SNMP. Assume still there
    return 0 if $result =~ /no such variable/i;  # Not in the MIB means no such session
    return uc($1) eq uc($name)
	if ($result =~ /^.*\"([^"]+)".*$/);
			      
    return 0; # not there
}

1;
