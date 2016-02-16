# Cisco.pm
#
# Updated by Utku Er <utkuer@utkuer.com>
# The old version could not verify ISDN users.
# Cisco cannot use SNMP to get the username of the ISDN users. (asked to TAC ;-))
# So if this is an ISDN user then we'll have to finger NAS
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: Cisco.pm,v 1.5 2012/09/24 22:06:06 mikem Exp $

package Radius::Nas::Cisco;
use Radius::SNMP;
use strict;

# RCS version number of this module
$Radius::Nas::Cisco::VERSION = '$Revision: 1.5 $';

# The Cisco SNMP MIB
# As at 2012, some SNMP tools dont ship with MIBs
#$Radius::Nas::CiscoMIB = '.iso.org.dod.internet.private.enterprises.9';
$Radius::Nas::CiscoMIB = '.1.3.6.1.4.1.9';


#####################################################################
#Format of finger in cisco is like:
#    Line       User       Host(s)              Idle       Location
#   2 tty 2     stas@guven Async interface          -
#   7 tty 7     merkoto@ne Async interface      00:01:21   PPP: 10.1.1.1
#  10 tty 10    asd        Async interface      00:00:00   PPP: 10.1.1.2
#  .....
#  Interface      User        Mode                     Idle     Peer Address
#  Vi8          briuser     Virtual PPP (Bundle) 00:00:00 10.3.3.3
#  Se6:6        briuser     Sync PPP                    -   Bundle: Vi8
#  Se6:28       briuser     Sync PPP                    -   Bundle: Vi8
#  Se7:23       otherbrius  Sync PPP             00:00:03   PPP: 10.4.4.4
#####################################################################
sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;

    return 1 unless &Radius::SNMP::snmpgetprogExists();

    #Checking if this is an ISDN connection
    if ($nas_port > 20000 ) 
    {
        &main::log($main::LOG_DEBUG, "Cisco: Checking ISDN $nas_id:$nas_port:$name" );
	
        my ($result, @lines) = &Radius::Nas::finger("\@$nas_id");
        return 1 if !$result; # Could not finger. Assume still there
	
        # We are getting the "SerialXX:YY" port number for this connection
        # Nas port is structured like 2XXYY. This means SerialXX:YY
        my $part1 = substr($nas_port, 1, 2);
        my $part2 = substr($nas_port, 3, 2);
        my $port = sprintf("Se%d:%d",$part1,$part2); #Sprintf works even XX is zero
        #&main::log($main::LOG_DEBUG, "Cisco:ISDN Part1:$part1 Part2:$part2");
        &main::log($main::LOG_DEBUG, "Cisco:ISDN User is in this port:$port");
        # Finger only shows the first 10 characters of username@domain
        my $nameshort = substr($name, 0, 10);

        my $line;
        foreach $line (@lines)
        {
            if ($line =~ /$port.*$nameshort/) 
	    {
                &main::log($main::LOG_DEBUG, "Cisco: ISDN User online: $line");
                return 1;
            }
        }
        return 0; # not there
    }
    else 
    {
        my $result = &Radius::SNMP::snmpget
	    ($nas_id,
	     $client->{SNMPCommunity},
	     "$Radius::Nas::CiscoMIB.2.9.2.1.18.$nas_port");

	&main::log($main::LOG_DEBUG, "Cisco: snmpget result: $result");
	return uc($1) eq uc($name)
	    if ($result =~ /^.*\"([^"]+)".*$/);
    }

    return 0;
}

1;
