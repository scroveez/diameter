# NortelCVX1800.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: NortelCVX1800.pm,v 1.3 2012/09/24 22:06:06 mikem Exp $

package Radius::Nas::NortelCVX1800;
use Radius::SNMP;
use strict;

# RCS version number of this module
$Radius::Nas::NortelCVX1800::VERSION = '$Revision: 1.3 $';

# The Nortel CVX 1800
# As at 2012, some SNMP tools dont ship with MIBs
#$Radius::Nas::CVXMIB = '.iso.org.dod.internet.private.enterprises.2637';
$Radius::Nas::CVXMIB = '.1.3.6.1.4.1.2637';

#####################################################################
# Check Nortel by using SNMP
# Contributed by James H. Thompson <jht@lj.net>
# This routine depends on particular Nortel CVX config settings:
#
# parameter: session_id_style
# config path: system/ip_services/ip_aaa_remote/ip_aaa_group <number>/
#    ip_aaa_radius_config <number>>
# command: set session_id_style hex
#
# parameter: session_id_size
# config path: system/ip_services/ip_aaa_remote/ip_aaa_group <number>/
#    ip_aaa_radius_config <number>>
# command: set session_id_size 64_bit
#
sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;


    return 1 unless &Radius::SNMP::snmpgetprogExists();

    #$session_id is in format: BAF46AA6:00006D0B
    #where number after the colon is the session number in hex
    my $nas_session = unpack("N",pack("H16",(split(/:/,$session_id))[1]));
    my $result = &Radius::SNMP::snmpget($nas_id,
			 $client->{SNMPCommunity},
			 "$Radius::Nas::CVXMIB.2.2.102.1.12.$nas_session");

    if ($result =~ /error/i) 
    {
	# some errors might be OK, we get an error when the 
	# session number doesn't exist on the Nortel.
        return 0;
    }

    my $session_name;
    if ($result =~ /^.*\"([^"]+)".*$/)
    {			
        $session_name = $1;
        return 0 if $session_name ne $name;
        #might still be OK if active flag is zero

        $result = &Radius::SNMP::snmpget($nas_id,
			 $client->{SNMPCommunity},
			 "$Radius::Nas::CVXMIB.2.2.102.1.3.$nas_session");

        if ($result =~ /error/i) 
	{
	    # some errors might be OK, we get an error 
	    # when the session number
	    # doesn't exist on the Nortel.
            return 0;
	}
        if ($result =~ /^.*=\s*(\S+)\s*$/) 
	{
            return 1 == $1;
	}
    }
    return 0;
}
1;
