#NomadixSNMP.pm
#
# Implements Radiator routines for communicating with a Nomadix USG over SNMP
# Uses snmpwalk to get username indexes and then checks with snmpget 
# by user index if authentication is still "Valid"
#
# Author tomkar@estpak.ee with thanks to Friik.
# Copyright (C) Open System Consultants
#

package Radius::Nas::NomadixSNMP;
use Radius::SNMP;
use strict;

# RCS version number of this module
$Radius::Nas::NomadixSNMP::VERSION = '$Revision: 1.3 $';

#The Nomadix SNMP MIB
# As at 2012, some SNMP tools dont ship with MIBs
#$Radius::Nas::NomadixMIB = '.iso.org.dod.internet.private.enterprises.3309';
$Radius::Nas::NomadixMIB = '.1.3.6.1.4.1.3309';


sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;


#These are commented out because there is no support for extra arguments to snmp programs,
# -v 2c in this case, for now it can be defined in config like "SnmpgetProg /usr/bin/snmpget -v 2c"

#    return 1 unless &Radius::SNMP::snmpgetprogExists();
#    return 1 unless &Radius::SNMP::snmpwalkprogExists();

    #Get a list of usernames online

    my $result = &Radius::SNMP::snmpwalk($nas_id,
		    $client->{SNMPCommunity},
		    "$Radius::Nas::NomadixMIB.1.1.1.2.17.1.1.5");
    return if ($result =~ /error/i);
    #Gets the index for username
    my @sessions = map {/(\d+)(\s=\s\w+\W\s)(\"$name\")$/ ? $1 : ()} split(/\n/, $result);

    #Get the authentication status of that username index
    my $status = &Radius::SNMP::snmpget($nas_id,
		$client->{SNMPCommunity},
		"$Radius::Nas::NomadixMIB.1.1.1.2.17.1.1.8.$sessions[0]");

    #return 1 if status was "Valid" and 0 if not.
    return 1 if $status =~ /Valid/;
    return 0; # not there
}
1;
