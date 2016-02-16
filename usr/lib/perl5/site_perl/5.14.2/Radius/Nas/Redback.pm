#Redback.pm
#
# Implements Radiator routines for communicating with a Redback SMS over SNMP
# Calculates SNMP instance from Acct-Session-Id
#
# Author tomkar@estpak.ee with thanks to Friik.
# Copyright (C) Open System Consultants
#

package Radius::Nas::Redback;
use Radius::SNMP;
use strict;

# RCS version number of this module
$Radius::Nas::Redback::VERSION = '$Revision: 1.3 $';

#The Redback SNMP MIB
# As at 2012, some SNMP tools dont ship with MIBs
#$Radius::Nas::RedbackMIB = '.iso.org.dod.internet.private.enterprises.2352';
$Radius::Nas::RedbackMIB = '.1.3.6.1.4.1.2352';


sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;

#These are commented out because there is no support for extra arguments to snmp programs,
# -v 2c in this case, for now it can be defined in config like "SnmpgetProg /usr/bin/snmpget -v 2c"

#    return 1 unless &Radius::SNMP::snmpgetprogExists();


    my $i;
    my @list;
    my @name= split(//,$session_id);
    for ($i=0;$i<@name;$i++){
        my $piece=ord(@name[$i]);
	push (@list,$piece);
    }
    my $snmpacctsessionid=join('.',@list);
    my $objcount = @list."";

    my $instance = "$objcount.$snmpacctsessionid";
    my $result = &Radius::SNMP::snmpget($nas_id,
		$client->{SNMPCommunity},
		"$Radius::Nas::RedbackMIB.2.10.1.1.1.1.2.$instance");
&main::log($main::LOG_DEBUG,"Result = $result/n");
    if ($result =~ /No Such Instance/i) {
        # This is normal when that session does not exist on NAS
        return 0;
    }
    if ($result =~ /INTEGER: 1/i) {
	# Session with that Acct-Session-Id exists on NAS
        return 1;
    }
}
1;
