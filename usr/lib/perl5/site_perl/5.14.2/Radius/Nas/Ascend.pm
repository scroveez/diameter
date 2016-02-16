# Ascend.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: Ascend.pm,v 1.3 2012/09/24 22:06:06 mikem Exp $

package Radius::Nas::Ascend;
use Radius::SNMP;
use strict;

# RCS version number of this module
$Radius::Nas::Ascend::VERSION = '$Revision: 1.3 $';

# The Ascend SNMP MIB
# As at 2012, some SNMP tools dont ship with MIBs
#$Radius::Nas::AscendMIB = '.iso.org.dod.internet.private.enterprises.529';
$Radius::Nas::AscendMIB = '.1.3.6.1.4.1.529';

#####################################################################
# Check whether an Ascend Max or similar is online with finger
sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;

    my ($result, @lines) = &Radius::Nas::finger("$name\@$nas_id");
    return 1 if !$result; # Could not finger. Assume still there

    my $line;
    foreach $line (@lines)
    {
	return 1 if $line =~ /Session/;
    }
    return 0; # not there
}

#####################################################################
# Returns a list of active sessions for an Ascend Max
# Walks .iso.org.dod.internet.private.enterprises.529.12.3.1.1
# which is a list of session IDs
sub activeSessions
{
    my ($nas_id, $client) = @_;

    return 1 unless &Radius::SNMP::snmpwalkprogExists();

    my $result = &Radius::SNMP::snmpwalk($nas_id,
			 $client->{SNMPCommunity},
			 "$Radius::Nas::AscendMIB.12.3.1.1");

    return if ($result =~ /error/i);

    # Array of current session IDs
    my @sessions = map {/(\d+)$/ ? $1 : ()} split(/\n/, $result);

    return (1, @sessions)
}

# Forcibly disconnects a user from an Ascend box
# Requires only the session ID to identify which session
sub disconnectUser
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;

    return 1 unless &Radius::SNMP::snmpsetprogExists();

    # Sets the ssnActiveValidFlag for this session_id
    # to 1, which disconnects the user
    my $result = &Radius::SNMP::snmpset($nas_id,
			 $client->{SNMPCommunity},
			 "$Radius::Nas::AscendMIB.12.3.1.3.$session_id",
			 'i', 1);

    return !($result =~ /error/i);
}

1;

