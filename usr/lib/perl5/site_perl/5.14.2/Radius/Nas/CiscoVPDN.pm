# CiscoVPDN.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: CiscoVPDN.pm,v 1.3 2012/12/13 20:19:47 mikem Exp $

package Radius::Nas::CiscoVPDN;
use Radius::SNMP;
use strict;

# RCS version number of this module
$Radius::Nas::CiscoVPDN::VERSION = '$Revision: 1.3 $';

#####################################################################
# Use SNMP to check if a user is amongst the VPDN terminated users
# Contributed by "Jesús M Díaz" <jesus.diaz@telia-iberia.com>
#
# From his notes:
# 'isOnlineCisco' doesn't
# work fine. why? because that functions search the user among directly
# connected ones and not among those connected via VPDN interfaces
# (Virtual-Access), created dinamicly by a l2tp, pptp or l2f tunnel.
sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;

    &Radius::SNMP::snmpwalkprogExists() || return 1;

    &main::log($main::LOG_NOTICE, "CiscoVPDN: Checking $nas_id:$nas_port:$name" );

    my $list;

    # make port->id map
    $list = &Radius::SNMP::snmpwalk
        (
         $nas_id,
         $client->{SNMPCommunity},
         '.1.3.6.1.2.1.2.2.1.2'
         );


    my %ports = map { /^[a-z0-9\.]+\.(\d+)\s*=\s*Virtual\-Access(\d+)/i ? ($2=>$1) : () } split "\n", $list;

    return 0 if !defined $ports{$nas_port};

    # make id->if map
    $list = &Radius::SNMP::snmpwalk(
            $nas_id,
            $client->{SNMPCommunity},
            '.1.3.6.1.4.1.9.10.24.1.3.2.1.11'
    );

    my %ifs = map { /^[a-z0-9\.]+\.(\d+)\s*=\s*(\d+)/i ? ($2=>$1) : () } split "\n", $list;

    return 0 if !defined $ifs{$ports{$nas_port}};

    # make if->user map
    $list = &Radius::SNMP::snmpwalk(
            $nas_id,
            $client->{SNMPCommunity},
            '.1.3.6.1.4.1.9.10.24.1.3.2.1.2'
    );

    my %users = map { /^[a-z0-9\.]+\.(\d+)\s*=\s*\"(.+)\"/i ? ($1=>$2) : () } split "\n", $list;

    return 0 if !defined $users{$ifs{$ports{$nas_port}}};
    return $users{$ifs{$ports{$nas_port}}} eq $name;
}

1;

