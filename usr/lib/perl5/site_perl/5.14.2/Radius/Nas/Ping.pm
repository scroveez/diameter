# Ping.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: Ping.pm,v 1.3 2012/12/13 20:19:47 mikem Exp $

package Radius::Nas::Ping;
use Net::Ping;
use strict;

# RCS version number of this module
$Radius::Nas::Ping::VERSION = '$Revision: 1.3 $';

# The timeout to be used for doing pings
$Radius::Nas::PingTimeout = 1;

#####################################################################
# Check whether a user is still connected by pinging the
# Framed-IP-Address from the SessionDatabase SQL 
# This is not foolproof, as we may have missed a stop and the address
# may have been reallocated in the meantime
sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client, $framed_ip_address) = @_;

    # No framed-IP address?
    return 0 unless $framed_ip_address;

    # Build a ping packet
    my $p = Net::Ping->new("icmp");

    # and send it with a one second timeout
    my $ret = $p->ping($framed_ip_address, $Radius::Nas::PingTimeout);
    $p->close();     

    return $ret; # there = 1, not there = 0
}

1;
