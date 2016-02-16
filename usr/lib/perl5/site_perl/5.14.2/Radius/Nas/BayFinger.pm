# BayFinger.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: BayFinger.pm,v 1.3 2012/12/13 20:19:47 mikem Exp $

package Radius::Nas::BayFinger;
use Radius::SNMP;
use strict;

# RCS version number of this module
$Radius::Nas::BayFinger::VERSION = '$Revision: 1.3 $';

#####################################################################
# Check on Bay/Xylo products with finger - *NOTE* - Requires you to
# -not- have 'finger' in 'disabled_modules'.  The default setup is
# to allow finger connections, so this will not work ONLY if you have
# changed it from default.
#
# Format of finger is:
# Port  What User             Location         When          Idle  Address
# asy1  PPP  hourigan         ---              11:23pm        :02  203.41.12.101
sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;

    my ($result, @lines) = &Radius::Nas::finger("$name\@$nas_id");
    return 1 if !$result; # Could not finger. Assume still there

    my $line;
    foreach $line (@lines)
    {
	return 1 if $line =~ /asy$nas_port/;
    }
    return 0; # not there
}

1;
