# Portmaster4.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: Portmaster4.pm,v 1.4 2012/12/13 20:19:47 mikem Exp $

package Radius::Nas::Portmaster4;
use Radius::SNMP;
use strict;

# RCS version number of this module
$Radius::Nas::Portmaster4::VERSION = '$Revision: 1.4 $';

#####################################################################
# Check Portmaster 4 by using pmwho
# The value reported by the PortMaster 4 for NAS-Port in RADIUS
# accounting-request packets has been enhanced to encode the 
# PortMaster 4 slot number (0-9), line number (0-31, although 
# only 0-3 are used now), and channel number (0-31).
# 
# The NAS-Port Number Format in network byte order is as follows:
# 
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    | Channel |  Line   |  Slot |  All zero                         |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# 
# So channel 4 of line 1 in slot 2 is, for example,
# NAS-Port = 2084 (4 + 1 * 32 + 2 * 1024).
# 
# This is from http://www.dataman.nl/ with search query:
# "portmaster 4 radius accounting"
#Port  User            Host/Inet/Dest   Type    Dir Status         Start   Idle
#----- --------------- ---------------- ------- --- ------------- ------ ------
#C0    -               -                Log/Net In  USERNAME           0      0
#C1    -               -                Log/Net In  USERNAME           0      0
#Port  User            Host/Inet/Dest   Type    Dir Status         Start   Idle
#----- --------------- ---------------- ------- --- ------------- ------ ------
#S0    jpampalone@syst ras13230.systec. Netwrk  In  ESTABLISHED    11:29      5
#S1    hugh            ras13265.systec. Netwrk  In  ESTABLISHED       30      0
#S2    MANEMAN         ras13284.systec. Netwrk  In  ESTABLISHED     2:08      0
#S3    hippydude       ras13242.systec. Netwrk  In  ESTABLISHED        2      0
#S4    -               -                Log/Net In  IDLE               0      0
#S5    gzaino          ras13259.systec. Netwrk  In  ESTABLISHED     1:58      0
#S6    DSAMUELS        ras13254.systec. Netwrk  In  ESTABLISHED       44      5
#S7    dazz            ras13212.systec. Netwrk  In  ESTABLISHED       12      6
#S8    MAGRUNSEICH@sys ras13272.systec. Netwrk  In  ESTABLISHED       25      5
#S9    bushill         ras13243.systec. Netwrk  In  ESTABLISHED     6:02      0
#
# The pmwho is encoded with one group of S0-S94 per slot. The
# S number is computed as channel*24 + line
sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;

    if (!-x $main::config->{PmwhoProg})
    {
	&main::log($main::LOG_ERR, "$main::config->{PmwhoProg} is not executable. Check and configure Nas.pm");
	return 1; # Assume the worst
	
    }

    # Mask off the low order bits to get the slot, channel and line
    my $slot    = ($nas_port >> 10) & 0xf;
    my $channel = ($nas_port >> 5) & 0x1f;
    my $line    = $nas_port & 0xf;
    my $wantedport = ($channel * 24) + $line;

    # pmwho listing username might be truncated to 15 chars
    $name = substr($name, 0, 15);
    # The current slot we are up to in parsing;
    my $curslot = -1;

    open (PMWHO, "$main::config->{PmwhoProg} $nas_id|");
    while (<PMWHO>)
    {
	next if (/Port/);
	next if (/---/);
	$curslot++ if /^S0/; # Count which slot we are up to
	my ($port, $user) = split;
	$port =~ s/^S//;
	$user =~ s/^[PSC]//;
	$user =~ s/\.(ppp|slip|cslip)$//;
	
	if ($port == $wantedport && $curslot == $slot) 
	{ 
	    close PMWHO;
	    return ($user eq $name);
	}
    }
    close (PMWHO);
    return 0; # Not there
}

1;
