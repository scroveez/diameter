# PortslaveMoxa.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: PortslaveMoxa.pm,v 1.3 2012/12/13 20:19:47 mikem Exp $

package Radius::Nas::PortslaveMoxa;
use strict;

# RCS version number of this module
$Radius::Nas::PortslaveMoxa::VERSION = '$Revision: 1.3 $';

#####################################################################
# Check Portslave runing on Linux/Moxa by using finger
#Added by Le Anh Tuan, 27/05/2000
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
#Port  User            Host/Inet/Dest   Type    Dir Status         Start
#Idle
#----- --------------- ---------------- ------- --- ------------- ------ ------
#C0    -               -                Log/Net In  USERNAME           00
#C1    -               -                Log/Net In  USERNAME           00
#Port  User            Host/Inet/Dest   Type    Dir Status         StartIdle
#----- --------------- ---------------- ------- --- ------------- ------ ------
#S0    jpampalone@syst ras13230.systec. Netwrk  In  ESTABLISHED    11:295
#S1    hugh            ras13265.systec. Netwrk  In  ESTABLISHED       300
#S2    MANEMAN         ras13284.systec. Netwrk  In  ESTABLISHED     2:080
#S3    hippydude       ras13242.systec. Netwrk  In  ESTABLISHED        20
#S4    -               -                Log/Net In  IDLE               00
#S5    gzaino          ras13259.systec. Netwrk  In  ESTABLISHED     1:580
#S6    DSAMUELS        ras13254.systec. Netwrk  In  ESTABLISHED       445
#S7    dazz            ras13212.systec. Netwrk  In  ESTABLISHED       126
#S8    MAGRUNSEICH@sys ras13272.systec. Netwrk  In  ESTABLISHED       255
#S9    bushill         ras13243.systec. Netwrk  In  ESTABLISHED     6:020
#
sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;
    
    my $Login_seen = 0;
    my ($result, @lines) = &Radius::Nas::finger("\@$nas_id");
    return 1 if !$result; # Could not finger. Assume still there
    my $line;
    
    $name = substr($name, 0, 15);
    
    foreach $line (@lines)
    {
	$_ = $line;
	next if (/Port/);
	next if (/---/);
	next if !(/^S/);
	my ($port, $user) = split;
	$port =~ s/^S//;
	return ($user eq $name)
	    if ($port == $nas_port);
			    
    }
    return 0; # Not there
}

1;

