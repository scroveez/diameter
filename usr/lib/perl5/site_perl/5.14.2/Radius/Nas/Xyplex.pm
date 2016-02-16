# Xyplex.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: Xyplex.pm,v 1.4 2012/12/13 20:19:47 mikem Exp $

package Radius::Nas::Xyplex;
use Radius::SNMP;
use strict;

# RCS version number of this module
$Radius::Nas::Xyplex::VERSION = '$Revision: 1.4 $';

#####################################################################
# Check whether a Xyplex or similar is online with finger
# Xyplex finger results look like this:
#User Name        Port   Idle   Login        Port Name        
#Status            
#omegatv            1  00:00:00 24-Feb 13:57 PPP001.THE   PPP
#bouris             4  00:00:00 24-Feb 13:56 PPP004.THE   PPP
#sivris             6  00:00:00 24-Feb 13:54 PPP006.THE   PPP
sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;

    my ($result, @lines) = &Radius::Nas::finger("\@$nas_id");
    return 1 if !$result; # Could not finger. Assume still there

    my $line;
    foreach $line (@lines)
    {
	if ($line =~ /(\S+)\s+(\d+)/ 
	    && $1 eq $name 
	    && $2 == $nas_port)
	{
	    return 1;
	}
    }
    return 0; # not there
}

1;
