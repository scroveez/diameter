# Shiva.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: Shiva.pm,v 1.3 2012/12/13 20:19:47 mikem Exp $

package Radius::Nas::Shiva;
use strict;

# RCS version number of this module
$Radius::Nas::Shiva::VERSION = '$Revision: 1.3 $';

# Shiva finger results look like this:
#
# Shiva LanRover Access Switch, Version 5.4.2 98/08/05
# ShivOS Finger server. Uptime: 20:33:40 
# 
# finger log, users, processes
# 
# Call                      WAN        Modem  
#  Int Activity     User (sl/ln/ts) (sl/un/txspd/rxspd) Login Idle IP-Address
#   28      ppp pm039790   5/ 1/ 19   7/ 0/50000/28800  175     0  210.172.154.44
sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;

    # This is a very rough and ready test: the finger data from Shiva
    # includes slot details, but not radius port numbers. The
    # mapping between radius port number and sl/ln/ts depends
    # on the config of the Shiva. Without that info we can only test 
    # the correspondence between the 2 least sig digits of the NAS-Port
    # and the /ts number

    my $online = 0;
    my $last2digits = $nas_port % 100;

    my ($result, @lines) = &Radius::Nas::finger("\@$nas_id");
    return 1 if !$result; # Could not finger. Assume still there

    my $line;
    foreach $line (@lines)
    {  
	# Look for lines like this:
	#   28      ppp pm039790   5/ 1/ 19   7/ 0/50000/28800  175     0  210.172.154.44
	if ($line =~ /\s*\d+\s+\w+\s+(\w+)\s+\d+\/\s*\d+\/\s*(\d+)/)
	{
	    # its a user details line, check the user name and 
	    # last 2 digits of the port against 
	    if ($1 eq $name && $2 == $last2digits)
	    {
		return 1;
	    }
	}
    }
    return 0; # Not there
}

1;
