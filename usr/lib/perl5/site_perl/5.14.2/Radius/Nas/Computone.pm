# Computone.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: Computone.pm,v 1.3 2012/12/13 20:19:47 mikem Exp $

package Radius::Nas::Computone;
use strict;

# RCS version number of this module
$Radius::Nas::Computone::VERSION = '$Revision: 1.3 $';

#####################################################################
# Check whether an Computone Powerrack or similar is online with finger
sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;

    my ($result, @lines) = &Radius::Nas::finger("\@$nas_id");
    return 1 if !$result; # Could not finger. Assume still there

    my $line;
    foreach $line (@lines)
    {  
	return 1 if index($line, $name) > -1;
    }
    return 0; # Not there
}

1;
