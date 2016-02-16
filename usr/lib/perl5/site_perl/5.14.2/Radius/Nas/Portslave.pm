# Portslave.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: Portslave.pm,v 1.3 2012/12/13 20:19:47 mikem Exp $

package Radius::Nas::Portslave;
use strict;

# RCS version number of this module
$Radius::Nas::Portslave::VERSION = '$Revision: 1.3 $';

#####################################################################
# Check Portslave by using finger
sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;

    my $Port_seen = 0;

    my ($result, @lines) = &Radius::Nas::finger("\@$nas_id");
    return 1 if !$result; # Could not finger. Assume still there

    my $line;
    foreach $line (@lines)
    {
	#
	# Check for ^Port. If we don't see it we
	# wont get confused by non-portslave-finger
	# output too.
	if ($line =~ /^Port/) 
	{
	    $Port_seen++;
	    next;
	}
	next if (!$Port_seen);
	next if ($line =~ /^---/);

	my ($port, $user) = $line =~ /^.(...) (...............)/;
	
	$port =~ s/ .*//;
	$user =~ s/ .*//;

	# HACK: strip [PSC] from the front of the username,
	# and things like .ppp from the end.
	$user =~ s/^[PSC]//;
	$user =~ s/\.(ppp|slip|cslip)$//;
	
	# HACK: because ut_user usually has max. 8 characters
	# we only compare up the the length of $user if the
	# unstripped name had 8 chars.
	$name = substr($name, 0, 8)
	    if (length($user) == 8) ;
	
	if ($port == $nas_port) 
	{
	    # OK here is the port we are interested in
	    return $user eq $name;
	}
    }
    return 0; # Not there
}

1;
