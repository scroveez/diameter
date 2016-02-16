# PortslaveLinux.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: PortslaveLinux.pm,v 1.3 2012/12/13 20:19:47 mikem Exp $

package Radius::Nas::PortslaveLinux;
use strict;

# RCS version number of this module
$Radius::Nas::PortslaveLinux::VERSION = '$Revision: 1.3 $';

#####################################################################
# Check Portslave runing on Linux by using finger
# Format is something like this
#Login    Name                 Tty   Idle  Login Time   Office     Office Phone
#brahms   Ken Wood             *E17    34  Feb 22 16:03 (017:P.129.224)
#bulldog1 Bruce Davey          *E4      5  Feb 22 16:31 (004:P.129.184)
#
sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;

    my $Login_seen = 0;

    my ($result, @lines) = &Radius::Nas::finger("\@$nas_id");
    return 1 if !$result; # Could not finger. Assume still there

    my $line;
    foreach $line (@lines)
    {
	#
	# Check for ^Port. If we don't see it we
	# wont get confused by non-portslave-finger
	# output too.
	if ($line =~ /^Login/) 
	{
	    $Login_seen++;
	    next;
	}
	next if (!$Login_seen);

	my ($user, $fullname, $port) = $line =~ /^(\S+)\s+(\S*)\s+\*?E(\d+)/;
	next unless defined $user;
	
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
