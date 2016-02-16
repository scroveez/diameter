# TotalControl.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: TotalControl.pm,v 1.3 2012/12/13 20:19:47 mikem Exp $

package Radius::Nas::TotalControl;
use strict;

# RCS version number of this module
$Radius::Nas::TotalControl::VERSION = '$Revision: 1.3 $';

#####################################################################
# Check Total Control by using pmwho
sub isOnline
{
    my ($name, $nas_id, $nas_port, $session_id, $client) = @_;

    if (!-x $main::config->{PmwhoProg})
    {
	&main::log($main::LOG_ERR, "$main::config->{PmwhoProg} is not executable. Check and configure Nas.pm");
	return 1; # Assume the worst
	
    }

    open (PMWHO, "$main::config->{PmwhoProg} $nas_id|");
    while (<PMWHO>)
    {
	next if (/Port/);
	next if (/---/);
	my ($port, $user) = split;
	$port =~ s/^S//;
	$user =~ s/^[PSC]//;
	$user =~ s/\.(ppp|slip|cslip)$//;
	
	if ($port == $nas_port) 
	{ 
	    close PMWHO;
	    return ($user eq $name);
	}
    }
    close (PMWHO);
    return 0; # Not there
}


1;
