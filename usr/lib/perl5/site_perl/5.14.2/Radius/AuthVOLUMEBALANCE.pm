# AuthVOLUMEBALANCE.pm
#
# Object for handling Authentication with remote radius servers
# This subclass of AuthBy RADIUS implements host selection by
# volume balancing, including backoffs for failed hosts
#
# The volume balancing is based on the BogoMips rating for each
# host. The hosts with the largest BogoMips get the most requests
# sent to them. All hosts will get a proportion of requests, 
# based in the relative sizes of their BogoMips rating.
# If all hosts have the same number of BogoMips,
# the result is identical to ProxyAlgorithm ROUNDROBIN.
# A Host with BogoMips set to 0 will not be a candidate for proxying
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthVOLUMEBALANCE.pm,v 1.11 2014/09/09 20:57:29 hvn Exp $

package Radius::AuthVOLUMEBALANCE;
@ISA = qw(Radius::AuthRADIUS);
use Radius::AuthRADIUS;
use strict;

# RCS version number of this module
$Radius::AuthVOLUMEBALANCE::VERSION = '$Revision: 1.11 $';

#####################################################################
# Choose the next host for the volumebalance algorithm
sub chooseHost
{
    my ($self, $fp, $p) = @_;

    my ($host, $selectedhost, $summips, $highestchance);
    my $time = time;
    # First work out the total available BogoMips, and see if 
    # there is a host with a chance of being selected
    foreach $host (@{$self->{Hosts}})
    {
	next unless $host->isWorking() && $host->{BogoMips};
	$summips += $host->{BogoMips};
    }

    if ($summips == 0 || $fp->{hostRetries} >= @{$self->{Hosts}}) # No available hosts
    {
	$self->log($main::LOG_WARNING, 
	       "ProxyAlgorithm VOLUMEBALANCE Could not find a working host to proxy to", $p);
	return; # None found
    }

    # Now increment each hosts chances according to its available
    # Capacity, and choose the one that now has the highest chance
    # The total of all increments will be certainty (1)
    foreach $host (@{$self->{Hosts}})
    {
	next unless $host->isWorking() && $host->{BogoMips};
	$host->{selectionChance} += ($host->{BogoMips} / $summips);
	if ($host->{selectionChance} > $highestchance)
	{
	    $highestchance = $host->{selectionChance};
	    $selectedhost = $host;
	}
    }
    # Now reduce the chance of the selected host by certainty (1)
    $selectedhost->{selectionChance} -= 1 if $selectedhost;
    $fp->{hostRetries}++;

    return $selectedhost;
}

1;
