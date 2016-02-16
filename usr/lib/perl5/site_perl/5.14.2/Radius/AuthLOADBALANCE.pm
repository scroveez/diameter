# AuthLOADBALANCE.pm
#
# Object for handling Authentication with remote radius servers
# This subclass of AuthBy RADIUS implements host selection by
# load balancing, including backoffs for failed hosts.
# The load balancing is based on the request turnaround time
# (the time taken to process the request
# as measured by the proxying Radiator), scaled with the per-host
# BogoMips number.
# A Host with BogoMips set to 0 will not be a candidate for proxying
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthLOADBALANCE.pm,v 1.6 2013/06/18 21:13:18 hvn Exp $

package Radius::AuthLOADBALANCE;
@ISA = qw(Radius::AuthRADIUS);
use Radius::AuthRADIUS;
use Time::HiRes;
use strict;

# RCS version number of this module
$Radius::AuthLOADBALANCE::VERSION = '$Revision: 1.6 $';

#####################################################################
# Choose the next host for the loadbalancing algorithm
# Chooses the host with the smallest average processing time
sub chooseHost
{
    my ($self, $fp, $p) = @_;

    my $time = time;
    # Choose the host with the smallest average biassed 
    # processing time
    my $smallesttime = 1000000000;
    my ($host, $selectedhost);
    foreach $host (@{$self->{Hosts}})
    {
	next unless $host->isWorking();
	next if $host->{BogoMips} == 0;
	# Gradually rehabilitate hosts with long times
	# If we dont do this, their response time will
	# never be remeasured.
	$host->{averageProcTime} -= $host->{averageProcTime} / 100;

	if ($host->{averageProcTime} < $smallesttime)
	{
	    $smallesttime = $host->{averageProcTime};
	    $selectedhost = $host;
	}
    }
    $self->log($main::LOG_WARNING, 
	       "ProxyAlgorithm LOADBALANCE Could not find a working host to proxy to", $p) if !$selectedhost;
    $fp->{LastSendUTime} = &Time::HiRes::time();
    return $selectedhost;
}

#####################################################################
# Called when a reply is successfully received and after it is relayed
# back to the NAS
sub succeeded
{
    my ($self, $host, $p, $op, $sp) = @_;

    # See how long it took to be processed, and adjust the load
    # balancing average processing time
    my $proc_time = &Time::HiRes::time() - $sp->{LastSendUTime};
    # Calculate a moving window average, biassed by BogoMips
    my $biassed_proc_time = $proc_time * $host->{BogoMips};
    $host->{averageProcTime} += 
	($biassed_proc_time - $host->{averageProcTime}) / 10;
}

1;
