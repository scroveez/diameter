# AuthROUNDROBIN.pm
#
# Object for handling Authentication with remote radius servers
# This subclass of AuthBy RADIUS implements host selection by
# round robin, including backoffs for failed hosts
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthROUNDROBIN.pm,v 1.8 2013/06/18 21:13:18 hvn Exp $

package Radius::AuthROUNDROBIN;
@ISA = qw(Radius::AuthRADIUS);
use Radius::AuthRADIUS;
use strict;

# RCS version number of this module
$Radius::AuthROUNDROBIN::VERSION = '$Revision: 1.8 $';

#####################################################################
# Choose the next host for the round robin algorithm
# Chooses the 'next' available host.
# 
# Do a real RoundRobin for a not-retried request
# and do a walk of the RR list for a retried request
# Bail out if no working hosts are found or we already
# tried all the hosts in a list.
#

sub chooseHost
{
    my ($self, $fp, $p) = @_;

    my $i = 0; # If all are unavailable, bomb out
    my $time = time;
    my $host_index;
    
    # For a first try, find a working host and remember it if we need to retry it.
    if (not defined($fp->{hostRetries})) {
    	while ($i++ < @{$self->{Hosts}})
        {
            $host_index = $self->{roundRobinCounter}++ % @{$self->{Hosts}};
	    my $host = $self->{Hosts}[$host_index];
	    next unless $host->isWorking();
            $fp->{hostRetries} = 1;
            $fp->{firstHostTried} = $host_index;
            $fp->{lastHostTried} = $host_index;
	    return $host;
        }
        return; # None found
    }

    # This is a retry. Take the next host from the RR list 
    # and try it. If we looped back to the host we tried as
    # first give up.
    while (1)
    {
        $host_index = ($fp->{lastHostTried}+1) % @{$self->{Hosts}};
        $fp->{lastHostTried} = $host_index;
        $self->log($main::LOG_INFO, "AuthROUNDROBIN: Retry " . $fp->{hostRetries} . ", firstHostTried " . $fp->{firstHostTried} . ", lastHostTried " . $fp->{lastHostTried});
        last if ($host_index == $fp->{firstHostTried});
        my $host = $self->{Hosts}[$host_index];
	next unless $host->isWorking();
        $fp->{hostRetries}++;
	return $host;
    }
    $self->log($main::LOG_WARNING, "AuthROUNDROBIN: Request was tried for " . $fp->{hostRetries} . " times. All alive server from the RoundRobin list were tried.");
    return; # None found
}

1;
