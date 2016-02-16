# AuthMULTICAST.pm
#
# Object for handling Authentication with remote radius servers
# This subclass of AuthBy RADIUS forwards the request to ALL
# hosts. This was written to deal with an SLB scenario where
# neighbouring hosts in a cluster must all receive Accounting-On
# and Accounting-Off records so they may respond to NAS reboots
# and reclaim addresses in their privately managed IP pools.
#
# Author: Andrew Ivins (aivins@swiftel.com.au)
# Reproduced courtesy of Andrew Ivins and Swiftel
# Copyright (C) Open System Consultants
# $Id: AuthMULTICAST.pm,v 1.8 2014/08/12 20:58:13 hvn Exp $
# Date: 20040911

package Radius::AuthMULTICAST;
@ISA = qw(Radius::AuthRADIUS);
use Radius::AuthRADIUS;
use strict;

%Radius::AuthMULTICAST::ConfigKeywords =
('LoopDetection'		=>  
 ['flag', 'If this optional parameter is set, Radiator will not forward a request to a Host if the request to be forwarded was originally received from the same address. Defaults to no loop detection.', 1],
 );

# RCS version number of this module
$Radius::AuthMULTICAST::VERSION = '$Revision: 1.8 $';

########################################################################
# forward
# Send the packet to ALL hosts in the list of hosts for this RADIUS.
# $fp is the packet to be sent to the remote server
# $p is the original request packet from the NAS
# Always returns true
sub forward
{
    my ($self, $fp, $p) = @_;

    return unless defined $self->{Hosts};

    while ($fp->{hostRetries} < @{$self->{Hosts}})
    {
        my $host = $self->{Hosts}[$fp->{hostRetries}++];
	next unless $host->isWorking();
	
	# Skip forwarding if a loop is detected
	if ($self->{LoopDetection})
	{
	    my (undef, $srcaddr) = Radius::Util::unpack_sockaddr_in($p->{RecvFrom});
	    my $dstaddr = @{$host->{Address}}[$host->{roundRobinCounter} % @{$host->{Address}}];
	    next if $srcaddr eq $dstaddr;
	}

	# make a copy of the fp reference so that we can run
	# more than one concurrent forwarding
	my $nfp = {};
	%$nfp = %$fp;
	bless($nfp, ref($fp));
  
	# Make sure the host is updated with stats
	push(@{$p->{StatsTrail}}, \%{$host->{Statistics}});
	    
	# Then send the new fp to the host
	$self->sendHost($host, $nfp, $p);
    }
    return 1;
}


#####################################################################
# Called after Retries transmissions to a host without
# a response. Decide what to do next.
# Default behaviour of normal AuthRADIUS is to try to send it to
# another host, which is a behaviour this method overrides. Instead,
# just give up, since all hosts have had data sent to them already.
sub failed
{
    my ($self, $host, $fp, $p) = @_;
                                                                                
    my ($port, $addr) = Radius::Util::unpack_sockaddr_in($fp->{SendTo});
    my $ip = Radius::Util::inet_ntop($addr);
    $self->log($main::LOG_INFO,
               "AuthRADIUS: No reply after $host->{Retries} retransmissions to $ip:$port for $p->{OriginalUserName}  ($p->{Identifier})", $p);
    $host->{backoff_until} = time + $self->{FailureBackoffTime};
    $host->{is_failed} = 1;

    # Don't call failed()
}




