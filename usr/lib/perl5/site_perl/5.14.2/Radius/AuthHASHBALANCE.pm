# AuthHASHBALANCE.pm
#
# Object for handling Authentication with remote radius servers
# This subclass of AuthBy RADIUS implements host selection by
# a hash of a range of attributes in the incoming requests, with the
# intention that all related requests go to the same target server, enabling stateful
# RADIUS transactions to be loadbalanced without interfering with streams 
# of related requests.
# Hint: in EAP capable environments and environments where all RADIUS clients are known to support 
# the RADIUS State attribtue correctly, AuthBy HASBALANCE is deprtecated in favour of 
# AuthBy EAPBALANCE, which has stronger protection for EAP streams.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthHASHBALANCE.pm,v 1.14 2011/09/20 22:15:34 mikem Exp $

package Radius::AuthHASHBALANCE;
@ISA = qw(Radius::AuthRADIUS);
use Radius::AuthRADIUS;
use Radius::EAP;
use Digest::MD5;
use strict;

%Radius::AuthHASHBALANCE::ConfigKeywords =
(
 'HashAttributes' => 
 ['string', 'Specifies which attributes in the incoming request will be used to select the target RADIUS server. ', 1],

);

# RCS version number of this module
$Radius::AuthHASHBALANCE::VERSION = '$Revision: 1.14 $';

#####################################################################
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{HashAttributes} = '%{Request:Calling-Station-Id}:%n';
}

#####################################################################
# Choose the host for this request
sub chooseHost
{
    my ($self, $fp, $p) = @_;

    my $time = time;
    
    # Hash a number of attributes from the request and use that to choose
    # a preferred host
    my $numhosts = @{$self->{Hosts}};
    if (!defined $fp->{hashbalance_start_index})
    {
	my $hash_attrs = &Radius::Util::format_special($self->{HashAttributes}, $p);
	my $hash = Digest::MD5::md5($hash_attrs);
	# Take the top 32 bits of the hash, modulo the number of hosts
	$fp->{hashbalance_start_index} = unpack('N', $hash) % $numhosts;
	$fp->{hashbalance_index} = 0;
    }

    # Iterate over the hosts, starting at the preferred one until a working one is found
    my $desthost;
    while ($fp->{hashbalance_index} < $numhosts)
    {
	my $index = ($fp->{hashbalance_start_index} + $fp->{hashbalance_index}++) 
	    % $numhosts;
	my $host = $self->{Hosts}[$index];
	$desthost = $host,last if $host->isWorking();
    }

    # Now make sure we never break up EAP streams from the same user 
    # between failing hosts
    my $eapmessage = $p->getAttrByNum($Radius::Radius::EAP_MESSAGE);
    if (defined $eapmessage)
    {
	my $context = $self->getEAPContext($p);
	my ($code, $identifier, $length, $eaptype) = unpack('C C n C', $eapmessage);
	# If this is not identity and the last one went to a different proxy, drop it
	if ($eaptype != $Radius::EAP::EAP_TYPE_IDENTITY
	    && exists $context->{last_proxy_host}
	    && $context->{last_proxy_host} != $desthost)
	{
	    my $last_proxy_host = $context->{last_proxy_host};
	    $self->log($main::LOG_WARNING, 
		       "ProxyAlgorithm HASHBALANCE declines to break up an EAP stream after failover from $last_proxy_host->{Name}:$last_proxy_host->{AuthPort}:$last_proxy_host->{AcctPort} to $desthost->{Name}:$desthost->{AuthPort}:$desthost->{AcctPort}", $p);
	    $p->{RadiusResult} = $main::REJECT;
	    return;
	}
	else
	{
	    $context->{last_proxy_host} = $desthost;
	}
	    
    }

    $self->log($main::LOG_WARNING, 
	       "ProxyAlgorithm HASHBALANCE Could not find a working host to proxy to", $p) unless $desthost;
    return $desthost;
}

1;
