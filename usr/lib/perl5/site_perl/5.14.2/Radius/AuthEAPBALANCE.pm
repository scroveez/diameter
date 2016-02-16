# AuthEAPBALANCE.pm
#
# Object for distributing EAP requests among multiple backends, and ensuring
# that each EAP conversation always go to the same backend.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2009 Open System Consultants
# $Id: AuthEAPBALANCE.pm,v 1.6 2012/09/25 00:18:03 mikem Exp $
package Radius::AuthEAPBALANCE;
@ISA = qw(Radius::AuthHASHBALANCE);
use Radius::AuthHASHBALANCE;
use strict;

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();

    # We label backend Hosts so we can recover them using the State
    my $id = 0;
    foreach (@{$self->{Hosts}})
    {
	$_->{eapbalance_id} = $id++;
    }
}

#####################################################################
# Choose a host for this request
# If there is a State attribtue use it to determine the backend, else
# let the HASHBALANCE choose one
sub chooseHost
{    
    my ($self, $fp, $p) = @_;

    my $state = $p->getAttrByNum($Radius::Radius::STATE);
    if (defined $state && $state =~ /EAPBALANCE:id=(.*)/)
    {
	# Remove the FIRST instance of State. Subsequent instances may exist, set by the target host
	# This allows interoperation with othe RADIUS servers that rely on State
	# REVISIT: this should really be a function in AttrVal.pm
	my $i;
	for ($i = 0; $i < @{$fp->{Attributes}}; $i++)
	{
	    splice(@{$fp->{Attributes}}, $i--, 1), last
		if ($fp->{Attributes}->[$i]->[0] eq 'State');
	}


	# Make sure all replies in the stream get the State
	my $host = $self->{Hosts}[$1];
	if (!$p->{eapbalance_host_tried} && $host && $host->isWorking())
	{
	    $p->{rp}->changeAttrByNum($Radius::Radius::STATE, $state);
	    $p->{eapbalance_host_tried}++;
	    return $host;
	}

	$self->log($main::LOG_WARNING, 
		   "ProxyAlgorithm EAPBALANCE declines to break up an EAP stream after detecting failure of Host $host->{Name}:$host->{AuthPort}:$host->{AcctPort}", $p);
	$p->{RadiusResult} = $main::REJECT;

	return;
    }
    else
    {
	# No recognisable state, must be the first request in a conversation, 
	# use HASHBALANCE to choose a target
	my $host = $self->SUPER::chooseHost($fp, $p);
	if ($host && $p->{rp})
	{
	    # Label the reply (if there is one: may be a keepalive) with the State
	    $p->{rp}->changeAttrByNum($Radius::Radius::STATE, "EAPBALANCE:id=$host->{eapbalance_id}");
	}
	return $host;
    }
    return;
}

1;
