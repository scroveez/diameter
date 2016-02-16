# SessINTERNAL.pm
#
# Object for handling session database as an internal hash
# We keep a session count for each user, and a session details hash, keyed
# by nas_id:nas_port
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: SessINTERNAL.pm,v 1.24 2007/11/27 23:14:35 mikem Exp $

package Radius::SessINTERNAL;
@ISA = qw(Radius::SessGeneric);
use Radius::SessGeneric;
use Radius::Client;
use strict;

# RCS version number of this module
$Radius::SessINTERNAL::VERSION = '$Revision: 1.24 $';

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->{SessionCount} = ();
    $self->{Sessions} = ();
}

#####################################################################
# Do per-instance default initialization
# This is called by Configurable during Configurable::new before
# the config file is parsed. Its a good place initialize instance 
# variables
# that might get overridden when the config file is parsed.
# Do per-instance default initialization. This is called after
# construction is complete
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
}

#####################################################################
# Override the keyword function in Configurable
# Return 0 if not understood, else 1
# just inherit from the superclass

#####################################################################
sub add
{
    my ($self, $name, $nas_id, $nas_port, $p) = @_;

    $self->log($main::LOG_DEBUG, 
	       "$self->{Identifier} Adding session for $name, $nas_id, $nas_port", $p);
    # Add a new entry for this user, we may need
    # the info about the session later to check if
    # its still up

    # Protect against lost stops
    my $key = "$nas_id:$nas_port";
    if (!defined $self->{Sessions}{$key})
    {
	my $session_id = $p->getAttrByNum
	    ($Radius::Radius::ACCT_SESSION_ID);
	my $framed_ip_address = $p->getAttrByNum
	    ($Radius::Radius::FRAMED_IP_ADDRESS);

	$self->{SessionCount}{$name}++;
	$self->{Sessions}{$key} = "$name\001$session_id\001$framed_ip_address";
    }
}

#####################################################################
# Modification here so that we do not require the user name:
# we deduce it from the Sessions table. This is more likely
# to keep Sessions and SessionCount in sync
sub delete
{
    my ($self, $name, $nas_id, $nas_port, $p) = @_;

    no warnings qw(uninitialized);
    $self->log($main::LOG_DEBUG, 
	       "$self->{Identifier} Deleting session for $name, $nas_id, $nas_port", $p);

    # Remove the entry for the user on this port
    # Protect against lost stops
    my $key = "$nas_id:$nas_port";
    if (defined $self->{Sessions}{$key})
    {
	my ($this_name, $this_session_id, $this_framed_ip_address) 
	    = split(/\001/, $self->{Sessions}{$key});

	delete $self->{Sessions}{$key};

	$self->{SessionCount}{$this_name}--;
	delete $self->{SessionCount}{$this_name} 
            if $self->{SessionCount}{$this_name} <= 0; # Save unneeded mem
    }
}

#####################################################################
sub clearNas
{
    my ($self, $nas_id, $p) = @_;

    $self->log($main::LOG_DEBUG, 
	       "$self->{Identifier} Deleting all sessions for $nas_id", $p);
    my ($key, $value);
    while (($key, $value) = each %{$self->{Sessions}})
    {
	my ($this_nas_id, $this_nas_port) = split(/:/, $key);
	if ($this_nas_id eq $nas_id)
	{
	    my ($this_name, $this_session_id, $this_framed_ip_address) = split(/\001/, $value);
	    $self->delete($this_name, $this_nas_id, $this_nas_port, $p);
	}
    }
}

#####################################################################
sub exceeded
{
    my ($self, $max, $name, $p) = @_;

    # Quick and easy check if we are obviously in the clear
    no warnings "uninitialized";
    return 0 
	if $self->{SessionCount}{$name} < $max;

    # Hmmmm we think that there are too many current sessions
    # now we go through the longwinded (and slow) process of
    # checking whether the sessions we think are up
    # are really still up
    # REVISIT: should we fork here, or something?
    # but if we fork, we cant readjust the counts in the parent

    my ($key, $value, $this_name, $this_session_id, 
	$this_framed_ip_address, $nas_id, $nas_port, $client);
    while (($key, $value) = each %{$self->{Sessions}})
    {
	# The name and session ID are encoded in the value
	# We are not interested in this one unles its for the user
	# we want.
	($this_name, $this_session_id, $this_framed_ip_address) = split(/\001/, $value);
	next unless $this_name eq $name;

	# The key is NAS id and port joined by a colon 
	# The value is a reference to a hash describing the
	# session, including the start time session id and
	# the Client it came in on
	($nas_id, $nas_port) = split(/:/, $key);

	# The Client who received this knows how to ask the NAS
	# if they are still online
	if ($client = &Radius::Client::findAddress(Radius::Util::inet_pton($nas_id)))
	{
	    if (!$client->isOnline
		($name, $nas_id, $nas_port, 
		 $this_session_id,
		 $this_framed_ip_address))
	    {
		# Hmmm they are not really online anymore, remove this session
		$self->log($main::LOG_INFO, 
			   "$self->{Identifier} Session for $name at $nas_id:$nas_port has gone away", $p);
		$self->delete($name, $nas_id, $nas_port, $p);
	    }
	}
	else
	{
	    $self->log($main::LOG_WARNING, 
		       "$self->{Identifier} Could not find a Client for NAS $nas_id to double-check Simultaneous-Use. Perhaps you do not have a reverse DNS for that NAS?", $p);
	}
    }
    # Ok weve checked all the sessions, see if we are under the 
    # limit now
    return ($self->{SessionCount}{$name} >= $max);
}

1;








