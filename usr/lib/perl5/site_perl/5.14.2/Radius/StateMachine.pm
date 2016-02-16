# StateMachine.pm
#
# Implements a generic event driven state machine
# state machines are descibed by a hash:
# %smspec = (
#   'state1' => { 'event1' => [ 'state2', [\&proc1a, \&proc1b]]},
#   'state2' => { 'event2' => [ 'state3', [\&proc2]]},
#   'state3' => { 'event3' => [ 'state2', [\&proc3]],
#   	      'event4' => [ 'state1', [\&proc4]]},
#   );
# Each proc in the list will be called when the given event occurs in the given state
# 
# Part of the Radius project.
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2004 Open System Consultants
# $Id: StateMachine.pm,v 1.3 2007/11/27 23:14:35 mikem Exp $

package Radius::StateMachine;
use base ('Radius::Logger');
use strict;

# RCS version number of this module
$Radius::StateMachine::VERSION = '$Revision: 1.3 $';

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();
    $self->reset();
}

#####################################################################
# Runs the procedures associated with the event in the current state and
# then makes a transition to the next state
# Returns the new state
# Each procedure is called with ($self, @args), and can be overridden in 
# subclasses
sub event
{
    my ($self, $event, @args) = @_;

    my $last_state = $self->{State};
    if (exists $self->{Spec}->{$self->{State}}->{$event})
    {
	# There is an event transtion spec for this state/event combo
	my @actions = @{$self->{Spec}->{$self->{State}}->{$event}};
	# $actions[0] is the next state and $actions[1] is an array of transition procedures to call

	$self->log($main::LOG_DEBUG, "StateMachine::event $event in state $self->{State}. Calling @{$actions[1]}");
	$self->{State} = $actions[0];
	my $p; # Points to the resolved, possibly overridden fn
	my @a = @{$actions[1]};
	# Call the action functions. CAUTION: may be recursive
	map { ($p = $self->can($_)) && &$p($self, @args)} @a;
    }
    &{$self->{ChangeStateCallback}}($self, $last_state, $self->{State})
	if $last_state ne $self->{State} && $self->{ChangeStateCallback};
    $self->log($main::LOG_DEBUG, "StateMachine::event event $event $last_state -> $self->{State}");
    return $self->{State};
}

#####################################################################
# Return the current state
sub state
{
    return $_[0]->{State};
}

#####################################################################
# Set the current state, returns the old state
# no event transitions are run
sub setState
{
    my $oldstate = $_[0]->{State};
    $_[0]->{State} = $_[1];
    return $oldstate;
}

#####################################################################
sub reset
{
    my ($self) = @_;

    $self->setState($self->{InitialState});
}

1;
