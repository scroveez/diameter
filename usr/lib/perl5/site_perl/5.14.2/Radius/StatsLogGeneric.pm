# StatsLogGeneric.pm
#
# Generic module for logging statistics
# Traverses the object hierarchy from ServerConfig on down, 
# loging the contents of the
# Statistics hash for each type of object that has one
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2002 Open System Consultants
# $Id: StatsLogGeneric.pm,v 1.4 2007/12/18 21:23:50 mikem Exp $

package Radius::StatsLogGeneric;
@ISA = qw(Radius::Configurable);
use Radius::Configurable;
use Radius::Select;
use strict;

%Radius::StatsLogGeneric::ConfigKeywords = 
('Interval' => 
 ['integer', 'This is the time interval (in seconds) between each set of statistics. Defaults to 600 seconds (10 minutes).', 1],

 );

# RCS version number of this module
$Radius::StatsLogGeneric::VERSION = '$Revision: 1.4 $';

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();

    # Set the first timeout ready to go
    $self->{_timeouthandle} = &Radius::Select::add_timeout
	(time + $self->{Interval},
	 \&handle_timeout, $self);
}

#####################################################################
sub destroy
{
    my ($self) = @_;

    print "StatsLogGeneric destroy\n";
    &Radius::Select::remove_timeout($self->{_timeouthandle});
}

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{Interval} = 600;
}

#####################################################################
# handle_timeout
# This is called from within Select::process_timeouts
# Each time the time interval expires
sub handle_timeout
{
    my ($handle, $self) = @_;

    $self->logAll();

    # Schedule the timeout again
    &Radius::Select::add_timeout
	(time + $self->{Interval}, \&handle_timeout, $self);
}

#####################################################################
# Override this to get control before and after loging starts
sub logAll
{
    my ($self) = @_;

    # Log the ServerConfig stats and the stats of any objects within it
    # recursively
    $self->logObject($main::config);
    map $self->logObject($_), (@{$main::config->{Client}});
    map $self->logHandler($_), (@{$main::config->{Realm}}, @{$main::config->{Handler}});
}

#####################################################################
# Log all the Statistics from one object
# Override this to do the work of logging stats from a single
# object
sub logObject
{
    my ($self, $object) = @_;

    $self->log($main::LOG_ERR, "You did not override logObject() in StatsLogGeneric");
}

#####################################################################
sub logAuth
{
    my ($self, $object) = @_;

    $self->logObject($object);

    # Recurse inside AuthBy GROUP
    if ($object->isa('Radius::AuthGROUP'))
    {
	map $self->logAuth($_), (@{$object->{AuthBy}});
    }
    # Do the Hosts inside AuthBy RADIUS
    if ($object->isa('Radius::AuthRADIUS'))
    {
	map $self->logAuth($_), (@{$object->{Hosts}});
    }
}

#####################################################################
sub logHandler
{
    my ($self, $object) = @_;

    $self->logObject($object);

    # Do any AuthBys contained in here
    map $self->logAuth($_), (@{$object->{AuthBy}});
}

1;
