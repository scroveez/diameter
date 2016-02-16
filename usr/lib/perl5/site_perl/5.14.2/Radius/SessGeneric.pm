# SessGeneric.pm
#
# Generic object for handling session databases
# In order to create a new sesion database, you need to 
# subclass this and override a number of functions
#
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: SessGeneric.pm,v 1.14 2013/08/13 20:58:45 hvn Exp $

package Radius::SessGeneric;
@ISA = qw(Radius::Configurable);
use Radius::Configurable;
use strict;

# RCS version number of this module
$Radius::SessGeneric::VERSION = '$Revision: 1.14 $';

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    $self->SUPER::check_config();
    return;
}

#####################################################################
# Do per-instance default initialization. This is called after
# construction is complete
sub initialize
{
    my ($self) = @_;

    # The last one in the config file is the default
    $Radius::SessGeneric::db = $self; 

    $self->SUPER::initialize;
    $self->{ObjType} = 'SessionDatabase'; # Automatically register this object
}

#####################################################################
sub add
{
    my ($self, $name, $nas_id, $nas_port, $p) = @_;

    $self->log($main::LOG_ERR, "You did not override add in SessGeneric", $p);
}

#####################################################################
# By default update (called for Alive and similar packets)
# does the same as an add
sub update
{
    my ($self, $name, $nas_id, $nas_port, $p) = @_;

    $self->add($name, $nas_id, $nas_port, $p);
}

#####################################################################
sub delete
{
    my ($self, $name, $nas_id, $nas_port, $p) = @_;

    $self->log($main::LOG_ERR, "You did not override delete in SessGeneric", $p);
}

#####################################################################
sub clearNas
{
    my ($self, $nas_id, $p) = @_;

    $self->log($main::LOG_ERR, "You did not override clearNas in SessGeneric", $p);
}

#####################################################################
sub exceeded
{
    my ($self, $max, $name, $p) = @_;

    $self->log($main::LOG_ERR, "You did not override exceeded in SessGeneric", $p);
}

#####################################################################
# Returns an array of all the session IDs that should be up on this NAS
# returns 1, and a list of session IDs of the query succedded. If the 
# query failed, returns undef;
sub sessionsOnNAS
{
    my ($self, $nas_id, $p) = @_;

    $self->log($main::LOG_ERR, "You did not override sessionsOnNAS in SessGeneric", $p);
}

#####################################################################
# Find a Session Database with the given identifier
# If not found, return the main default one
sub find
{
    my ($identifier) = @_;

    my $ret = &Radius::Configurable::find('SessionDatabase', $identifier) 
	|| $Radius::SessGeneric::db;
    return $ret;
}
1;
