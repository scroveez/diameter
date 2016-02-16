# Context.pm
#
# Object for holding temporary keyed storage, with optional automatic
# time-based destruction. Each context has a unique identifying key.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001 Open System Consultants
# $Id: Context.pm,v 1.8 2012/10/17 10:33:32 mikem Exp $
package Radius::Context;
use strict;

# RCS version number of this module
$Radius::Context::VERSION = '$Revision: 1.8 $';

%Radius::Context::contexts = ();

# Make sure we get reinitialized on sighup
push(@main::reinitFns, \&reinitialize);

#####################################################################
sub new
{
    my ($class, $id, $timeout) = @_;

    my $self = { 'id' => $id };
    $self->{_timeouthandle} = &Radius::Select::add_timeout
	(time + $timeout, \&handle_timeout, $id) 
	    if defined $timeout;
    $Radius::Context::contexts{$id} = $self;
    bless $self, $class;
    return $self;
}

#####################################################################
# If a context with this key already exists, return it, else
# undef
sub find
{    
    my ($id) = @_;    

    return $Radius::Context::contexts{$id}
        if exists $Radius::Context::contexts{$id};
    return;
}

#####################################################################
# If a context with this key already exists, return it, else
# create a new one
sub get
{    
    my ($id, $timeout) = @_;    

    if (exists $Radius::Context::contexts{$id})
    {
	# Reset the timeout, if there is one
	my $context = $Radius::Context::contexts{$id};
	&Radius::Select::remove_timeout($context->{_timeouthandle}) 
	    if defined $context->{_timeouthandle};
	$context->{_timeouthandle} = &Radius::Select::add_timeout
	    (time + $timeout, \&handle_timeout, $id) 
	    if defined $timeout;
	return $Radius::Context::contexts{$id};
    }
    return Radius::Context->new($id, $timeout);
}

#####################################################################
sub destroy
{
    my ($id) = @_;

    my $timeouthandle = $Radius::Context::contexts{$id}->{_timeouthandle};
    &Radius::Select::remove_timeout($timeouthandle) 
	if defined $timeouthandle;
    delete $Radius::Context::contexts{$id};
}

#####################################################################
# Called whenever a context has been active for too long
sub handle_timeout
{
    my ($handle, $id) = @_;

    destroy($id);
}

#####################################################################
# Reinitialize this instance
sub reinitialize
{
    my ($self) = @_;
    
    %Radius::Context::contexts = ();
}

#####################################################################
# Call a function with args when the timeout goes off, or the destroy
# function is called
sub destroy_callback
{
    my ($self, @args) = @_;
    @{$self->{_destroy_callback}} = @args;
}

#####################################################################
sub DESTROY
{
    my ($self) = @_;

#    print "Context $self DESTROY:\n";
#    my $key;
#    foreach $key (keys %$self)
#    {
#	print "$key: $self->{$key}\n";
#    }

    if ($self->{_destroy_callback})
    {
	my @args = @{$self->{_destroy_callback}};
	my $fn = shift @args;
	&{$fn}($self, @args); 
    }
}

1;
