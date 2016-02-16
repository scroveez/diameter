# LogGeneric.pm
#
# Generic superclass for handling logging
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: LogGeneric.pm,v 1.12 2014/09/19 19:56:39 hvn Exp $

package Radius::LogGeneric;
use Radius::Configurable;
@ISA = qw(Radius::Configurable);
use strict;

%Radius::LogGeneric::ConfigKeywords = 
('Trace'            => 
 ['integer', 
  'Logging trace level. Only messages with the specified or higher priority will be logged', 
  0],

 'LogMicroseconds'  => 
 ['flag', 
  'When logging, include microseconds in the time (requires Time::HiRes)',
  1],

 'IgnorePacketTrace'  => 
 ['flag', 
  'Exclude this logger from PacketTrace debugging',
  1],

 'MaxMessageLength' => 
 ['integer', 
  'Sets the maximum length of log messages. All messages longer than MaxMessageLength characters wil be truncated to MaxMessageLength.', 
  1],

 'LogFormatHook' =>
 ['hook',
  'Specifies an optional Perl hook that will be run for each log message when defined. By default no Hook is defined.',
  1],

 );

# RCS version number of this module
$Radius::LogGeneric::VERSION = '$Revision: 1.12 $';

# Maps our LOG_* numbers into strings
@Radius::LogGeneric::priorityToString  = 
    ('ERR', 'WARNING', 'NOTICE', 'INFO', 'DEBUG');

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
    $self->{Trace} = 0;
    $self->{ObjType} = 'Log';
}

#####################################################################
# Log a message 
# $priority is the message priority, $s is the message
# $r is the current request packet, if any
sub log
{
    my ($self, $priority, $s, $p) = @_;

    &main::log($main::LOG_ERR, "You did not override log() in LogGeneric", $p);
}

#####################################################################
# Return true if a message should be logged by this logger
# at the given log level
sub willLog
{
    my ($self, $priority, $p) = @_;

    # Check against the trace level first.
    return 1 if $priority <= $self->{Trace};
    
    # Priority was not high enough. See if PacketTrace is enabled for $p.
    return $p && $p->{PacketTrace} && !$self->{IgnorePacketTrace};
}

#####################################################################
# Adjust the current trace level up or down
# Returns the current trace level
sub adjustTrace
{
    my ($self, $increment) = @_;

    $self->{Trace} += $increment;
    $self->log($main::LOG_INFO, "Trace level changed to $self->{Trace}");
    return $self->{Trace};
}

#####################################################################
# Sets the current trace level directly
# Returns the current trace level
sub setTrace
{
    my ($self, $new_level) = @_;

    $self->{Trace} = $new_level;
    # Not logging trace change here. We may be called per backet basis
    # which would cause log litter.
    return $self->{Trace};
}

#####################################################################
# Become a global logger. Logger that are declared at the top level
# are automatically global loggers (ie log through the 
# $main::config->{Log} list)
sub add_logger
{
    my ($self) = @_;

    push (@{$main::config->{Log}}, $self);
}

#####################################################################
# Stop being a global logger. Only necessary if you called add_logger before
sub remove_logger
{
    my ($self) = @_;

    my $i;
    for ($i = 0; $i < @{$main::config->{Log}}; $i++)
    {
	splice(@{$main::config->{Log}}, $i--, 1)
	    if @{$main::config->{Log}}[$i] == $self;
    }
}

1;
