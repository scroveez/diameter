# Log.pm
#
# Object for handling logging
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: Log.pm,v 1.24 2013/12/13 21:55:14 hvn Exp $

# Message priorities to pass to log
# These are the same abbreviations as used by syslog
# These are exported to main for convenience
$main::LOG_ERR = 0;        # Error conditions
$main::LOG_WARNING = 1;    # Warning conditions
$main::LOG_NOTICE = 2;     # Normal but significant
$main::LOG_INFO = 3;       # Informational
$main::LOG_DEBUG = 4;      # For debugging
$main::LOG_EXTRA_DEBUG = 5; # Detailed hex packet dumps

package Radius::Log;
use Radius::LogFILE;
use strict;

# RCS version number of this module
$Radius::Log::VERSION = '$Revision: 1.24 $';

# Maps our LOG_* numbers into priority level names
@Radius::Log::priorityToString = 
    ('ERR', 'WARNING', 'NOTICE', 'INFO', 'DEBUG', 'DEBUG');
@Radius::Log::priorityToLongString = 
    ('Error', 'Warning', 'Notice', 'Info', 'Debug', 'Extra Debug');

# Catch recursion in calls to log
my $in_log = 0;

# For backwards compatibility, a default FILE logger
my $default_logger;

# Make sure we get reinitialized on sighup
push(@main::reinitFns, \&reinitialize);

#####################################################################
# Bump the trace level of all global loggers
sub adjustTrace
{
    my ($increment) = @_;

    map { $_->adjustTrace($increment) } @{$main::config->{Log}};

    return $main::config->{Trace} + $increment;
}

#####################################################################
# Set the trace level of all global loggers
sub setTrace
{
    my ($new_level) = @_;

    map {$_->setTrace($new_level) } @{$main::config->{Log}};

    return $new_level;
}

#####################################################################
# This is the systems main logging routine. Its in package main::
# Log a message to all the loggers defined
# $priority is the message priority, $s is the message
# $p is the current request packet, if any
no warnings qw(redefine);
sub main::log
{
    my ($priority, $s, $p) = @_;

    # Catch recursion
    return if $in_log++;

    # Print to stdout as well, if required
    print $main::config->format_ctime() . ': ' 
	. $Radius::Log::priorityToString[$priority] . ': ' . $s . "\n"
	if $main::config->{LogStdout} 
           && ($priority <= $main::config->{Trace} 
	       || ($p && $p->{PacketTrace}));

    # Call each log module with $priority, $s
    map $_->log($priority, $s, $p), @{$main::config->{Log}};

    $in_log = 0;
}

#####################################################################
# Return true if at least one logger is required to log
# Can be a shortcut to prevent length logging calculations
sub main::willLog
{
    my ($priority, $p) = @_;
    return 1 
	if ($main::config->{LogStdout}
            && ($priority <= $main::config->{Trace} 
               || ($p && $p->{PacketTrace})))
	   || grep $_->willLog($priority, $p), @{$main::config->{Log}};
}

#####################################################################
# Make a default file logger. If one already exists, adjust its
# parameters
# Returns the default logger instance
sub setupDefaultLogger
{
    my ($filename, $trace) = @_;

    # For backwards compatibility, create a basic FILE logger
    # if they have defined a log filename in the global config
    # This will disappear one day
    if (!$default_logger && $filename ne '')
    {
	$default_logger = Radius::LogFILE->new(undef, 'DEFAULT');
	$default_logger->add_logger();
	$default_logger->activate();
    }

    # If one exists, maybe change its setup
    if ($default_logger)
    {
	$default_logger->{Filename} = $filename;
	$default_logger->{Trace} = $trace;
    }
    return $default_logger;
}

#####################################################################
# REInitialize the log module
sub reinitialize
{
    # Forget about the previous default logger
    $default_logger = undef;
}

1;
