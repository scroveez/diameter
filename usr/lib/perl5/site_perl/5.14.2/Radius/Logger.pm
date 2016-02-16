# Logger.pm
#
# Routines for logging messages from objects
# This will take over from Configurable one day soon
#
# Part of the Radius project.
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2004 Open System Consultants
# $Id: Logger.pm,v 1.5 2007/12/18 21:23:50 mikem Exp $

package Radius::Logger;
use base ('Radius::Configurable');
use Radius::Log;
use strict;

%Radius::Logger::ConfigKeywords = 
('LogStdout'  => 
 ['flag', 'Controls whether messages will be logged to STDOUT', 1],

 'Trace'      => 
 ['integer', 'Logging trace level. Only messages with the specified or higher priority will be logged', 1],

 'Log'        => 
 ['objectlist', 'List of Loggers which will be used to log messages generated by this object', 1],

 );

# RCS version number of this module
$Radius::Logger::VERSION = '$Revision: 1.5 $';

# Maps our LOG_* numbers into priority level names
@Radius::Log::priorityToString  = ('ERR', 'WARNING', 'NOTICE', 'INFO', 'DEBUG', 'EXTRA_DEBUG');


#####################################################################
# Provide some glue between Radiameter compatible Logger modules and older Radius 
# compatible Configurable modules
sub new
{
    my ($class, @args) = @_;

    return $class->SUPER::new(undef, undef, @args);
}

#####################################################################
# $priority is the message priority, $s is the message
my $in_log;
sub log
{
    my ($self, @args) = @_;

    return if $in_log++;

    # Call each private log module with $priority, $string, $currentpacket
    map $_->log(@args), @{$self->{Log}};

    # Then call any global loggers
    &main::log(@args);
    $in_log = 0;
}

1;
