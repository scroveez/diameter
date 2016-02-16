# LogFILE.pm
#
# Log to a file
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: LogFILE.pm,v 1.14 2014/09/19 19:56:39 hvn Exp $

package Radius::LogFILE;
use Radius::LogGeneric;
@ISA = qw(Radius::LogGeneric);
use File::Path;
use File::Basename;
use strict;

%Radius::LogFILE::ConfigKeywords = 
('Filename'  => 
 ['string', 'The name of the file that will be logged to. The file name can include special path name characters as defined in "Special characters in file names and other parameters" in the Radiator Reference manual. The default is %L/logfile, i.e. a file named logfile in LogDir.', 0],

 'LogFormat' => 
 ['string', 'This optional parameter permits you to customize the log string. Any special formatting character is permitted. %0 is replaced with the message severity as an integer, %1 with the severity as a string, and %2 with the log message. ', 1],

 );

# RCS version number of this module
$Radius::LogFILE::VERSION = '$Revision: 1.14 $';

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
    $self->{Filename} = '%L/logfile';
}

#####################################################################
# Log a message 
# $priority is the message priority, $s is the message
# $r is the current request packet, if any
sub log
{
    my ($self, $priority, $s, $p) = @_;

#    print "Logger $self->{Identifier}, $priority, $s, $p\n";
    if ($self->{Filename} ne '' && $self->willLog($priority, $p))
    {
	#print "logging to $self->{Filename}\n";
	my $message;
	if (defined $self->{LogFormatHook})
	{
	    ($message) = $self->runHook('LogFormatHook', $p, $priority, $s, $p);
	}
	elsif (defined $self->{LogFormat})
	{
	    $message = &Radius::Util::format_special
		($self->{LogFormat},
		 $p, undef, 
		 $priority,
		 $Radius::Log::priorityToString[$priority],
		 $s);
	}
	else
	{
	    $message = $self->format_ctime() . ': ' . $Radius::Log::priorityToString[$priority] . ': ' . $s;
	}

	my $filename = &Radius::Util::format_special($self->{Filename}, $p, undef, $priority, $s);
	&Radius::Util::append($filename, $message . "\n")
	    || warn "Log could not append '$message' to log file '$filename': $!";
    }
}

1;
