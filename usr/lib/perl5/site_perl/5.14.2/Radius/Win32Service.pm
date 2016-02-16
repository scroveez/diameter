# Win32Service.pm
#
# Utility routines For running Radiator as a Windows service
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2003 Open System Consultants Pty Ltd
#
# Requires Win32::Daemon, install with
#     ppm install http://www.roth.net/perl/packages/win32-daemon.ppd
#
# $Id: Win32Service.pm,v 1.5 2008/02/17 22:54:19 mikem Exp $

package Radius::Win32Service;
use Win32::Daemon;
use strict;

# RCS version number of this module
$Radius::Win32Service::VERSION = '$Revision: 1.5 $';

#####################################################################
# Start and run as a service, monitor for changes in state
sub service
{
    &Win32::Daemon::StartService();

    my $state;
    my $prev_state = SERVICE_START_PENDING;
    while (($state = &Win32::Daemon::State()) != SERVICE_STOPPED)
    {
	if ($state == SERVICE_START_PENDING
	    || $main::restart)
	{
	    &main::initialize;
	    &Win32::Daemon::State(SERVICE_RUNNING);
	    $prev_state = SERVICE_RUNNING;
	}	
	elsif ($state == SERVICE_RUNNING)
	{ 
	    # This will handle a few events and then return
	    &main::handleEvents();
	}
	elsif ($state == SERVICE_STOP_PENDING)
	{ 
	    &Win32::Daemon::State(SERVICE_STOPPED);
	    $prev_state = SERVICE_STOPPED;
	}
	elsif ($state == SERVICE_PAUSE_PENDING)
	{ 
	    &Win32::Daemon::State(SERVICE_PAUSED);
	    $prev_state = SERVICE_PAUSED;
	}
	elsif ($state == SERVICE_CONTINUE_PENDING)
	{ 
	    &Win32::Daemon::State(SERVICE_RUNNING);
	    $prev_state = SERVICE_RUNNING;
	}
	else
	{
	    &Win32::Daemon::State($prev_state);
	    sleep(1);
	}
    }
    &Win32::Daemon::StopService();
}

#####################################################################
# Permanently install this executable as a service
sub install
{
    &uninstall();

    # Do some sanity checks:
    if ($0 !~ /^\D:/)
    {
	print STDERR "ERROR: You have specified '$0' 
as your Radiator program name.
To run Radiator as a service, the Radiator program name
must be given as a FULL path name including the drive letter,
typically something like 
  C:\\Perl\\bin\\radiusd
Radiator was not installed\n";
    }
    elsif ($main::config_file !~ /^\D:/)
    {
	print STDERR "ERROR: You have specified '$main::config_file' 
as your Radiator configuration file name.
To run Radiator as a service, the configuration file name
must be given as a FULL path name including the drive letter,
typically something like 
  -config_file \"C:\\Program Files\\Radiator\\radius.cfg\"
Radiator was not installed\n";
    }
    elsif (!-f $main::config_file)
    {
	print STDERR "ERROR: You have specified '$main::config_file' 
as your Radiator configuration file name, but that name does
not seem to exist as a readable file on this system.
To run Radiator as a service, the configuration file name
must be given as a FULL path name including the drive letter,
typically something like 
  -config_file \"C:\\Program Files\\Radiator\\radius.cfg\"
Radiator was not installed\n";
    }
    else
    {
	# OK to install
	# Build a command line for the service
	# Quote any options in the command line that may have spaces
	my $servicename = $main::servicename || 'Radiator';
	my @command = ($0, '-service', @main::original_argv);
	foreach (@command)
	{
	    $_ = "\"$_\"" if /\s/;
	}
	
	# These options install on the local machine to run under the System Account
	my %options = 
	    (
	     machine     => '',
	     name        => $servicename,
	     display     => "$servicename Radius Server",
	     path        => $^X,
	     user        => '',
	     pwd         => '',
	     description => 'Provides RADIUS authentication, authorization and accounting services for dialup and wireless network access',
	     parameters  => join(' ', $main::serviceperlargs, @command),
	     );
	
	if (!&Win32::Daemon::CreateService(\%options))
	{
	    my $error = Win32::Daemon::GetLastError();
	    print STDERR "Failed to install Radiator as a Windows service named $servicename: $error\n";
	}
    }
}

#####################################################################
# Permanently uninstall this executable as a service
sub uninstall
{
    my $servicename = $main::servicename || 'Radiator';
    if (!&Win32::Daemon::DeleteService('', $servicename))
    {
	my $error = Win32::Daemon::GetLastError();
	print STDERR "Failed to uninstall Radiator as a Windows service named $servicename: $error\n"
	    unless $error == 1060 || $error == 1072;
    }
}

1;



