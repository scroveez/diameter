# Nas.pm
# 
# Routines for communicating directly with NASs
#
# Looks for a NAS-specific module in Radius/Nas/type.pm, and then tries
# to run the isOnline (or whatever) funtion in that module.
#
# This makes it easier to add support for new NAS types.
# If you add support for your type of NAS, please consider sending
# it to Open System Consultants for inclusion in future releases.
#
# Policy statement: in general, software failures or configuration
# problems act to accept logins, rather than reject them. This is 
# thought to be better for end-users.
#
# One day, this file will be split into a separate file for each NAS
# type
#
# Copyright (C) 1997-2002 Open System Consultants
# Author: Mike McCauley (mike@open.com.au)
# $Id: Nas.pm,v 1.29 2012/09/20 07:27:51 mikem Exp $

package Radius::Nas;
use strict;
use Radius::Log;

# RCS version number of this module
$Radius::Nas::VERSION = '$Revision: 1.29 $';

# Hash of loaded module names to short circuit slow eval
my %module_loaded;

#####################################################################
# Wrapper that can handle any NAS type
# Returns 1 if they are still online, according to the NAS
# I really dont like carrying the $client pointer down here just to
# get the SNMP Community for some Nas types.
sub isOnline
{
    my ($nas_type, $name, $nas_id, $nas_port, $session_id, $client, $framed_ip_address) = @_;

    &main::log($main::LOG_DEBUG, 
	       "Checking if user is still online: $nas_type, $name, $nas_id, $nas_port, $session_id $framed_ip_address");

    if  ($nas_type =~ /^Exec-Program\s+(.*)/)
    {
	system(&Radius::Util::format_special
	       ($1, undef, undef, 'isonline', 
		$name, $nas_id, $nas_port, $session_id, $framed_ip_address));
	return $? >> 8;
    }
    else
    {
	my $nas_module = "Radius::Nas::$nas_type";
	if (!$module_loaded{$nas_module} && !eval("require $nas_module"))
	{
	    # Anything else, unknown type, assume the worst
	    &main::log($main::LOG_ERR, "Could not load NAS-specific module $nas_module: $@");
	    return 1;
	}
	$module_loaded{$nas_module} = 1;
	my $fn = "${nas_module}::isOnline";
	if (defined(&$fn))
	{
	    no strict 'refs'; # So we can use symbolic references
	    return &$fn($name, $nas_id, $nas_port, $session_id, $client, $framed_ip_address);
	}
	else
	{
	    # module does not define an isOnline fn. Assume the worst: they are still online
	    return 1;
	}
    }
}

#####################################################################
# Wrapper that can handle any NAS type
# Returns 1 and a list of session IDs if successful, else undef
sub activeSessions
{
    my ($nas_type, $nas_id, $client) = @_;

    &main::log($main::LOG_DEBUG, "Getting active sessions from $nas_id");

    if  ($nas_type =~ /^Exec-Program\s+(.*)/)
    {
	system(&Radius::Util::format_special
	       ($1, undef, undef, 'active', $nas_id));
	return $? >> 8;
    }
    else
    {
	my $nas_module = "Radius::Nas::$nas_type";
	if (!eval("require $nas_module"))
	{
	    # Anything else, unknown type, assume the worst
	    &main::log($main::LOG_ERR, 
		       "Could not load NAS-specific module $nas_module: $@");
	    return 1;
	}
	else
	{
	    my $fn = "${nas_module}::activeSessions";
	    if (defined(&$fn))
	    {
		no strict 'refs'; # So we can use symbolic references
		return &$fn($nas_id, $client);
		use strict 'refs';
	    }
	    else
	    {
		# module does not define an activeSessions fn. Assume the worst
		return;
	    }
	}
    }
}

#####################################################################
# Wrapper that can handle any NAS type
# returns true if we think it worked, else undef
sub disconnectUser
{
    my ($nas_type, $name, $nas_id, $nas_port, $session_id, $client) = @_;

    &main::log($main::LOG_DEBUG, 
	       "Checking if user is still online: $nas_type, $name, $nas_id, $nas_port, $session_id");

    if  ($nas_type =~ /^Exec-Program\s+(.*)/)
    {
	system(&Radius::Util::format_special
	       ($1, undef, undef, 'disconnect', $name, $nas_id, $nas_port, 
		$session_id));
	return $? >> 8;
    }
    else
    {
	my $nas_module = "Radius::Nas::$nas_type";
	if (!eval("require $nas_module"))
	{
	    # Anything else, unknown type, assume the worst
	    &main::log($main::LOG_ERR, 
		       "Could not load NAS-specific module $nas_module: $@");
	    return 1;
	}
	else
	{
	    my $fn = "${nas_module}::disconnectUser";
	    if (defined(&$fn))
	    {
		no strict 'refs'; # So we can use symbolic references
		return &$fn($name, $nas_id, $nas_port, $session_id, $client);
		use strict 'refs';
	    }
	    else
	    {
		# module does not define an disconnectUser fn. Assume the worst
		return;
	    }
	}
    }
}


#####################################################################
# Call the internal or external finger, depending on the setting
# of fingerprog. Returns 1, and an array of lines read from finger
# or undef if an error occurred (which we logged)
# REVISIT: should move this somewhere else
sub finger
{
    my ($addr) = @_;

    my @lines;

    if ($main::config->{FingerProg})
    {
	&main::log($main::LOG_DEBUG, "Using external program $main::config->{FingerProg} to finger $addr");

	# use the external finger program
	if (!-x $main::config->{FingerProg})
	{
	    &main::log($main::LOG_ERR, "$main::config->{FingerProg} is not executable. Please check the value of FingerProg in your configuration file");
	    return;
	}

	if (!open(FINGER, "$main::config->{FingerProg} $addr|"))
	{
	    &main::log($main::LOG_ERR, "Could not open $main::config->{FingerProg}: $!");
	    return;
	}

	while (<FINGER>) 
	{  
	    push(@lines, $_);
	}
	close FINGER;
	
	my $result = $?; # so we dont lose it due sigchld hadlers
	if ($result)
	{
	    &main::log($main::LOG_ERR, "The command '$main::config->{FingerProg} $addr' failed with error $result. Please check the value of FingerProg in your configuration file");
	    return;
	}
    }
    else
    {
	if (!eval{require Net::Finger;})
	{
	    &main::log($main::LOG_ERR, 'Need Net::Finger to finger $addr, but it is not installed.');
	    return;
	}

	# use the internal finger client
	&main::log($main::LOG_DEBUG, "Using Net::Finger to finger $addr");

	@lines = Net::Finger::finger($addr);
	if ($Net::Finger::error)
	{
	    &main::log($main::LOG_ERR, "The Net::Finger failed with: $Net::Finger::error");
	    return;
	}
    }
    return (1, @lines);
}

1;
