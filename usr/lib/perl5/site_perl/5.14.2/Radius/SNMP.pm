# SNMP.pm
#
# Wrapper for SNMP functions
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1999 Open System Consultants
# $Id: SNMP.pm,v 1.11 2012/12/11 22:17:43 mikem Exp $

package Radius::SNMP;
use strict;

# RCS version number of this module
$Radius::SNMP::VERSION = '$Revision: 1.11 $';

# A hash of the latest error times for each NAS/community combination
my %nas_errortime = ();

# Check whether the snmpgetprog exists, and is executable etc
sub snmpgetprogExists
{
    return 1 if -x $main::config->{SnmpgetProg};

    &main::log($main::LOG_ERR, "$main::config->{SnmpgetProg} is not executable. Check SnmpgetProg in your configuration file");
    return; # Assume the worst
}

# Check whether the snmpwalkprog exists, and is executable etc
sub snmpwalkprogExists
{
    return 1 if -x $main::config->{SnmpwalkProg};

    &main::log($main::LOG_ERR, "$main::config->{SnmpwalkProg} is not executable. Check SnmpwalkProg in your configuration file");
    return; # Assume the worst
}

# Check whether the snmpwalkprog exists, and is executable etc
sub snmpsetprogExists
{
    return 1 if -x $main::config->{SnmpsetProg};

    &main::log($main::LOG_ERR, "$main::config->{SnmpsetProg} is not executable. Check SnmpsetProg in your configuration file");
    return; # Assume the worst
}

# Do an snmpget, and report an error if there is a problem
# Returns the value
sub snmpget
{
    my ($nas_id, $community, $oid) = @_;

    if ( defined($nas_errortime{$nas_id . $community}) 
	 && time() - $nas_errortime{$nas_id . $community} < $main::config->{SnmpNASErrorTimeout}) 
    {
	&main::log($main::LOG_WARNING, "Snmpget for NAS $nas_id blocked due to recent error for $main::config->{SnmpNASErrorTimeout} seconds");
	return;
    }
     
    my $command = "$main::config->{SnmpgetProg} -c \"$community\" $nas_id $oid 2>&1";
    &main::log($main::LOG_DEBUG, "Running command `$command`");
    my $result = `$command`;
    if (   $result =~ /error/i || $result =~ /no response/i 
	|| $result =~ /timeout/i || $result =~ /Unknown Object Identifier/) 
    {
	&main::log($main::LOG_ERR, "The command '$command' failed with an error: $result");
	$nas_errortime{$nas_id . $community} = time()
	    if $main::config->{SnmpNASErrorTimeout} > 0;
    }
    return $result;
}

# Do an snmpget, and report an error if there is a problem
# Returns the value
sub snmpwalk
{
    my ($nas_id, $community, $oid) = @_;

    if ( defined($nas_errortime{$nas_id . $community}) 
	 && time() - $nas_errortime{$nas_id . $community} < $main::config->{SnmpNASErrorTimeout}) 
    {
	&main::log($main::LOG_WARNING, "Snmpwalk for NAS $nas_id blocked due to recent error for $main::config->{SnmpNASErrorTimeout} seconds");
	return;
    }
     
    my $command = "$main::config->{SnmpwalkProg} -c \"$community\" $nas_id $oid 2>&1";
    &main::log($main::LOG_DEBUG, "Running command `$command`");
    my $result = `$command`;
    if ($result =~ /error/i || $result =~ /no response/i || $result =~ /timeout/i) 
    {
	&main::log($main::LOG_ERR, "The command '$command' failed with an error: $result");
	$nas_errortime{$nas_id . $community} = time()
	    if $main::config->{SnmpNASErrorTimeout} > 0;
    }
    return $result;
}

# Do an snmpget, and report an error if there is a problem
# Returns the resulting value
sub snmpset
{
    my ($nas_id, $community, $oid, $type, $value) = @_;

    if ( defined($nas_errortime{$nas_id . $community}) 
	 && time() - $nas_errortime{$nas_id . $community} < $main::config->{SnmpNASErrorTimeout}) 
    {
	&main::log($main::LOG_WARNING, "Snmpset for NAS $nas_id blocked due to recent error for $main::config->{SnmpNASErrorTimeout} seconds");
	return;
    }
    
    my $command = "$main::config->{SnmpsetProg} -c \"$community\" $nas_id $oid $type '$value' 2>&1";
    &main::log($main::LOG_DEBUG, "Running command `$command`");
    my $result = `$command`;
    if ($result =~ /error/i || $result =~ /no response/i || $result =~ /timeout/i) 
    {
	&main::log($main::LOG_ERR, "The command '$command' failed with an error: $result");
	$nas_errortime{$nas_id . $community} = time()
	    if $main::config->{SnmpNASErrorTimeout} > 0;
    }
    return $result;
}

1;

