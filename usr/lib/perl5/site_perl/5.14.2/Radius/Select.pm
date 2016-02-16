# Select.pm
#
# Routines for handling select()ing from several filehandles at
# once.
#
# You can register callbacks filehandles with add_file. 
# You can remove previously registered callbacks with remove_file
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: Select.pm,v 1.23 2009/04/05 09:33:16 mikem Exp $

package Radius::Select;
use strict;

# RCS version number of this module
$Radius::Select::VERSION = '$Revision: 1.23 $';

# These variables hold the callback functions and args indexed by fileno
# Each item is a list. The first element is tha callback funciton, the 
# second element is the argument list to be passed to the callback fn
my @read_callbacks = ();
my @write_callbacks = ();
my @except_callbacks = ();

# These variables hold the current vectors for select
my $read_vec = '';
my $write_vec = '';
my $except_vec = '';
my $max_fno = 0;

# This is a presorted stack of timouts. The next timout due to run is
# at the beginning of the stack
# Each item in the stack is a 3 element list. The first element is the
# the time the timeout is due (seconds in the Unix epoch), 
# the second is the 
# callback function to call, the third element is the argument list 
# to pass to the callback fn
@Radius::Select::timeouts = ();

# The time the next timeout is due
$Radius::Select::next_timeout = undef;

#####################################################################
# add_file
# Registers the callback function for the file number.
# if $doread is set, $callback will be called whenever select
# shows a read can be done on that file.
# Similarly for write and except.
# The callback function will be called like &$fn($fileno, @args)
# You can register different callbacks for read, write and except
# by calling add_file several times with the appropriate flags set
sub add_file
{
    my ($fileno, $doread, $dowrite, $doexcept, $fn, @args) = @_;

    if ($doread)
    {
	$read_callbacks[$fileno] = [ $fn, [ @args ]];
	vec($read_vec, $fileno, 1) = 1;
    }
    if ($dowrite)
    {
	$write_callbacks[$fileno] = [ $fn, [ @args ]];
	vec($write_vec, $fileno, 1) = 1;
    }
    if ($doexcept)
    {
	$except_callbacks[$fileno] = [ $fn, [ @args ]];
	vec($except_vec, $fileno, 1) = 1;
    }
    # Adjust the largest file we need to look at
    $max_fno = $fileno if $fileno > $max_fno;
    return $fileno;
}

#####################################################################
# remove_file
# Removes the nominated registered callbacks for the 
# specified file number
sub remove_file
{
    my ($fileno, $doread, $dowrite, $doexcept) = @_;

    if ($doread)
    {
	$read_callbacks[$fileno] = undef;
	vec($read_vec, $fileno, 1) = 0;
    }
    if ($dowrite)
    {
	$write_callbacks[$fileno] = undef;
	vec($write_vec, $fileno, 1) = 0;
    }
    if ($doexcept)
    {
	$except_callbacks[$fileno] = undef;
	vec($except_vec, $fileno, 1) = 0;
    }

    # $max_fno may have to get smaller
    my $i;
    my $newmax = 0;
    foreach $i (0 .. $max_fno)
    {
	$newmax = $i 
	    if     vec($read_vec, $i, 1) 
		|| vec($write_vec, $i, 1) 
		|| vec($except_vec, $i, 1);
    }
    $max_fno = $newmax;
}

#####################################################################
# remove_all
# Removes all the  previously registered callbacks
# Zero the callback arrays to release any object references in them
sub remove_all
{
    $read_vec = $write_vec = $except_vec = '';
    @read_callbacks = @write_callbacks = @except_callbacks = ();
    $max_fno = 0;
    &remove_all_timeouts();
}

#####################################################################
# select
# Waits for activity on the files previously specified with add_file
# When any file becomes available for activity, calls the read, write
# and exception callbacks if any have been specified for that 
# file and returns  the number of filehandles that were ready.
# If timeout is specified and no files are ready to go, 
# will wait that many seconds before before returning with 0. If
# timeout is undefined, will not wait at all.
# Returns the number of files that became active, 
# and 0 if no files became active
sub select
{
    my ($timeout) = @_;

    # Bit vectors of fds actually ready to go. Fastest way to do it
    my ($rout, $wout, $xout, $count, $timeleft);
    # $count will be set to -1 if there is an error or a signal
    # we dont scan the descriptors if so, because we are not
    # using non-blocking IO
    if ((($count, $timeleft) = select($rout = $read_vec, 
				      $wout = $write_vec, 
				      $xout = $except_vec, 
				      $timeout))
	&& $count > 0)
    {
	my $f;
	foreach $f (0 .. $max_fno)
	{
	    vec($rout, $f, 1) 
		&& $read_callbacks[$f]
		&& &{$read_callbacks[$f]->[0]}
	            ($f, @{$read_callbacks[$f]->[1]});
	    vec($wout, $f, 1) 
		&& $write_callbacks[$f]
		&& &{$write_callbacks[$f]->[0]}
	            ($f, @{$write_callbacks[$f]->[1]});
	    vec($xout, $f, 1) 
		&& $except_callbacks[$f]
		&& &{$except_callbacks[$f]->[0]}
	            ($f, @{$except_callbacks[$f]->[1]});

	}
    }
    return $count;
}

#####################################################################
# add_timeout
# Adds a timeout to the list of timeouts we are handling
# The callback function $callback will be called as soon as possible
# after $time as we can manage. The callback will be called like
# &$callback($handle, @args);
# Returns the handle which can be used to pass to remove_timout later
sub add_timeout
{
    my ($time, $callback, @args) = @_;

    my $tarray = [ $time, $callback, [ @args ] ]; # Anon array
    # Earliest times are at the beginning of the array
    if (@Radius::Select::timeouts == 0 || $time <= $Radius::Select::timeouts[0]->[0])
    {
	# Insert at head
	unshift(@Radius::Select::timeouts, $tarray);
	$Radius::Select::next_timeout = $time;
    }
    else
    {
	my $min = 0;
	my $max = $#Radius::Select::timeouts;
	my $latest = $Radius::Select::timeouts[$max]->[0];
	if ($time >= $latest)
	{
	    # Append to tail
	    push(@Radius::Select::timeouts, $tarray);
	}
	else
	{
	    # ITs somewhere between $earliest and $latest
	    # Conduct a binary search for the insertion point
	    my $guess;
	    while ($min < $max-1)
	    {
		$guess = int($min + (($max - $min) / 2));
		if ($Radius::Select::timeouts[$guess]->[0] > $time)
		{
		    # Guess is too big
		    $max = $guess;
		}
		else
		{
		    $min = $guess;
		}
	    }
	    # This is where we insert it
	    splice(@Radius::Select::timeouts, $min+1, 0, $tarray);
	}
    }
    return $tarray;
}

#####################################################################
# remove_timeout
# Removes a previously registered timeout
sub remove_timeout
{
    my ($handle) = @_;

    # Break any possible reference loop and notify process_timeouts that the
    # timeout has been removed
    $handle->[2] = undef;

    # Get the next timout time without creating an 
    # entry if there isnt one already
    $Radius::Select::next_timeout = @Radius::Select::timeouts 
	? $Radius::Select::timeouts[0]->[0] 
	    : undef;
}

#####################################################################
# Unconditionally remove all timeouts
sub remove_all_timeouts
{
    my $t;
    while ($t = shift @Radius::Select::timeouts)
    {
	# Break any possible reference loop
	$t->[2] = undef;
    }
}

#####################################################################
# process_timeouts
# Finds and calls all the timeouts that are due to have gone off by now
# Returns the number of timeouts called
# This does a linear search through a presorted array. 
# Its the best I can do.
sub process_timeouts
{
    my $now = time;

    return 0 
	if !defined $Radius::Select::next_timeout
	|| $Radius::Select::next_timeout > $now;

    my $count = 0;
    while (   scalar @Radius::Select::timeouts
	   && $Radius::Select::timeouts[0]->[0] <= $now)
    {
	my $t = shift @Radius::Select::timeouts;

	# process the timeout if it hasn't been removed
        if (defined($t->[2]))
	{
		# Call the callback fn
		&{$t->[1]}($t,@{$t->[2]});
		$count++;
	
		# Break any possible reference loop
		$t->[2] = undef;
	}
    }

    # Get the next timeout time without creating an
    # entry if there isnt one already
    $Radius::Select::next_timeout = @Radius::Select::timeouts 
	? $Radius::Select::timeouts[0]->[0] 
	    : undef;

    return $count;
}

#####################################################################
# Simple-minded main loop
sub simple_main_loop
{
    $Radius::Select::exit_simple_main_loop = 0;
    while (!$Radius::Select::exit_simple_main_loop)
    {
	&Radius::Select::select(1);
	&Radius::Select::process_timeouts();
    }
}

#####################################################################
sub exit_simple_main_loop
{
    $Radius::Select::exit_simple_main_loop++;
}


1;

