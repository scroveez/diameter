# SqlDbINTERBASE.pm
#
# Object for handling an INTERBASE SQL database. 
# Routines are provided to connect to a server (and fall back
# to alternates if not available.
# Also routines to do generic prepare/execute
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: SqlDbINTERBASE.pm,v 1.1 1999/07/12 02:01:35 mikem Exp $

package Radius::SqlDb;
use Radius::Configurable;
use IBPerl;
use strict;

use vars qw($VERSION @ISA);
BEGIN 
{
    @ISA = qw(Radius::Configurable);
}

#####################################################################
# Constructs a new SQL database
sub new
{
    my ($class, $file, @args) = @_;

    my $self = $class->SUPER::new($file);

    &main::log($main::LOG_WARNING, 
	       "No DBSource defined for $class at '$main::config_file' line $.")
	if @{$self->{DBSource}} == 0;

    return $self;
}

#####################################################################
# Do per-instance default initialization
# This is called by Configurable during Configurable::new before
# the config file is parsed. Its a good place initalze 
# instance variables
# that might get overridden when the config file is parsed.
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    # Empty arrays for database details
    $self->{DBSource}   = [];
    $self->{DBUsername} = [];
    $self->{DBAuth}     = [];

}

#####################################################################
# Override the keyword function in Configurable
sub keyword
{
    my ($self, $file, $keyword, $value) = @_;

    if ($keyword eq 'DBSource')
    {
	push @{$self->{DBSource}}, $value;
    }
    elsif ($keyword eq 'DBUsername')
    {
	push @{$self->{DBUsername}}, $value;
    }
    elsif ($keyword eq 'DBAuth')
    {
	push @{$self->{DBAuth}}, $value;
    }
    else
    {
	return $self->SUPER::keyword($file, $keyword, $value);
    }
    return 1;
}

#####################################################################
# reconnect
# Connect or reconnect to a database
# Returns true if there is a viable database connection available
sub reconnect
{
    my ($self) = @_;

    if (!defined $self->{dbh})
    {
	# A new connection is required, try all the 
	# ones in the $self->{DBSource} in order til we 
	# find a good one
	my $i;
	for ($i = 0; $i < @{$self->{DBSource}}; $i++)
	{
	    my ($server, $path) = split(':', $self->{DBSource}[$i]);
	    $self->{dbh} = new IBPerl::Connection
		(Server => $server,
		 Path => $path,
		 User => $self->{DBUsername}[$i],
		 Password => $self->{DBAuth}[$i]);
	    
	    if ($self->{dbh}{Handle} != -1)
	    {
		return 1; # Database is available
	    }
	    &main::log($main::LOG_ERR, "Could not connect to INTERBASE database with DBI->connect $self->{DBSource}[$i], $self->{DBUsername}[$i], $self->{DBAuth}[$i]: $self->{dbh}{Error}");
	}
	&main::log($main::LOG_ERR, "Could not connect to any SQL database. Request is ignored.");
	$self->{dbh} = undef;
	return 0;  # Database is not available
    }
    return 1; # Database is still up

}

#####################################################################
# Turn a Unix epoch seconds count into an SQL format date
# of the format Sep 3, 1995 13:37
# Uses local time
my @months = (
	      'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
	      'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
	      );

sub formatSQLDate
{
    my ($time) = @_;

    my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) 
	= localtime($time);
    $year += 1900 if $year < 1900; # Y2K
    return "$months[$mon] $mday, $year $hour:$min";
}

#####################################################################
# Convenience function to prepare and execute a query.
# If it fails to execute, complain, and try to reconnect and reexecute.
# If it still fails to execute, return undef, else a statement handle
sub prepareAndExecute
{
    my ($self, $q) = @_;
    my $attempts;
    my $sth;
    &main::log($main::LOG_DEBUG, "Query is: $q\n");

    # Try to execute the query. If we fail due to database failure
    # try to reconnect and try again. If that also fails, give up
    while (!$sth && $attempts++ < 2)
    {
	if ($self->reconnect())
	{
	    my $trans = new IBPerl::Transaction(Database => $self->{dbh});
	    if ($trans->{Handle} == -1)
	    {
		&main::log($main::LOG_ERR, 
			   "Could not create transaction for '$q': $trans->{Error}");
		next;
	    }

	    $sth = new IBPerl::Statement
		(Transaction => $trans,
		 Stmt => $q);
	    if ($sth->{Handle} != -1)
	    {
		return $sth if $sth->open() == 0;

		&main::log($main::LOG_ERR, 
			   "Open failed for '$q': $sth->{Error}");
	    }
	    else
	    {
		&main::log($main::LOG_ERR, 
			   "Prepare failed for '$q': $sth->{Error}");
	    }
	    # Hmm, failed prob due to database failure, try reconnect
	    $self->{dbh}->disconnect;
	    $self->{dbh} = undef;
	    $sth = undef;
	}
    }
    return undef;
}

#####################################################################
# Convenience function to do a query.
# If it fails to execute, complain, and try to reconnect and reexecute.
sub do
{
    my ($self, $q) = @_;
    my $attempts;
    my $rc;

    &main::log($main::LOG_DEBUG, "do query is: $q\n");
	
    while (!defined($rc) && $attempts++ < 2)
    {
	if ($self->reconnect())
	{
	    my $trans = new IBPerl::Transaction(Database => $self->{dbh});
	    if ($trans->{Handle} == -1)
	    {
		&main::log($main::LOG_ERR, 
			   "Could not create transaction for '$q': $trans->{Error}");
		next;
	    }

	    my $sth = new IBPerl::Statement
		(Transaction => $trans,
		 Stmt => $q);
	    if ($sth->{Handle} != -1)
	    {
		# This should be a row count, but I dont know how
		# to get that yet.
		return 1 if $sth->execute() == 0;

		&main::log($main::LOG_ERR, 
			   "Execute failed for '$q': $sth->{Error}");
	    }
	    else
	    {
		&main::log($main::LOG_ERR, 
			   "Prepare failed for '$q': $sth->{Error}");
	    }
	    # Hmm, failed prob due to database failure, try reconnect
	    $self->{dbh}->disconnect;
	    $self->{dbh} = undef;
	    $sth = undef;

	}
    }
    return undef;
}

# Fake the fetchrow entry point from DBI that all the Radiator code wants to use
sub IBPerl::Statement::fetchrow
{
    my ($sth) = @_;

    my @result;
    $sth->fetch(\@result);
    return @result;
}

sub IBPerl::Statement::finish
{
}

# Fake the quote function from DBI
sub IBPerl::Connection::quote
{
    my ($dbh, $s) = @_;

    return "NULL" unless defined $s;
    $s =~ s/'/''/g;		# ISO SQL2
    return "'$s'";
}
1;
