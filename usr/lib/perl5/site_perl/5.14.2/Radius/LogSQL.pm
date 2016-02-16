# LogSQL.pm
#
# Log to an SQL table
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: LogSQL.pm,v 1.25 2014/03/05 22:17:29 hvn Exp $

package Radius::LogSQL;
@ISA = qw(Radius::LogGeneric Radius::SqlDb);
use File::Path;
use File::Basename;
use Radius::LogGeneric;
use Radius::SqlDb;
use strict;

%Radius::LogSQL::ConfigKeywords = 
('Table' => 
 ['string', 'Defines the name of the SQL table to insert into. Defaults to "RADLOG". Special formatting characters are permitted.', 1],

 'LogQuery' => 
 ['string', 'This optional parameter allows you to control the SQL query that is used to insert log messages into the database. Special formatting characters are permitted. %0 is replaced with the message severity as an integer, %1 with the severity as a string, and %2 with the log message. %3 is converted to the table name defined by the Table parameter.', 1],

 'LogQueryParam' =>
 ['stringarray', 'This optional parameter enables the use of bound variables (where supported by the SQL server) and query caching. If you specify one or more LogQueryParam parameters, they will be used in order to replace parameters named with a question mark (\`?\') in LogQuery, and the query will be cached for future reuse by the SQL server. Only the first QueryCacheSize queries will be cached.', 1],

 );

# RCS version number of this module
$Radius::LogSQL::VERSION = '$Revision: 1.25 $';

# Catch recursion in calls to log
# LogSQL needs its own private recursion protection, because
# it inherits from SQlDb, which does $self->log()
my $in_log = 0;

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    $self->Radius::LogGeneric::check_config();
    $self->Radius::SqlDb::check_config();
    return;
}

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->Radius::LogGeneric::activate;
    $self->Radius::SqlDb::activate;
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

    $self->Radius::LogGeneric::initialize;
    $self->Radius::SqlDb::initialize;
    $self->{Table} = 'RADLOG';
    $self->{LogQuery} = 'insert into %3 (TIME_STAMP, PRIORITY, MESSAGE) values (%t, %0, %2)';
}

#####################################################################
# Log a message 
# $priority is the message priority, $s is the message
# $r is the current request packet, if any
sub log
{
    my ($self, $priority, $s, $p) = @_;

    # Catch recursion
    return if $in_log++;

    if ($self->willLog($priority, $p) && $self->reconnect())
    {
	my $table = &Radius::Util::format_special($self->{Table}, $p, $self);
	$s = substr($s, 0, $self->{MaxMessageLength}) if $self->{MaxMessageLength};

	# Always format the query. This allows the table name to be
	# set with a special also when query parameters are used.
	my $q = &Radius::Util::format_special
	    ($self->{LogQuery}, $p, $self,
	     $priority,
	     $Radius::Log::priorityToString[$priority],
	     $self->quote($s),
	     $table,
	     $p ? $self->quote($p->getUserName()) : 'NULL');

	if (!$self->{LogQueryParam})
	{
	    $self->do($q);
	}
	else
	{
	    my @bind_values;
	    map (push(@bind_values, Radius::Util::format_special(
			  $_, $p, $self,
			  $priority,
			  $Radius::Log::priorityToString[$priority],
			  $s,
			  $table,
			  $p ? $p->getUserName() : 'NULL')),
		 @{$self->{LogQueryParam}});

	    $self->prepareAndExecute($q, @bind_values);
	}
    }
    $in_log = 0;
}

1;
