# SqlDb.pm
#
# Object for handling an SQL database. 
# Routines are provided to connect to a server (and fall back
# to alternates if not available.
# Also routines to do generic prepare/execute
#
# This module also implements database handle sharing: all instances
# that connect to the same database with the same username and password
# will share the same database connection
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: SqlDb.pm,v 1.44 2014/08/26 21:07:20 hvn Exp $

package Radius::SqlDb;
@ISA = qw(Radius::Configurable);
use Radius::Configurable;
use DBI;
use strict;

%Radius::SqlDb::ConfigKeywords = 
('DBSource'           => 
 ['stringarray', 
  'The data source name to use for each databse. This parameter is used by Perl DBI to specify the database driver and database system to connect to. It will usually begin with dbi:driver_name:. There is no standard for the text following the driver name. Consult the details for your DBD driver. Examples are dbi:mysql:radius, dbi:ODBC:Rodopi etc.', 
  0],

 'DBUsername'         => 
 ['stringarray', 
  'The SQL username to use to log in to each database, in the same order as the DBSource list', 0],

 'DBAuth'             => 
 ['stringarray', 
  'The password to use for each DBUsername to log in to each database, in the same order as the DBUsername list', 
  0],

 'Timeout'            =>
 ['integer', 
  'Specifies a timeout interval in seconds that Radiator will wait for when trying to contact the SQL server specified by DBAuth. If the server does not respond within the Timeout period, Radiator will consider the SQL server to be failed, and will stop trying to contact the SQL server until the FailureBackoffTime is expired
', 
  1],

 'FailureBackoffTime' => 
 ['integer', 'If Radiator detects an SQL server failure, it will wait for this number of seconds before trying to contact the SQL server again. ', 1],

 'SQLRetries' => 
 ['integer', 'When executing a query, Radiator will try up to SQLRetries attempts to execute the query, retrying if certain types of SQL error are seen. Defaults to 2.', 2],

 'DateFormat'         => 
 ['string', 
  'Specifies the format to be used to format dates for insertion into the AccountingTable. Any of the special % characters are permitted. Defaults to \'%b %e, %Y %H:%M\' (e.g. \'Sep 3, 1995 13:37\').', 1],

 'DisconnectAfterQuery' => ['flag', 'Forces this module to disconnect from SQL after each query.', 2],

 'SQLRecoveryFile'    => 
 ['string', '<b>This feature is known not to work as expected with some types of database. Its use is deprecated: you are strongly discouraged from using this feature. Support for it may be removed in future versions.</b><p>
This optional parameter specifies the name of a file where any failed SQL do queries will be logged, perhaps for later recovery. The default is no logging. The SQLRecoveryFile file is always opened written and closed for each failed SQL do query, so you can safely rotate it at any time. ', 3],

 'ConnectionHook'     => 
 ['hook', 
  'Specifies a Perl hook that will be run every time this clause (re)connects to the SQL database. This is most useful for executing func() to configure the database connection in customised ways.', 
  2],

 'ConnectionAttemptFailedHook' => 
 ['hook', 
  'Specifies a Perl hook that will be run whenever the module attempts to conent to an SQL database and fails to connect. The default just logs the failure.', 
  2],

 'NoConnectionsHook'           => 
 ['hook', 
  'Specifies a Perl hook that will be run whenever the module fails to connet to any SQL server. The default just logs the failure.', 
  2],
 'RoundRobinOnFailure'           => 
 ['flag', 
  'This flag specifies that in the event of a database failure or timeout, it will attempt to connect to the next database in the list, instead of going back to the first database in the list', 
  1],
 );

# RCS version number of this module
$Radius::SqlDb::VERSION = '$Revision: 1.44 $';

# This is a hash of "$dbsource;$dbusername;$dbauth" to database handle
# that allows multiple instances to share handles
%Radius::SqlDb::handles = ();

# This is a hash of "$dbsource;$dbusername;$dbauth" to prepared statements
# that allows multiple instances to share prepared statements
%Radius::SqlDb::statements = ();

#
# Define the maximum number of cached prepared statements
#
$Radius::SqlDb::MAX_CACHED_PREPARED_STATEMENTS = 32;


#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    my $type = ref($self);
    $self->log($main::LOG_WARNING, "No DBSource defined for $type in '$main::config_file'")
	unless @{$self->{DBSource}};

    $self->SUPER::check_config();
    return;
}

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();

    $self->{backoff_until} = 0;
    $self->{roundrobin_counter} = 0;
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
    $self->{Timeout}    = 60; # Seconds
    $self->{SQLRetries} = 2;
    $self->{FailureBackoffTime} = 600; # Seconds
    $self->{DateFormat} = '%b %e, %Y %H:%M'; # eg 'Sep 3, 1995 13:37'

    $self->set("ConnectionAttemptFailedHook",
               'sub {
                      my $self = shift;
                      my $dbsource = shift;
                      my $dbusername = shift;
                      my $dbauth = shift;

	              # If the connect failed, we get an exception, with
	              # the message in $@
 	              $self->log($main::LOG_ERR, "Could not connect to SQL database with DBI->connect $dbsource, $dbusername, **obscured**: $@ $DBI::errstr");
                     }');

    $self->set("NoConnectionsHook",
               'sub { 
                      my $self = shift;

	              $self->log($main::LOG_ERR, "Could not connect to any SQL database. Request is ignored. Backing off for $self->{FailureBackoffTime} seconds");
                     }');

}

#####################################################################
# reconnect
# Connect or reconnect to a database
# Returns true if there is a viable database connection available
sub reconnect
{
    my ($self) = @_;

    # Implement backoff strategy in case of database failure
    return 0 if time < $self->{backoff_until};

    # Maybe restart at the first one
    $self->{roundrobin_counter} = 0 unless $self->{RoundRobinOnFailure};

    if (!$self->{dbname} || !$Radius::SqlDb::handles{$self->{dbname}})
    {
	#print "Reconnecting to $self->{dbname}\n";
	# A new connection is required, try all the 
	# ones in the $self->{DBSource} in order til we 
	# find either an existing shared one, or a can create
	# a new connection
	my $i;
	my $database_count = @{$self->{DBSource}};
	for ($i = 0; $i < $database_count; $i++)
	{
	    my ($dbsource, $dbusername, $dbauth) 
		= ($self->{DBSource}[$self->{roundrobin_counter}], 
		   $self->{DBUsername}[$self->{roundrobin_counter}],
		   $self->{DBAuth}[$self->{roundrobin_counter}]);
	    $dbsource = &Radius::Util::format_special($dbsource, undef, $self);
	    $dbusername = &Radius::Util::format_special($dbusername, undef, $self);
	    $dbauth = &Radius::Util::format_special($dbauth, undef, $self);
	    $self->{dbsource} = $dbsource;
	    $self->{dbname} = "$dbsource;$dbusername;$dbauth";
	    $self->{roundrobin_counter} = ($self->{roundrobin_counter} + 1) % $database_count;
	    return 1 
		if $Radius::SqlDb::handles{$self->{dbname}};

	    $self->log($main::LOG_DEBUG, "Connecting to '$dbsource'\n");
	    # We evaluate the connection 
	    # with an alarm for the timeout period
	    # pending. If the alarm goes off, the eval will die
	    &Radius::Util::exec_timeout($self->{Timeout},
                    sub {
			$Radius::SqlDb::handles{$self->{dbname}} 
			= DBI->connect($dbsource,
				       $dbusername,
				       $dbauth,
				       { PrintError => 0 });
		    });

	    if ($Radius::SqlDb::handles{$self->{dbname}})
	    {
		$Radius::SqlDb::handles{$self->{dbname}}->{AutoCommit} = 1;
		# This one stops DBD-Sybase finish causing hangs
		# in MS-SQL, see Sybase.pm in DBD-Sybase.
		$Radius::SqlDb::handles{$self->{dbname}}->{syb_flush_finish} = 1;

		# Call the ConnectionHook, if there is one
		$self->runHook('ConnectionHook', undef, $self, $Radius::SqlDb::handles{$self->{dbname}});

#		$Radius::SqlDb::handles{$self->{dbname}}->trace(15);

                delete $Radius::SqlDb::statements{$self->{dbname}};

		return 1; # Database is available
	    }
	    $self->runHook('ConnectionAttemptFailedHook', undef, $self, $dbsource, $dbusername, $dbauth);
	}
	$self->runHook('NoConnectionsHook', undef, $self);
	$self->{backoff_until} = time + $self->{FailureBackoffTime};

	return 0;  # Database is not available
    }
    return 1; # Database is still up

}

#####################################################################
# Turn a Unix epoch seconds count into an SQL format date
# of the format Sep 3, 1995 13:37
# Uses local time
# This is deprecated and will be removed one day soon
# use $self->formatDate() or
# Radius::Util::strftime($self->{DateFormat}) instead
sub formatSQLDate
{
    return Radius::Util::strftime('%b %e, %Y %H:%M', $_[0]);
}

# Format a date according to DateFormat
sub formatDate
{
    my ($self, $time) = @_;
    return Radius::Util::strftime($self->{DateFormat}, $time);
}

#####################################################################
# Convenience function to prepare and execute a query.
# If it fails to execute, complain, and try to reconnect and reexecute.
# If it still fails to execute, return undef, else a statement handle
# We keep a cache of the first MAX_CACHED_PREPARED_STATEMENTS statments
# that have bind variables, for the sake of the efficiency of the SQL server.
sub prepareAndExecute
{
    my ($self, $q, @bind_values) = @_;
    my ($attempts, $cached_sth, $sth, $rc);


    # Try to execute the query. If we fail due to database failure
    # try to reconnect and try again. If that also fails, give up
    while (!$sth && $attempts++ < $self->{SQLRetries})
    {
	if ($self->reconnect())
	{
	    $self->log($main::LOG_DEBUG, "Query to '$self->{dbsource}': '$q': @bind_values");
            $cached_sth = $sth = $Radius::SqlDb::statements{$self->{dbname}}{$q}
	        if @bind_values > 0;

	    # We evaluate the execution
	    # with an alarm for the timeout period
	    # pending. If the alarm goes off, the eval will die
	    &Radius::Util::exec_timeout($self->{Timeout},
		sub {
		$sth = $Radius::SqlDb::handles{$self->{dbname}}->prepare($q) 
		    if !$sth;
		$rc = $sth->execute(@bind_values) if $sth;
	    });


	    # Preparing a statement is a relatively expensive operation.
	    # Keep the statement around for future use.
	    #
	    if ((@bind_values > 0) && $sth && ($sth ne $cached_sth))
	    {
		my @tmp = keys %{$Radius::SqlDb::statements{$self->{dbname}}};
		
		# Cache the prepared statement only as long as we still have room
		$Radius::SqlDb::statements{$self->{dbname}}{$q} = $sth
		    if @tmp <= $Radius::SqlDb::MAX_CACHED_PREPARED_STATEMENTS;
	    }

	    # Some DBD drivers dont undef rc on DB failure
	    return $sth if $sth && $rc && !$DBI::err;
	    # If we got here, something went wrong
	    my $reason = $DBI::errstr;

	    # Primary key violation is not a cause for disconnection
	    return $sth if $reason =~ /violation/i
		          || $reason =~ /duplicate key/im
		          || $reason =~ /Duplicate entry/im
			  || $reason =~ /^ORA-00001/;
	    
	    $reason = "SQL Timeout" if $@ && $@ =~ /timeout/;
	    $reason = $@ unless defined $reason;
	    $self->log($main::LOG_ERR, "Execute failed for '$q': $reason");
	}
	# Hmm, failed prob due to database failure, try to reconnect
	# to an alternate
	$self->disconnect();
	$sth = undef;
    }
    return;
}

#####################################################################
# Convenience function to do a query.
# If it fails to execute, complain, and try to reconnect and reexecute up to MaxRetries times.
sub do
{
    my ($self, $q, @bind_values) = @_;
    my ($attempts, $rc, $reason);

    no warnings qw(uninitialized);
    $self->log($main::LOG_DEBUG, "do query to '$self->{dbsource}': '$q': @bind_values");
	
    while (!defined($rc) && $attempts++ < $self->{SQLRetries})
    {
	if ($self->reconnect())
	{
	    # We evaluate the execution
	    # with an alarm for the timeout period
	    # pending. If the alarm goes off, the eval will die
	    &Radius::Util::exec_timeout($self->{Timeout},
                     sub {
			 $rc = $Radius::SqlDb::handles{$self->{dbname}}->do
			     ($q, undef, @bind_values);
		     });
	    $self->disconnect() if $self->{DisconnectAfterQuery};
	    if (!$rc)
	    {
		$reason = $DBI::errstr;
		$reason = "SQL Timeout" if $@ && $@ =~ /timeout/;
		$self->log($main::LOG_ERR, 
			   "do failed for '$q': $reason");
	    }
	    # Primary key violation is not a cause for disconnection
	    return $rc if defined $rc 
		          || $reason =~ /violation/i
		          || $reason =~ /duplicate key/im
		          || $reason =~ /Duplicate entry/im
			  || $reason =~ /^ORA-00001/;
	}
	# there was an error (as opposed to no rows affected)
	$self->disconnect();
    }

    # Failure, maybe log the query to a file
    $self->saveQueryToFile($q, $self->{SQLRecoveryFile})
	if defined $self->{SQLRecoveryFile};
    return;
}

#####################################################################
# Save the text of an SQL query to a file, for later recovery
sub saveQueryToFile
{
    my ($self, $query, $file) = @_;

    &Radius::Util::append(&Radius::Util::format_special($file, undef, $self), $query . "\n");
}

#####################################################################
# Get a single row from a previously prepared handle, 
# with appropriate timeouts
sub getOneRow
{
    my ($self, $sth) = @_;

    my @row;
    &Radius::Util::exec_timeout($self->{Timeout},
       sub {
	   @row = $sth->fetchrow();
           $sth->finish;
       });
    
    $self->disconnect() if $self->{DisconnectAfterQuery};
    if ($@ && $@ =~ /timeout/)
    {
	# there was an error (as opposed to no rows affected)
	$self->disconnect();
	$self->log($main::LOG_ERR, "getOneRow timed out");
    }
    return @row;
}

#####################################################################
# Returns true if the database server is currently connected.
sub connected
{
    my ($self) = @_;

    return exists($Radius::SqlDb::handles{$self->{dbname}})
        && defined $Radius::SqlDb::handles{$self->{dbname}};
}

#####################################################################
# Force disconnection from the current database
# Protect against timeouts
sub disconnect
{
    my ($self) = @_;

    if (exists($Radius::SqlDb::handles{$self->{dbname}})
        && defined $Radius::SqlDb::handles{$self->{dbname}})
    {
        &Radius::Util::exec_timeout($self->{Timeout},
				    sub { $Radius::SqlDb::handles{$self->{dbname}}->disconnect });
    }
    delete $Radius::SqlDb::handles{$self->{dbname}};
    delete $Radius::SqlDb::statements{$self->{dbname}};
}

#####################################################################
# Quote a string in a DB dependent way, but hide the dbh
# Ensures the database is connected first.
# Protect against timeouts
sub quote
{
    my ($self, $s) = @_;

    return unless $self->reconnect();

    my $ret;
    &Radius::Util::exec_timeout
	($self->{Timeout},
	 sub { $ret = $Radius::SqlDb::handles{$self->{dbname}}->quote($s) });

    if ($@ && $@ =~ /timeout/)
    {
        $self->disconnect();
        $self->log($main::LOG_ERR, "dbh->quote timed out");
    }
    return $ret;
}

#####################################################################
sub queryOneRow
{
    my ($self, $q, @bind_values) = @_;

    my $sth = $self->prepareAndExecute($q, @bind_values);
    return unless $sth;
    return $self->getOneRow($sth);
}

1;
