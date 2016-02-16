#!/usr/bin/perl
# radwho.pl
# Radiator command line script to summarize "who is online" from 
# DBM or SQL SessionDatabase. Based on radwho.cgi
#
# Installation instructions
# 1. Modify $filename below to point to the place where your DBM session
#    file lives. Else you can call it with the -f argument
#    Else define $DBSource et al so the data comes from SQL
# 2. Install this file in your normal executable file directory
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001 Open System Consultants
# $Id: radwho.pl,v 1.3 2012/06/27 23:27:18 mikem Exp $

use Getopt::Long;
my @options = (
	       'h',          # Help, show usage
	       'f=s',        # DBM filename to use
	       't=s',        # Force a database type, DB_File, GDBM_File etc
	       's=s',        # Sort by
	       'reverse',    # Reverse sort
	       'delete=s',   # delete nas_id:nas_port
	       'terminate=s',   # terminate name:nas_is:nas_port
	       'dbsource=s',
	       'dbusername=s',
	       'dbauth=s',
	       'table=s',    # table name to use
	       );

&GetOptions(@options) || &usage;
&usage if $opt_h;

# This will cause perl to choose the 'best' DBM format available to
# you. You can force it to use another format by setting $dbtype to
# NDBM_File, DB_File, GDBM_File, SDBM_File or ODBM_File
$dbtype = 'AnyDBM_File';
$dbtype = $opt_t if defined $opt_t;
require "$dbtype.pm";

# ------------------------------------------------------------
# Configurable variables

# The default name of the detail file to summarize
# If you define $DBSource, the file wil be ignored, and the data will come
# from an SQL database
$filename = '/usr/local/etc/raddb/online';
$filename = $opt_f if defined $opt_f;

# If you define these, we get the data from SQL, rather than a flat file
# The config of this is still pretty rough and ready.
# You will probably need to tune the table name and queries to 
# suit your database. What we present here will suit the simple
# tables that are created by the sample schemas in the goodies directory.
$DBSource = undef;
$DBUsername = '';
$DBAuth = '';

# You can force different default SQL server details 
# here or use command line args
#$DBSource = 'dbi:mysql:radius';
#$DBUsername = 'mikem';
#$DBAuth = 'fred';

# Use command line args if present
$DBSource = $opt_dbsource if defined $opt_dbsource;
$DBUsername = $opt_dbusername if defined $opt_dbusername;
$DBAuth = $opt_dbauth if defined $opt_dbauth;

$table = $opt_table || 'RADONLINE';

# If you are using SQL, this array specifies the columns to get
# the headings to use and any conversions to apply
# If you want to display more or fewer attributes, change this
# array
#      Heading             Column Name        Type
@DBColumns = 
    (
     ['User-Name',         'USERNAME',        'string'],
     ['NAS-Identifier',    'NASIDENTIFIER',   'string'],
     ['NAS-Port',          'NASPORT',         'integer'],
     ['Acct-Session-Id',   'ACCTSESSIONID',   'string'],
     ['Timestamp',         'TIME_STAMP',      'integer-date'],
     ['Time On',           'TIME_STAMP',      'interval'],
     ['Framed-IP-Address', 'FRAMEDIPADDRESS', 'string'],
     ['NAS-Port-Type',     'NASPORTTYPE',     'string'],
     ['Service-Type',      'SERVICETYPE',     'string'],
     );

# You might need this or something like for your database
#$ENV{ORACLE_HOME} = '/usr/local/oracle/app/oracle/product/7.3.2';

# If you have a program to kick users off your NAS, define the full
# path to it here. It will add a new button allow you to kick off 
# an individual user. This is different to just deleting the session
# It will be called as "prog NAS-ID NAS-PORT USERNAME"
#$sessionTerminateProg = "/the/path/to/your/terminateprog";

# This controls the format for printing intervals, days, hours,
# minutes seconds
$interval_format = '%d %02d:%02d:%02d';

# End of Configurable variables
# ------------------------------------------------------------

# Default sort order is by User-Name
$sortBy = 'User-Name';
$sortBy = $opt_s if defined $opt_s;
$sortReverse = undef;
$sortReverse = $opt_r if defined $opt_r;

if (defined $opt_delete)
{
    my ($nas_id, $nas_port) = split(':', $opt_delete);
    &delete_session($nas_id, $nas_port);
}
elsif (defined $opt_terminate)
{
    # Force the NAS to terminate the session
    my ($name, $nas_id, $nas_port) = split(':', $opt_terminate);
    &terminate_session($name, $nas_id, $nas_port);
}
&show_sessions();
    

###############################################################
sub show_sessions
{
    my $done_at = scalar localtime(time);
    print "Current Sessions by $sortBy at $done_at\n";

    if (defined $DBSource)
    {
	# Show SQL. Build the heading from the table DBColumns

        my $r;
	foreach $r (@DBColumns)
	{
	    print "$r->[0]\t";
	}
	print "\n";
        &read_sql();
    }
    else
    {
	# Show file
	print "User-Name\tNAS-Identifier\tNAS-Port\tAcct-Session-Id\tTimestamp\tFramed-IP-Address\tNAS-Port-Type\tService-Type\n";
        &read_file();
	print "$usercount users\n";

    }
}

###############################################################
# Connect to the SQL server
sub sql_connect
{
    return if $dbh;

    require DBI;
    # Sigh: freetds prints stuff to stderr during setup
    # which breaks apache (and prob most other web servers)
    # Redirect stderr to /dev/null
    if ($^O ne 'MSWin32' && $DBSource =~ /FreeTDS/)
    {
	open(OLDERR, ">&STDERR");
	open(STDERR, ">/dev/null");
    }
    $dbh = DBI->connect($DBSource,
			$DBUsername,
			$DBAuth);

    if ($^O ne 'MSWin32' && $DBSource =~ /FreeTDS/)
    {
	open(STDERR, ">&OLDERR");
	close(OLDERR);
    }
    fatalError("Could not connect to database") unless $dbh;
}

###############################################################
# Read the SQL table, and accumulate or print details
sub read_sql
{
    sql_connect();

    my ($cols, $orderby, $r);
    # Get the column names from @DBColumns and join with commas
    foreach $r (@DBColumns)
    {
	$cols .= "$r->[1],";
	$orderby = " order by $r->[1]"
	    if ($sortBy eq $r->[0]);
    }
    $cols =~ s/,$//; # Strip the last trailing comma

    $orderby .= " descending" if $sortReverse;
    $q = "select $cols from $table $orderby";

    my $sth = &prepareAndExecute($dbh, $q);
    while (@vals = $sth->fetchrow())
    {
	my ($name, $nas_id, $nas_port);
	
	$usercount++;
	foreach $r (@DBColumns)
	{
	    my $d = shift @vals;
	    # do some trivial formatting
	    if ($r->[2] eq 'integer-date')
	    {
		$d = scalar localtime($d);
	    }
	    elsif ($r->[2] eq 'interval')
	    {
		$d = &formatInterval(time - $d);
	    }

	    print "$d\t";
	    # Figure out some specific attributes for using in the delete hotlink
	    $name = $d if $r->[0] eq 'User-Name';
	    $nas_id = $d if $r->[0] eq 'NAS-Identifier';
	    $nas_port = $d if $r->[0] eq 'NAS-Port';
	}
	print "\n";
    }
    $sth->finish;
    $dbh->disconnect;
}

###############################################################
# Open our DBM file and map it to %online
sub open_dbm
{
    return if $dbm_opened;
    tie (%online, $dbtype, $filename, O_RDWR, 0666)
	|| &fatalError("Could not open online database file '$filename' $!");
    $dbm_opened++;
}

###############################################################
# Read the DBM file, and accumulate details.
# We do the sort internally, cause DBM cant do it for us.
sub read_file
{
    # Make %online map to our DBM file
    open_dbm();

    my ($key, $value);
    my @sessions;
    while (($key, $value) = each %online)
    {
	my ($nas_id, $nas_port) = split(/:/, $key);
	my ($this_name, $session_id, $timestamp, $framed_address, 
	    $service_type, $port_type) 
	    = split(/:/, $value);
	# OK, now we have the raw dat from the DBM file. Save it in
	# a format easy to sort and to
	# get back after sorting: as an arrah of anonymous
	# hashes
	my $hash = {
	    'User-Name'         => $this_name,
	    'NAS-Identifier'    => $nas_id,
	    'NAS-Port'          => $nas_port,
	    'Acct-Session-Id'   => $session_id,
	    'Timestamp'         => $timestamp,
	    'Framed-IP-Address' => $framed_address,
	    'NAS-Port-Type'     => $port_type,
	    'Service-Type'      => $service_type,
	};
	push(@sessions, $hash);
    }
    untie %online;

    # Now sort the data using the sorter routine, which uses the 
    # $sortBy and $sortReverse variables
    foreach $s (sort sorter @sessions)
    {
	my $eventtime = scalar localtime($s->{'Timestamp'});
	
	$usercount++;
	print "$s->{'User-Name'}\t$s->{'NAS-Identifier'}\t$s->{'NAS-Port'}\t$s->{'Acct-Session-Id'}\t$eventtime\t$s->{'Framed-IP-Address'}\t$s->{'NAS-Port-Type'}\t$s->{'Service-Type'}\n";
    }
}

# Remove the indicated session from the database
sub delete_session
{
    my ($nas_id, $nas_port) = @_;

    if (defined $DBSource)
    {
	# Session database is SQL
	sql_connect();

	# BUG ALERT: this does not necessarily match whats in DBColumns
	my $q = "delete from $table 
where NASIDENTIFIER='$nas_id' and NASPORT=$nas_port";
	my $rc = $dbh->do($q)
	    || &fatalError("SessSQL do failed for '$q': $DBI::errstr");
    }
    else
    {
	# Session database is DBM
	open_dbm();
	my $key = "$nas_id:$nas_port";
	delete $online{$key};
    }
}

# Remove the indicated session from the database
sub terminate_session
{
    my ($name, $nas_id, $nas_port) = @_;

    if ($sessionTerminateProg)
    {
	system("$sessionTerminateProg $nas_id $nas_port $name");
	# Prob should check exit status here
	# Wait for a little, gives the session a chance to end and for 
	# Radiator to remove the sess from the database
	sleep 4;
    }
}

###############################################################
sub fatalError
{
    my ($msg) = @_;

    print STDERR $msg, "\n";
    exit 1;
}

###############################################################
# Format a time period in seconds into hh:mm:ss
sub formatDuration
{
    my ($duration) = @_;
    return sprintf('%d:%02d:%02d', 
		   int($duration / 3600), 
		   int(($duration / 60) % 60), 
		   $duration % 60);
}

#####################################################################
# Convenience function to prepare and execute a query.
# If it fails to execute, return undef, else a statement handle
sub prepareAndExecute
{
    my ($dbh, $q) = @_;

    my $sth = $dbh->prepare($q);
    if (!$sth)
    {
	&fatalError("Prepare failed for '$q': $DBI::errstr");
	return undef;
    }
    my $rc = $sth->execute;
    if (!$rc)
    {
	&fatalError("Execute failed for '$q': $DBI::errstr");
	return undef;
    }
    return $sth;
}

##########################################################################
# Generic ip address, mixed, alpha and numeric sorter
# for sorting by any attribute in the hashes, in ascending
# or descending order
#
# Todd A. Green <tagreen@ixl.com> has contributed some mods to this
# routine, and here are his comments:
# Here's the sorter modified to support by IP sorts (NAS-Identifier) 
# & mixed(NAS-Port on USR/3COM at least).
sub sorter
{
    my $aa = $a->{$sortBy};
    my $bb = $b->{$sortBy};
    if ($sortReverse)
    {
        my $temp = $aa;
        $aa = $bb;
        $bb = $temp;
    }
    if ($aa =~ /\d+\.\d+\.\d+\.\d+/ &&
        $bb =~ /\d+\.\d+\.\d+\.\d+/)
    {
      # IP sort
      # Fifth iteration of this routine has gotten very compact
      $aa = sprintf('%03d.%03d.%03d.%03d', $1, $2, $3, $4) if ($aa =~
/^(\d+)\.(\d+)\.(\d+)\.(\d+)/) ;
      $bb = sprintf('%03d.%03d.%03d.%03d', $1, $2, $3, $4) if ($bb =~
/^(\d+)\.(\d+)\.(\d+)\.(\d+)/) ;
      return $aa cmp $bb;
    }
    elsif (($sortBy eq 'NAS-Port') && ($aa =~ /^\w+\d/ && $bb =~ /^\w+\d/))
    {
        # Mixed Alpha & Numeric sort
        $aa = sprintf('%s%09d', $1, $2) if ($aa =~ /^(\w+)(\d+)/) ;
        $bb = sprintf('%s%09d', $1, $2) if ($bb =~ /^(\w+)(\d+)/) ;
        return $aa cmp $bb;
    }
    elsif ($aa =~ /^\d+$/ && $bb =~ /^\d+$/)
    {
        # Numeric sort
        return $aa <=> $bb;
    }
    else
    {
        # Alpha sort
        return $aa cmp $bb;
    }
}

# Format a number of seconds into the preferred time interval
# display format
sub formatInterval
{
    my ($secs) = @_;
    if (defined $secs)
    {
	return sprintf($interval_format, 
		       int($secs / 86400),
		       int($secs / 3600) % 24, 
		       int($secs / 60) % 60, 
		       $secs % 60);
    }
    else
    {
	return '';
    }
}

sub usage
{
    print "usage: $0 [-h] [-f dbmfile] [-t dbmtype] [-delete nas_id:nas_port]
    [-terminate name:nas_id:nas_port] [-s sortby] [-reverse]
    [-dbsource dbi:drivername:option] [-dbusername dbusername] 
    [-dbauth auth]\n";
    exit;
}
