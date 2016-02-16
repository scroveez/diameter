#!/usr/bin/perl
# radwho.cgi
# CGI script to summarize "who is online from DBM or SQL SessionDatabase
#
# Installation instructions
# 1. Modify $filename below to point to the place where your DBM session
#    file lives. Else you can call it with the filename tag set.
#    Else define $DBSource et al so the data comes from SQL
# 2. Install this file in your web server cgi directory
# 3. Configure your web server so that only your administration staff
#    can run this script
# 
# If you want to use this script to provide usage details to 
# your customers:
# 3. Uncomment the $secure = 1; line below
# 4. Install the file on your web server in a protected directory that
#    requires a username and password to access.
# 5. Configure your web server so that only your customers can run
#    this script. You might want to use the Pam Radius module for
#    Apache to authenticate them using radius.
#    
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: radwho.cgi,v 1.17 2004/08/02 01:16:23 mikem Exp $

use Fcntl;
use CGI;
# This will cause perl to choose the 'best' DBM format available to
# you. You can force it to use another format by setting $dbtype to
# NDBM_File, DB_File, GDBM_File, SDBM_File or ODBM_File
$dbtype = 'AnyDBM_File';
require "$dbtype.pm";

# ------------------------------------------------------------
# Configurable variables

# The default name of the detail file to summarize
# If you define $DBSource, the file wil be ignored, and the data will come
# from an SQL database
$filename = '/usr/local/etc/raddb/online';
#$filename = '/usr/local/projects/Radiator/online'; # For testing

# If you define these, we get the data from SQL, rather than a flat file
# The config of this is still pretty rough and ready.
# You will probably need to tune the table name and queries to 
# suit your database. What we present here will suit the simple
# tables that are created by the sample schemas in the goodies directory.
#$DBSource = 'dbi:mysql:radius';
#$DBUsername = 'mikem';
#$DBAuth = 'fred';

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
     ['Time-On',           'TIME_STAMP',      'interval'],
     ['Framed-IP-Address', 'FRAMEDIPADDRESS', 'string'],
     ['NAS-Port-Type',     'NASPORTTYPE',     'string'],
     ['Service-Type',      'SERVICETYPE',     'string'],
     );

# You might need this or something like for your database
#$ENV{ORACLE_HOME} = '/usr/local/oracle/app/oracle/product/7.3.2';

# If secure is set, radacct will only work from a secured web
# directory (ie will require a user name and password), and it will 
# only show information for thhat user.
# You might want to consider using the Pam Radius module for Apache 
# so that your users authenticate themselves to the web server
# in exactly the same way and with the same password as their
# network login.
#$secure = 1;

# Locally configurable HTML setup. You can change these to set up your own
# particular look and feel
$localheader = '<body bgcolor=white>';
$localfooter = '</body>';

# Define this to automatically refresh the main page every 
# $refresh_time seconds. If you comment it out, it wont
# automatically refresh
$refresh_time = 30;

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

CGI::ReadParse(*input);		# grab cgi parameters

print &CGI::PrintHeader;

# Debugging support
#print `env`;

$filename = $input{filename} if !$secure && defined $input{filename};
$me = $ENV{SCRIPT_NAME};

# If we are secure, no access unless we have a REMOTE_USER
# ie unless this script is secured
if ($secure && $ENV{'REMOTE_USER'} eq '')
{
    &fatalError("This script is not password protected. Please contact the webmaster");
}

# Default sort order is by User-Name
$sortBy = 'User-Name';
$sortBy = $input{sortBy} if defined $input{sortBy};

$refresh_time = $input{refresh_time} if defined $input{refresh_time};

if ($input{action} eq 'Delete')
{
    &delete_session($input{session_nas_id}, $input{session_nas_port});
}
elsif ($input{action} eq 'Terminate')
{
    # Force the NAS to terminate the session
    &terminate_session($input{session_name}, $input{session_nas_id}, $input{session_nas_port});
    $refresh_time = 0;
}
&show_sessions();
    

###############################################################
sub show_sessions
{
    if ($sessionTerminateProg)
    {
	$sesstermmessage = "<br>Click on \"terminate session\" to kick 
a user off the NAS.";
    }
    my $done_at = scalar localtime(time);
    my $refresh;
    $refresh = "<meta http-equiv=\"Refresh\" content=$refresh_time>"
	if $refresh_time;

	print <<EOF;
<html>
<head>
<title>Current Sessions by $sortBy at $done_at</title>
$refresh
</head>
$localheader
<h2>Current Sessions by $sortBy at $done_at</h2>
    This report shows all current sessions sorted by $sortBy. 
Click on the table headings to change the sort order.<br>
Click on \"delete session\" to remove bogus session details from 
your Session Database. $sesstermmessage
<p>
EOF
    if (defined $DBSource)
    {
	# Show SQL. Build the heading from the table DBColumns
	print <<EOF;
<table cellspacing=0 cellpadding=0 border=1>
<table cellspacing=0 cellpadding=0 border=1>
<tr BGCOLOR=orange>
EOF

        my $r;
	foreach $r (@DBColumns)
	{
	    print "<th><a href=$me?sortBy=$r->[0]>$r->[0]</a></th>\n";
	}
	print "</tr>\n";
        &read_sql();
	print "$table\n</table></body></html>\n";

    }
    else
    {
	# Show file
	print <<EOF;
<table cellspacing=0 cellpadding=0 border=1>
<table cellspacing=0 cellpadding=0 border=1>
<tr BGCOLOR=orange>
<th><a href=$me?sortBy=User-Name>User-Name</a></th>
<th><a href=$me?sortBy=NAS-Identifier>NAS-Identifier</a></th>
<th><a href=$me?sortBy=NAS-Port>NAS-Port</a></th>
<th><a href=$me?sortBy=Acct-Session-Id>Acct-Session-Id</a></th>
<th><a href=$me?sortBy=Timestamp>Timestamp</a></th>
<th><a href=$me?sortBy=Framed-IP-Address>Framed-IP-Address</a></th>
<th><a href=$me?sortBy=NAS-Port-Type>NAS-Port-Type</a></th>
<th><a href=$me?sortBy=Service-Type>Service-Type</a></th></tr>
EOF
        &read_file();
	print "$usercount users:<br>$table\n</table>$localfooter</html>\n";

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
	    if ($sortBy eq $r->[0])
    }
    $cols =~ s/,$//; # Strip the last trailing comma

    $q = "select $cols from RADONLINE $orderby";

    my $sth = &prepareAndExecute($dbh, $q);
    while (@vals = $sth->fetchrow())
    {
	my ($name, $nas_id, $nas_port);
	
	$usercount++;
	$table .= "<tr bgcolor=yellow>\n";
	foreach $r (@DBColumns)
	{
	    my $d = shift @vals;
	    $d =~ s/\0+$//g; # Some servers give us a trailing NUL!!!

	    # do some trivial formatting
	    if ($r->[2] eq 'integer-date')
	    {
		$d = scalar localtime($d);
	    }
	    elsif ($r->[2] eq 'interval')
	    {
		$d = &formatInterval(time - $d);
	    }

	    $table .= "<td>$d</td>\n";
	    # Figure out some specific attributes for using in the delete hotlink
	    $name = $d if $r->[0] eq 'User-Name';
	    $nas_id = $d if $r->[0] eq 'NAS-Identifier';
	    $nas_port = $d if $r->[0] eq 'NAS-Port';
	}
	if ($sessionTerminateProg)
	{
	    $table .= "<td><a href=\"$me?action=Terminate&session_name=$name&session_nas_id=$nas_id&session_nas_port=$nas_port\">terminate session</a></td>\n";
	    
	}
	$table .= "<td><a href=\"$me?action=Delete&session_nas_id=$nas_id&session_nas_port=$nas_port&sortBy=$sortBy\">delete session</a></td></tr>\n";
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
	
	if ($sessionTerminateProg)
	{
	    $terminator = "<td><a href=\"$me?action=Terminate&session_name=$s->{'User-Name'}&session_nas_id=$s->{'NAS-Identifier'}:$s->{'NAS-Port'}\">terminate session</a></td>\n";
	    
	}
	$usercount++;
	$table .= "<tr bgcolor=yellow>
<td>$s->{'User-Name'}</td>
<td>$s->{'NAS-Identifier'}</td>
<td>$s->{'NAS-Port'}</td>
<td>$s->{'Acct-Session-Id'}</td>
<td>$eventtime</td>
<td>$s->{'Framed-IP-Address'}</td>
<td>$s->{'NAS-Port-Type'}</td>
<td>$s->{'Service-Type'}</td>
$terminator
<td><a href=\"$me?action=Delete&session_nas_id=$s->{'NAS-Identifier'}&session_nas_port=$s->{'NAS-Port'}&sortBy=$sortBy\">delete session</a></td></tr>\n";
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
	my $q = "delete from RADONLINE 
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

    print <<EOF;
<html><head><title>Fatal Error</title></head>
<body><h1>Fatal Error</h1>
<strong>A serious problem was encountered:</strong>
<p>$msg
</body>
</html>
EOF
    exit 0;
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

