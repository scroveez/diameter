#!/usr/bin/perl
# Script Modified by Leigh Spiegel leigh@winshop.com.au to support Platypus call accounting
# Modifications
# 
# Changed field TIME_STAMP to CallDate on SQL Selects
# Changed 'stop' to 2 on SQL SELECTS
# Removed Scalar Local time conversion
# Updated default FramedAddress field
# Change default accounting table to Calls
#
# Tested on Linux using Sybase driver to connect to Microsoft SQL 6.5
#
#
# radacct.cgi
# CGI script to summarize various data from Radius detail files
# with drill-down to per-user and per-session details
# On each invocation, it scans the entire detail file, looking for
# the type of info selected by the type tag.
#
# If the "secure" configuration variable is set below, the info
# will be resricted to the username they authenticate to the web
# (ie, only current current customers will be able to see only
# their own usage details.
#
# Accepts the following tags:
#  filename   The name of the Radius detail file. 
#             Default /var/log/radius/detail (not allowed with secure)
#  type       What type of report.
#             default list of all users with total usage
#             user list of all connections for one user
#             session_id details of all requests for a given session_id
#  user       required for type=user and trype=session_id
#  session_id required for type=session_id
#  framed__ip_address required for type=framed_ip_address
#
# Installation instructions
# 1. Modify $filename below to point to the place where your detail
#    file lives. Else you can call it with the filename tag set
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
# $Id: platradacct.cgi,v 1.2 2002/08/20 00:56:30 mikem Exp $

use CGI;

# ------------------------------------------------------------
# Configurable variables

# The default name of the detail file to summarize
# If you define $DBSource, the file wil be ignored, and the data will come
# from an SQL database
# IF filename has a .gz extension it wil be decompressed with
# $gzip_prog
$filename = '/var/log/radius/detail';
#$filename = '/usr/local/projects/Radiator/detail';
#$filename = '/usr/local/projects/Radiator/open.com.au.detail.gz';
#$filename = '/usr/local/projects/Radiator/giga.net.au.detail';
#$filename = '/tmp/x';

# If you define these, we get the data from SQL, rather than a 
# flat file
# The config of this is still pretty rough and ready.
# You will probably need to tune the table name and queries to 
# suit your database. What we present here will suit the simple
# tables that are created by the sample schemas in the goodies 
# directory.
# Example Oracle config
#$DBSource = 'dbi:Oracle:osc';
#$DBUsername = 'system';
#$DBAuth = 'manager';
#$DBTableName = 'ACCOUNTING';  # Name of the accounting table 
# You might need this or something like this for your database:
#$ENV{ORACLE_HOME} = '/usr/local/oracle/app/oracle/product/7.3.2';

# Example mySQL config
#$DBSource = 'dbi:Sybase:radius';
#$DBUsername = 'platuser';
#$DBAuth = 'fred';
#$DBTableName = 'Calls';  # Name of the accounting table

# If your SQL database includes a column for Framed-IP-Address,
# specify the column name here, else comment it out
$DBFIACol = 'FramedAddress';

# Locally configurable HTML setup. You can change these to set up your own
# particular look and feel
$localheader = '<body bgcolor=white>';
$localfooter = '</body>';

# The name of the gzip program that will be used to unzip compressed
# detail files (ones with .gz extension)
$gzip_prog = '/usr/local/bin/gzip -dc';

# If secure is set, radacct will only work from a secured web
# directory (ie will require a user name and password), and it will 
# only show information for thhat user.
# You might want to consider using the Pam Radius module for Apache 
# so that your users authenticate themselves to the web server
# in exactly the same way and with the same password as their
# network login.
#$secure = 1;

# End of Configurable variables
# ------------------------------------------------------------

CGI::ReadParse(*input);		# grab cgi parameters

print &CGI::PrintHeader;

# Debugging support
#print `env`;

$/ = '';           # Read 1 paragraph at a time

$filename = $input{filename} if !$secure && defined $input{filename};
$me = $ENV{SCRIPT_NAME};

if (defined $DBSource)
{
    $datasource = "SQL accounting table $DBTableName";
}
else
{
    $datasource = "detail file $filename";
}

# If we are secure, no access unless we have a REMOTE_USER
# ie unless this script is secured
if ($secure && $ENV{'REMOTE_USER'} eq '')
{
    &fatalError("This script is not password protected. Please contact the webmaster");
}

if ($input{type} eq 'user')
{
    # Show all sessions for a single user
    &show_user();
}
elsif ($input{type} eq 'session_id')
{
    # Show details of a single session
    &show_session();
}
elsif ($input{type} eq 'framed_ip_address')
{
    # Show details of a single session
    &show_framed_ip_address();
}
elsif ($input{type} eq 'all_framed_ip_addresses')
{
    # Show details of a single session
    &show_all_framed_ip_addresses();
}
else
{
    # Default: list all users
    &show_user_summaries();
}
    

###############################################################
sub show_user
{
    print <<EOF;
<html>
<head>
<title>All Sessions for User</title>
</head>
$localheader
<h2>All Sessions for User</h2>
This report shows all the sessions for <b>$input{user}</b> 
in the Radius $datasource
<p>
<table cellspacing=0 cellpadding=0 border=1>
<tr BGCOLOR=orange><th>Session-Id</th><th>Stopped at</th><th>Framed-IP-Address</th><th>Acct-Session-Time</th><th>In-Octets</th><th>Out-Octets</th><th>In-Packets</th><th>Out-Packets</th></tr>
EOF

    # Initialise some counts
    $userSessions{$input{user}} = 0;
    $userSeconds{$input{user}} = 0;
    $userInOctets{$input{user}} = 0;
    $userOutOctets{$input{user}} = 0;
    $userInPackets{$input{user}} = 0;
    $userOutPackets{$input{user}} = 0;

    # Get the appropriate info from wherever
    &get_data($input{type}, $input{user}, $input{session_id});

    my $totalTime = &formatDuration($userSeconds{$input{user}});
    print "$table
<tr BGCOLOR=yellow><th BGCOLOR=orange>Totals</th><td>$userSessions{$input{user}} sessions</td><td>&nbsp;</td><td>$totalTime</td><td>$userInOctets{$input{user}}</td><td>$userOutOctets{$input{user}}</td><td>$userInPackets{$input{user}}</td><td>$userOutPackets{$input{user}}</td></tr>\n</table>$localfooter</html>\n";
}

###############################################################
sub show_session
{
    print <<EOF;
<html>
<head>
<title>All Records for Session</title>
</head>
$localheader
<h2>All Records for Session</h2>
This report shows all the records for Session-Id <b>$input{session_id}</b> for <b>$input{user}</b>
in the Radius $datasource
<p>
<table cellspacing=0 cellpadding=0 border=1>
EOF

    # Get the appropriate info from wherever
    &get_data($input{type}, $input{user}, $input{session_id});

    print "$table\n</table>$localfooter</html>\n";
}

###############################################################
sub show_framed_ip_address
{
    print <<EOF;
<html>
<head>
<title>All Records with Framed IP Address</title>
</head>
$localheader
<h2>All Records with Framed IP Address</h2>
This report shows all the Stop records with a Framed-IP-Address of <b>$input{framed_ip_address}</b>
in the Radius $datasource
<p>
<table cellspacing=0 cellpadding=0 border=1>
<tr BGCOLOR=orange><th>User-Name</th><th>Session-Id</th><th>Stopped at</th><th>Acct-Session-Time</th><th>In-Octets</th><th>Out-Octets</th><th>In-Packets</th><th>Out-Packets</th></tr>
EOF

    # Get the appropriate info from wherever
    &get_data($input{type}, $input{user}, $input{session_id}, $input{framed_ip_address});

    print "$table\n</table>$localfooter</html>\n";
}

###############################################################
sub show_user_summaries
{
    print <<EOF;
<html>
<head>
<title>All Users</title>
</head>
$localheader
<h2>All Users</h2>
This report shows summarised usage for all users in the Radius
$datasource. You can also see a <a href=$me?type=all_framed_ip_addresses&filename=$filename>summary by IP Address</a>.
<p>
<table cellspacing=0 cellpadding=0 border=1>
<tr BGCOLOR=orange><th>User-Name</th><th>Acct-Session-Time</th><th>In-Octets</th>
<th>Out-Octets</th><th>In-Packets</th><th>Out-Packets</th></tr>
EOF

    # Get the appropriate info from wherever
    &get_data($input{type}, $input{user}, $input{session_id});

    foreach $username (sort sorter keys %userSeconds)
    {
	$totalTime = &formatDuration($userSeconds{$username});
	print "<tr bgcolor=yellow><td><a href=$me?type=user&user=$username&filename=$filename>$username</a></td><td>$totalTime</td><td>$userInOctets{$username}</td><td>$userOutOctets{$username}</td><td>$userInPackets{$username}</td><td>$userOutPackets{$username}</td></tr>\n";
    }

    print "$table\n</table>$localfooter</html>\n";
}

###############################################################
sub show_all_framed_ip_addresses
{
    print <<EOF;
<html>
<head>
<title>All IP Addresses</title>
</head>
$localheader
<h2>All IP Addresses</h2>
This report shows summarised usage for all IP addresses in the Radius
$datasource.  You can also see a <a href=$me?filename=$filename>summary by user name</a>.
<p>
<table cellspacing=0 cellpadding=0 border=1>
<tr BGCOLOR=orange><th>Framed-IP-Address</th><th>Acct-Session-Time</th><th>In-Octets</th>
<th>Out-Octets</th><th>In-Packets</th><th>Out-Packets</th></tr>
EOF

    # Get the appropriate info from wherever
    &get_data($input{type}, $input{user}, $input{session_id});

    foreach $address (sort sorter keys %fiaSeconds)
    {
	$totalTime = &formatDuration($fiaSeconds{$address});
	print "<tr bgcolor=yellow><td><a href=$me?type=framed_ip_address&framed_ip_address=$address&filename=$filename>$address</a></td><td>$totalTime</td><td>$fiaInOctets{$address}</td><td>$fiaOutOctets{$address}</td><td>$fiaInPackets{$address}</td><td>$fiaOutPackets{$address}</td></tr>\n";
    }

    print "$table\n</table>$localfooter</html>\n";
}


###############################################################
# Load data from the appropriate accounting database
sub get_data
{
    if (defined $DBSource)
    {
	# Use SQL
	&read_sql(@_);
    }
    else
    {
	# Read from flat file
	&read_file(@_);
    }

}


###############################################################
# Read the SQL table, and accumulate or print details
sub read_sql
{
    my ($type, $username, $session_id, $framed_ip_address) = @_;

    require DBI;

    # Sigh: freetds prints stuff to stderr during setup
    # which breaks apache (and prob most other web servers)
    # Redirect stderr to /dev/null
    if ($^O ne 'MSWin32' && $DBSource =~ /FreeTDS/)
    {
	open(OLDERR, ">&STDERR");
	open(STDERR, ">/tmp/xxx");
    }
    my $dbh = DBI->connect($DBSource,
			   $DBUsername,
			   $DBAuth);

    if ($^O ne 'MSWin32' && $DBSource =~ /FreeTDS/)
    {
	open(STDERR, ">&OLDERR");
	close(OLDERR);
    }
    fatalError("Could not connect to database") unless $dbh;

    # Work out what optional columns to support
    my $extracols;
    $extracols = ", $DBFIACol" if $DBFIACol;

    if ($type eq 'user')
    {
	my $q = "select ACCTSESSIONID, CallDate, ACCTSESSIONTIME,
ACCTINPUTOCTETS, ACCTOUTPUTOCTETS $extracols from $DBTableName 
where USERNAME = '$username' and ACCTSTATUSTYPE=2
order by CallDate";
	my $sth = &prepareAndExecute($dbh, $q);
	my ($acctsessionid, $time_stamp, $acctsessiontime,
	    $acctinputoctets, $acctoutputoctets, $framed_ip_address);
	while (($acctsessionid, $time_stamp, $acctsessiontime,
		$acctinputoctets, $acctoutputoctets, 
                $framed_ip_address) = $sth->fetchrow)
	{
	    my $eventtime = $time_stamp;

	    $userSessions{$username}++;
	    $userSeconds{$username} += $acctsessiontime;
	    $userInOctets{$username} += $acctinputoctets;
	    $userOutOctets{$user} += $acctoutputoctets;

	    $time = &formatDuration($acctsessiontime);
	    $table .= "<tr bgcolor=yellow><td><a href=$me?filename=$filename&type=session_id&user=$username&session_id=$acctsessionid>$acctsessionid</a></td><td>$eventtime</td><td><a href=$me?type=framed_ip_address&filename=$filename&framed_ip_address=$framed_ip_address&filename=$filename>$framed_ip_address</a></td><td>$time</td><td>$acctinputoctets</td><td>$acctoutputoctets</td><td>?</td><td>?</td></tr>\n";
	}
    }
    elsif ($DBFIACol && $type eq 'framed_ip_address')
    {
	my $q = "select USERNAME, ACCTSESSIONID, CallDate, 
ACCTSESSIONTIME,
ACCTINPUTOCTETS, ACCTOUTPUTOCTETS from $DBTableName 
where $DBFIACol = '$framed_ip_address' and ACCTSTATUSTYPE=2
order by CallDate";
	my $sth = &prepareAndExecute($dbh, $q);
	my ($username, $acctsessionid, $time_stamp, $acctsessiontime,
	    $acctinputoctets, $acctoutputoctets);
	while (($username, $acctsessionid, $time_stamp, 
		$acctsessiontime,
		$acctinputoctets, $acctoutputoctets) = $sth->fetchrow)
	{
	    my $eventtime = $time_stamp;

	    $time = &formatDuration($acctsessiontime);
	    $table .= "<tr bgcolor=yellow><td><a href=$me?type=user&filename=$filename&user=$username>$username</a></td><td><a href=$me?type=session_id&filename=$filename&user=$username&session_id=$acctsessionid>$acctsessionid</a></td><td>$eventtime</td></td><td>$time</td><td>$acctinputoctets</td><td>$acctoutputoctets</td><td>?</td><td>?</td></tr>\n";
	}

    }
    elsif ($type eq 'session_id')
    {
	my $q = "select ACCTSTATUSTYPE, ACCTDELAYTIME, CallDate, ACCTSESSIONTIME, ACCTTERMINATECAUSE, NASIDENTIFIER,
NASPORT,
ACCTINPUTOCTETS, ACCTOUTPUTOCTETS from $DBTableName 
where USERNAME = '$username' and ACCTSESSIONID='$session_id'
order by CallDate";

	my $sth = &prepareAndExecute($dbh, $q);
	my ($acctstatustype, $acctdelaytime, $time_stamp, 
	    $acctsessiontime, $acctterminatecause, $nasidentifier, $nasport,
	    $acctinputoctets, $acctoutputoctets);
	while (($acctstatustype, $acctdelaytime, $time_stamp, 
	    $acctsessiontime, $acctterminatecause, $nasidentifier, $nasport,
	    $acctinputoctets, $acctoutputoctets) = $sth->fetchrow)
	{
	    my $eventtime = $time_stamp;

	    $table .= "<tr bgcolor=orange><th>$eventtime</th></tr>
<tr bgcolor=yellow><td>User-Name</td><td>$username</td></tr>
<tr bgcolor=yellow><td>Acct-Session-Id</td><td>$session_id</td></tr>
<tr bgcolor=yellow><td>Acct-Status-Type</td><td>$acctstatustype</td></tr>
<tr bgcolor=yellow><td>NAS-Identifier</td><td>$nasidentifier</td></tr>
<tr bgcolor=yellow><td>NAS-Port</td><td>$nasport</td></tr>";

	    $table .= "<tr bgcolor=yellow><td>Acct-Delay-Time</td><td>$acctdelaytime</td></tr>"
		if defined $acctdelaytime;
	    $table .= "<tr bgcolor=yellow><td>Acct-Session-Time</td><td>$acctsessiontime</td></tr>"
		if defined $acctsessiontime;
	    $table .= "<tr bgcolor=yellow><td>Acct-Terminate-Cause</td><td>$acctterminatecause</td></tr>"
		if defined $acctterminatecause;
	    $table .= "<tr bgcolor=yellow><td>Acct-Input-Octets</td><td>$acctinputoctets</td></tr>"
		if defined $acctinputoctets;
	    $table .= "<tr bgcolor=yellow><td>Acct-Output-Octets</td><td>$acctoutputoctets</td></tr>"
		if defined $acctoutputoctets;
	}

    }
    elsif ($DBFIACol && $type eq 'all_framed_ip_addresses')
    {
	my $q = "select $DBFIACol, sum(ACCTSESSIONTIME), 
sum(ACCTINPUTOCTETS), sum(ACCTOUTPUTOCTETS)
from $DBTableName group by $DBFIACol";
	my $sth = &prepareAndExecute($dbh, $q);
	my ($address, $acctsessiontime, $acctinputoctets, $acctoutputoctets);
	while (($address, $acctsessiontime, 
		$acctinputoctets, $acctoutputoctets) = $sth->fetchrow)
	{
	    $fiaSeconds{$address} += $acctsessiontime;
	    $fiaInOctets{$address} += $acctinputoctets;
	    $fiaOutOctets{$address} += $acctoutputoctets;
	    $fiaInPackets{$address} = '?';
	    $fiaOutPackets{$address} = '?';
	}
    }
    else
    {
	my $q = "select USERNAME, sum(ACCTSESSIONTIME), 
sum(ACCTINPUTOCTETS), sum(ACCTOUTPUTOCTETS)
from $DBTableName group by USERNAME";
	my $sth = &prepareAndExecute($dbh, $q);
	my ($username, $acctsessiontime, $acctinputoctets, $acctoutputoctets);
	while (($username, $acctsessiontime, 
		$acctinputoctets, $acctoutputoctets) = $sth->fetchrow)
	{
	    $userSessions{$username}++;
	    $userSeconds{$username} += $acctsessiontime;
	    $userInOctets{$username} += $acctinputoctets;
	    $userOutOctets{$username} += $acctoutputoctets;
	    $userInPackets{$username} = '?';
	    $userOutPackets{$username} = '?';
	}
    }
    $dbh->disconnect;
}

###############################################################
# Read the detail file, and accumulate or print details
sub read_file
{
    my ($type, $username, $session_id, $framed_ip_address) = @_;

    # Use gzip if its gzipped
    my $f = $filename;
    $f =~ s/(.*\.gz)\s*$/$gzip_prog $1|/;

    open(FILE, $f)
	|| &fatalError("Could not open detail file '$filename': $!<br>Perhaps you should alter \$filename in the script or user the filename tag");
    while (<FILE>)
    {
	$User_Name = undef;
	($Ddd, $Mmm, $Dd, $Time, $Yyyy) =
	    /^(\w+)\s+(\w+)\s+(\d+)\s+([\d:]+)\s+(\d+)/;
	($Acct_Session_Id)      = /Acct-Session-Id = "([^"]+)"/;
	($Acct_Session_Time)    = /Acct-Session-Time = (\d+)/;     # Stop only
	($Acct_Status_Type)     = /Acct-Status-Type = (\w+)/;      # Start/Stop
	($Client_Port_Id)       = /Client-Port-Id = (\d+)/;
	($Framed_IP_Address)    = /Framed-IP-Address = ([\d.]+)/;
	($User_Name)            = /User-Name = \"([^"]+)\"/;
	($User_Name)            = /User-Name = (\S+)/ if !$User_Name;
	# Ascend only.
	
	($Client_Port_Id)       = /NAS-Port = (\d+)/;
	($InOctets)             = /Acct-Input-Octets = (\d+)/;
	($OutOctets)            = /Acct-Output-Octets = (\d+)/;
	($InPackets)            = /Acct-Input-Packets = (\d+)/;
	($OutPackets)           = /Acct-Output-Packets = (\d+)/;
#	($Caller_Id)            = /Caller-Id = "([^"]*)"/;
					      
	# If we are secure, ignore anything that is not for this user
	next if $secure && $User_Name ne $ENV{'REMOTE_USER'};
	
	if (   $type eq '' 
	       && $Acct_Status_Type eq '2')
	{
	    $userSessions{$User_Name}++;
	    $userSeconds{$User_Name} += $Acct_Session_Time;
	    $userInOctets{$User_Name} += $InOctets;
	    $userOutOctets{$User_Name} += $OutOctets;
	    $userInPackets{$User_Name} += $InPackets;
	    $userOutPackets{$User_Name} += $OutPackets;
	}
	elsif (   $type eq 'all_framed_ip_addresses' 
	       && $Acct_Status_Type eq '2')
	{
	    $fiaSeconds{$Framed_IP_Address} += $Acct_Session_Time;
	    $fiaInOctets{$Framed_IP_Address} += $InOctets;
	    $fiaOutOctets{$Framed_IP_Address} += $OutOctets;
	    $fiaInPackets{$Framed_IP_Address} += $InPackets;
	    $fiaOutPackets{$Framed_IP_Address} += $OutPackets;
	}
	elsif (   $type eq 'user' 
		  && $User_Name eq $username
		  && $Acct_Status_Type eq '2')
	{
	    $time = &formatDuration($Acct_Session_Time);
	    $userSessions{$User_Name}++;
	    $userSeconds{$User_Name} += $Acct_Session_Time;
	    $userInOctets{$User_Name} += $InOctets;
	    $userOutOctets{$User_Name} += $OutOctets;
	    $userInPackets{$User_Name} += $InPackets;
	    $userOutPackets{$User_Name} += $OutPackets;
	    $table .= "<tr bgcolor=yellow><td><a href=$me?type=session_id&user=$User_Name&session_id=$Acct_Session_Id&filename=$filename>$Acct_Session_Id</a></td><td>$Dd&nbsp;$Mmm&nbsp;$Yyyy&nbsp;$Time</td><td><a href=$me?type=framed_ip_address&framed_ip_address=$Framed_IP_Address&filename=$filename>$Framed_IP_Address</a></td><td>$time</td><td>$InOctets</td><td>$OutOctets</td><td>$InPackets</td><td>$OutPackets</td></tr>\n";
	}				   
	elsif (   $type eq 'framed_ip_address' 
		  && $Framed_IP_Address eq $framed_ip_address
		  && $Acct_Status_Type eq '2')
	{
	    $time = &formatDuration($Acct_Session_Time);
	    $table .= "<tr bgcolor=yellow><td><a href=$me?type=user&user=$User_Name&filename=$filename>$User_Name</a></td><td><a href=$me?type=session_id&user=$User_Name&session_id=$Acct_Session_Id&filename=$filename>$Acct_Session_Id</a></td><td>$Dd&nbsp;$Mmm&nbsp;$Yyyy&nbsp;$Time</td><td>$time</td><td>$InOctets</td><td>$OutOctets</td><td>$InPackets</td><td>$OutPackets</td></tr>\n";
	}				   
	elsif (   $type eq 'session_id' 
		  && $User_Name eq $username
		  && $Acct_Session_Id eq $session_id)
	{
	    @lines = split(/\n/, $_);
	    foreach $line (@lines)
	    {
		chomp $line;
		if ($line =~ /^\s+(.*)\s+=\s+(.*)/)
		{
		    # Its an attribute=val line
		    ($attr, $val) = ($1, $2);
		    # Possibly strip surrounding quotes from the value
		    $val =~ s/^\s*"(.*)"\s*$/$1/;
		    $table .= "<tr bgcolor=yellow><td>$attr</td><td>$val</td></tr>\n";
		}
		else
		{
		    # Its the first line of a record
		    $table .= "<tr bgcolor=orange><th>$line</th></tr>\n";
		}
	    }
	}
	
    }
    close(FILE)
	|| &fatalError("Could not close detail file '$filename': $!");
}

###############################################################
sub fatalError
{
    my ($msg) = @_;

    print <<EOF;
<html><head><title>Fatal Error</title></head>
$localheader
<body><h1>Fatal Error</h1>
<strong>A serious problem was encountered:</strong>
<p>$msg
$localfooter
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
    my $aa = $a;
    my $bb = $b;

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

