#!/usr/bin/perl

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
# $Id: radacctSorted.cgi,v 1.3 2004/05/18 01:57:23 mikem Exp $

use CGI;

# ------------------------------------------------------------
# Configurable variables

# The default name of the detail file to summarize
# If you define $DBSource, the file wil be ignored, and the data will come
# from an SQL database
$filename = '/var/raddb/logs/detail';
#$filename = '/usr/local/projects/Radiator/detail';
#$filename = '/usr/local/projects/Radiator/open.com.au.detail';
#$filename = '/usr/local/projects/Radiator/giga.net.au.detail';

# If you define these, we get the data from SQL, rather than a flat file
# The config of this is still pretty rough and ready.
# You will probably need to tune the table name and queries to 
# suit your database. What we present here will suit the simple
# tables that are created by the sample schemas in the goodies directory.
#$DBSource = 'dbi:mysql:radius';
#$DBUsername = 'mikem';
#$DBAuth = 'fred';
#$DBTableName = 'ACCOUNTING';  # Name of the table to get accounting from
# You might need this or something like ot for your database
#$ENV{ORACLE_HOME} = '/usr/local/oracle/app/oracle/product/7.3.2';

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

{
local ($oldbar) = $|;
$cfh = select (STDOUT);
$| = 1;
#
# print your HTTP headers here
print &CGI::PrintHeader;
#
$| = $oldbar;
select ($cfh);
} 

# Debugging support
#print `env`;

$/ = '';           # Read 1 paragraph at a time

$filename = $input{filename} if !$secure && defined $input{filename};
$me = $ENV{SCRIPT_NAME};

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
<title>All Sessions for User $input{user}</title>
</head>
<body bgcolor=white>
<h2>All Sessions for User</h2>
This report shows all the sessions for <b>$input{user}</b> 
in the Radius detail file
<p>
<table cellspacing=0 cellpadding=0 border=1>
<tr BGCOLOR=orange><th>Session-Id</th><th>Stopped at</th><th>Session-Time</th><th>In-Octets</th><th>Out-Octets</th><th>Connect-Speed</th><th>IP-Address</th><th>Mod-Type</th><th>Disconnect</th></tr>
EOF

    # Get the appropriate info from wherever
    &get_data($input{type}, $input{user}, $input{session_id});

    print "$table\n</table></body></html>\n";
}

###############################################################
sub show_session
{
    print <<EOF;
<html>
<head>
<title>All Records for Session $input{session_id} for $input{user}</title>
</head>
<body bgcolor=white>
<h2>All Records for Session</h2>
This report shows all the records for Session-Id <b>$input{session_id}</b> for <b>$input{user}</b>
in the Radius detail file
<p>
<table cellspacing=0 cellpadding=0 border=1>
EOF

    # Get the appropriate info from wherever
    &get_data($input{type}, $input{user}, $input{session_id});

    print "$table\n</table></body></html>\n";
}

# sort using explicit subroutine name
sub byTime
{
    $userSeconds{$b} <=> $userSeconds{$a};        # presuming integers
}
sub byOctets
{
    $userOutOctets{$b} <=> $userOutOctets{$a};        # presuming integers
}
sub byUpload
{
    $userInOctets{$b} <=> $userInOctets{$a};        # presuming integers
}
sub byLogins
{
    $userLogins{$b} <=> $userLogins{$a};        # presuming integers
}

###############################################################
sub show_user_summaries
{
# $sorted = $input(sort_by);

    print <<EOF;
<html>
<head>
<title>All Users by $input{sort_by}</title>
</head>
<body bgcolor=white>
<h2>All Users by $input{sort_by}</h2>
This report shows summarised usage for all users in the Radius detail file sorted by $input{sort_by} 
<p>
<P><A HREF="$me?filename=/var/raddb/logs/detail.1&sort_by=$sortkey">Previous Month</A></P>
<P><A HREF="$me?filename=/var/raddb/logs/detail.2&sort_by=$sortkey">Current Month - 2</A></P>
<table cellspacing=0 cellpadding=0 border=1>
<tr BGCOLOR=orange><th><a href=$me>User-Name</a></th><th><a href=$me?sort_by=time>Acct-Session-Time</a></th><th><a href=$me?sort_by=upload>In-Octets</a></th><th><a href=$me?sort_by=download>Out-Octets</a></th><th><a href=$me?sort_by=logins>Total Logins</a></th><th>Avg Connect</th></tr>
EOF

    # Get the appropriate info from wherever
    &get_data($input{type}, $input{user}, $input{session_id});

    if ($input{sort_by} eq 'time')
    {
	@keys = keys %userSeconds;
	@sorted = sort byTime @keys;
	foreach $key (@sorted)
        {
	    $avgConnectionSpeed = sprintf("%.0f", $userConnectSpeed{$key} / $userLogins{$key});
	    $avgOverallSpeed += $avgConnectionSpeed;
	    $totalTime = &formatDuration($userSeconds{$key});
	    print "<tr bgcolor=yellow><td><a href=$me?type=user&user=$key>$key</href></td><td>$totalTime</td><td>$userInOctets{$key}</td><td>$userOutOctets{$key}</td><td>$userLogins{$key}</td><td>$avgConnectionSpeed</td></tr>\n";
        }
    }
    elsif ($input{sort_by} eq 'logins')
    {
	@keys = keys %userLogins;
	@sorted = sort byLogins @keys;
	foreach $key (@sorted)
        {
	    $avgConnectionSpeed = sprintf("%.0f", $userConnectSpeed{$key} / $userLogins{$key});
	    $avgOverallSpeed += $avgConnectionSpeed;
	    $totalTime = &formatDuration($userSeconds{$key});
	    print "<tr bgcolor=yellow><td><a href=$me?type=user&user=$key>$key</href></td><td>$totalTime</td><td>$userInOctets{$key}</td><td>$userOutOctets{$key}</td><td>$userLogins{$key}</td><td>$avgConnectionSpeed</td></tr>\n";
        }
    }
    elsif ($input{sort_by} eq 'download')
    {
	@keys = keys %userOutOctets;
	@sorted = sort byOctets @keys;
	foreach $key (@sorted)
        {
	    $avgConnectionSpeed = sprintf("%.0f", $userConnectSpeed{$key} / $userLogins{$key});
	    $avgOverallSpeed += $avgConnectionSpeed;
	    $totalTime = &formatDuration($userSeconds{$key});
	    print "<tr bgcolor=yellow><td><a href=$me?type=user&user=$key>$key</href></td><td>$totalTime</td><td>$userInOctets{$key}</td><td>$userOutOctets{$key}</td><td>$userLogins{$key}</td><td>$avgConnectionSpeed</td></tr>\n";
        }
    }
    elsif ($input{sort_by} eq 'upload')
    {
	@keys = keys %userInOctets;
	@sorted = sort byUpload @keys;
	foreach $key (@sorted)
        {
	    $avgConnectionSpeed = sprintf("%.0f", $userConnectSpeed{$key} / $userLogins{$key});
	    $avgOverallSpeed += $avgConnectionSpeed;
	    $totalTime = &formatDuration($userSeconds{$key});
	    print "<tr bgcolor=yellow><td><a href=$me?type=user&user=$key>$key</href></td><td>$totalTime</td><td>$userInOctets{$key}</td><td>$userOutOctets{$key}</td><td>$userLogins{$key}</td><td>$avgConnectionSpeed</td></tr>\n";
        }
    }
    else
    {
        foreach $user (sort keys %userSeconds)
        {
	    $avgConnectionSpeed = sprintf("%.0f", $userConnectSpeed{$user} / $userLogins{$user});
	    $avgOverallSpeed += $avgConnectionSpeed;
	    $totalTime = &formatDuration($userSeconds{$user});
	    print "<tr bgcolor=yellow><td><a href=$me?type=user&user=$user>$user</href></td><td>$totalTime</td><td>$userInOctets{$user}</td><td>$userOutOctets{$user}</td><td>$userLogins{$user}</td><td>$avgConnectionSpeed</td></tr>\n";
        }
    }

    foreach $key (%userLogins)
    {
	$totalUsers ++;
	$totalSeconds += $userSeconds{$key};
	$totalInOctets += $userInOctets{$key};
	$totalOutOctets += $userOutOctets{$key};
	$totalLogins += $userLogins{$key};
    }

    $totalTime = &formatDuration($totalSeconds);
    $totalUsers = $totalUsers / 2;
    print "<tr bgcolor=cyan><td>total: <b>$totalUsers<b></td><td>$totalTime</td><td>$totalInOctets</td><td>$totalOutOctets</td><td>$totalLogins</td><td>\&nbsp\;</td></tr>\n";

    $totalSeconds = sprintf("%.0f", $totalSeconds / $totalUsers);
    $totalInOctets = sprintf("%.0f", $totalInOctets / $totalUsers);
    $totalOutOctets = sprintf("%.0f", $totalOutOctets / $totalUsers);
    $totalLogins = sprintf("%.2f", $totalLogins / $totalUsers);
    $avgOverallSpeed = sprintf("%.0f", $avgOverallSpeed / ($totalUsers - 2));
    $totalTime = &formatDuration($totalSeconds);
    print "<tr bgcolor=cyan><td><b>Average</b></td><td>$totalTime</td><td>$totalInOctets</td><td>$totalOutOctets</td><td>$totalLogins</td><td>$avgOverallSpeed</td></tr>\n";

    print "$table\n</table></body></html>\n";
}


###############################################################
# Load data from the appropriate accounting database
sub get_data
{
    my ($type, $user, $session_id) = @_;

    if (defined $DBSource)
    {
	# Use SQL
	&read_sql($type, $user, $session_id);
    }
    else
    {
	# Read from flat file
	&read_file($type, $user, $session_id);
    }

}


###############################################################
# Read the SQL table, and accumulate or print details
sub read_sql
{
    my ($type, $user, $session_id) = @_;

    require DBI;
    my $dbh = DBI->connect($DBSource,
			   $DBUsername,
			   $DBAuth)
	|| fatalError("Could not connect to database");

    if ($type eq 'user')
    {
	my $q = "select ACCTSESSIONID, TIME_STAMP, ACCTSESSIONTIME,
ACCTINPUTOCTETS, ACCTOUTPUTOCTETS from $DBTableName 
where USERNAME = '$user' and ACCTSTATUSTYPE='Stop'
order by TIME_STAMP";
	my $sth = &prepareAndExecute($dbh, $q);
	my ($acctsessionid, $time_stamp, $acctsessiontime,
	    $acctinputoctets, $acctoutputoctets);
	while (($acctsessionid, $time_stamp, $acctsessiontime,
		$acctinputoctets, $acctoutputoctets) = $sth->fetchrow)
	{
	    my $eventtime = scalar localtime($time_stamp);

	    $time = &formatDuration($acctsessiontime);
	    $table .= "<tr bgcolor=yellow><td><a href=$me?type=session_id&user=$user&session_id=$acctsessionid>$acctsessionid</a></td><td>$eventtime</td><td>?</td><td>$time</td><td>$acctinputoctets</td><td>$acctoutputoctets</td><td>?</td><td>?</td></tr>\n";
	}

    }
    elsif ($type eq 'session_id')
    {
	my $q = "select ACCTSTATUSTYPE, ACCTDELAYTIME, TIME_STAMP, ACCTSESSIONTIME, ACCTTERMINATECAUSE, NASIDENTIFIER, NASPORT
ACCTINPUTOCTETS, ACCTOUTPUTOCTETS from $DBTableName 
where USERNAME = '$user' and ACCTSESSIONID='$session_id'
order by TIME_STAMP";
	my $sth = &prepareAndExecute($dbh, $q);
	my ($acctstatustype, $acctdelaytime, $time_stamp, 
	    $acctsessiontime, $acctterminatecause, $nasidentifier, $nasport,
	    $acctinputoctets, $acctoutputoctets);
	while (($acctstatustype, $acctdelaytime, $time_stamp, 
	    $acctsessiontime, $acctterminatecause, $nasidentifier, $nasport,
	    $acctinputoctets, $acctoutputoctets) = $sth->fetchrow)
	{
	    my $eventtime = scalar localtime($time_stamp);

	    $table .= "<tr bgcolor=orange><th>$eventtime</th></tr>
<tr bgcolor=yellow><td>User-Name</td><td>$user</td></tr>
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
    else
    {
	my $q = "select USERNAME, count(ACCTSESSIONTIME), sum(ACCTSESSIONTIME), 
sum(ACCTINPUTOCTETS), sum(ACCTOUTPUTOCTETS)
from $DBTableName group by USERNAME";
	my $sth = &prepareAndExecute($dbh, $q);
	my ($username, $count, $acctsessiontime, $acctinputoctets, $acctoutputoctets);
	while (($username, $count, $acctsessiontime, 
		$acctinputoctets, $acctoutputoctets) = $sth->fetchrow)
	{
	    $userLogins{$username} += $count;
	    $userSeconds{$username} += $acctsessiontime;
	    $userInOctets{$username} += $acctinputoctets;
	    $userOutOctets{$username} += $acctoutputoctets;
	}
    }
    $dbh->disconnect;
}

###############################################################
# Read the detail file, and accumulate or print details
sub read_file
{
    my ($type, $user, $session_id) = @_;

    open(FILE, $filename)
	|| &fatalError("Could not open detail file '$filename': $!<br>Perhaps you should alter \$filename in the script or user the filename tag");
    while (<FILE>)
    {
	($Ddd, $Mmm, $Dd, $Time, $Yyyy) =
	    /^(\w+)\s+(\w+)\s+(\d+)\s+([\d:]+)\s+(\d+)/;
	($Acct_Session_Id)      = /Acct-Session-Id = \"([0-9A-F]+)\"/;
	($Acct_Session_Time)    = /Acct-Session-Time = (\d+)/;     # Stop only
	($Acct_Status_Type)     = /Acct-Status-Type = (\w+)/;      # Start/Stop
	($Client_Port_Id)       = /NAS-Port = (\d+)/;
	($Framed_Address)       = /Framed-IP-Address = ([\d.]+)/;
	($User_Name)            = /User-Name = \"([^"]+)\"/;
	($Modulation_Type)	= /Modulation-Type = (\w+)/;
	($Connection_Speed)     = /Connect-Speed = (\d+)/;
	($IP_Address)		= /Framed-IP-Address = ([\d.]+)/;
	($Disconnect)		= /Acct-Terminate-Cause = ([\w-]+)/;
	($InOctets)             = /Acct-Input-Octets = (\d+)/;
	($OutOctets)            = /Acct-Output-Octets = (\d+)/;
					      
	# If we are secure, ignore anything that is not for this user
	next if $secure && $User_Name ne $ENV{'REMOTE_USER'};
	
	if (   $type eq '' 
	       && $Acct_Status_Type eq 'Stop')
	{
	    if ($User_Name ne 'unauthenticated')
	    {
		$userSeconds{$User_Name} += $Acct_Session_Time;
	    }
	    $userInOctets{$User_Name} += $InOctets;
	    $userOutOctets{$User_Name} += $OutOctets;
	    $userLogins{$User_Name} += 1;
	    $userConnectSpeed{$User_Name} += $Connection_Speed;
	}
	elsif (   $type eq 'user' 
		  && $User_Name eq $user
		  && $Acct_Status_Type eq 'Stop')
	{
	    $time = &formatDuration($Acct_Session_Time);
	    $table .= "<tr bgcolor=yellow align=center><td><a href=$me?type=session_id&user=$User_Name&session_id=$Acct_Session_Id&filename=$filename>$Acct_Session_Id</a></td><td>$Dd&nbsp;$Mmm&nbsp;$Yyyy&nbsp;$Time</td><td>$time</td><td>$InOctets</td><td>$OutOctets</td><td>$Connection_Speed</td><td>$IP_Address</td><td>$Modulation_Type</td><td>$Disconnect</td></tr>\n";
	}				   
	elsif (   $type eq 'session_id' 
		  && $User_Name eq $user
		  && $Acct_Session_Id eq $session_id)
	{
	    @lines = split(/\n/, $_);
	    foreach $line (@lines)
	    {
		chomp $line;
		if ($line =~ /^\s/)
		{
		    # Its an attribute=val line
		    ($attr, $val) = split(/=/, $line);
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

