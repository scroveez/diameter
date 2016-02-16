#!/bin/perl
# nasclear.cgi
#
# Written by Aaron Holtz <aholtz@bright.net>
# (many snippets of code taken from radwho.cgi)
# 28 January 1999
# ComNet Inc. 
#  
# This software may be used with permission.
#
# This script goes through the database and finds every unique nas
# in the db.  Then you have the option of clearing out everyone
# from the db who is recorded as being logged in from this NAS.
# Useful if a circuit goes down and you need to remove everyone
# at once as you know no stop records will be showing up.  
# Since this script is run on the fly, you don't need to keep a list
# of all NAS's who may have a user on that need cleared - this finds
# just the unique entries at run time.  This script could easily be
# fitted for a dbm setup, but I'm running an SQL db backend, so there
# it is....

use Fcntl;
use CGI;
# for the inet_aton function.
use Socket;
use AnyDBM_File;

# ------------------------------------------------------------
# Configurable variables

# Change the following two lines to conform with your database type

$DBSource = 'dbi:Pg:dbname=db';
$DBUsername = 'dbuser';

# Locally configurable HTML setup. You can change these to set up your own
# particular look and feel
$localheader = '<body bgcolor=white>';
$localfooter = '</body>';

# The url is the web server this thing lives on.  The name of the script is
# appended to the end for the Location tag later on.
$url = "http://www.domain.com";

# End of Configurable variables
# ------------------------------------------------------------

CGI::ReadParse(*input);		# grab cgi parameters

# Debugging support
#print `env`;

$me = $ENV{SCRIPT_NAME};
# Let's check to see if we are supposed to be deleting something or
# whether we are just going to display the entries in the db.

if ($input{action} eq 'Delete')
{
    &delete_session($input{session});
	# The following is to remove the nasty looking URL you get on submitting items. :-)
    print "Location: $url$me\n\n";
} else {
    print &CGI::PrintHeader;
    &show_sessions();
}    

###############################################################
sub show_sessions
{
	print <<EOF;
<html>
<head>
<title>Current NAS units with entries in the DB</title>
</head>
$localheader
<h2>Current NAS units with entries in the DB</h2>
    This report shows all current NAS units with at least
one user in the db.  
Click on \"delete users\" to remove bogus all entries in the db
that have users on that unit.
<p>
EOF
	print <<EOF;
<table cellspacing=0 cellpadding=0 border=1>
<table cellspacing=0 cellpadding=0 border=1>
<tr BGCOLOR=orange>
EOF

	print "<th>NAS Unit IP/Host Name</a></th>\n";
	print "<th>Remove entries from DB</a></th></tr>\n";
	print "</tr>\n";
        &read_sql();
	print "$table\n</table></body></html>\n";
}

###############################################################
# Connect to the SQL server
sub sql_connect
{
    return if $dbh;

    require DBI;
    $dbh = DBI->connect($DBSource,
			$DBUsername,
			$DBAuth)
	|| &fatalError("Could not connect to database");
}

###############################################################
# Read the SQL table, and accumulate or print details
sub read_sql
{
    sql_connect();

    $q = "select distinct nasidentifier from RADONLINE";

    my $sth = &prepareAndExecute($dbh, $q);
    while (@vals = $sth->fetchrow())
    {
	# for each unique NAS IP we found in the db, let's do a 
        # gethostbyaddr on them to get their PTR record.
	foreach $val (@vals) {
		$pack = inet_aton($val);
            	$host = gethostbyaddr($pack, AF_INET );
		# This is kinda ugly, but let's make an array that contains the
		# the host name and the IP.  We'll need the IP for creating the 
		# table, but we also need to check to ensure we got an answer
		# back from gethostbyaddr.  This array allows us to sort the output
		# from the lookups.
		$output{$val} = "$host:$val";
	}
     }

	# Let's go through all of the values in the array, sort them and then create the table.
	# Since the 'session' value must be the IP (or the match won't happen in the DB), we
	# split the values in the array. 

	foreach $values ( sort values %output ) {
	($host, $ipaddress) = split ( /:/, $values);

	# If the gethostbyaddr succeeded....
	if ( $host ) {
		$table .= "<tr bgcolor=yellow>\n";
            	$table .= "<td>$host</td>\n";
            	$table .= "<td><a href=$me?action=Delete&session=$ipaddress>Delete all entries</a></td></tr>\n";
	# If it failed....
	} else {
		$table .= "<tr bgcolor=yellow>\n";
            	$table .= "<td>$ipaddress</td>\n";
            	$table .= "<td><a href=$me?action=Delete&session=$ipaddress>Delete all entries</a></td></tr>\n";
	}

	}

    $sth->finish;
    $dbh->disconnect;
}

# Remove the indicated users based on the nas IP address
sub delete_session
{
    my ($nas_id) = @_;

    if (defined $DBSource)
    {
	# Session database is SQL
	sql_connect();

	# Simple SQL statement to wipe every use from that NAS.
	my $q = "delete from RADONLINE where NASIDENTIFIER='$nas_id'";
	my $rc = $dbh->do($q)
	    || &fatalError("SessSQL do failed for '$q': $DBI::errstr");
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

