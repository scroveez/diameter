#!/usr/bin/perl
# -*- mode: Perl -*-
# checkOnlineSql.pl
# Check that all the users in an SQL SessionDatabase are 
# still online, and delete the ones that arent. Uses a client table to determine Nas type etc.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2005 Open System Consultants
# $Id: checkOnlineSql.pl,v 1.3 2012/06/27 23:27:18 mikem Exp $

use Getopt::Long;
use Radius::ClientListSQL;
use Radius::Log;

my @options= 
    (
     'v',        # Print usage
     'n',        # Dont actually delete anything
     'trace=n',
     'dbsource=s',
     'dbusername=s',
     'dbauth=s',
     'getclientquery=s',
     'getsessionquery=s',
     'deletesessionquery=s',
     'snmpgetprog=s',
     'snmpwalkprog=s',
     'fingerprog=s',
     'pmwhoprog=s',
     'snmpnaserrortimeout=n',
     );

&GetOptions(@options) || &usage;
&usage if $opt_v;

# Fake up some variables that are normally done by serverconfig.
$main::config->{LogStdout} = 1;
$main::config->{Trace} = $opt_trace || 0;
$main::config->{SnmpgetProg} = $opt_snmpgetprog || '/usr/bin/snmpget';
$main::config->{SnmpwalkProg} = $opt_snmpwalkprog || '/usr/bin/snmpwalk';
$main::config->{FingerProg} = $opt_fingerprog || '';
$main::config->{PmwhoProg} = $opt_pmwhoprog  || '/usr/local/sbin/pmwho';
$main::config->{SnmpNASErrorTimeout} = $opt_snmpnaserrortimeout  || 60;

# The name of trhe table to insert into and other
# configuranble SQL parameters
# You may want to edit these to suit your site
my $dbsource   = $opt_dbsource   || 'dbi:mysql:radius';
my $dbusername = $opt_dbusername || 'mikem';
my $dbauth     = $opt_dbauth     || 'fred';
my $errors;
my %clientlistargs = 
(
 DBSource => [$dbsource],
 DBUsername => [$dbusername],
 DBAuth => [$dbauth]
);
$clientlistargs{GetClientQuery} = $opt_getclientquery if defined $opt_getclientquery;

my $getsessionquery = $opt_getsessionquery || 
    'select USERNAME, NASIDENTIFIER, NASPORT, ACCTSESSIONID, FRAMEDIPADDRESS from RADONLINE';
my $deletesessionquery = $opt_deletesessionquery ||
    'delete from RADONLINE where NASIDENTIFIER=\'%1\' and NASPORT=0%2';

# Load all the clients from the SQL database
my $client_list = Radius::ClientListSQL->new(undef, 'ClientListSQL',  %clientlistargs);

# Read all the entries in the Session Database
my $sth = $client_list->prepareAndExecute($getsessionquery);
die "Could not get sessions from session database: SQL prepare failed" unless $sth;

# For each existing session in the session database, check whether it is still online
my ($username, $nasidentifier, $nasport, $acctsessionid, $framedipaddress);
while (($username, $nasidentifier, $nasport, $acctsessionid, $framedipaddress) = $sth->fetchrow())
{
    &main::log($main::LOG_DEBUG, "Found online user: $username, $nasidentifier, $nasport, $acctsessionid, $framedipaddress");

    my $c = Radius::Client::find($nasidentifier);
    if (!$c)
    {
	&main::log($main::LOG_ERR, "Found user $username online at $nasidentifier:$nasport, but could not find a matching Client in the database. Dont now how to check online status. Ignoring");
	next;
    }
    # We pass a few extra variables to format_special just in case someone needs them
    if (!$c->isOnline($username, $nasidentifier, $nasport, $acctsessionid, $framedipaddress))
    {
	&main::log($main::LOG_DEBUG, "After checking with the NAS, user $username is apparently not online anymore. Delete from session database");
	
	$client_list->do(&Radius::Util::format_special
			 ($deletesessionquery, undef, undef,
			  $client_list->quote($username),
			  $nasidentifier, $nasport + 0,
			  $client_list->quote($acctsessionid),
			  $client_list->quote($framedipaddress))) unless $opt_n;
    }
}
$sth->finish;


sub usage
{
    print "usage: $0 [-v] [-n] [-trace n]
  [-dbsource dbi:db:etc] [-dbusername username] [-dbauth password]
  [-getclientquery query] [-getsessionquery query] [-deletesessionquery query]
  [-snmpgetprog path] [-fingerprog path] [-pmwhoprog path] 
  [-snmpnaserrortimeout timeout]

  Check that all the users in an SQL SessionDatabase are 
  still online, and delete the ones that arent. 
  Uses a client SQL table to determine Nas types.
  -v
   Print this usage
  -n
   Dont actually delete anything from the session database, for non-destructive testing
  -trace 0|1|2|3|4
   Set the trace level. 4 is DEBUG. Default is 0
  -dbsource sourcename
   DBI data source name. Default is 'dbi:mysql:radius'
  -dbusername username
   DBI database user name. Default is 'mikem'
  -dbauth password
   DBI database password. Default is 'fred'
   \n";
    exit;
}

