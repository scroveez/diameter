#!/usr/bin/perl
#
# Create new accounting table for the current month.
# Contributed by Ray Van Dolson <rayvd@digitalpath.net>
#

use strict;

use DBI;
use POSIX qw(strftime);

my $DATABASE = 'radiator';
my $DBUSER   = 'radius';
my $DBPASS   = 'dbpass';
my $TMPL_TBL = 'ACCOUNTING_TMPL';
my $TS       = strftime('%Y%m', localtime(time()));

my $dbh = DBI->connect("DBI:mysql:$DATABASE", $DBUSER, $DBPASS,
             { RaiseError => 1, AutoCommit => 1});

# Let's make sure the table doesn't exist already.
my $sth = $dbh->prepare("SHOW TABLE STATUS LIKE 'ACCOUNTING$TS'");
$sth->execute;
my @results;

if (not @results = $sth->fetchrow_array()) {
   $sth->finish;
   $sth = $dbh->prepare("SHOW CREATE TABLE $TMPL_TBL");
   $sth->execute;
   my @tbl_row = $sth->fetchrow_array();
   my $create_sql = $tbl_row[1];
   $sth->finish;

   # Replace table name with correct one.
   $create_sql =~ s/ACCOUNTING_TMPL/ACCOUNTING$TS/;

   $sth = $dbh->prepare($create_sql);
   $sth->execute;
   $sth->finish;
   print "Table ACCOUNTING$TS created.\n";
} else {
   $sth->finish;
   print "Table ACCOUNTING$TS already exists.\n";
}

$dbh->disconnect;
