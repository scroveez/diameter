#!/usr/bin/perl
# About the issue you mention, we also needed to be able to select prehandler 
# hook from an SQL value, but as Mike pointed out back then, that is not 
# possible, at least directly. By further testing, we also realized that 
# Radiator doesn't know how to update its client list during runtime, i.e. the 
# client list is only read once, during initialization (or kill -USR1, I 
# think, am I wrong Hugh?). Then our final solution was simply to use a clause 
# like

#include /home/radiator/Radiator-3.3.1/rad_clients|

#and setup a perl file containing:


use DBI;
$dbh = DBI->connect ( "dbi:Pg:dbname=xxxxxxx;host=xx.xx.xx.xx", "xxxxx", "xxxxx");
if ( !defined $dbh ) {
die "Cannot connect to database!\n";
}

$sth = $dbh->prepare( "SELECT nasidentifier, nastype, secret, prehandlerhook FROM radclientlist");
if ( !defined $sth ) {
die "Cannot prepare statement: $DBI::errstr\n";
}
$sth->execute;
while ( ($nas_id, $nas_type, $nas_secret, $pre_handler) = $sth->fetchrow()){

print "<Client $nas_id>\n   Secret $nas_secret\n   NasType $nas_type\n   
PreHandlerHook $pre_handler\n</Client>\n";
}
$sth->finish;
$dbh->disconnect;


#This way, the client list is generated (from SQL data) at daemon startup and 
#included inline with the rest of the configuration, so we can enjoy the best 
#of both worlds, the client data stored efficiently in SQL and the compact 
#'file:"scriptname.pl"' notation as a pointer to further code. Perhaps it 
#needs some refinement, especially in error handling, but it works fine. 
#Anyway, I continue thinking that it would be better to have it handled 
#directly by the main code, but I was unable to convince Mike and Hugh at 
#that time :-)
