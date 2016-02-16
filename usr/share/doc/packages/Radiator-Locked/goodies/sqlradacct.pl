# support code for inserting accouting data into a radacct table
# compatible with FreeRADIUS or ICRADIUS, as used with Freeside
# Contributed by Ivan Kohler, http://www.sisd.com/freeside/
# and integrated by Mike McCauley (mikem@open.com.au)
#
# Copyright (c) 2002 Ivan Kohler.  All rights reserved.
# This program is free software; you can redistribute it and/or modify it
# under the same terms as Perl itself.  Specifically, YOU MAY NOT REMOVE THIS
# NOTICE AND REDISTRIBUTE THE CODE UNDER A DIFFERENT LICENSE.
#
# Be sure to change $datasrc, $username and $password to suit
# your database (with the radacct table, not your Freeside database)

# This code is designed to be called as AcctHook from AuthBy INTERNAL

# $p us the current request,
# $rp is the current part assembled reply
# $extras is an extra check items (can ignore for freeside)
sub
{
    use DBI;
    use Date::Format;
    
    my ($p, $rp, $extras) = @_;
    my $date = $p->get_attr('Timestamp');
    
    # Change these to suit your database
    my $datasrc = 'dbi:Pg:dbname=radiator;host=localhost';
    my $username = '';
    my $password = '';

    my $dbh = DBI->connect($datasrc, $username, $password);
    if (!$dbh)
    {
	&main::log($main::LOG_ERR, "Could not connect to database: $DBI::errstr");
	return ($main::IGNORE, 'Database failure');
    }

    my $acct_type = $p->get_attr('Acct-Status-Type');
    if ($acct_type eq 'Start' ) 
    {
	my $q = "INSERT INTO radacct (
              AcctSessionId, AcctUniqueId, UserName, Realm,
              NASIPAddress,
              NASPortId, NasPortType, AcctStartTime, AcctSessionTime,
              AcctAuthentic, ConnectInfo_start, ConnectInfo_stop,
              AcctInputOctets, AcctOutputOctets, CalledStationId,
              CallingStationId, AcctTerminateCause, ServiceType,
              FramedProtocol, FramedIPAddress, AcctStartDelay,
              AcctStopDelay )
            VALUES ( ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,? )";
	my $sth = $dbh->prepare($q);
	if (!$sth)
	{
	    $dbh->disconnect;
	    &main::log($main::LOG_ERR, "Could not prepare: ". $dbh->errstr);
	    return ($main::IGNORE, 'Database failure');
	}
	if (!$sth->execute
	    (
	     $p->get_attr('Acct-Session-Id'),
	     ( $p->get_attr('Acct-Unique-Session-Id') || ''),
	     $p->get_attr('User-Name'),
	     ( $p->get_attr('Realm') || '' ),
	     $p->get_attr('NAS-IP-Address'),
	     $p->get_attr('NAS-Port'),
	     $p->get_attr('NAS-Port-Type'),
	     time2str("%Y-%m-%d %T", $date),
	     0,
	     $p->get_attr('Acct-Authentic'),
	     ( $p->get_attr('Connect-Info') || ''),
	     '',
	     0,
	     0,
	     $p->get_attr('Called-Station-Id'),
	     $p->get_attr('Calling-Station-Id'),
	     '',
	     $p->get_attr('Service-Type'),
	     $p->get_attr('Framed-Protocol'),
	     $p->get_attr('Framed-IP-Address'),
	     ( $p->get_attr('Acct-Delay-Time') || 0 ),
	     0,
	     )) 
	{
	    $dbh->disconnect;
	    &main::log($main::LOG_ERR, "Could not execute: ". $sth->errstr);
	    return ($main::IGNORE, 'Database failure');
	}
    } 
    elsif ($acct_type eq 'Stop') 
    {
	my $q = "UPDATE radacct SET AcctStopTime = ?,
                 AcctSessionTime = ?,
                 AcctInputOctets = ?,
                 AcctOutputOctets = ?,
                 AcctTerminateCause = ?,
                 AcctStopDelay = ?,
                 FramedIPAddress = ?,
                 ConnectInfo_stop = ?
                 WHERE AcctSessionId = ?
                 AND UserName = ?
                 AND NASIPAddress = ?
                 AND ( AcctStopTime IS NULL OR AcctStopTime = 0 )";
	my $sth = $dbh->prepare($q);
	if (!$sth)
	{
	    $dbh->disconnect;
	    &main::log($main::LOG_ERR, "Could not prepare: ". $dbh->errstr);
	    return ($main::IGNORE, 'Database failure');
	}
	if (!$sth->execute
	    (
	     time2str("%Y-%m-%d %T", $date),
	     $p->get_attr('Acct-Session-Time'),
	     $p->get_attr('Acct-Input-Octets'),
	     $p->get_attr('Acct-Output-Octets'),
	     ( $p->get_attr('Acct-Terminate-Cause') || ''),
	     ( $p->get_attr('Acct-Delay-Time') || 0 ),
	     ( $p->get_attr('Framed-IP-Address') || '' ),
	     ( $p->get_attr('Connect-Info') || ''),
	     $p->get_attr('Acct-Session-Id'),
	     $p->get_attr('User-Name'),
	     $p->get_attr('NAS-IP-Address'),
	     ))
	{
	    $dbh->disconnect;
	    &main::log($main::LOG_ERR, "Could not execute: ". $sth->errstr);
	    return ($main::IGNORE, 'Database failure');
	}
    } 
    else 
    {
	$dbh->disconnect;
	unless ( grep { $acct_type eq $_ } qw( Alive ) ) {
    	    &main::log($main::LOG_WARNING,
	               "unhandled Acct-Status-Type: $acct_type");
	}
	return ($main::IGNORE, 'unhandled Acct-Status-Type');
    }
    # Tell AuthBy INTERNAL to accept this
    $dbh->disconnect;
    return ($main::ACCEPT);
}

