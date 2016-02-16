# AuthPRESENCESQL.pm
#
# Object for handling presence discovery using the RADIUS protocol
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthPRESENCESQL.pm,v 1.7 2013/08/13 20:58:45 hvn Exp $

package Radius::AuthPRESENCESQL;
@ISA = qw(Radius::AuthGeneric Radius::SqlDb);
use Radius::AuthGeneric;
use Radius::SqlDb;
use DBI;
use strict;

%Radius::AuthPRESENCESQL::ConfigKeywords = 
('PresenceSelect'         => 
 ['string', 'SQL query that looks for accounting starts and stops for a given user it is expected to return <p><code><pre>timestamp, statustype, locationname</pre></code><p> in descending timestamp order. timestamp is unix epoch time
statustype is "Start" or "Stop", locationname a access point name. ', 0],

 'MapLocation'            => 
 ['stringhash', 'Maps a locationname into a string. If you have several APs at one physical location, you may want to map them all to one canonical location name, or you may just want to give sensible names to specific devices for the benefit of the client who is asking for the presence info. Format is<p><code><pre>locationname,string</pre></code>', 0],

 );

# RCS version number of this module
$Radius::AuthPRESENCESQL::VERSION = '$Revision: 1.7 $';

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    $self->Radius::AuthGeneric::check_config();
    $self->Radius::SqlDb::check_config();
    return;
}

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->Radius::AuthGeneric::activate;
    $self->Radius::SqlDb::activate;
}

#####################################################################
# Do per-instance default initialization
# This is called by Configurabel during Configurable::new before
# the config file is parsed. Its a good place initalze 
# instance variables
# that might get overridden when the config file is parsed.
sub initialize
{
    my ($self) = @_;

    $self->Radius::AuthGeneric::initialize;
    $self->Radius::SqlDb::initialize;

    $self->{PresenceSelect} = 'select TIME_STAMP, ACCTSTATUSTYPE, NASIDENTIFIER from ACCOUNTING where USERNAME=%0 order by TIME_STAMP desc';
}

#####################################################################
# Handle a request
# Looks for presence requests.
# For a presence request, tries to figure what the most recent event really
# was, which can be confused by late Stops during roaming among APs.
# The possible cases are:
# 1: Start ap1: user is present at ap1
# 2: Start ap1, Stop ap1: user is not present, last seen at ap1
# 3: Start ap1, Stop ap2: stale stop, user is present, last seen at ap1
# 4: Stop ap1: missing start, user is not present, last seen at ap1
# 5: no records: user is not present
sub handle_request
{
    my ($self, $p, $dummy, $extra_checks) = @_;

    my $type = ref($self);
    $self->log($main::LOG_DEBUG, "Handling with $type", $p);

    if ($p->code eq 'Access-Request' 
	&& $p->getAttrByNum($Radius::Radius::SERVICE_TYPE) eq 'Call-Check-User')
    {
	# Access request with Service-Type=Call-Check-User
	return ($main::REJECT, 'Database failure') unless $self->reconnect;

	my $user_name = $p->getUserName;
	my $qname = $self->quote($user_name);
	# Issue SQL query for data about this user. Make sure we deal with
	# weird issues like roaming with a late stop from the departed AP
	my $q = &Radius::Util::format_special
	    ($self->{PresenceSelect}, $p, $self, $qname);
	print "query is $q\n";

	my $sth = $self->prepareAndExecute($q);
	return ($main::REJECT, 'Database execute failure')
	    unless $sth;
    
	my (@row, $done, %stops, @laststop);
	while (!$done && (@row = $sth->fetchrow()))
	{
	    # We expect row to be in order:
	    # TIME_STAMP, ACCTSTATUSTYPE, NASIDENTIFIER
	    # looking backwards in time
	    $self->log($main::LOG_DEBUG, "Got PresenceSelect row: @row");
	    if ($row[1] eq 'Start')
	    {
		if (exists $stops{$row[2]})
		{
		    # Case 2
		    $self->log($main::LOG_DEBUG, 'Presence case 2');
		    $p->{rp}->change_attr('OSC-User-Presence-Indicator', 'NotPresent');
		    $p->{rp}->change_attr('OSC-User-Presence-Location', 
					  $self->map_location($row[2]));
		    $p->{rp}->change_attr('OSC-User-Presence-Timestamp', $stops{$row[2]});
		}
		else
		{
		    # Case 1 or 3
		    $self->log($main::LOG_DEBUG, 'Presence case 1 or 3');
		    $p->{rp}->change_attr('OSC-User-Presence-Indicator', 'Present');
		    $p->{rp}->change_attr('OSC-User-Presence-Location',  
					  $self->map_location($row[2]));
		    $p->{rp}->change_attr('OSC-User-Presence-Timestamp', $row[0]);
		    
		}
		$done++;
	    }
	    elsif ($row[1] eq 'Stop')
	    {
		# Hmmmm, last thing is a Stop, keep going looking for a
		# matching start. Keep a record of stop timestamps for each
		# AP stop
		$stops{$row[2]} = $row[0];
		@laststop = ($row[2], $row[0]) unless @laststop;
	    }
	}
	$sth->finish();
	if (!$done)
	{
	    $p->{rp}->change_attr('OSC-User-Presence-Indicator', 'NotPresent');
	    # See if there were any stops at all for case 4 or 5
	    if (%stops)
	    {
		# Case 4, use the latest stop
		$self->log($main::LOG_DEBUG, 'Presence case 4');
		$p->{rp}->change_attr('OSC-User-Presence-Location', 
				      $self->map_location($laststop[0]));
		$p->{rp}->change_attr('OSC-User-Presence-Timestamp', $laststop[1]);
	    }
	    else
	    {
		# Else never saw anything, case 5
		$self->log($main::LOG_DEBUG, 'Presence case 5');
	    }
	}
	return ($main::ACCEPT);
    }
    else
    {
	# Ordinary access request? IGNORE so we can fall through
	return ($main::IGNORE, 'Not a presence request');
    }
}

#####################################################################
# Map a location name (maybe NASIDENTIFIER or CALLEDSTATIONID)
# into a string that makes sense to the clinet asking for presence info
# may want to do this in case there are several APs responsible for one 
# presence location
sub map_location
{
    my ($self, $name) = @_;

    if (defined $self->{MapLocation})
    {
	return $self->{MapLocation}{$name}
	    if exists $self->{MapLocation}{$name};

	return "Unknown mapping for location $name";
    }

    # No mappings, just use the name
    return $name;
}


1;
