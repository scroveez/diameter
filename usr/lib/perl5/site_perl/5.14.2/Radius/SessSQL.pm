# SessSQL.pm
#
# Implement the session database as SQL database
# Having the session database externally allows us to synchronise
# the simultaneous-use limits across several instances of Radiator
#
# The default key for the SQL table is Nas-IP-Address, NAS-Port
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: SessSQL.pm,v 1.44 2014/11/18 18:32:36 hvn Exp $

package Radius::SessSQL;
@ISA = qw(Radius::SessGeneric Radius::SqlDb);
use Radius::SessGeneric;
use Radius::SqlDb;
use Radius::Client;
use strict;

%Radius::SessSQL::ConfigKeywords = 
('AddQuery'              => 
 ['string', 'This SQL statement is executed whenever a new user session starts (i.e. when an Accounting-Request Start message is received). It is expected to record the details of the new session in the SQL database. Special formatting characters may be used (the %{attribute} ones are probably the most useful). Special formatting characters may be used. %0 is replaced by the quoted user name to be deleted, %1 by the NAS IP address, %2 by the NAS-Port, %3 by the SQL quoted Acct-Session-Id. If AddQuery is defined as an empty string, then the query will not be executed. ', 1],

 'AddQueryParam' =>
 ['stringarray', 'This optional parameter enables the use of bound variables (where supported by the SQL server) and query caching. If you specify one or more AddQueryParam parameters, they will be used in order to replace parameters named with a question mark (\`?\') in AddQuery, and the query will be cached for future reuse by the SQL server. Only the first QueryCacheSize queries will be cached.', 1],

 'DeleteQuery'           => 
 ['string', 'This SQL statement is executed whenever a user session finishes (i.e. when an Accounting-Request Stop message is received). It is expected to remove the details of the session from the SQL database. Special formatting characters may be used. %0 is replaced by the quoted user name to be deleted, %1 by the NAS IP address, %2 by the NAS-Port, %3 by the SQL quoted Acct-Session-Id. If DeleteQuery is defined as an empty string, then the query will not be executed.', 1],

 'DeleteQueryParam' =>
 ['stringarray', 'This optional parameter enables the use of bound variables (where supported by the SQL server) and query caching. If you specify one or more DeleteQueryParam parameters, they will be used in order to replace parameters named with a question mark (\`?\') in DeleteQuery, and the query will be cached for future reuse by the SQL server. Only the first QueryCacheSize queries will be cached.', 1],

 'ReplaceQuery'          => 
 ['string', 'If this optional parameter is defined, it will be used to replace a record in the session database. If it is not defined, DeleteQuery and AddQuery will be used instead. By default, it is not defined. %0 is replaced by the quoted user name to be deleted, %1 by the NAS IP address, %2 by the NAS-Port, %3 by the SQL quoted Acct-Session-Id.', 1],

 'ReplaceQueryParam' =>
 ['stringarray', 'This optional parameter enables the use of bound variables (where supported by the SQL server) and query caching. If you specify one or more ReplaceQueryParam parameters, they will be used in order to replace parameters named with a question mark (\`?\') in ReplaceQuery, and the query will be cached for future reuse by the SQL server. Only the first QueryCacheSize queries will be cached.', 1],

'UpdateQuery'              => 
 ['string', 'This SQL statement is executed whenever Accounting-Request Alive or Interim-Update message is received. It is expected to update the details of the session in the SQL database. Special formatting characters may be used (the %{attribute} ones are probably the most useful). %0 is replaced by the quoted user name to be deleted, %1 by the NAS IP address, %2 by the NAS-Port, %3 by the SQL quoted Acct-Session-Id. If UpdateQuery is defined as an empty string, then the query will not be executed. The default is the empty string.', 1],

 'UpdateQueryParam' =>
 ['stringarray', 'This optional parameter enables the use of bound variables (where supported by the SQL server) and query caching. If you specify one or more UpdateQueryParam parameters, they will be used in order to replace parameters named with a question mark (\`?\') in UpdateQuery, and the query will be cached for future reuse by the SQL server. Only the first QueryCacheSize queries will be cached.', 1],

 'ClearNasQuery'         => 
 ['string', 'This SQL statement is executed whenever a NAS reboot is detected. It is expected to clear the details of all sessions on that NAS from the SQL database. Special formatting characters may be used (the %{attribute} ones are probably the most useful). %0 is replaced by the NAS identifier. If ClearNasQuery is defined as an empty string, then the query will not be executed.', 1],

 'ClearNasQueryParam' =>
 ['stringarray', 'This optional parameter enables the use of bound variables (where supported by the SQL server) and query caching. If you specify one or more ClearNasQueryParam parameters, they will be used in order to replace parameters named with a question mark (\`?\') in ClearNasQuery, and the query will be cached for future reuse by the SQL server. Only the first QueryCacheSize queries will be cached.', 1],

 'ClearNasSessionQuery'  => 
 ['string', 'This SQL statement is executed whenever Radiator needs the number of sessions currently logged on to a particular NAS. This is only required if HandleAscendAccessEventRequest is defined and an Ascend-Access-Event-Request is received. %1 is replaced by the NAS IP address.', 1],

 'ClearNasSessionQueryParam' =>
 ['stringarray', 'This optional parameter enables the use of bound variables (where supported by the SQL server) and query caching. If you specify one or more ClearNasSessionQueryParam parameters, they will be used in order to replace parameters named with a question mark (\`?\') in ClearNasSessionQuery, and the query will be cached for future reuse by the SQL server. Only the first QueryCacheSize queries will be cached.', 1],

 'CountQuery'            => 
 ['string', 'This SQL statement is executed whenever a Simultaneous-Use check item or MaxSessions must be checked during an Access-Request. It is expected to find and return details of all the user sessions currently in the Session Database for the given User-Name. For each entry, it is expected to return the NAS-Identifier, NAS-Port and Acct-Session-Id, IP Address and optionally a user name (in that order) of each session currently in the Session Database. The returned rows are counted, and if there are apparently too many sessions, SessionDatabase SQL will query each NAS and port to confirm if the user is still on line at that port with that session ID. If a user name is present as the fifth field returned by the query, that is the user name that will be used to confirm the user is still on line. If CountQuery is defined as an empty string, then the query will not be executed, and the current session count will be fixed at 0.', 1],

 'CountQueryParam' =>
 ['stringarray', 'This optional parameter enables the use of bound variables (where supported by the SQL server) and query caching. If you specify one or more CountQueryParam parameters, they will be used in order to replace parameters named with a question mark (\`?\') in CountQuery, and the query will be cached for future reuse by the SQL server. Only the first QueryCacheSize queries will be cached.', 1],

 'CountNasSessionsQuery' => 
 ['string', 'This SQL statement is executed whenever Radiator needs the number of sessions currently logged on to a particular NAS. This is only required if HandleAscendAccessEventRequest is defined and an Ascend-Access-Event-Request is received. %1 is replaced by the NAS IP address.', 1],

 'CountNasSessionsQueryParam' =>
 ['stringarray', 'This optional parameter enables the use of bound variables (where supported by the SQL server) and query caching. If you specify one or more CountNasSessionsQueryParam parameters, they will be used in order to replace parameters named with a question mark (\`?\') in CountNasSessionQuery, and the query will be cached for future reuse by the SQL server. Only the first QueryCacheSize queries will be cached.', 1],
 );

# RCS version number of this module
$Radius::SessSQL::VERSION = '$Revision: 1.44 $';

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    $self->Radius::SessGeneric::check_config();
    $self->Radius::SqlDb::check_config();
    return;
}

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->Radius::SessGeneric::activate;
    $self->Radius::SqlDb::activate;
}

#####################################################################
# Do per-instance default initialization
# This is called by Configurable during Configurable::new before
# the config file is parsed. Its a good place initialize instance 
# variables
# that might get overridden when the config file is parsed.
# Do per-instance default initialization. This is called after
# construction is complete
sub initialize
{
    my ($self) = @_;

    $self->Radius::SessGeneric::initialize;
    $self->Radius::SqlDb::initialize;

    $self->{AddQuery} = "insert into RADONLINE (USERNAME, NASIDENTIFIER, NASPORT, ACCTSESSIONID, TIME_STAMP, FRAMEDIPADDRESS, NASPORTTYPE, SERVICETYPE) values (%0, '%1', %2, %3, %{Timestamp}, '%{Framed-IP-Address}', '%{NAS-Port-Type}', '%{Service-Type}')";
    $self->{DeleteQuery} = "delete from RADONLINE where NASIDENTIFIER='%1' and NASPORT=0%2";
    $self->{ClearNasQuery} = "delete from RADONLINE where NASIDENTIFIER='%0'";
    $self->{ClearNasSessionQuery} = "delete from RADONLINE where NASIDENTIFIER='%0' and ACCTSESSIONID=%1";
    $self->{CountQuery} = "select NASIDENTIFIER, NASPORT, ACCTSESSIONID, FRAMEDIPADDRESS from RADONLINE where USERNAME=%0";
    $self->{CountNasSessionsQuery} = "select ACCTSESSIONID from RADONLINE where NASIDENTIFIER='%0'";
    $self->{UpdateQuery} = "";

}

#####################################################################
sub add
{
    my ($self, $name, $nas_id, $nas_port, $p) = @_;
    my $session_id = $p->get_attr('Acct-Session-Id');
    $nas_port += 0;

    if ($self->{ReplaceQuery})
    {
	# Replace any existing record
	$self->log($main::LOG_DEBUG,
		   "$self->{Identifier} Replacing session for $name, $nas_id, $nas_port", $p);
	if (!$self->{ReplaceQueryParam})
	{
	    return $self->do(&Radius::Util::format_special
			     ($self->{ReplaceQuery}, $p, $self,
			      $self->quote($name), $nas_id, $nas_port,
			      $self->quote($session_id)));
	}
	else
	{
	    my @bind_values;
	    map (push(@bind_values, Radius::Util::format_special(
			  $_, $p, $self,
			  $name, $nas_id, $nas_port,
			  $session_id)),
		      @{$self->{ReplaceQueryParam}});
	    return $self->prepareAndExecute($self->{ReplaceQuery}, @bind_values);
	}
    }
    elsif ($self->{AddQuery})
    {
	$self->log($main::LOG_DEBUG, 
		   "$self->{Identifier} Adding session for $name, $nas_id, $nas_port", $p);
	if ($self->{DeleteQuery})
	{
	    # Delete any existing session on this port first: its clearly defunct
	    my $framed_ip_address = $p->get_attr('Framed-IP-Address');
	    $self->delete($name, $nas_id, $nas_port, $p, $session_id, $framed_ip_address);
	}
	
	# Now add the new one
	if (!$self->{AddQueryParam})
	{
	    return $self->do(&Radius::Util::format_special($self->{AddQuery}, $p, $self, 
		       $self->quote($name), $nas_id, $nas_port,
		       $self->quote($session_id)));
	}
	else
	{
	    my @bind_values;
	    map (push(@bind_values, Radius::Util::format_special(
			  $_, $p, $self,
			  $name, $nas_id, $nas_port,
			  $session_id)),
		      @{$self->{AddQueryParam}});
	    return $self->prepareAndExecute($self->{AddQuery}, @bind_values);
	}
    }
}

#####################################################################
sub update
{
    my ($self, $name, $nas_id, $nas_port, $p) = @_;
    my $session_id = $p->get_attr('Acct-Session-Id');
    $nas_port += 0;

    # query is optional. Fallback to old behaviour
    return $self->add($name, $nas_id, $nas_port, $p) unless $self->{UpdateQuery};

    $self->log($main::LOG_DEBUG, 
	       "$self->{Identifier} Updating session for $name, $nas_id, $nas_port", $p);

    if (!$self->{UpdateQueryParam})
    {
	$self->do(&Radius::Util::format_special($self->{UpdateQuery}, $p, $self,
	          $self->quote($name), $nas_id, $nas_port,
	          $self->quote($session_id)));
    }
    else
    {
	my @bind_values;
	map (push(@bind_values, Radius::Util::format_special(
		  $_, $p, $self,
		  $name, $nas_id, $nas_port,
		  $session_id)),
	      @{$self->{UpdateQueryParam}});
	return $self->prepareAndExecute($self->{UpdateQuery}, @bind_values);
    }
}

#####################################################################
sub delete
{
    my ($self, $name, $nas_id, $nas_port, $p, $session_id, $framed_ip_address) = @_;
    $nas_port += 0;

    # query is optional
    return unless $self->{DeleteQuery};

    $self->log($main::LOG_DEBUG, 
	       "$self->{Identifier} Deleting session for $name, $nas_id, $nas_port", $p);

    if (!$self->{DeleteQueryParam})
    {
	return $self->do(&Radius::Util::format_special($self->{DeleteQuery}, $p, $self,
		   $self->quote($name), $nas_id, $nas_port,
		   $self->quote($session_id), $framed_ip_address));
    }
    else
    {
	my @bind_values;
	map (push(@bind_values, Radius::Util::format_special(
		      $_, $p, $self,
		      $name, $nas_id, $nas_port,
		      $session_id, $framed_ip_address)),
	     @{$self->{DeleteQueryParam}});
	return $self->prepareAndExecute($self->{DeleteQuery}, @bind_values);
    }
}

#####################################################################
sub clearNas
{
    my ($self, $nas_id, $p) = @_;

    # query is optional
    return unless $self->{ClearNasQuery};

    $self->log($main::LOG_DEBUG, 
	       "$self->{Identifier} Deleting all sessions for $nas_id", $p);
    if (!$self->{ClearNasQueryParam})
    {
	return $self->do(&Radius::Util::format_special($self->{ClearNasQuery}, $p,
						       $self, $nas_id));
    }
    else
    {
	my @bind_values;
	map (push(@bind_values, Radius::Util::format_special(
		      $_, $p, $self,
		      $nas_id)),
	     @{$self->{ClearNasQueryParam}});
	return $self->prepareAndExecute($self->{ClearNasQuery}, @bind_values);
    }
}

#####################################################################
# CLears a single session from the NAS
sub clearNasSession
{
    my ($self, $nas_id, $session, $p) = @_;

    # query is optional
    return unless $self->{ClearNasSessionQuery};

    $self->log($main::LOG_DEBUG, 
	       "$self->{Identifier} Deleting session $session for $nas_id", $p);
    if (!$self->{ClearNasSessionQueryParam})
    {
	return $self->do(&Radius::Util::format_special
	          ($self->{ClearNasSessionQuery}, $p,
	           $self, $nas_id, $self->quote($session)));
    }
    else
    {
	my @bind_values;
	map (push(@bind_values, Radius::Util::format_special(
		      $_, $p, $self,
		      $nas_id, $session)),
	     @{$self->{ClearNasSessionQueryParam}});
	return $self->prepareAndExecute($self->{ClearNasSessionQuery}, @bind_values);
    }
}

#####################################################################
sub exceeded
{
    my ($self, $max, $name, $p) = @_;

    # query is optional
    return 0 unless $self->{CountQuery};

    # (Re)-connect to the database if necessary, but dont let
    # a dead database prevent logins
    return 0 unless $self->reconnect;

    my $count = 0; # Number of current sessions for the user
    my $sth;
    if (!$self->{CountQueryParam})
    {
	$sth = $self->prepareAndExecute(&Radius::Util::format_special
		  ($self->{CountQuery}, $p, $self, $self->quote($name), $max));
    }
    else
    {
	my @bind_values;
	map (push(@bind_values, Radius::Util::format_special(
		      $_, $p, $self,
		      $name, $max)),
	     @{$self->{CountQueryParam}});
	$sth = $self->prepareAndExecute($self->{CountQuery}, @bind_values);
    }
    return 0 unless $sth; # Dont let a dead database stop logins

    my (@sessions, $session, $nas_id, $nas_port, 
	$session_id, $framed_ip_address, $user_name);
    while (($nas_id, $nas_port, $session_id, $framed_ip_address, $user_name) 
	   = $sth->fetchrow())
    {
	push(@sessions, [$nas_id, $nas_port, $session_id, $framed_ip_address, $user_name]);
	$count++;
    }
    if ($count >= $max)
    {
	# Hmmm, looks like we have to double check: 
	# go through them all again
	# Double check by asking the Client who owns the NAS
	foreach $session (@sessions)
	{
	    ($nas_id, $nas_port, $session_id, $framed_ip_address, $user_name) = @$session;
	    $user_name ||= $name;
	    my $client;
	    if ($client = &Radius::Client::findAddress(Radius::Util::inet_pton($nas_id)))
	    {
		if (!$client->isOnline($user_name, $nas_id, $nas_port, $session_id, $framed_ip_address))
		{
		    # Hmmm they are not online anymore, 
		    # remove this session
		    $self->log($main::LOG_INFO, 
			       "$self->{Identifier} Session for $name at $nas_id:$nas_port has gone away", $p);
		    $self->delete($name, $nas_id, $nas_port, $p, $session_id, $framed_ip_address);
		    $count--;
		    last if $count < $max;
		}
	    }
	    else
	    {
		$self->log($main::LOG_WARNING, 
			   "$self->{Identifier} Could not find a Client for NAS $nas_id to double-check Simultaneous-Use. Perhaps you do not have a reverse DNS for that NAS?", $p);
	    }
	}
    }
    return $count >= $max ;
}

#####################################################################
# Returns an array of all the session IDs that should be up on this NAS
# returns 1, and a list of session IDs of the query succeeded. If the 
# query failed, returns undef;
sub sessionsOnNAS
{
    my ($self, $nas_id, $p) = @_;

    # Query is optional
    return unless $self->{CountNasSessionsQuery};

    $self->log($main::LOG_DEBUG, 
	       "$self->{Identifier} Counting sessions for $nas_id", $p);
    my $sth;
    if (!$self->{CountNasSessionsQueryParam})
    {
	$sth = $self->prepareAndExecute(&Radius::Util::format_special
	    ($self->{CountNasSessionsQuery}, $p, $self, $nas_id));
    }
    else
    {
	my @bind_values;
	map (push(@bind_values, Radius::Util::format_special(
		      $_, $p, $self,
		      $nas_id)),
	     @{$self->{CountNasSessionsQueryParam}});
	$sth = $self->prepareAndExecute($self->{CountNasSessionsQuery}, @bind_values);
    }
    return unless $sth;

    my ($session, @sessions);
    while (($session) = $sth->fetchrow())
    {
	push(@sessions, $session);
    }
    return (1, @sessions);
}
1;
