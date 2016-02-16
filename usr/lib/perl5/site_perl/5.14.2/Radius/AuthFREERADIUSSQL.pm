# AuthFREERADIUSSQL.pm
#
# Object for handling Authentication and accounting with a FreeRadius
# SQL database.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthFREERADIUSSQL.pm,v 1.9 2014/09/29 19:39:11 hvn Exp $

package Radius::AuthFREERADIUSSQL;
@ISA = qw(Radius::AuthSQL);
use Radius::AuthSQL;
use strict;

%Radius::AuthFREERADIUSSQL::ConfigKeywords = 
('AccountingTable'        => 
 ['string', '', 1],

 'AuthCheck'              => 
 ['string', 'This optional parameter specifies an SQL query that is used to get check items for a user. Special characters are supported, as well as a single bind variable for the user name being searched.', 1],

 'AuthReply'              => 
 ['string', 'This optional parameter specifies an SQL query that is used to get reply items for a user. Special characters are supported, as well as a single bind variable for the user name being searched.', 1],

 'AuthGroupCheck'         => 
 ['string', 'This optional parameter specifies an SQL query that is used to get check items for a user\'s group. Special characters are supported, as well as a single bind variable for the group name being searched. ', 1],

 'AuthGroupReply'         => 
 ['string', 'This optional parameter specifies an SQL query that is used to get reply items for a user\'s group. Special characters are supported, as well as a single bind variable for the group name being searched.', 1],

 'AcctOnoffQuery'         => 
 ['string', 'SQL Query to handle Accounting ON-Off requests', 1],

 'AcctStartQuery'         => 
 ['string', 'SQL Query to handle Accounting Start', 1],

 'AcctStartQueryAlt'      => 
 ['string', 'Alternate SQL Query to handle Accounting Start. It will be run if AcctStartQuery fails', 1],

 'AcctUpdateQuery'        => 
 ['string', 'SQL Query to handle Accounting Update', 1],

 'AcctUpdateQueryAlt'     => 
 ['string', 'Alternate SQL Query to handle Accounting Update. It will be run if AcctUpdateQuery fails', 1],

 'AcctStopQuery'          => 
 ['string', 'SQL Query to handle Accounting Stop', 1],

 'AcctStopQueryAlt'       => 
 ['string', 'Alternate SQL Query to handle Accounting Stop. It will be run if AcctStopQuery fails', 1],

 );

# RCS version number of this module
$Radius::AuthFREERADIUSSQL::VERSION = '$Revision: 1.9 $';

#####################################################################
# Do per-instance default initialization
# This is called by Configurabel during Configurable::new before
# the config file is parsed. Its a good place initalze 
# instance variables
# that might get overridden when the config file is parsed.
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;

    $self->{AuthCheck} = 'SELECT id, UserName, Attribute, Value, op FROM  radcheck WHERE Username=? ORDER BY id';
    $self->{AuthReply} = 'SELECT id, UserName, Attribute, Value, op FROM radreply WHERE Username = ? ORDER BY id';
    $self->{AuthGroupCheck} = 'SELECT radgroupcheck.id,radgroupcheck.GroupName,radgroupcheck.Attribute,radgroupcheck.Value,radgroupcheck.op  FROM radgroupcheck,radusergroup WHERE radusergroup.Username = ? AND radusergroup.GroupName = radgroupcheck.GroupName ORDER BY radgroupcheck.id';
    $self->{AuthGroupReply} = 'SELECT radgroupreply.id,radgroupreply.GroupName,radgroupreply.Attribute,radgroupreply.Value,radgroupreply.op  FROM radgroupreply,radusergroup WHERE radusergroup.Username = ? AND radusergroup.GroupName = radgroupreply.GroupName ORDER BY radgroupreply.id';
    $self->{GroupMembershipQuery} = 'SELECT GroupName FROM radusergroup WHERE UserName=?';
    $self->{AcctOnoffQuery} = "UPDATE radacct SET AcctStopTime='%J', AcctSessionTime=unix_timestamp('%J') - unix_timestamp(AcctStartTime), AcctTerminateCause='%{Acct-Terminate-Cause}', AcctStopDelay = '%{Acct-Delay-Time}' WHERE AcctSessionTime=0 AND AcctStopTime=0 AND NASIPAddress= '%{NAS-IP-Address}' AND AcctStartTime <= '%J'";
    $self->{AcctStartQuery} = "INSERT into radacct (AcctSessionId, AcctUniqueId, UserName, Realm, NASIPAddress, NASPortId, NASPortType, AcctStartTime, AcctStopTime, AcctSessionTime, AcctAuthentic, ConnectInfo_start, ConnectInfo_stop, AcctInputOctets, AcctOutputOctets, CalledStationId, CallingStationId, AcctTerminateCause, ServiceType, FramedProtocol, FramedIPAddress, AcctStartDelay, AcctStopDelay) values('%{Acct-Session-Id}', '%{Acct-Unique-Session-Id}', %0, '%{Realm}', '%{NAS-IP-Address}', '%{NAS-Port}', '%{NAS-Port-Type}', '%J', '0', '0', '%{Acct-Authentic}', '%{Connect-Info}', '', '0', '0', '%{Called-Station-Id}', '%{Calling-Station-Id}', '', '%{Service-Type}', '%{Framed-Protocol}', '%{Framed-IP-Address}', '%{Acct-Delay-Time}', '0')";
    $self->{AcctStartQueryAlt} = "UPDATE radacct SET AcctStartTime = '%J', AcctStartDelay = '%{Acct-Delay-Time}', ConnectInfo_start = '%{Connect-Info}' WHERE AcctSessionId = '%{Acct-Session-Id}' AND UserName = %0 AND NASIPAddress = '%{NAS-IP-Address}'";
    $self->{AcctUpdateQuery} = "UPDATE radacct SET FramedIPAddress = '%{Framed-IP-Address}', AcctSessionTime = '%{Acct-Session-Time}', AcctInputOctets = '%{Acct-Input-Octets}', AcctOutputOctets = '%{Acct-Output-Octets}' WHERE AcctSessionId = '%{Acct-Session-Id}' AND UserName = %0 AND NASIPAddress= '%{NAS-IP-Address}'";
    $self->{AcctUpdateQueryAlt} = "INSERT into radacct (AcctSessionId, AcctUniqueId, UserName, Realm, NASIPAddress, NASPortId, NASPortType, AcctStartTime, AcctSessionTime, AcctAuthentic, ConnectInfo_start, AcctInputOctets, AcctOutputOctets, CalledStationId, CallingStationId, ServiceType, FramedProtocol, FramedIPAddress, AcctStartDelay) values('%{Acct-Session-Id}', '%{Acct-Unique-Session-Id}', %0, '%{Realm}', '%{NAS-IP-Address}', '%{NAS-Port}', '%{NAS-Port-Type}', DATE_SUB('%J',INTERVAL (%{Acct-Session-Time:-0} + %{Acct-Delay-Time:-0}) SECOND), '%{Acct-Session-Time}', '%{Acct-Authentic}', '', '%{Acct-Input-Octets}', '%{Acct-Output-Octets}', '%{Called-Station-Id}', '%{Calling-Station-Id}', '%{Service-Type}', '%{Framed-Protocol}', '%{Framed-IP-Address}', '0')";
    $self->{AcctStopQuery} = "UPDATE radacct SET AcctStopTime = '%J', AcctSessionTime = '%{Acct-Session-Time}', AcctInputOctets = '%{Acct-Input-Octets}', AcctOutputOctets = '%{Acct-Output-Octets}', AcctTerminateCause = '%{Acct-Terminate-Cause}', AcctStopDelay = '%{Acct-Delay-Time}', ConnectInfo_stop = '%{Connect-Info}' WHERE AcctSessionId = '%{Acct-Session-Id}' AND UserName = %0 AND NASIPAddress = '%{NAS-IP-Address}'";
    $self->{AcctStopQueryAlt} = "INSERT into radacct (AcctSessionId, AcctUniqueId, UserName, Realm, NASIPAddress, NASPortId, NASPortType, AcctStartTime, AcctStopTime, AcctSessionTime, AcctAuthentic, ConnectInfo_start, ConnectInfo_stop, AcctInputOctets, AcctOutputOctets, CalledStationId, CallingStationId, AcctTerminateCause, ServiceType, FramedProtocol, FramedIPAddress, AcctStartDelay, AcctStopDelay) values('%{Acct-Session-Id}', '%{Acct-Unique-Session-Id}', %0, '%{Realm}', '%{NAS-IP-Address}', '%{NAS-Port}', '%{NAS-Port-Type}', DATE_SUB('%J', INTERVAL (%{Acct-Session-Time:-0} + %{Acct-Delay-Time:-0}) SECOND), '%J', '%{Acct-Session-Time}', '%{Acct-Authentic}', '', '%{Connect-Info}', '%{Acct-Input-Octets}', '%{Acct-Output-Octets}', '%{Called-Station-Id}', '%{Calling-Station-Id}', '%{Acct-Terminate-Cause}', '%{Service-Type}', '%{Framed-Protocol}', '%{Framed-IP-Address}', '0', '%{Acct-Delay-Time}')";

    $self->{AcctTotalSinceQuery} = "SELECT SUM(AcctSessionTime - GREATEST((%1 - UNIX_TIMESTAMP(AcctStartTime)), 0)) FROM radacct WHERE UserName=%0 AND UNIX_TIMESTAMP(AcctStartTime) + AcctSessionTime > %1";
    $self->{AcctTotalQuery} = "SELECT SUM(AcctSessionTime) FROM radacct WHERE UserName=%0";

    # These fool AuthSQL into cooperating with us.
    $self->{AuthSelect}       = 'NOT USED BY FREERADIUSSQL';
    $self->{AcctSQLStatement} = [];
}

#####################################################################
# Find a the named user by looking in the database, and constructing
# User object if we found the named user
# $name is the user name we want
# $p is the current request we are handling
sub findUser
{
    my ($self, $name, $p) = @_;

    # (Re)-connect to the database if necessary, 
    return (undef, 1) unless $self->reconnect;

    # First look for per-user check items
    # CAUTION: not all check item ops are supported
    my $q = &Radius::Util::format_special($self->{AuthCheck}, $p);
    my $sth = $self->prepareAndExecute($q, $name);
    return unless $sth;

    # No such user?
    return unless $sth->rows();

    my $user = new Radius::User $name;
    my (@row, $rows);
    while (@row = $sth->fetchrow())
    {
	$rows++;
	# Expect: id, UserName, Attribute, Value, op
	$self->log($main::LOG_DEBUG, "Got user check row: @row");
	if ($row[4] eq '=')
	{
	    # Add if not exist
	    $user->get_check->add_if_not_exist_attr($row[2], $row[3]);
	}
	elsif ($row[4] eq ':=')
	{
	    # Add or replace
	    $user->get_check->change_attr($row[2], $row[3]);
	}
	elsif ($row[4] eq '==' || $row[4] eq '+=' )
	{
	    # Append
	    $user->get_check->add_attr($row[2], $row[3]);
	}
	else
	{
	    $self->log($main::LOG_WARNING, "Dont know how to handle user check item op: $row[4]. Ignored");
	}
    }
    $sth->finish();
    return unless $rows; # No such user?

    # OK , now see if there are any per-user reply items
    $q = &Radius::Util::format_special($self->{AuthReply}, $p);
    $sth = $self->prepareAndExecute($q, $name);
    return unless $sth;

    while (@row = $sth->fetchrow())
    {
	# Expect: id, UserName, Attribute, Value, op
	$self->log($main::LOG_DEBUG, "Got user reply row: @row");
	if ($row[4] eq '=')
	{
	    # Add if not exist
	    $user->get_reply->add_if_not_exist_attr($row[2], $row[3]);
	}
	elsif ($row[4] eq ':=')
	{
	    # Add or replace
	    $user->get_reply->change_attr($row[2], $row[3]);
	}
	elsif ($row[4] eq '+=')
	{
	    # Append
	    $user->get_reply->add_attr($row[2], $row[3]);
	}
	else
	{
	    $self->log($main::LOG_WARNING, "Dont know how to handle user reply item op: $row[4]. Ignored");
	}
    }
    $sth->finish();

    # OK , now see if there are any per-group check items
    $q = &Radius::Util::format_special($self->{AuthGroupCheck}, $p);
    $sth = $self->prepareAndExecute($q, $name);
    return unless $sth;

    while (@row = $sth->fetchrow())
    {
	# Expect: id, GroupName, Attribute, Value, op
	$self->log($main::LOG_DEBUG, "Got group check row: @row");
	if ($row[4] eq '=')
	{
	    # Add if not exist
	    $user->get_check->add_if_not_exist_attr($row[2], $row[3]);
	}
	elsif ($row[4] eq ':=')
	{
	    # Add or replace
	    $user->get_check->change_attr($row[2], $row[3]);
	}
	elsif ($row[4] eq '==' || $row[4] eq '+=' )
	{
	    # Append
	    $user->get_check->add_attr($row[2], $row[3]);
	}
	else
	{
	    $self->log($main::LOG_WARNING, "Dont know how to handle group check item op: $row[4]. Ignored");
	}
    }
    $sth->finish();

    # OK , now see if there are any per-group reply items
    $q = &Radius::Util::format_special($self->{AuthGroupReply}, $p);
    $sth = $self->prepareAndExecute($q, $name);
    return unless $sth;

    while (@row = $sth->fetchrow())
    {
	# Expect: id, GroupName, Attribute, Value, op
	$self->log($main::LOG_DEBUG, "Got group reply row: @row");
	if ($row[4] eq '=')
	{
	    # Add if not exist
	    $user->get_reply->add_if_not_exist_attr($row[2], $row[3]);
	}
	elsif ($row[4] eq ':=')
	{
	    # Add or replace
	    $user->get_reply->change_attr($row[2], $row[3]);
	}
	elsif ($row[4] eq '+=')
	{
	    # Append
	    $user->get_reply->add_attr($row[2], $row[3]);
	}
	else
	{
	    $self->log($main::LOG_WARNING, "Dont know how to handle group reply item op: $row[4]. Ignored");
	}
    }
    $sth->finish();

    return $user;
}
#####################################################################
# Handle an accounting request
sub handle_accounting
{
    my ($self, $p) = @_;

    my $status_type = $p->getAttrByNum($Radius::Radius::ACCT_STATUS_TYPE);
    my $username = $self->quote($p->getUserName());
    my $acct_failed;
    if (   $status_type eq 'Accounting-On'
	|| $status_type eq 'Accounting-Off')
    {
	my $q = &Radius::Util::format_special
	    ($self->{AcctOnoffQuery}, $p, undef, $username);
	$acct_failed++ if !$self->do($q);
    }
    elsif ($status_type eq 'Start')
    {
	my $q = &Radius::Util::format_special
	    ($self->{AcctStartQuery}, $p, undef, $username);
	if (!$self->do($q))
	{
	    $q = &Radius::Util::format_special
		($self->{AcctStartQueryAlt}, $p, undef, $username);
	    $acct_failed++ if !$self->do($q);
	}
    }
    elsif ($status_type eq 'Alive')
    {
	my $q = &Radius::Util::format_special
	    ($self->{AcctUpdateQuery}, $p, undef, $username);
	if (!$self->do($q))
	{
	    $q = &Radius::Util::format_special
		($self->{AcctUpdateQueryAlt}, $p, undef, $username);
	    $acct_failed++ if !$self->do($q);
	}
    }
    elsif ($status_type eq 'Stop')
    {
	my $q = &Radius::Util::format_special
	    ($self->{AcctStopQuery}, $p, undef, $username);
	if (!$self->do($q))
	{
	    $q = &Radius::Util::format_special
		($self->{AcctStopQueryAlt}, $p, undef, $username);
	    $acct_failed++ if !$self->do($q);
	}
    }

    if ($acct_failed)
    {
	$self->log($main::LOG_ERR, "Failed to handle accounting request", $p);
	if ($self->{AcctFailedLogFileName})
	{
	    # Anonymous subroutine hides the details from logAccounting
	    my $format_hook;
	    $format_hook = sub { $self->runHook('AcctLogFileFormatHook', $p, $p); }
	        if $self->{AcctLogFileFormatHook};

	    &Radius::Util::logAccounting
		($p, undef, 
		 $self->{AcctFailedLogFileName}, 
		 $self->{AcctLogFileFormat},
		 $format_hook);
	}
    }

    # Dont need to commit: AutoCommit is on
    # Send a generic reply on our behalf: ACK
    return ($main::ACCEPT); 
}

1;
