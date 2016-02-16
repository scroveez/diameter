# AuthEMERALD4.pm
#
# Object for handling Authentication and accounting from Emerald version 4
# (http://www.emerald.iea.com)
# This is a subclass of SQL that can also get radius attributes
# from Emeralds special attribute tables.
#
# Reject List is not supported
# Ip Pooling is not supported
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997-2002 Open System Consultants
# $Id: AuthEMERALD4.pm,v 1.5 2012/06/27 23:27:18 mikem Exp $

package Radius::AuthEMERALD4;
@ISA = qw(Radius::AuthSQL);
use Radius::AuthSQL;
use strict;

%Radius::AuthEMERALD4::ConfigKeywords = 
('ConcurrencyControl'     => 
 ['flag', 'Controls whether to apply Simultaneous-Use limtis to each user. Defaults to false.', 1],
 'TimeBanking'            => 
 ['flag', 'Control whether Time Banking limits are to be enforced. Defaults to false.', 1],
 'HonourServers'          => 
 ['flag', 'Controls whether this module will use the Rodopi Servers list as an additional source of Radius Client addresses. ClientQuery is used to fetch the client list. Defaults to false.', 1],
 'HonourServerPortAccess' => 
 ['flag', 'Controls whether this module will enforce time-based access limits for certain NAS ports. PortAccessQuery is used to fetch details of port restrictions. Defaults to false.', 1],
 'HonourDNISGroups'       => 
 ['flag', 'Controls whether this module will enforce limits on Called-Station-Id. DNISGroupQuery is used to fetch details of permitted groups. Defaults to false.', 1],
 'HonourRoamServers'      => 
 ['flag', 'Controls whether RoamQuery will be used to get roaming restrictions. Defaults to false.', 1],
 'DNISGroupQuery'         => 
 ['string', 'SQL query used to fetch DNIS Groups.', 1],
 'PortAccessQuery'        => 
 ['string', 'SQL query used to fetch permitted ports.', 1],
 'RadUserQuery'           => 
 ['string', 'SQL query used to fetch user attributes.', 1],
 'ClientQuery'            => 
 ['string', 'SQL query used to fetch RADIUS client details.', 1],
 'RoamQuery'              => 
 ['string', 'SQL query used to fetch roaming restrictions.', 1],
 );

# RCS version number of this module
$Radius::AuthEMERALD4::VERSION = '$Revision: 1.5 $';

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();

    $self->createClients() if $self->{HonourServers};
    $self->createRoam() if $self->{HonourRoamServers};
}


#####################################################################
# Do per-instance Adefault initialization
# This is called by Configurable during Configurable::new before
# the config file is parsed. Its a good place initalze 
# instance variables
# that might get overridden when the config file is parsed.
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{AuthSelect} = 'exec RadGetUser %0, NULL';
    $self->{DNISGroupQuery} = 'select dn.DNISNumber from AccountTypes a, 
DNISNumbers dn where a.AccountType=\'%0\' and a.DNISGroupID=dn.DNISGroupID 
and dn.DNISNumber=\'%1\'';
    $self->{PortAccessQuery} = 'select sa.StartTime, sa.StopTime, 
sa.MaxSessionLength from Servers s, ServerAccess sa, AccountTypes at
where s.IPAddress=\'%{Client:Name}\' 
and s.ServerID = sa.ServerID 
and (sa.Port=%0 or sa.Port=9214328)
and sa.AccountTypeID=at.AccountTypeID
and at.AccountType=\'%1\'
order by sa.Port';
    $self->{RadUserQuery} = 'exec RadGetConfigs %0';
    $self->{ClientQuery} = 'select IPAddress, Secret, Community, ServerID from Servers';
    $self->{RoamQuery} = 'exec RadRoamCache';
}

#####################################################################
# Find a the named user by looking in the database, and constructing
# User object if we found the named user
# This is tailored exactly to Emerald's user database
sub findUser
{
    my ($self, $name, $p) = @_;

    # (Re)-connect to the database if necessary, 
    return (undef, 1) unless $self->reconnect;

    my $qname = $self->quote($name);
    
    my $q = &Radius::Util::format_special
	($self->{AuthSelect}, $p, undef, $qname);

    my $sth = $self->prepareAndExecute($q);
    return undef unless $sth;

    my ($account_id, $login, $password, $dummy1, $account_type,
	$login_limit, $timeleft, $master_expire, $sub_expire, 
	$over_limit, $start_date, $user);

    if (($account_id, $login, $password, $dummy1, $account_type,
	$login_limit, $timeleft, $master_expire, $sub_expire, 
	$over_limit, $start_date) 
	= $self->getOneRow($sth))
    {
	$self->log($main::LOG_DEBUG, 
		   "Select results: $account_id, $login, $password, $dummy1, $account_type,
	$login_limit, $timeleft, $master_expire, $sub_expire, 
	$over_limit, $start_date", $p);
	
	$user = new Radius::User $name;
	$account_id = int $account_id; # MSSQL 7 makes it numeric

	# Add a *-Password check item unless the correct password
	# was NULL in the database, This means that if 
	# the password column for a user is NULL,
	# then any password is accepted for that user.
	if (defined $password)
	{
	    $user->get_check->add_attr
		(defined $self->{EncryptedPassword} ? 
		 'Encrypted-Password' : 'User-Password', $password);
	}
	# Expiry is in days since 1/1/1970
	$user->get_check->add_attr('Expiration', $master_expire * 86400)
	    if defined $master_expire;
	$user->get_check->add_attr('Expiration', $sub_expire * 86400)
	    if defined $sub_expire;

	if ($start_date)
	{
	    $user->get_check->add_attr('ValidFrom', $start_date);
	}
	else
	{
	    # Inactive
	    $self->log($main::LOG_DEBUG, "User $name account is inactive", $p);
	    return undef;
	}

	if ($over_limit)
	{
	    # Exceeded max allowable debit?
	    $self->log($main::LOG_DEBUG, "User $name account is over credit limit", $p);
	    return undef;
	}
	
	$user->get_check->add_attr('Simultaneous-Use', $login_limit)
	    if ($self->{ConcurrencyControl} && defined $login_limit);

	my $session_timeout;
	if ($self->{TimeBanking} && defined $timeleft)
	{
	    if ($timeleft <= 0)
	    {
		$self->log($main::LOG_DEBUG, 
			   "User $name has no more time left", $p);
		return undef;
	    }
	    $session_timeout = $timeleft;
	}

	# Now maybe get DNIS records
	my $dnis;
	if ($self->{HonourDNISGroups}
	    && defined ($dnis = $p->getAttrByNum($Radius::Radius::CALLED_STATION_ID)))
	{
	    $q = &Radius::Util::format_special
		($self->{DNISGroupQuery}, $p, undef, $account_type, $dnis);
	    $sth = $self->prepareAndExecute($q);
	    return undef unless $sth;
	    if (! $sth->fetchrow())
	    {
		$self->log($main::LOG_DEBUG, 
			   "No valid DNIS Group for $dnis, Account Type $account_type", $p);
		return undef;
	    }
	}

	# Now maybe get ServerAccess records
	my $nas_port;
	if ($self->{HonourServerPortAccess}
	    && defined ($nas_port = $p->getAttrByNum($Radius::Radius::NAS_PORT)))
	{
	    $q = &Radius::Util::format_special
		($self->{PortAccessQuery}, $p, undef, $nas_port, $account_type);
	    $sth = $self->prepareAndExecute($q) || return;

	    my ($start_time, $stop_time, $session_length);
	    if (($start_time, $stop_time, $session_length)
		= $sth->fetchrow())
	    {
		# Enforce Max Session Time. 0 means no limit
		$session_timeout = $session_length
		    if     $session_length
			&& (   $session_length < $session_timeout
			    || !defined $session_timeout);

		$user->get_check->add_attr
		    ('Block-Logon-Until',
		     sprintf("%d:%02d", 
			     $start_time/60, 
			     $start_time%60))
			if $start_time;
		$user->get_check->add_attr
		    ('Block-Logon-From',
		     sprintf("%d:%02d", 
			     $stop_time/60, 
			     $stop_time%60))
			if $stop_time;

		$sth->finish;
	    }
	}
	    
	$user->get_reply->add_attr('Session-Timeout', $session_timeout)
	    if defined $session_timeout;

	my ($attr_id, $vendor_id, $vendor_type,
	    $attr_name, $attr_data, $attr_value, $attr_type, 
	    $radcheck, $attr_list, $tag);
	# Now get any radius attributes from the Emerald database for this
	# account ID and account type
	$q = &Radius::Util::format_special
	    ($self->{RadUserQuery}, $p, undef, $account_id);
	$sth = $self->prepareAndExecute($q) || return;

	my (@attrDetails);
	while (($attr_id, $attr_name, $attr_data, $attr_value, $attr_type, $vendor_id, $vendor_type, $radcheck, $tag)
	       = $sth->fetchrow())
	{
	    # Dictionaries may not agree, so we use the 
	    # attribute number to find the name
	    # Some DBs return attr_id as a float!
	    $attr_id = int $attr_id;
	    if ($vendor_id && $attr_id == 26)
	    {
		@attrDetails = $main::dictionary->attrByNum
		    ($vendor_type, $vendor_id);
	    }
	    else
	    {
		@attrDetails = $main::dictionary->attrByNum
		    ($attr_id);
	    }
	    
	    $attr_list = $radcheck ? $user->get_check() : $user->get_reply();
	    
	    # Integer or string?
	    $attr_list->add_attr($attrDetails[0], 
				 $attr_type == 1 
				 ? int $attr_value : $attr_data);

	}

	# Set the Class attribute in the reply, similar
	# to RadiusNT
	$user->get_reply->add_attr('Class', "IEAS1\001${account_id}2\001$p->{Client}->{Identifier}");

    }
    return $user;
}

#####################################################################
# Use the Servers table to define which Radius clisnt to hounour
# We use the data there to create Client objects
# This is similar behaviour to ClientListSQL
sub createClients
{
    my ($self) = @_;

    my $q = &Radius::Util::format_special($self->{ClientQuery});
    my $sth = $self->prepareAndExecute($q) || return;

    # Loop through the rows, creating a new Client from each one
    # row is IPAddress, Secret, Community, ServerID
    my @row;
    while (@row = $sth->fetchrow()) 
    {
	my $client = Radius::Client->new
	    (undef, $row[0],
	     Secret => $row[1],
	     Identifier => $row[3]);
	$client->{SNMPCommunity} = $row[2] if defined $row[2];
	$client->activate();
	$self->log($main::LOG_DEBUG, "Added Client $row[0]");
    }
    $sth->finish();
}

#####################################################################
# Look at the roam servers and roam domains tables, creating
# Realm, AuthBy RADIUS and Host objects.
# Note: Attribute mangling, domain stripping for jst auth and just acct
# are not supported.
sub createRoam
{
    my ($self) = @_;

    require Radius::AuthRADIUS;
    
    my $q = &Radius::Util::format_special($self->{RoamQuery});
    my $sth = $self->prepareAndExecute($q) || return;

    # Loop through the rows, creating a new AuthBy RADIUS and a Realm
    # from each one
    # @row is realm, server, address, secret, authport, acctport, priority, 
    # timeout, retries, stripdomain, treataslocal, accounttype, ratetarget, 
    # ratemax
    my @row;
    while (@row = $sth->fetchrow()) 
    {
	next if $row[2] eq 'None' || $row[10]; # treataslocal
	# The first set of records returned by the stored proc
	# are just RadRoamServers, with the server id in the first field
	next if $row[0] =~ /^\d+$/; 

	my $realm = $Radius::Realm::realms{$row[0]};
	my $authby;
	if (!$realm)
	{
	    $realm = Radius::Realm->new(undef, $row[0]);
	    $authby = Radius::AuthRADIUS->new();
	    $authby->activate();
	    push(@{$realm->{AuthBy}}, $authby);
	    $realm->activate();
	    $self->log($main::LOG_DEBUG, 
	        "Created Realm and AuthBY RADIUS for $row[0]");
	}
	else
	{
	    $authby = $realm->{AuthBy}[0];
	}
	next unless $authby; # Can this happen?

	my $host = Radius::Host->new
	    (undef, $row[2],
	     'Identifier' => $row[1],
	     'Secret'     => $row[3],
	     'AuthPort'   => $row[4],
	     'AcctPort'   => $row[5],
	     'Timeout'    => $row[7],
	     'Retries'    => $row[8]);
	$host->activate();
	push(@{$authby->{Hosts}}, $host);

	if ($row[9])
	{
	    # Add a RewriteUsername to strip the domain
	    # REVISIT: we are ignoring the optoins to strip
	    # only for accounting  or authentication
	    # Also, stripping domains is a per-server thing in
	    # Emerald 4, but a per-realm thing in Radiator
	    push(@{$realm->{RewriteUsername}}, 's/^([^@]+).*/$1/');
	}
	$self->log($main::LOG_DEBUG, "Added Host for $row[1] to $row[0]");
    }
}

1;
