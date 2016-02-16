# AuthEMERALD.pm
#
# Object for handling Authentication and accounting from Emerald
# (http://www.emerald.iea.com)
# This is a subclass of SQL that can also get radius attributes
# from Emeralds special attribute tables.
#
# We only need to override the findUser function so that it 
# extracts reply items from RadConfifgs and RadATConfigs
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthEMERALD.pm,v 1.24 2007/12/18 21:23:50 mikem Exp $

package Radius::AuthEMERALD;
@ISA = qw(Radius::AuthSQL);
use Radius::AuthSQL;
use Radius::Client;
use strict;

%Radius::AuthEMERALD::ConfigKeywords = 
(
 'TimeBanking'            => 
 ['flag', 'Control whether Time Banking limits are to be enforced', 1],

 'HonourServers'          => 
 ['flag', 'Controls whether this module will use the Rodopi Servers list as an additional source of Radius Client addresses. ClientQuery is used to fetch the client list', 1],

 'HonourServerPortAccess' => 
 ['flag', 'Controls whether this module will enforce time-based access limits for certain NAS ports. PortAccessQuery is used to fetch details of port restrictions', 1],

 'HonourDNISGroups'       => 
 ['flag', 'Controls whether this module will enforce limits on Called-Station-Id. DNISGroupQuery is used to fetch details of permitted groups', 1],

 'HonourRoamServers'      => 
 ['flag', 'Controls whether RoamQuery will be used to get roaming restrictions.', 1],

 'DNISGroupQuery'         => 
 ['string', 'SQL query used to fetch DNIS Groups', 1],

 'PortAccessQuery'        => 
 ['string', 'SQL query used to fetch permitted ports', 1],

 'RadUserQuery'           => 
 ['string', 'SQL query used to fetch user details', 1],

 'ClientQuery'            => 
 ['string', 'SQL query used to fetch RADIUS client details', 1],

 'RoamQuery'              => 
 ['string', 'SQL query used to fetch roaming restrictions', 1],

 'AddATDefaults'          => 
 ['flag', 'If this optional parameter is defined, then the account-type-specific Radius reply items will be used unless there was a user-specific reply item. This allows you to use the account-specific reply items as defaults.', 1],

 'RadAccountQuery'        => 
 ['string', 'SQL qery to fetch per-account-type check and reply items', 1],

 'RoamServerQuery'        => 
 ['string', 'SQL qery to fetch roaming servers', 1],

 'RoamRealmQuery'         => 
 ['string', 'SQL qery to fetch roaming realms', 1],
 );

# RCS version number of this module
$Radius::AuthEMERALD::VERSION = '$Revision: 1.24 $';

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();

    $self->createClients() if $self->{HonourServers};
    $self->createRoam() if $self->{HonourRoamServers};
}


#####################################################################
# Do per-instance default initialization
# This is called by Configurable during Configurable::new before
# the config file is parsed. Its a good place initalze 
# instance variables
# that might get overridden when the config file is parsed.
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{AuthSelect} = ' ';
    $self->{DNISGroupQuery} = 'select dn.DNISNumber from AccountTypes a, 
DNISNumbers dn where a.AccountType=\'%0\' and a.DNISGroupID=dn.DNISGroupID 
and dn.DNISNumber=\'%1\'';
    $self->{PortAccessQuery} = 'select sa.StartTime, sa.StopTime, 
sa.MaxSessionLength from Servers s, ServerAccess sa 
where s.IPAddress=\'%{Client:Name}\' 
and s.ServerID = sa.ServerID 
and sa.Port=%0
and sa.AccountType=\'%1\'';
    $self->{RadUserQuery} = 'select ra.RadAttributeID, ra.RadVendorID, 
ra.RadVendorType, 
Data, Value, Type, RadCheck 
from RadConfigs rc, RadAttributes ra
where ra.RadAttributeID = rc.RadAttributeID 
and ra.RadVendorID = rc.RadVendorID
and ra.RadVendorType = rc.RadVendorType
and rc.AccountID=%0';
    $self->{RadAccountQuery} = 'select ra.RadAttributeID, ra.RadVendorID, 
ra.RadVendorType, 
Data, Value, Type, RadCheck 
from RadATConfigs rc, RadAttributes ra
where ra.RadAttributeID = rc.RadAttributeID 
and ra.RadVendorID = rc.RadVendorID
and ra.RadVendorType = rc.RadVendorType
and rc.AccountType=\'%0\'';
    $self->{ClientQuery} = 'select IPAddress, Secret, Community from Servers';
    $self->{RoamServerQuery} = 'select Server, IPAddress, Secret, Timeout, Retries, AuthPort, AcctPort from RadRoamServers';
    $self->{RoamRealmQuery} = 'select rd.Domain, rs.Server, rs.StripDomain
from RadRoamServers rs, RadRoamDomains rd 
where rs.RadRoamServerID = rd.RadRoamServerID';
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

    my $q = "select DateAdd(Day, ma.extension+ma.overdue, maExpireDate),
DateAdd(Day, sa.extension, saExpireDate), sa.AccountID, sa.AccountType,
sa.password, sa.login, sa.shell, sa.TimeLeft $self->{AuthSelect}
from masteraccounts ma, subaccounts sa 
where (sa.login = '$name' or sa.shell = '$name') 
and ma.customerid = sa.customerid 
and sa.active <> 0 and ma.active <> 0";
	
    my $sth = $self->prepareAndExecute($q);
    return undef unless $sth;

    my $user;
    my ($date1, $date2, $account_id, $account_type, 
	$password, $login, $shell, $timeleft, @extras);
    if (($date1, $date2, $account_id, $account_type, 
	$password, $login, $shell, $timeleft, @extras) 
	= $self->getOneRow($sth))
    {
	$self->log($main::LOG_DEBUG, 
		   "Select results: $date1, $date2, $account_id, $account_type, $password, $login, $shell, $timeleft, @extras", $p);
	
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
	$user->get_check->add_attr('Expiration', $date1)
	    if defined $date1;
	$user->get_check->add_attr('Expiration', $date2)
	    if defined $date2;

	my $session_timeout;
	if (defined $timeleft && $self->{TimeBanking})
	{
	    if ($timeleft > 0)
	    {
		$session_timeout = $timeleft * 60;
	    }
	    else
	    {	   
		$self->log($main::LOG_DEBUG, 
			   "User $name has no more time left", $p);
		return undef;
	    }
	}

	# Now maybe get ServerAccess records
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
	    $sth = $self->prepareAndExecute($q);
	    return undef unless $sth;
	    my ($start_time, $stop_time, $session_length);
	    if (($start_time, $stop_time, $session_length)
		= $sth->fetchrow())
	    {
		# Enforce Max Session Time 
		$session_timeout = 60 * $session_length
		    if $session_length
			&& ($session_length < $session_timeout
			    || !defined $session_timeout);

		if ($start_time && $stop_time)
		{
		    $user->get_check->add_attr
			('Block-Logon-Until',
			 sprintf("%d:%02d", 
				 $start_time/60, 
				 $start_time%60));
		    $user->get_check->add_attr
			('Block-Logon-From',
			 sprintf("%d:%02d", 
				 $stop_time/60, 
				 $stop_time%60));
		}
		$sth->finish;
	    }
	}
	    
	$user->get_reply->add_attr('Session-Timeout', $session_timeout)
	    if defined $session_timeout;

	# If the config has defined how to handle the columns
	# in the AuthSelect statement with AuthColumnDef, use
	# that to extraxt check and reply items from @extras	
	$self->getAuthColumns($user, $p, @extras)
	    if defined $self->{AuthColumnDef};

	my ($attr_id, $vendor_id, $vendor_type,
	    $attr_name, $attr_data, $attr_value, $attr_type, 
	    $radcheck, $attr_list);
	# Now get any radius attributes from the Emerald database for this
	# account ID and account type
	$q = &Radius::Util::format_special
	    ($self->{RadUserQuery}, $p, undef, $account_id);
	$sth = $self->prepareAndExecute($q);
	return undef unless $sth;
	my $got_configs; # Dont get AT Configs if there are per-user

	# Modification by Andrew Ruthven - 1999/02/20
	# This will allow us to specify default settings and then have
	# user specific settings over ride them.
	my (@set_configs, @attrDetails);
	while (($attr_id, $vendor_id, $vendor_type, $attr_data, $attr_value, $attr_type, $radcheck)
	       = $sth->fetchrow())
	{
	    # Modification by Andrew Ruthven - 1999/02/20
            # Added the test on 1999/02/27
	    defined $self->{AddATDefaults}
		    ? $set_configs[$attr_id]++ : $got_configs++;

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
	    
	    $attr_list = $radcheck 
		? $user->get_check()
		    : $user->get_reply();
	    
	    # Integer or string?
	    $attr_list->add_attr($attrDetails[0], 
				 $attr_type == 1 
				 ? int $attr_value : $attr_data);

	}

	# We only get the Account Type configs if there were no per
	# user configs, or if AddATDefaults is set
	if (!$got_configs)
	{
	    $q = &Radius::Util::format_special
		($self->{RadAccountQuery}, $p, undef, $account_type);
	    $sth = $self->prepareAndExecute($q);
	    return undef unless $sth;

	    while (($attr_id, $vendor_id, $vendor_type, $attr_data, $attr_value, $attr_type, $radcheck)
		   = $sth->fetchrow())
	    {
		# Modification by Andrew Ruthven - 1999/02/20
		next if $set_configs[$attr_id];

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
		
		$attr_list = $radcheck 
		    ? $user->get_check()
			: $user->get_reply();

		# Integer or string?
		$attr_list->add_attr($attrDetails[0], 
				     $attr_type == 1 
				     ? int $attr_value : $attr_data);
	    }
	}
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
    my $sth = $self->prepareAndExecute($q);
    return unless $sth;
    my @row;

    # Loop through the rows, creating a new Client from each one
    while (@row = $sth->fetchrow()) 
    {
	my $client = Radius::Client->new(undef, $row[0],
					 Secret => $row[1]);
	$client->{SNMPCommunity} = $row[2] if defined $row[2];
	$client->activate();
	$self->log($main::LOG_DEBUG, "Added Client $row[0]");
    }
    $sth->finish();
}

#####################################################################
# Look at the 
sub createRoam
{
    my ($self) = @_;

    require Radius::AuthRADIUS;
    
    my $q = &Radius::Util::format_special($self->{RoamServerQuery});
    my $sth = $self->prepareAndExecute($q);
    return unless $sth;
    my @row;

    # Loop through the rows, creating a new AuthBy RADIUS from each one
    # Each with an Identifier, so we can set up a REalm referring
    # to it later
    while (@row = $sth->fetchrow()) 
    {
	next if $row[1] eq 'None';
	my $forwarder = Radius::AuthRADIUS->new
	    (undef, undef,
	     'Identifier' => $row[0],
	     'Secret'     => $row[2],
	     'Timeout'    => $row[3],
	     'Retries'    => $row[4],
	     'AuthPort'   => $row[5],
	     'AcctPort'   => $row[6]);
	$forwarder->addHosts($row[1]);
	$forwarder->activate();
	$self->log($main::LOG_DEBUG, "Added AuthBy RADIUS for $row[0]: $row[1]");
    }

    $q = &Radius::Util::format_special($self->{RoamRealmQuery});
    $sth = $self->prepareAndExecute($q);
    return unless $sth;

    # Loop through the rows, creating a new Realm from each one
    # referring to the Identifier of the AuthBy RADIUS we created above
    while (@row = $sth->fetchrow()) 
    {
	my $realm = Radius::Realm->new(undef, $row[0]);
	$realm->findAndUse('AuthBy', $row[1]);
	if ($row[2])
	{
	    # Add a RewriteUsername to strip the domain
	    push(@{$realm->{RewriteUsername}}, 's/^([^@]+).*/$1/');
	}
	$realm->activate();
	$self->log($main::LOG_DEBUG, "Added Realm for $row[1]");
    }
}

1;
