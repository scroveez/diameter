# ClientListSQL.pm
#
# Implement a Client list in an SQL database
# Having the Client database externally allows us to administer
# the Client list from something like RAdmin and/or Nets
#
# The default key for the SQL table is Nas-IP-Address
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: ClientListSQL.pm,v 1.38 2014/10/06 13:18:53 hvn Exp $

package Radius::ClientListSQL;
@ISA = qw(Radius::SqlDb);
use Radius::SqlDb;
use Radius::Client;
use strict;

%Radius::ClientListSQL::ConfigKeywords = 
('GetClientQuery' => 
 ['string', 'This parameter specifies the SQL query that will be used to fetch client details from the SQL database specified by DBSource. The database can store all the same parameters that are used to configure a <Client> clause. See the Radiator Reference manual for more details', 1],

 'Client'          => 
 ['objectlist', 'List of hardwaired fallback Client clauses, which will be checked if there is no appropriate SQL entry', 1],

 'RefreshPeriod'   => 
 ['integer', 'If this optional parameter is set to non-zero, it specifies the time period in seconds that ClientListSQL will refresh the client list by rereading the database. If set to 0, then ClientListSQL will only read the client list from the database at startup and on SIGHUP. Defaults to 0.', 1],
 );

# RCS version number of this module
$Radius::ClientListSQL::VERSION = '$Revision: 1.38 $';

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    $self->SUPER::check_config();
    return;
}

#####################################################################
# Contruct a new Client list database handler
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();

    $self->clientCreate();

    # Set the first timeout ready to go
    &Radius::Select::add_timeout(time + $self->{RefreshPeriod}, \&refresh_timeout, $self) 
	if $self->{RefreshPeriod};
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

    $self->SUPER::initialize();

    $self->{GetClientQuery} = "select 
	NASIDENTIFIER,
	SECRET,
	IGNOREACCTSIGNATURE,
	DUPINTERVAL,
	DEFAULTREALM,
	NASTYPE,
	SNMPCOMMUNITY,
	LIVINGSTONOFFS,
	LIVINGSTONHOLE,
	FRAMEDGROUPBASEADDRESS,
	FRAMEDGROUPMAXPORTSPERCLASSC,
	REWRITEUSERNAME,
	NOIGNOREDUPLICATES,
	PREHANDLERHOOK from RADCLIENTLIST";
}

#####################################################################
sub clientCreate
{
    my ($self) = @_;

    # (Re)-connect to the database if necessary, 
    return undef unless $self->reconnect;

    $self->log($main::LOG_DEBUG, "Adding Clients from SQL database");

    # Re-format query from config file
    my $q = &Radius::Util::format_special($self->{GetClientQuery}, undef, $self);

    # Execute the query
    my $sth = $self->prepareAndExecute($q);
    return unless $sth;

    my @row;
    # Loop through the rows, creating a new Client from each one
    while (@row = $sth->fetchrow()) 
    {
	my $client = Radius::Client->new(undef, $row[0], Secret => $row[1]);
	$client->{IgnoreAcctSignature} = $row[2] if defined $row[2];
	$client->{DupInterval} = $row[3] if defined $row[3];
	$client->{DefaultRealm} = $row[4] if defined $row[4];
	$client->{NasType} = $row[5] if defined $row[5];
	$client->{SNMPCommunity} = $row[6] if defined $row[6];
	$client->{LivingstonOffs} = $row[7] if defined $row[7];
	$client->{LivingstoneHole} = $row[8] if defined $row[8];
	push @{$client->{FramedGroupBaseAddress}}, split(/[,\s]+/, $row[9]) if defined $row[9];
	$client->{FramedGroupMaxPortsPerClassC} = $row[10] if defined $row[10];
	push @{$client->{RewriteUsername}}, $row[11] if defined $row[11];
 
	%{$client->{NoIgnoreDuplicates}} = map(($_, 1), split(/\s+/, $row[12]))
	    if defined $row[12];

	$client->set('PreHandlerHook', $self->file_substitution($row[13])) 
	    if defined $row[13]; # Make sure it gets compiled
	$client->{Identifier}     = $row[14] if defined $row[14];
	$client->{DefaultReply}   = $row[15] if defined $row[15];
	$client->{FramedGroup}    = $row[16] if defined $row[16];
	$client->{StripFromReply} = $row[17] if defined $row[17];
	$client->{AllowInReply}   = $row[18] if defined $row[18];
	$client->{AddToReply}     = $row[19] if defined $row[19];
	$client->{AddToReplyIfNotExist} = $row[20] if defined $row[20];
	$client->{DynamicReply}   = $row[21] if defined $row[21];
	$client->{AddToRequest}   = $row[22] if defined $row[22];
	$client->{StripFromRequest}   = $row[23] if defined $row[23];
	$client->{AddToRequestIfNotExist}   = $row[24] if defined $row[24];
	$client->set('ClientHook', $self->file_substitution($row[25])) 
	    if defined $row[25]; # Make sure it gets compiled
	$client->{UseContentsForDuplicateDetection}   = $row[26] if defined $row[26];

	# Contributed by "Tony B" <tonyb@go-concepts.com>
	# Last row can be a comma separated list of flag names
	map $client->{$_}++, split(/,/, $row[27]);

	# Rememebr which client list added this one, so we can remove
	# only Clients from this ClientList when we refresh
	$client->{ClientListSource} = scalar $self;

	$self->log($main::LOG_DEBUG, "ClientListSQL adds Client $row[0]");

	# Add to the main list of clients, so we can see them in Radar etc
	push(@{$main::config->{Client}}, $client);
	$client->check_config();
	$client->activate();
    }

    my $ret = 1;
    # Check that we did not get an empty list because of an error
    if ($sth->err) 
    {
	$self->log($main::LOG_ERR, 'ClientListSQL got error from SQL: ' . $DBI::errstr);
	$ret = 0;
    }

    $sth->finish(); 
    $self->disconnect() if $self->{DisconnectAfterQuery};
    return $ret;
}

#####################################################################
# Every RefreshPeriod this handler runs to reread the client list
sub refresh_timeout
{
    my ($handle, $self) = @_;

    $self->log($main::LOG_DEBUG, 'ClientListSQL automatic refresh');

    my @old_main_clients;
    my %old_radius_clients;
    # Can get crashes if no clients defined
    if ($main::config->{Client})
    {
	# Save the old client lists, in case we have to back out after a databse failure.
	@old_main_clients = @{$main::config->{Client}};
	%old_radius_clients = %Radius::Client::clients;

	# Remove any clients that this instance previously created from both the $main::config->{Client} list
	# and the %Radius::Client::clients hash
	my $i;
	for ($i = 0; $i < scalar @{$main::config->{Client}}; $i++)
	{
	    my $client = $main::config->{Client}->[$i];
	    if ($client->{ClientListSource} eq scalar $self)
	    {
		$self->log($main::LOG_DEBUG, "ClientListSQL removes previously added Client $client->{Name}");
		# Make sure any reference loops get broken else the Client may not get destroyed
		$client->{DupCache} = {};
		$client->{DupCacheOrder} = [];
		splice(@{$main::config->{Client}}, $i--, 1);
	    }
	}
	foreach (keys %Radius::Client::clients)
	{
	    delete $Radius::Client::clients{$_} if $Radius::Client::clients{$_}->{ClientListSource} eq scalar $self;
	}
    }

    # Reread the clients
    if ($self->clientCreate()) 
    {
	$self->log($main::LOG_DEBUG, 'Automatic ClientListSQL refresh has succeeded, using new Client list');
    } 
    else 
    {
	$self->log($main::LOG_ERR, 'Automatic ClientListSQL refresh failed, keeping old list');
	# Restore old lists
	@{$main::config->{Client}} = @old_main_clients;
	%Radius::Client::clients = %old_radius_clients;
    }

    # Schedule the timeout again
    &Radius::Select::add_timeout(time + $self->{RefreshPeriod}, \&refresh_timeout, $self) ;
}

1;
