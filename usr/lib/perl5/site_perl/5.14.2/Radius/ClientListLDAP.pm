# ClientListLDAP.pm
#
# Implement a Client list in an LDAP database
# Having the Client database externally allows us to administer
# the Client list from something like RAdmin and/or Nets
#
# The default key for the LDAP table is Nas-IP-Address
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: ClientListLDAP.pm,v 1.19 2014/10/06 13:18:53 hvn Exp $

package Radius::ClientListLDAP;
@ISA = qw(Radius::Ldap);
use Radius::Ldap;
use Radius::Client;
use strict;

%Radius::ClientListLDAP::ConfigKeywords = 
('Client'          => 
 ['objectlist', 'List of hardwaired fallback Client clauses, which will be checked if there is no appropriate LDAP entry', 1],

 'ClientAttrDef'   => 
 ['stringhash', 'This optional parameter specifies the name of an LDAP attribute to fetch, and the name of the Client parameter that it will be used for in the Client clause. The format is:<p><code><pre>ldapattrname,clientparamname</pre></code>', 1],

 'RefreshPeriod'   => 
 ['integer', 'If this optional parameter is set to non-zero, it specifies the time period in seconds that ClientListLDAP will refresh the client list by rereading the database. If set to 0, then ClientListLDAP will only read the client list from the database at startup and on SIGHUP. Defaults to 0.', 1],

 );

# RCS version number of this module
$Radius::ClientListLDAP::VERSION = '$Revision: 1.19 $';

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
# Do per-instance default initialization. This is called after
# construction is complete
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;

    $self->{SearchFilter} = '(objectclass=oscRadiusClient)';
}

#####################################################################
sub clientCreate
{
    my ($self) = @_;

    # (Re)-connect to the database if necessary, 
    return undef unless $self->reconnect;

    my $authdn = &Radius::Util::format_special($self->{AuthDN});
    my $authpassword = &Radius::Util::format_special($self->{AuthPassword});
    return unless $self->bind($authdn, $authpassword);
    
    $self->log($main::LOG_DEBUG, "Adding Clients from LDAP database");

    # Default HostAttrDef are compatible with the default behaviour
    # of AuthBy LDAPRADIUS and the example LDAP schema
    %{$self->{ClientAttrDef}}  = 
	(oscRadiusClientName                     => 'Name',
	 oscRadiusSecret                         => 'Secret',
	 oscRadiusIgnoreAcctSignature            => 'IgnoreAcctSignature',
	 oscRadiusDupInterval                    => 'DupInterval',
	 oscRadiusNasType                        => 'NasType',
	 oscRadiusSNMPCommunity                  => 'SNMPCommunity',
	 oscRadiusLivingstonOffs                 => 'LivingstonOffs',
	 oscRadiusLivingstonHole                 => 'LivingstonHole',
	 oscRadiusFramedGroupBaseAddress         => 'FramedGroupBaseAddress',
	 oscRadiusFramedGroupMaxPortsPerClassC   => 'FramedGroupMaxPortsPerClassC',
	 oscRadiusFramedGroupPortOffset          => 'FramedGroupPortOffset',
	 oscRadiusRewriteUsername                => 'RewriteUsername',
	 oscRadiusUseOldAscendPasswords          => 'UseOldAscendPasswords',
	 oscRadiusStatusServerShowClientDetails  => 'StatusServerShowClientDetails',
	 oscRadiusPreHandlerHook                 => 'PreHandlerHook',
	 oscRadiusPacketTrace                    => 'PacketTrace',
	 oscRadiusIdenticalClients               => 'IdenticalClients',
	 oscRadiusNoIgnoreDuplicates             => 'NoIgnoreDuplicates',
	 oscRadiusDefaultReply                   => 'DefaultReply',
	 oscRadiusFramedGroup                    => 'FramedGroup',
	 oscRadiusStripFromReply                 => 'StripFromReply',
	 oscRadiusAllowInReply                   => 'AllowInReply',
	 oscRadiusAddToReply                     => 'AddToReply',
	 oscRadiusAddToReplyIfNotExist           => 'AddToReplyIfNotExist',
	 oscRadiusDynamicReply                   => 'DynamicReply',
	 oscRadiusStripfromRequest               => 'StripFromRequest',
	 oscRadiusAddToRequest                   => 'AddToRequest',
	 oscRadiusAddToRequestIfNotExist         => 'AddToRequestIfNotExist',
	 oscRadiusDefaultRealm                   => 'DefaultRealm',
	 oscRadiusIdentifier                     => 'Identifier')
	unless defined  $self->{ClientAttrDef};

    # The keys of ClientAttrDef are the (now translated) names of the LDAP attributes to fetch
    my @attrs = (keys %{$self->{ClientAttrDef}});
    my $filter = &Radius::Util::format_special($self->{SearchFilter});
    my $basedn = &Radius::Util::format_special($self->{BaseDN});
    $self->log($main::LOG_DEBUG, "ClientListLDAP SearchFilter: $filter, BaseDN: $basedn, attrs: @attrs");
    # We evaluate the search
    # with an alarm for the timeout period
    # pending. If the alarm goes off, the eval will die
    my $result;
    &Radius::Util::exec_timeout($self->{Timeout},
       sub {
	   $result = $self->{ld}->search
	       (base => $basedn,
		scope => $self->{Scope},
		filter => $filter,
		attrs => \@attrs);
	   
       });

    # $result is an object of type Net::LDAP::Search
    if (!$result || $result->code() != Net::LDAP::LDAP_SUCCESS)
    {
	my $code = $result ? $result->code() : -1;
	my $errname = Net::LDAP::Util::ldap_error_name($code);
	$errname = 'LDAP Timeout' if $@ && $@ =~ /timeout/;
	$self->log($main::LOG_ERR, "ClientListLDAP search failed with error $errname.");
	if ($errname eq  'LDAP_NO_SUCH_OBJECT')
	{
	    # No records there
	    $self->log($main::LOG_DEBUG, "ClientListLDAP found no client records");
	}
	elsif ($errname eq  'LDAP_PARAM_ERROR')
	{
	    # Something unpleasant in the search filter?
	    $self->log($main::LOG_ERR, "LDAP_PARAM_ERROR");
	}
	else
	{
	    # Any other error probably indicates we lost the connection to 
	    # the database. Make sure we try to reconnect again later.
	    $self->log($main::LOG_ERR, "Disconnecting from LDAP server (server $self->{Host}:$self->{Port}).");
	}
	$self->close_connection();
	return;
    }

    my $entry;
    foreach $entry ($result->entries())
    {
	my $dn = $entry->dn;
	$self->log($main::LOG_DEBUG, "ClientListLDAP got result for $dn");
	
	my ($attr, $clientname, %args);
	foreach $attr ($entry->attributes())
	{
	    # This should work for ldap-perl before and after 0.20
	    # vals is now a reference to an array
	    my $vals = $entry->get($attr);

	    # Some LDAP servers (MS) leave trailing NULs
	    map s/\0$//, @$vals;

	    $self->log($main::LOG_DEBUG, "ClientListLDAP got $attr: @$vals");

	    my $attrib = ${$self->{ClientAttrDef}}{$attr}; # The config parameters for the Client object
	    if ($attrib eq 'Name') 
	    {
		$clientname = $$vals[0];
	    }
	    elsif (   $attrib eq 'FramedGroupBaseAddress'
		   || $attrib eq 'IdenticalClients'
		   || $attrib eq 'RewriteUsername'
		   || $attrib eq 'DynamicReply')
	    {
		# stringarray types
		$args{$attrib} = [@$vals];
	    }
	    elsif ($attrib eq 'NoIgnoreDuplicates')
	    {
		# counthash types
		%{$args{NoIgnoreDuplicates}} = map(($_, 1), @$vals);
	    }
	    else
	    {
		# First value only is used if multi-valued
		$args{$attrib} = $$vals[0];
	    }
	}
	next if $clientname eq ''; # No LDAP parameter mapped to Client name

	# Rememebr which client list added this one, so we can remove
	# only Clients from this ClientList when we refresh
	$args{ClientListSource} = scalar $self;

	# Make sure any hooks get compiled
	my $c = Radius::Client->new(undef, $clientname, %args);
	$c->set('PreHandlerHook', $self->file_substitution($args{PreHandlerHook})) if defined $args{PreHandlerHook};
	$c->set('ClientHook', $self->file_substitution($args{ClientHook})) if defined $args{ClientHook};
	$c->check_config();
	$c->activate();
	# Add to the main list of clients, so we can see them in Radar etc
	push(@{$main::config->{Client}}, $c);
    }
    $self->close_connection();
    return 1;
}

#####################################################################
# Every RefreshPeriod this handler runs to reread the client list
sub refresh_timeout
{
    my ($handle, $self) = @_;

    $self->log($main::LOG_DEBUG, 'ClientListLDAP automatic refresh');

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
		$self->log($main::LOG_DEBUG, "ClientListLDAP removes previously added Client $client->{Name}");
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
	
    if ($self->clientCreate()) 
    {
	$self->log($main::LOG_DEBUG, 'Automatic ClientListLDAP refresh has succeeded, using new Client list');
    } 
    else 
    {
	$self->log($main::LOG_ERR, 'Automatic ClientListLDAP refresh failed, keeping old list');
	# Restore old lists
	@{$main::config->{Client}} = @old_main_clients;
	%Radius::Client::clients = %old_radius_clients;
    }

    # Schedule the timeout again
    &Radius::Select::add_timeout(time + $self->{RefreshPeriod}, \&refresh_timeout, $self) ;
}

1;
