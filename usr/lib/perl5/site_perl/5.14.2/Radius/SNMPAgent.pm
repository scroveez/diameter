# SNMPAgent.pm
#
# Object for handling SNMP requests as per draft-ietf-radius-servmib-04.txt
# and RFC2619 and RFC2621
# updated for RFC4669 and RFC4671
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997-2011 Open System Consultants
# $Id: SNMPAgent.pm,v 1.39 2014/08/04 15:19:28 hvn Exp $

package Radius::SNMPAgent;
@ISA = qw(Radius::Configurable);
use strict;
use Radius::Mib;
use Radius::Util;
use Radius::Radius;
use Radius::Configurable;
use Radius::Select;
use SNMP_util;
use Socket;

%Radius::SNMPAgent::ConfigKeywords = 
('Port'         => 
 ['string', 'This optional parameter specifies the UDP port number that the SNMP Agent is to listen on. It defaults to 161. There should only rarely be any reason to change it. The argument may be either a numeric port number or an alphanumeric service name as specified in /etc/services (or its moral equivalent on your system). Port may contain special formatting characters. A typical use of special formatting characters is with GlobalVar and command line arguments.', 1],

 'BindAddress'  => 
 ['string', 'This optional parameter specifies a single host address to listen for SNMP requests on. It is only useful if you are running Radiator on a multi-homed host (i.e. a host that has more than one network address). Defaults to the global value of BindAddress (usually 0.0.0.0 i.e. listen on all networks connected to the host, but see Section 5.4.6 on page 22). BindAddress can include special formatting characters. Requires SNMP_Session version 0.92 or greater.', 1],

 'Community'    => 
 ['string', 'Deprecated. SNMP V1 and V2c provide a weak method of authenticating SNMP requests, using the "community name". This optional parameter allows you to specify the SNMP V1 community name that will be honored by SNMPAgent. Any SNMP request that does not include the correct community name will be ignored. Defaults to nothing. We strongly recommend that you choose a community name and keep it secret.
<p>Community is now deprecated, but is still honoured for backwards compatibility. New implementations should use ROCommunity and /or RWCommunity.', 1],

 'RWCommunity'  => 
 ['string', 'This optional parameter allows you to specify the SNMP V1 or V2c community name that will be used by SNMPAgent to authenticate read-write access. Knowing this secret you are able to reset Radiator via SNMP. Defaults to nothing. If you don\'t need resetting via SNMP use only ROCommunity.', 1],

 'ROCommunity'  => 
 ['string', 'SNMP V1 and V2c provide a weak method of authenticating SNMP requests, using the "community name". This optional parameter allows you to specify the SNMP V1 or V2c community name that will be honored by SNMPAgent for read-only access. Defaults to nothing, you have to define one by yourself.<p>
We strongly recommend that you choose a community name and keep it secret.', 1],

 'SNMPVersion'  => 
 ['string', 'This optional parameter allows you to specify the SNMP version the agent uses. Currently supported versions are 1 and 2c. Defaults to 1.', 1],

 'Managers'     => 
 ['splitstringarray', 'This optional parameter specifies a list of SNMP managers that have access to SNMPAgent. The value is a list of host names or addresses, separated by white space or comma. You can have any number of Managers lines. Defaults to nothing with all hosts allowed.', 1],

 );

# RCS version number of this module
$Radius::SNMPAgent::VERSION = '$Revision: 1.39 $';

# The one and only agent in this instance
$Radius::SNMPAgent::agent = undef;

# OID describing this system for sysObjectID
# 1.3.6.1.4.1.9048.1.1 is allocated by OSC to Radiator
@Radius::SNMPAgent::sysObjectID = qw(1 3 6 1 4 1 9048 1 1);

# Make sure we get reinitialized on sighup
push(@main::reinitFns, \&reinitialize);

# OIDs for objects in the radius server MIB
# This is a convenience so we can refer to OIDs by name
my %OIDS = 
(
 # These are a subset of SNMP MIB 2
 'sysDescr'                             => '1.3.6.1.2.1.1.1.0',
 'sysObjectID'                          => '1.3.6.1.2.1.1.2.0',

 'sysUpTime'                            => '1.3.6.1.2.1.1.3.0',
 'sysName'                              => '1.3.6.1.2.1.1.5.0',

 # These are the ones from draft-ietf-radius-servmib-04.txt
 'radiusServIdent'                      => '1.3.6.1.3.79.1.1.1.1',
 'radiusServUpTime'                     => '1.3.6.1.3.79.1.1.1.2',
 'radiusServResetTime'                  => '1.3.6.1.3.79.1.1.1.3',
 'radiusServConfigReset'                => '1.3.6.1.3.79.1.1.1.4',
 'radiusServInvalidClientAddresses'     => '1.3.6.1.3.79.1.1.1.5',
 'radiusClientIndex'                    => '1.3.6.1.3.79.1.1.1.6.1.1',
 'radiusClientAddress'                  => '1.3.6.1.3.79.1.1.1.6.1.2',
 'radiusClientID'                       => '1.3.6.1.3.79.1.1.1.6.1.3',
 'radiusServAccessRequests'             => '1.3.6.1.3.79.1.1.1.6.1.4',
 'radiusServDupAccessRequests'          => '1.3.6.1.3.79.1.1.1.6.1.5',
 'radiusServAccessAccepts'              => '1.3.6.1.3.79.1.1.1.6.1.6',
 'radiusServAccessRejects'              => '1.3.6.1.3.79.1.1.1.6.1.7',
 'radiusServAccessChallenges'           => '1.3.6.1.3.79.1.1.1.6.1.8',
 'radiusServMalformedAccessRequests'    => '1.3.6.1.3.79.1.1.1.6.1.9',
 'radiusServAuthenticationBadAuthenticators' => '1.3.6.1.3.79.1.1.1.6.1.10',
 'radiusServPacketsDropped'             => '1.3.6.1.3.79.1.1.1.6.1.11',
 'radiusServAccountingRequests'         => '1.3.6.1.3.79.1.1.1.6.1.12',
 'radiusServDupAccountingRequests'      => '1.3.6.1.3.79.1.1.1.6.1.13',
 'radiusServAccountingResponses'        => '1.3.6.1.3.79.1.1.1.6.1.14',
 'radiusServAccountingBadAuthenticators' => '1.3.6.1.3.79.1.1.1.6.1.15',
 'radiusServMalformedAccountingRequests' => '1.3.6.1.3.79.1.1.1.6.1.16',
 'radiusServAccountingNoRecord'         => '1.3.6.1.3.79.1.1.1.6.1.17',
 'radiusServUnknownType'                => '1.3.6.1.3.79.1.1.1.6.1.18',
 
 # These are the new ones from RFC 2619
 'radiusAuthServIdent'                  => '1.3.6.1.2.1.67.1.1.1.1.1',
 'radiusAuthServUpTime'                 => '1.3.6.1.2.1.67.1.1.1.1.2',
 'radiusAuthServResetTime'              => '1.3.6.1.2.1.67.1.1.1.1.3',
 'radiusAuthServConfigReset'            => '1.3.6.1.2.1.67.1.1.1.1.4',
 'radiusAuthServTotalAccessRequests'    => '1.3.6.1.2.1.67.1.1.1.1.5',
 'radiusAuthServTotalInvalidRequests'   => '1.3.6.1.2.1.67.1.1.1.1.6',
 'radiusAuthServTotalDupAccessRequests' => '1.3.6.1.2.1.67.1.1.1.1.7',
 'radiusAuthServTotalAccessAccepts'     => '1.3.6.1.2.1.67.1.1.1.1.8',
 'radiusAuthServTotalAccessRejects'     => '1.3.6.1.2.1.67.1.1.1.1.9',
 'radiusAuthServTotalAccessChallenges'  => '1.3.6.1.2.1.67.1.1.1.1.10',
 'radiusAuthServTotalMalformedAccessRequests' => '1.3.6.1.2.1.67.1.1.1.1.11',
 'radiusAuthServTotalBadAuthenticators' => '1.3.6.1.2.1.67.1.1.1.1.12',
 'radiusAuthServTotalPacketsDropped'    => '1.3.6.1.2.1.67.1.1.1.1.13',
 'radiusAuthServTotalUnknownTypes'      => '1.3.6.1.2.1.67.1.1.1.1.14',
 'radiusAuthClientIndex'                => '1.3.6.1.2.1.67.1.1.1.1.15.1.1',
 'radiusAuthClientAddress'              => '1.3.6.1.2.1.67.1.1.1.1.15.1.2',
 'radiusAuthClientID'                   => '1.3.6.1.2.1.67.1.1.1.1.15.1.3',
 'radiusAuthServAccessRequests'         => '1.3.6.1.2.1.67.1.1.1.1.15.1.4',
 'radiusAuthServDupAccessRequests'      => '1.3.6.1.2.1.67.1.1.1.1.15.1.5',
 'radiusAuthServAccessAccepts'          => '1.3.6.1.2.1.67.1.1.1.1.15.1.6',
 'radiusAuthServAccessRejects'          => '1.3.6.1.2.1.67.1.1.1.1.15.1.7',
 'radiusAuthServAccessChallenges'       => '1.3.6.1.2.1.67.1.1.1.1.15.1.8',
 'radiusAuthServMalformedAccessRequests' => '1.3.6.1.2.1.67.1.1.1.1.15.1.9',
 'radiusAuthServBadAuthenticators'      => '1.3.6.1.2.1.67.1.1.1.1.15.1.10',
 'radiusAuthServPacketsDropped'         => '1.3.6.1.2.1.67.1.1.1.1.15.1.11',
 'radiusAuthServUnknownTypes'           => '1.3.6.1.2.1.67.1.1.1.1.15.1.12',

 # These are the new ones from RFC 2621
 'radiusAccServIdent'                   => '1.3.6.1.2.1.67.2.1.1.1.1',
 'radiusAccServUpTime'                  => '1.3.6.1.2.1.67.2.1.1.1.2',
 'radiusAccServResetTime'               => '1.3.6.1.2.1.67.2.1.1.1.3',
 'radiusAccServConfigReset'             => '1.3.6.1.2.1.67.2.1.1.1.4',
 'radiusAccServTotalRequests'           => '1.3.6.1.2.1.67.2.1.1.1.5',
 'radiusAccServTotalInvalidRequests'    => '1.3.6.1.2.1.67.2.1.1.1.6',
 'radiusAccServTotalDupRequests'        => '1.3.6.1.2.1.67.2.1.1.1.7',
 'radiusAccServTotalResponses'          => '1.3.6.1.2.1.67.2.1.1.1.8',
 'radiusAccServTotalMalformedRequests'  => '1.3.6.1.2.1.67.2.1.1.1.9',
 'radiusAccServTotalBadAuthenticators'  => '1.3.6.1.2.1.67.2.1.1.1.10',
 'radiusAccServTotalPacketsDropped'     => '1.3.6.1.2.1.67.2.1.1.1.11',
 'radiusAccServTotalNoRecords'          => '1.3.6.1.2.1.67.2.1.1.1.12',
 'radiusAccServTotalUnknownTypes'       => '1.3.6.1.2.1.67.2.1.1.1.13',
 'radiusAccClientIndex'                 => '1.3.6.1.2.1.67.2.1.1.1.14.1.1',
 'radiusAccClientAddress'               => '1.3.6.1.2.1.67.2.1.1.1.14.1.2',
 'radiusAccClientID'                    => '1.3.6.1.2.1.67.2.1.1.1.14.1.3',
 'radiusAccServPacketsDropped'          => '1.3.6.1.2.1.67.2.1.1.1.14.1.4',
 'radiusAccServRequests'                => '1.3.6.1.2.1.67.2.1.1.1.14.1.5',
 'radiusAccServDupRequests'             => '1.3.6.1.2.1.67.2.1.1.1.14.1.6',
 'radiusAccServResponses'               => '1.3.6.1.2.1.67.2.1.1.1.14.1.7',
 'radiusAccServBadAuthenticators'       => '1.3.6.1.2.1.67.2.1.1.1.14.1.8',
 'radiusAccServMalformedRequests'       => '1.3.6.1.2.1.67.2.1.1.1.14.1.9',
 'radiusAccServNoRecords'               => '1.3.6.1.2.1.67.2.1.1.1.14.1.10',
 'radiusAccServUnknownTypes'            => '1.3.6.1.2.1.67.2.1.1.1.14.1.11',

 # These are the new ones from RFC 4669
 'radiusAuthClientExtIndex'                 => '1.3.6.1.2.1.67.1.1.1.1.16.1.1',
 'radiusAuthClientInetAddressType'          => '1.3.6.1.2.1.67.1.1.1.1.16.1.2',
 'radiusAuthClientInetAddress'              => '1.3.6.1.2.1.67.1.1.1.1.16.1.3',
 'radiusAuthClientExtID'                    => '1.3.6.1.2.1.67.1.1.1.1.16.1.4',
 'radiusAuthServExtAccessRequests'          => '1.3.6.1.2.1.67.1.1.1.1.16.1.5',
 'radiusAuthServExtDupAccessRequests'       => '1.3.6.1.2.1.67.1.1.1.1.16.1.6',
 'radiusAuthServExtAccessAccepts'           => '1.3.6.1.2.1.67.1.1.1.1.16.1.7',
 'radiusAuthServExtAccessRejects'           => '1.3.6.1.2.1.67.1.1.1.1.16.1.8',
 'radiusAuthServExtAccessChallenges'        => '1.3.6.1.2.1.67.1.1.1.1.16.1.9',
 'radiusAuthServExtMalformedAccessRequests' => '1.3.6.1.2.1.67.1.1.1.1.16.1.10',
 'radiusAuthServExtBadAuthenticators'       => '1.3.6.1.2.1.67.1.1.1.1.16.1.11',
 'radiusAuthServExtPacketsDropped'          => '1.3.6.1.2.1.67.1.1.1.1.16.1.12',
 'radiusAuthServExtUnknownTypes'            => '1.3.6.1.2.1.67.1.1.1.1.16.1.13',
 'radiusAuthServCounterDiscontinuity'       => '1.3.6.1.2.1.67.1.1.1.1.16.1.14',

 # These are the new ones from RFC 4671
 'radiusAccClientExtIndex'                 => '1.3.6.1.2.1.67.2.1.1.1.15.1.1',
 'radiusAccClientInetAddressType'          => '1.3.6.1.2.1.67.2.1.1.1.15.1.2',
 'radiusAccClientInetAddress'              => '1.3.6.1.2.1.67.2.1.1.1.15.1.3',
 'radiusAccClientExtID'                    => '1.3.6.1.2.1.67.2.1.1.1.15.1.4',
 'radiusAccServExtPacketsDropped'          => '1.3.6.1.2.1.67.2.1.1.1.15.1.5',
 'radiusAccServExtRequests'                => '1.3.6.1.2.1.67.2.1.1.1.15.1.6',
 'radiusAccServExtDupRequests'             => '1.3.6.1.2.1.67.2.1.1.1.15.1.7',
 'radiusAccServExtResponses'               => '1.3.6.1.2.1.67.2.1.1.1.15.1.8',
 'radiusAccServExtBadAuthenticators'       => '1.3.6.1.2.1.67.2.1.1.1.15.1.9',
 'radiusAccServExtMalformedRequests'       => '1.3.6.1.2.1.67.2.1.1.1.15.1.10',
 'radiusAccServExtNoRecords'               => '1.3.6.1.2.1.67.2.1.1.1.15.1.11',
 'radiusAccServExtUnknownTypes'            => '1.3.6.1.2.1.67.2.1.1.1.15.1.12',
 'radiusAccServerCounterDiscontinuity'     => '1.3.6.1.2.1.67.2.1.1.1.15.1.13',

);


#####################################################################
# arg is the arbitrary arg passed to Mib::create. It is a reference
# to the array of the OID we are interested in
sub get_oid
{
    my ($arg, @path) = @_;
    return ($Radius::Mib::ERROR_OK, BER::encode_oid(@$arg), @path);
}

#####################################################################
# arg is the arbitrary arg passed to Mib::create. It is a reference
# to the string we are interested in
sub get_string
{
    my ($arg, @path) = @_;
    return ($Radius::Mib::ERROR_OK, BER::encode_string($$arg), @path);
}

#####################################################################
# arg is the arbitrary arg passed to Mib::create. It is a reference
# to the string we are interested in
sub get_int
{
    my ($arg, @path) = @_;
    return ($Radius::Mib::ERROR_OK, BER::encode_int(int $$arg), @path);
}

#####################################################################
# arg is the arbitrary arg passed to Mib::create. It is a reference
# to the string we are interested in
sub get_draft_uptime
{
    my ($arg, @path) = @_;
    return ($Radius::Mib::ERROR_OK, 
	  BER::encode_int(time - $main::statistics{start_time}), @path);
}

#####################################################################
# arg is the arbitrary arg passed to Mib::create. It is a reference
# to the string we are interested in
sub get_draft_resettime
{
    my ($arg, @path) = @_;
    return ($Radius::Mib::ERROR_OK, 
	  BER::encode_int(time - $main::statistics{reset_time}), @path);
}

#####################################################################
# arg is the arbitrary arg passed to Mib::create. It is a reference
# to the string we are interested in
sub get_uptime
{
    my ($arg, @path) = @_;
    return ($Radius::Mib::ERROR_OK, 
	  BER::encode_timeticks((time - $main::statistics{start_time}) * 100), @path);
}

#####################################################################
# arg is the arbitrary arg passed to Mib::create. It is a reference
# to the string we are interested in
sub get_resettime
{
    my ($arg, @path) = @_;
    return ($Radius::Mib::ERROR_OK, 
	  BER::encode_timeticks((time - $main::statistics{reset_time}) * 100), @path);
}

#####################################################################
# get_server_data_int($arg, @path)
# Get a statistic integer from the server. The name of the statistic is
# passed as $arg. 
sub get_server_data_int
{
    my ($arg, @path) = @_;

    return ($Radius::Mib::ERROR_OK, 
	  BER::encode_int($main::config->{Statistics}{$arg}));
}

#####################################################################
# get_server_data_coutner32($arg, @path)
# Get a statistic coutner32 from the server. The name of the statistic is
# passed as $arg. 
sub get_server_data_counter32
{
    my ($arg, @path) = @_;

    return ($Radius::Mib::ERROR_OK, 
	  BER::encode_counter32($main::config->{Statistics}{$arg}));
}

#####################################################################
# get_client_data($arg, @path)
# Get a statistic from a Client. The name of the statistic is
# passed as $arg. The first element of @path will be the index
# of the client we are interested in. Its a bt cavalier about looking
# inside the Client structure.
sub get_client_data
{
    my ($arg, @path) = @_;

    my $index = shift(@path); # 1 based

    # A RadSec configuration e.g., may not have Clients. Prevent
    # Client autovivification.
    return ($Radius::Mib::ERROR_NOSUCHNAME, undef, ($index))
	if !defined $main::config->{Client};

    # We may be falling off the end during walk or someone is asking
    # for an invalid index
    return ($Radius::Mib::ERROR_NOSUCHNAME, undef, ($index))
	if !defined $main::config->{Client}[$index-1];

    my $client = $main::config->{Client}[$index-1];
    if ($arg eq 'radiusClientIndex')
    {
	return ($Radius::Mib::ERROR_OK, 
	    BER::encode_int($index), 
	    ($index));
    }
    elsif ($arg eq 'radiusClientAddress')
    {
	if (length($client->{Host}) == 4)
	{
	    return ($Radius::Mib::ERROR_OK, 
		    BER::encode_ip_address($client->{Host}), 
		    ($index));
	}
	else
	{
	    return ($Radius::Mib::ERROR_BADVALUE, 
		    BER::encode_int($arg), @path);
	}
    }
    elsif ($arg eq 'radiusClientID')
    {
	return ($Radius::Mib::ERROR_OK, 
	    BER::encode_string($client->{Name}), 
	    ($index));
    }
    else
    {
	# Its an integer in the Statistics structure
	return ($Radius::Mib::ERROR_OK, 
	      BER::encode_counter32($client->{Statistics}{$arg}), 
		($index));
    }
}

# BER does not have this
sub encode_ipv6_address ($) {
    my ($addr)=@_;
    my @octets;

    if (length $addr == 16) {
      ## Four bytes... let's suppose that this is a binary IP address
      ## in network byte order.
      return BER::encode_string($addr);
    } else {
      return BER::error ("IP address must be four bytes long or a dotted-quad");
    }
}

#####################################################################
# get_client_data($arg, @path)
# Get a statistic from a Client. The name of the statistic is
# passed as $arg. The first element of @path will be the index
# of the client we are interested in. Its a bt cavalier about looking
# inside the Client structure.
sub get_clientext_data
{
    my ($arg, @path) = @_;

    my $index = shift(@path); # 1 based

    # A RadSec configuration e.g., may not have Clients. Prevent
    # Client autovivification.
    return ($Radius::Mib::ERROR_NOSUCHNAME, undef, ($index))
	if !defined $main::config->{Client};

    # We may be falling off the end during walk or someone is asking
    # for an invalid index
    return ($Radius::Mib::ERROR_NOSUCHNAME, undef, ($index))
	if !defined $main::config->{Client}[$index-1];

    my $client = $main::config->{Client}[$index-1];
    if ($arg eq 'radiusClientIndex')
    {
	return ($Radius::Mib::ERROR_OK, 
	    BER::encode_int($index), 
	    ($index));
    }
    elsif ($arg eq 'radiusClientInetAddressType')
    {
	if (length($client->{Host}) == 4)
	{
	    return ($Radius::Mib::ERROR_OK, 
		    BER::encode_int(1), 
		    ($index));
	}
	else
	{
	    return ($Radius::Mib::ERROR_OK, 
		    BER::encode_int(2), 
		    ($index));
	}
    }
    elsif ($arg eq 'radiusClientInetAddress')
    {
	return ($Radius::Mib::ERROR_OK, 
		BER::encode_string($client->{Host}), 
		($index));
    }
    elsif ($arg eq 'radiusClientID')
    {
	return ($Radius::Mib::ERROR_OK, 
	    BER::encode_string($client->{Name}), 
	    ($index));
    }
    else
    {
	# Its an integer in the Statistics structure
	return ($Radius::Mib::ERROR_OK, 
	      BER::encode_counter32($client->{Statistics}{$arg}), 
		($index));
    }
}

#####################################################################
# getnext_client
# getnext routine for all Client statistics nodes.
sub getnext_client_data
{
    my ($arg, @path) = @_;

    my $index = shift(@path); # 1 based

    # Note the increment of $index
    return get_client_data($arg, ($index+1));
}

#####################################################################
# getnext_clientext
# getnext routine for all Client statistics nodes.
sub getnext_clientext_data
{
    my ($arg, @path) = @_;

    my $index = shift(@path); # 1 based

    # Note the increment of $index
    return get_clientext_data($arg, ($index+1));
}

#####################################################################
# create_client_data
# Create a new leaf node in the MIB that will return an integer
# from a Client Statistics 
# $targetname is the name of the Client attribute to get
# $name is the name of the OID in  %OIDS above
# if $targetname  is nort defined, its the same as $name
sub create_client_data
{
    my ($self, $name, $targetname) = @_;

    $targetname = $name unless defined $targetname;

    $self->log($main::LOG_ERR, "No definition for SNMPAgent OID $name")
	unless exists $OIDS{$name};
    
    $self->{mib}->createPretty([\&get_client_data, 
				\&getnext_client_data, 
				undef, 
				$targetname], 
			       $OIDS{$name});
}

#####################################################################
# create_clientext_data
# For RFC 4669 and RFC 4671
# Create a new leaf node in the MIB that will return an integer
# from a Client Statistics 
# $targetname is the name of the Client attribute to get
# $name is the name of the OID in  %OIDS above
# if $targetname  is nort defined, its the same as $name
sub create_clientext_data
{
    my ($self, $name, $targetname) = @_;

    $targetname = $name unless defined $targetname;

    $self->log($main::LOG_ERR, "No definition for SNMPAgent OID $name")
	unless exists $OIDS{$name};
    
    $self->{mib}->createPretty([\&get_clientext_data, 
				\&getnext_clientext_data, 
				undef, 
				$targetname], 
			       $OIDS{$name});
}

#####################################################################
# create_server_statistic
# Create a new leaf node in the MIB that will return an integer
# from $main::config->{Statistics}->{targetname}
# $targetname is the name of the statistic to get
# $name is the name of the OID in  %OIDS above
# if $targetname  is not defined, its the same as $name
sub create_server_statistic_int
{
    my ($self, $name, $targetname) = @_;

    $targetname = $name unless defined $targetname;

    $self->log($main::LOG_ERR, "No definition for SNMPAgent OID $name")
	unless exists $OIDS{$name};
    
    $self->{mib}->createPretty([\&get_server_data_int, 
				undef, 
				undef, 
				$targetname], 
			       $OIDS{$name});
}

#####################################################################
# create_server_statistic_counter32
# Create a new leaf node in the MIB that will return an counter32
# from $main::config->{Statistics}->{targetname}
# $targetname is the name of the statistic to get
# $name is the name of the OID in  %OIDS above
# if $targetname  is not defined, its the same as $name
sub create_server_statistic_counter32
{
    my ($self, $name, $targetname) = @_;

    $targetname = $name unless defined $targetname;

    $self->log($main::LOG_ERR, "No definition for SNMPAgent OID $name")
	unless exists $OIDS{$name};
    
    $self->{mib}->createPretty([\&get_server_data_counter32, 
				undef, 
				undef, 
				$targetname], 
			       $OIDS{$name});
}

#####################################################################
sub set_config_state
{
    my ($arg, $value, @path) = @_;

    ($value) = BER::decode_int($value);
    if ($value == 2)
    {
	&main::request_reset();
	return ($Radius::Mib::ERROR_OK, 
	      BER::encode_int($value), @path);
    }
    else
    {
	return ($Radius::Mib::ERROR_BADVALUE, 
	      BER::encode_int($$arg), @path);
    }
}

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    if ($self->{Community}) # backwards compatibiliity
    {
	$self->log($main::LOG_WARNING,
	   "SNMPAgent: old Community configured, please use new ROCommunity/RWCommunity");
	$self->{ROCommunity} = $self->{Community}
	    unless $self->{ROCommunity};
	$self->{RWCommunity} = $self->{Community}
	    unless $self->{RWCommunity};
    }

    $self->log($main::LOG_ERR, "SNMPAgent: no community defined")
	unless    defined $self->{ROCommunity}
               || defined $self->{RWCommunity};

    $self->SUPER::check_config();
    return;
}

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();

    undef $self->{managerAddresses};
    if (defined($self->{Managers}))
    {
	my $i;
	for ($i = 0; $i <= $#{$self->{Managers}}; $i++)
	{
	    my $manager = ${$self->{Managers}}[$i];
	    ${$self->{managerAddresses}}[$i] = Radius::Util::inet_pton($manager) or
		$self->log($main::LOG_ERR,
			   "SNMPAgent: Could not resolve an address for Manager '$manager'");
	}
    }
   
    # This holds our MIB tree
    $self->{mib} = new Radius::Mib;

    # REVISIT: populate the tree
    # These are for MIB2
    $self->{mib}->createPretty([\&get_string, undef, undef, \$main::ident], 
			 $OIDS{sysDescr});
    $self->{mib}->createPretty([\&get_oid, undef, undef, \@Radius::SNMPAgent::sysObjectID],
			 $OIDS{sysObjectID});
    $self->{mib}->createPretty([\&get_string, undef, undef, \$main::hostname], 
			 $OIDS{sysName});
    $self->{mib}->createPretty([\&get_uptime, undef, undef], 
			 $OIDS{sysUpTime});

    # These are leaf nodes, and so there is no getnext function
    # These ones from draft-ietf-radius-servmib-04.txt
    $self->{mib}->createPretty([\&get_string, undef, undef, \$main::ident], 
			 $OIDS{radiusServIdent});
    $self->{mib}->createPretty([\&get_draft_uptime, undef, undef], 
			 $OIDS{radiusServUpTime});
    $self->{mib}->createPretty([\&get_draft_resettime, undef, undef], 
			 $OIDS{radiusServResetTime});
    $self->{mib}->createPretty([\&get_int, undef, \&set_config_state, 
				\$main::config_state], 
			       $OIDS{radiusServConfigReset});
    $self->create_server_statistic_int('radiusServInvalidClientAddresses',
                                   'invalidClientAddresses');
    # Now add nodes for the integers in the Client Statistics
    $self->create_client_data('radiusClientIndex');
    $self->create_client_data('radiusClientAddress');
    $self->create_client_data('radiusClientID');
    $self->create_client_data('radiusServAccessRequests', 'accessRequests');
    $self->create_client_data('radiusServDupAccessRequests', 'dupAccessRequests');
    $self->create_client_data('radiusServAccessAccepts', 'accessAccepts');
    $self->create_client_data('radiusServAccessRejects', 'accessRejects');
    $self->create_client_data('radiusServAccessChallenges', 
                              'accessChallenges');
    $self->create_client_data('radiusServMalformedAccessRequests', 
                              'malformedAccessRequests');
    $self->create_client_data('radiusServAuthenticationBadAuthenticators',
                              'badAuthAccessRequests');
    $self->create_client_data('radiusServPacketsDropped', 'droppedRequests');
    $self->create_client_data('radiusServAccountingRequests', 
                              'accountingRequests');
    $self->create_client_data('radiusServDupAccountingRequests', 
                              'dupAccountingRequests');
    $self->create_client_data('radiusServAccountingResponses', 
                              'accountingResponses');
    $self->create_client_data('radiusServAccountingBadAuthenticators', 
                              'badAuthAccountingRequests');
    $self->create_client_data('radiusServMalformedAccountingRequests',
                              'malformedAccountingRequests');
    $self->create_client_data('radiusServAccountingNoRecord', 'noRecord');
    $self->create_client_data('radiusServUnknownType', 'unknownType');

    # These ones from RFC 2619 (Auth Radius Server MIB)
    $self->{mib}->createPretty([\&get_string, undef, undef, \$main::ident], 
			 $OIDS{radiusAuthServIdent});
    $self->{mib}->createPretty([\&get_uptime, undef, undef], 
			 $OIDS{radiusAuthServUpTime});
    $self->{mib}->createPretty([\&get_resettime, undef, undef], 
			 $OIDS{radiusAuthServResetTime});
    $self->{mib}->createPretty([\&get_int, undef, \&set_config_state, 
				\$main::config_state], 
			       $OIDS{radiusAuthServConfigReset});

    $self->create_server_statistic_counter32('radiusAuthServTotalAccessRequests',
                                   'accessRequests');
    $self->create_server_statistic_counter32('radiusAuthServTotalInvalidRequests',
                                   'invalidClientAddresses');
    $self->create_server_statistic_counter32('radiusAuthServTotalDupAccessRequests',
                                   'dupAccessRequests');
    $self->create_server_statistic_counter32('radiusAuthServTotalAccessAccepts',
                                   'accessAccepts');
    $self->create_server_statistic_counter32('radiusAuthServTotalAccessRejects',
                                   'accessRejects');
    $self->create_server_statistic_counter32('radiusAuthServTotalAccessChallenges',
                                   'accessChallenges');
    $self->create_server_statistic_counter32('radiusAuthServTotalMalformedAccessRequests',
                                   'malformedAccessRequests');
    $self->create_server_statistic_counter32('radiusAuthServTotalBadAuthenticators',
                                   'badAuthAccessRequests');
    $self->create_server_statistic_counter32('radiusAuthServTotalPacketsDropped',
                                   'droppedAccessRequests');
    $self->create_server_statistic_counter32('radiusAuthServTotalUnknownTypes',
                                   'unknownType');

    $self->create_client_data('radiusAuthClientIndex',
			      'radiusClientIndex');
    $self->create_client_data('radiusAuthClientAddress',
			      'radiusClientAddress');
    $self->create_client_data('radiusAuthClientID',
			      'radiusClientID');
    $self->create_client_data('radiusAuthServAccessRequests',
			      'accessRequests');
    $self->create_client_data('radiusAuthServDupAccessRequests',
			      'dupAccessRequests');
    $self->create_client_data('radiusAuthServAccessAccepts',
			      'accessAccepts');
    $self->create_client_data('radiusAuthServAccessRejects',
			      'accessRejects');
    $self->create_client_data('radiusAuthServAccessChallenges',
			      'accessChallenges');
    $self->create_client_data('radiusAuthServMalformedAccessRequests',
			      'malformedAccessRequests');
    $self->create_client_data('radiusAuthServBadAuthenticators',
			      'badAuthAccessRequests');
    $self->create_client_data('radiusAuthServPacketsDropped', 
                              'droppedAccessRequests');
    $self->create_client_data('radiusAuthServUnknownTypes', 'unknownType');

    # These ones from RFC 2621 (Acct Radius Server MIB)
    $self->{mib}->createPretty([\&get_string, undef, undef, \$main::ident], 
			 $OIDS{radiusAccServIdent});
    $self->{mib}->createPretty([\&get_uptime, undef, undef], 
			 $OIDS{radiusAccServUpTime});
    $self->{mib}->createPretty([\&get_resettime, undef, undef], 
			 $OIDS{radiusAccServResetTime});
    $self->{mib}->createPretty([\&get_int, undef, \&set_config_state, 
				\$main::config_state], 
			       $OIDS{radiusAccServConfigReset});
    $self->create_server_statistic_counter32('radiusAccServTotalRequests',
                                   'accountingRequests');
    $self->create_server_statistic_counter32('radiusAccServTotalInvalidRequests',
                                   'invalidClientAddresses');
    $self->create_server_statistic_counter32('radiusAccServTotalDupRequests',
                                   'dupAccountingRequests');
    $self->create_server_statistic_counter32('radiusAccServTotalResponses',
                                   'accountingResponses');
    $self->create_server_statistic_counter32('radiusAccServTotalMalformedRequests',
                                   'malformedAccountingRequests');
    $self->create_server_statistic_counter32('radiusAccServTotalBadAuthenticators',
                                   'badAuthAccountingRequests');
    $self->create_server_statistic_counter32('radiusAccServTotalPacketsDropped',
                                   'droppedAccountingRequests');
    $self->create_server_statistic_counter32('radiusAccServTotalNoRecords',
                                   'noRecord');
    $self->create_server_statistic_counter32('radiusAccServTotalUnknownTypes',
                                   'unknownType');

    $self->create_client_data('radiusAccClientIndex',
			      'radiusClientIndex');
    $self->create_client_data('radiusAccClientAddress',
			      'radiusClientAddress');
    $self->create_client_data('radiusAccClientID',
			      'radiusClientID');
    $self->create_client_data('radiusAccServPacketsDropped', 
                              'droppedAccountingRequests');
    $self->create_client_data('radiusAccServRequests',
			      'accountingRequests');
    $self->create_client_data('radiusAccServDupRequests',
			      'dupAccountingRequests');
    $self->create_client_data('radiusAccServResponses',
			      'accountingResponses');
    $self->create_client_data('radiusAccServBadAuthenticators',
			      'badAuthAccountingRequests');
    $self->create_client_data('radiusAccServMalformedRequests',
			      'malformedAccountingRequests');
    $self->create_client_data('radiusAccServNoRecords', 'noRecord');
    $self->create_client_data('radiusAccServUnknownTypes', 'unknownType');

    # These from RFC4669
    $self->create_clientext_data('radiusAuthClientExtIndex',
			      'radiusClientIndex');
    $self->create_clientext_data('radiusAuthClientInetAddressType',
			      'radiusClientInetAddressType');
    $self->create_clientext_data('radiusAuthClientInetAddress',
			      'radiusClientInetAddress');
    $self->create_clientext_data('radiusAuthClientExtID',
			      'radiusClientID');
    $self->create_clientext_data('radiusAuthServExtAccessRequests',
			      'accessRequests');
    $self->create_clientext_data('radiusAuthServExtDupAccessRequests',
			      'dupAccessRequests');
    $self->create_clientext_data('radiusAuthServExtAccessAccepts',
			      'accessAccepts');
    $self->create_clientext_data('radiusAuthServExtAccessRejects',
			      'accessRejects');
    $self->create_clientext_data('radiusAuthServExtAccessChallenges',
			      'accessChallenges');
    $self->create_clientext_data('radiusAuthServExtMalformedAccessRequests',
			      'malformedAccessRequests');
    $self->create_clientext_data('radiusAuthServExtBadAuthenticators',
			      'badAuthAccessRequests');
    $self->create_clientext_data('radiusAuthServExtPacketsDropped', 
                              'droppedAccessRequests');
    $self->create_clientext_data('radiusAuthServExtUnknownTypes', 'unknownType');
    $self->create_clientext_data('radiusAuthServCounterDiscontinuity', 'counterDiscontinuity');

    # These from RFC 4671
    $self->create_clientext_data('radiusAccClientExtIndex',
			      'radiusClientIndex');
    $self->create_clientext_data('radiusAccClientInetAddressType',
			      'radiusClientInetAddressType');
    $self->create_clientext_data('radiusAccClientInetAddress',
			      'radiusClientInetAddress');
    $self->create_clientext_data('radiusAccClientExtID',
			      'radiusClientID');
    $self->create_clientext_data('radiusAccServExtPacketsDropped', 
                              'droppedAccountingRequests');
    $self->create_clientext_data('radiusAccServExtRequests',
			      'accountingRequests');
    $self->create_clientext_data('radiusAccServExtDupRequests',
			      'dupAccountingRequests');
    $self->create_clientext_data('radiusAccServExtResponses',
			      'accountingResponses');
    $self->create_clientext_data('radiusAccServExtBadAuthenticators',
			      'badAuthAccountingRequests');
    $self->create_clientext_data('radiusAccServExtMalformedRequests',
			      'malformedAccountingRequests');
    $self->create_clientext_data('radiusAccServExtNoRecords', 'noRecord');
    $self->create_clientext_data('radiusAccServExtUnknownTypes', 'unknownType');
    $self->create_clientext_data('radiusAccServerCounterDiscontinuity', 'counterDiscontinuity');


    # Resolve the port to an integer port number
    # The port number may be overridden by a comand line arg
    $self->{Port} = $Radius::SNMPAgent::port if $Radius::SNMPAgent::port; 
    $self->{BindAddress} = &Radius::Util::format_special($self->{BindAddress});

    my $port = Radius::Util::get_port(&Radius::Util::format_special($self->{Port}));

    # And create a socket to listen for SNMP requests
    # REVISIT: Last arg should be BindAddress, 
    # but a bug in SNMP_Session 0.83 prevents it being used with that version
    if ($self->{SNMPVersion} eq '2c')
    {
	$self->{session} = SNMPv2c_Session->open
	    (undef, '', $port, undef,
	     $port, undef,
	     $SNMP_Session::VERSION >= 0.92 ? $self->{BindAddress} : undef);
    }
    else
    {
	$self->{session} = SNMP_Session->open
	    (undef, '', $port, undef,
	     $port, undef,
	     $SNMP_Session::VERSION >= 0.92 ? $self->{BindAddress} : undef);
    }

    if ($self->{session})
    {
	# Now add a read handler which will be called whenever there is a 
	# packet available to be read
	&Radius::Select::add_file($self->{session}->sockfileno,
			      1, undef, undef, 
			      \&Radius::SNMPAgent::handle_socket_read,
			      $self); 
    }
    else
    {
	$self->log($main::LOG_ERR,
        "Could not open SNMP Agent port $port on $self->{BindAddress}: $!");
    }

    $Radius::SNMPAgent::agent = $self;
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

    $self->SUPER::initialize;
    $self->{Port} = SNMP_Session::standard_udp_port;
    $self->{BindAddress} = $main::config->{BindAddress} || '0.0.0.0';
    $self->{SNMPVersion} = '1';
    $self->{ObjType} = 'SNMPAgent'; # Auto register with Configurable
}

#####################################################################
# This function is called whenever there is a packet waiting to
# be read from the SNMP port
sub handle_socket_read
{
    my ($fileno, $self) = @_;

    my ($request, $iaddr, $port) = $self->{session}->receive_request();
    if (defined $request)
    {
	my ($type, $requestid, $bindings, $community) 
	    = $self->{session}->decode_request($request);
	
	unless (defined $type)
	{
	    $self->log($main::LOG_WARNING, "SNMPAgent: could not decode request from ".
		       Radius::Util::inet_ntop($iaddr));
	    return;
	}

	$self->log($main::LOG_DEBUG, "SNMPAgent: received request from ".
	    Radius::Util::inet_ntop($iaddr). ", $type, $requestid, $community");

	my ($error, $errorstatus, $errorindex);
	$errorstatus = $errorindex = 0;

	# Check if the requesting machine has snmp access
	if (defined $self->{managerAddresses})
	{
	    unless (grep {$iaddr eq $_} @{$self->{managerAddresses}})
	    {
		$self->log($main::LOG_WARNING,
		    "SNMPAgent: requesting host not defined as manager. Request from "
		    . Radius::Util::inet_ntop($iaddr) . " ignored");
		return;

	    }

	}

	# Check the community, don't compare against undefined communities
	if ($type == SNMP_Session::set_request)
	{
	    if (!defined($self->{RWCommunity}) or ($community ne $self->{RWCommunity}))
	    {
		$self->log($main::LOG_WARNING,
		    "SNMPAgent: wrong RW community: '$community'. Request from "
		    . Radius::Util::inet_ntop($iaddr) . " ignored");
		return;

	    }
	}
	elsif (!defined($self->{ROCommunity}) or ($community ne $self->{ROCommunity}))
	{
	    if (!defined($self->{RWCommunity}) or ($community ne $self->{RWCommunity}))
	    {
		$self->log($main::LOG_WARNING,
		    "SNMPAgent: wrong community: '$community'. Request from "
		    . Radius::Util::inet_ntop($iaddr) . " ignored");
		return;

	    }
	}

	my $index = 0;

	my @results;
	binding: while (!$errorstatus && $bindings ne '') 
	{
	    my $binding;
	    ($binding, $bindings) = BER::decode_sequence($bindings);
	    while (!$errorstatus && $binding ne '')
	    {
		($b, $binding) = BER::decode_sequence($binding);
		$index++;
		if ($type == SNMP_Session::get_request)
		{
		    my ($oid) = BER::decode_oid($b);  # Binary oid
		    my $poid = BER::pretty_oid($oid);

		    my ($error, $value, @fromoid) 
			= $self->{mib}->get(split(/\./, $poid));
		    $oid = BER::encode_oid(@fromoid);
		    $errorstatus = $error if $error;
		    push(@results, BER::encode_sequence($oid, $value))
			unless $errorstatus;
		}
		elsif ($type == SNMP_Session::getnext_request)
		{
		    my ($oid) = BER::decode_oid($b);  # Binary oid
		    my $poid = BER::pretty_oid($oid);
		    my ($error, $value, @fromoid) 
			= $self->{mib}->getnext(split(/\./, $poid));
		    $oid = BER::encode_oid(@fromoid);
		    $errorstatus = $error if $error;

		    push(@results, BER::encode_sequence($oid, $value))
			unless $errorstatus; 
		}
		elsif ($type == SNMP_Session::set_request)
		{
		    my ($oid, $value) = BER::decode_by_template($b, "%O%@");
		    my $poid = BER::pretty_oid($oid);
		    my ($error, $newvalue, @fromoid) 
			= $self->{mib}->set($value, split(/\./, $poid));
		    $oid = BER::encode_oid(@fromoid);
		    $errorstatus = $error if $error;

		    push(@results, BER::encode_sequence($oid, $newvalue))
			unless $errorstatus;
		}
		else
		{
		    $self->log($main::LOG_WARNING,
		    "SNMPAgent: error decoding request: " . $BER::errmsg);
		    return;
		}
		if ($errorstatus)
		{
		    $errorindex = $index;
		    last binding;
		}
	    }
	}

	# OK we've got everything they asked for, so return it
	$request = BER::encode_tagged_sequence(SNMP_Session::get_response,
					     BER::encode_int($requestid),
					     BER::encode_int($errorstatus), 
					     BER::encode_int($errorindex),
					     BER::encode_sequence(@results))
	    || $self->log($main::LOG_ERR,
		    "SNMPAgent: error encoding reply: " . $BER::errmsg);

	$self->{session}->{remote_addr} = Socket::pack_sockaddr_in($port, $iaddr);
	$self->{session}->{community} = $community;
	# UNfortunately, wrap_request has its own ideas about the
	# SNMP version. Currently no way to reply
	# with the same version number as in the request
	$request = $self->{session}->wrap_request($request);

	# tell the session where to send the reply to
	$self->{session}->send_query($request)
	    || $self->log($main::LOG_ERR,
		    "SNMPAgent: error sending reply: $!");
    }
    else
    {
	$self->log($main::LOG_WARNING,
		   "SNMPAgent: receive_request failed: $!");
    }
}

#####################################################################
# Reinitialize this module
sub reinitialize
{
    # This will DESTROY any agent left from a previous initialization
    $Radius::SNMPAgent::agent 
	&& $Radius::SNMPAgent::agent->{session} 
        && $Radius::SNMPAgent::agent->{session}->close();
    $Radius::SNMPAgent::agent = undef;
}


1;
