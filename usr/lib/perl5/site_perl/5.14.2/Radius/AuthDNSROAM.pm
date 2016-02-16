# AuthDNSROAM.pm
#
# Object for handling Authentication with remote radius servers
# determined through DNS
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997-2005 Open System Consultants
# $Id: AuthDNSROAM.pm,v 1.32 2012/04/02 21:42:55 mikem Exp $

package Radius::AuthDNSROAM;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthRADSEC;
use Radius::AuthRADIUS;
use Radius::Select;
use Radius::TLSConfig;
use strict;

%Radius::AuthDNSROAM::ConfigKeywords = 
('RewriteTargetRealm'         => 
 ['stringarray', 'This optional parameter can be used to specify one or more rewriting rules which will be used to rewrite the Realm name used by Resolver to discover the appropriate target server.', 1],

 # Defaults for Route clauses
 'Address'                    => 
 ['string', 'Default Address for each Route', 1],
 'Transport'                  => 
 ['string', 'Default Transport for each Route', 1],
 
 # Defaults for both RADIUS and RADSEC
 'StripFromRequest'           => 
 ['string', 'Strips the named attributes from the request before forwarding it to any Host. The value is a comma separated list of attribute names. StripFromRequest removes attributes from the request before AddToRequest adds any to the request.', 1],
 'AddToRequest'               => 
 ['string', 'Adds attributes to the request before forwarding to any Host. Value is a list of comma separated attribute value pairs all on one line, exactly as for any reply item. StripFromRequest removes attributes from the request before AddToRequest adds any to the request. You can use any of the special % formats in the attribute values. ', 1],
 'ReplyHook'                  => 
 ['hook', 'Perl function that will be called after a reply is received from a remote server and before it is relayed back to the original client. ', 1],
 'NoReplyHook'                => 
 ['hook', 'Perl function that will be called if no replyis received from a remote server.', 1],
 'NoForwardAuthentication'    => 
 ['flag', 'Prevents forwarding of Authentication-Requests. They are ACCEPTED, but no further action is taken with them. This is different in meaning to IgnoreAuthentication, which IGNOREs them.', 1],
 'NoForwardAccounting'        => 
 ['flag', 'Prevents forwarding of Accounting-Requests. They are ACCEPTED, but no further action is taken with them. This is different in meaning to IgnoreAccounting, which IGNOREs them. ', 1],
 'AllowInRequest'             => 
 ['string', 'This optional parameter specifies a list of attribute names that are permitted in forwarded requests. Attributes whose names do not apear in this list will be stripped from the request before forwarding.', 1],
 
 # Defaults for AuthBy RADSEC hosts
 'IgnoreReject'               => 
 ['flag', 'This optional parameter causes Radiator to ignore (i.e. not send back to the original NAS) any Access-Reject messages received from the remote RadSec server. This is sometimes useful for authenticating from multiple Radius servers. However, you should note that if all the remote radius servers reject the request, then the NAS will receive no reply at all.', 1],
 'IgnoreAccountingResponse'   => 
 ['flag', 'This optional flag causes AuthBy RADSEC to ignore replies to accounting requests, instead of forwarding them back to the originating host. This can be used in conjunction with the AccountingHandled flag in a Handler or Realm (see Section 5.17.10 on page 60) to ensure that every proxied accounting request is replied to immediately, and the eventual reply from the remote RADSEC server is dropped.', 1],
 @Radius::AuthRADSEC::hostkeywords,
 
 # Defaults for AuthBy RADIUS hosts
 @Radius::AuthRADIUS::hostkeywords,
 
 'Synchronous'                => 
 ['flag', 'Normally, AuthBy RADIUS will complete as soon as the request has been forwarded to the remote radius server. It will not wait for a reply before moving on to other AuthBy classes, or handling new requests. You can change this behaviour with the Synchronous flag, but make sure you understand what you are doing before enabling the Synchronous flag.', 1],
 'IgnoreAccountingResponse'   => 
 ['flag', 'This optional flag causes this module to ignore replies to accounting requests, instead of forwarding them back to the originating host. This can be used in conjunction with the AccountingHandled flag in a Handler or Realm to ensure that every proxied accounting request is replied to immediately, and the eventual reply from the remote server is dropped.', 1],
 'CacheOnNoReply'             => 
 ['flag', 'If CacheOnNoReply is set (the default), then the Access-Request will always be proxied to the rmote Radius server, and password cache will only be consulted if there is no reply from of any of the remote Radius servers. If no reply is received from any of the remote Radius servers, and If there is a cached reply that matches the password and has not exceeded the CachePasswordExpiry time limit, then the request will be accepted.
If CacheOnNoReply is not set, then the password cache will consulted before proxying. If there is a cached reply that matches the password and has not exceeded the CachePasswordExpiry time limit, then the request will be accepted immediately without being proxied to any remote Radius server.', 1],
 'Routes'                     => 
 ['objectlist', 'List of Routes. Each Route is a hardwired proxy target, either RadSec, RADIUS', 0],

 'RedespatchIfNoTarget'                => 
 ['flag', 'For a given request, if Resolver does not find a target and there is no explicit Route, and no DEFAULT Route and this flag is set, the request will be redepatched to the Handler/Realm system for handling. This allows for a flexible fallback in the case where DNSROAM cannot find how to route a request. The redespatched request will have the attribute OSC-Environment-Identifier=DNSROAM set in the request.', 1],
 );

# RCS version number of this module
$Radius::AuthDNSROAM::VERSION = '$Revision: 1.32 $';

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;

    # Defaults for Route
    $self->{Address} = 'localhost';
    $self->{Transport} = 'tcp';
    $self->{Protocol} = 'radsec';
    $self->{Port} = 2083; # IANA official for RadSec
    $self->{UseTLS} = 1;

    $self->{Secret} = 'mysecret';
    $self->{Host} = 'localhost';
    $self->{MaxBufferSize} = 100000;
    $self->{Protocol} = 'tcp';
    $self->{NoreplyTimeout} = 5;
    $self->{_nextidentifier} = 0;
    $self->{_nextpsid} = 0;
}

#####################################################################
# Override the object function in Configurable
sub object
{
    my ($self, $file, $keyword, $name, @args) = @_;

    if ($keyword eq 'Route')
    {
	# Hardwired target realms
	$self->addRoute($name, $file, @args);
	return 1;
    }
    return $self->SUPER::object($file, $keyword, $name, @args);
}

#####################################################################
# Handle a request
sub handle_request
{
    my ($self, $p, $dummy, $extra_checks) = @_;

    $self->log($main::LOG_DEBUG, 'Handling with Radius::AuthDNSROAM', $p);

    # Now we might fork before processing the request
    # Should only do this for "slow" authentication methods
    return ($main::IGNORE, 'forked')
	if $self->{Fork} && !$self->handlerFork();

    # Trivial handling follows
    if ($p->code eq 'Access-Request')
    {
	return ($main::ACCEPT)
	    if $self->{NoForwardAuthentication};
	return ($main::IGNORE, 'Ignored due to IgnoreAuthentication')
	    if $self->{IgnoreAuthentication} ;

	# Handle cached replies
	if ($self->{CachePasswords})
	{
	    my $cachedreply = $self->cachedReply($p);
	    if ($cachedreply)
	    {
		$self->log($main::LOG_DEBUG, 'AuthDNSROAM: Using cached reply', $p);	
		$cachedreply->set_identifier($p->identifier());
		$cachedreply->set_authenticator($p->authenticator());
		$p->{rp} = $cachedreply;
		return ($main::ACCEPT);
	    }
	}
    }
    elsif ($p->code eq 'Accounting-Request')
    {
	return ($main::ACCEPT) if $self->{NoForwardAccounting};
	return ($main::IGNORE, 'Ignored due to IgnoreAccounting')
	    if $self->{IgnoreAccounting};

	my $status_type = $p->getAttrByNum($Radius::Radius::ACCT_STATUS_TYPE);
	# If we have a HandleAcctStatusTypes and this type is not mentioned
	# Acknowledge it, but dont do anything else with it
	return ($main::ACCEPT)
	    if defined $self->{HandleAcctStatusTypes}
	       && !exists $self->{HandleAcctStatusTypes}{$status_type};

	# If AccountingStartsOnly is set, only process Starts
	# Acknowledge and drop anything else
	return ($main::ACCEPT)
	    if $self->{AccountingStartsOnly}
	       && $status_type ne 'Start';
	
	# If AccountingStopsOnly is set, only process Stops
	# Acknowledge and drop anything else
	return ($main::ACCEPT)
	    if $self->{AccountingStopsOnly}
	       && $status_type ne 'Stop';

	# If AccountingAlivesOnly is set, only process Alives
	# Acknowledge and drop anything else
	return ($main::ACCEPT)
	    if $self->{AccountingAlivesOnly}
	       && $status_type ne 'Alive';
    }

    # The first step is find a target RADSEC server based on the realm
    my ($user, $realmName) = split(/@/, $p->getUserName);

    # Maybe rewrite the realm before finding the target server
    my $rule;
    foreach $rule (@{$self->{RewriteTargetRealm}})
    {
	# We use an eval so an error in the pattern wont kill us.
	eval("\$realmName =~ $rule");
	$self->log($main::LOG_ERR, "Error while rewriting target realm $realmName: $@", $p) 
	    if $@;
	    
	$self->log($main::LOG_DEBUG, "Rewrote target realm to $realmName", $p);
    }

    # See of there is an existing or hardwired realm->server mapping
    # If it has been discovered, make sure it has not expired
    if (exists $self->{routes}{$realmName} 
	&& (   !defined $self->{routes}{$realmName}->{Expires}
	    || $self->{routes}{$realmName}->{Expires} > time))
    {
	return $self->{routes}{$realmName}->handle_request($p);
    }
    else
    {
	# No hardwired mapping, use DNS discovery
	# Check a resolver is avilable
	if (!$Radius::Resolver::default)
	{
	    $self->log($main::LOG_WARNING, 'AuthBy DNSROAM requires a Resolver to discover servers, but no Resolver clause is available. Ignoring', $p);
	    return ($main::IGNORE, 'No Resolver available');
	}
	
	# When the Resolver has discovered all the RadSec servers for this realm, 
	# it will call our callback
	$Radius::Resolver::default->discoverServers($realmName, sub {$self->discoveredServers($p, $realmName, @_)});
	return ($main::IGNORE, 'Discovering RadSec servers');
    }
}

#####################################################################
# Called when the address(es) to contact for a realm have been discovered from 
# DNS. @results is an array of hashes describing each address that was discovered, 
# in order of preference
sub discoveredServers
{
    my ($self, $p, $realmName, $answer) = @_;

    if (@{$answer->{Results}})
    {
	# IF there are multiple servers found, should they be considered primary/secondary etc?
	# REVISIT: just connect to the highest preference/priority/weight for now
	my $result = ${$answer->{Results}}[0];
	$self->log($main::LOG_DEBUG, "AuthDNSROAM: Discovered server for $realmName: $result->{Address}($result->{IPAddress}):$result->{Port}, $result->{Protocol}, $result->{Transport}, $result->{UseTLS}, $result->{SRVName}", $p);	
	# See if there already exists a discovered host with the same target
	# Caution: cant be sure the Port will come back from the resolver
	if (exists $self->{routes}{$realmName}
	    && $self->{routes}{$realmName}->isRouteFor($result))
	{
	    $self->log($main::LOG_INFO, "AuthBy DNSROAM rediscovered the same target for $realmName", $p);
	}
	else
	{
	    my $existingroute = $self->findRouteFor($result);
	    if ($existingroute)
	    {
		$self->log($main::LOG_INFO, "AuthBy DNSROAM reused existing target for $realmName", $p);
		$self->{routes}{$realmName} = $existingroute;
	    }
	    else
	    {
		$self->log($main::LOG_INFO, "AuthBy DNSROAM adding new target for $realmName", $p);
		$self->addRoute($realmName, undef, Realm => $realmName, Expires => $answer->{Expires}, %$result);
	    }
	}
	$self->{routes}{$realmName}->handle_request($p);
    }
    elsif (exists $self->{routes}{DEFAULT})
    {
	# DNS did not discover any servers, send to the default
	$self->log($main::LOG_DEBUG, "AuthBy DNSROAM: No hardwired Route, no discovered Route, using DEFAULT Route for $realmName", $p);
	$self->{routes}{DEFAULT}->handle_request($p);
    }
    elsif ($self->{RedespatchIfNoTarget})
    {
	$self->log($main::LOG_DEBUG, "AuthBy DNSROAM: No hardwired Route, no discovered Route, no DEFAULT route. Redespatching to find a Realm or Handler", $p);
	$p->add_attr('OSC-Environment-Identifier', $self->{Identifier} || 'DNSROAM');
	$self->redespatch($p, undef, $realmName);
    }
    else
    {
	$self->log($main::LOG_WARNING, "AuthBy DNSROAM: No hardwired Route, no discovered Route and no DEFAULT Route for $realmName. Ignoring", $p);
    }
}

#####################################################################
# Add a new host to the list of hosts to proxy to.
# The host name is resolved to a list of addresses
# The host name may consist of multiple names separated by 
# commas
# The secret etc default to the ones for the AuthBy RADIUS clause
sub addRoute
{
    my ($self, $name, $file, @args) = @_;

    my $object =  Radius::AuthDNSROAM::Route->new
	($file, $name,
	 (map {defined $self->{$_} ? ($_ => $self->{$_}) : ()} 
	  (qw(Address Transport Protocol Port UseTLS SRVName

	      StripFromRequest AddToRequest ReplyHook ReplyHook.compiled NoReplyHook NoReplyHook.compiled
              StripFromReply AllowInReply
	      NoForwardAuthentication NoForwardAccounting AllowInRequest

	      NoreplyTimeout IgnoreReject 
	      IgnoreAccountingResponse FailureBackoffTime MaxBufferSize 
	      ReconnectTimeout ConnectOnDemand UseTLS TLS_CAFile TLS_CAPath 
	      TLS_CertificateFile TLS_CertificateChainFile TLS_CertificateType TLS_PrivateKeyFile 
	      TLS_PrivateKeyPassword TLS_RandomFile TLS_DHFile TLS_CRLCheck TLS_CRLFile 
	      TLS_SessionResumption TLS_SessionResumptionLimit TLS_ExpectedPeerName 
	      TLS_SubjectAltNameURI TLS_CertificateFingerprint
	      
	      AuthPort AcctPort Secret Retries RetryTimeout UseOldAscendPasswords 
	      ServerHasBrokenPortNumbers ServerHasBrokenAddresses IgnoreReplySignature
	      UseExtendedIds MaxFailedRequests MaxFailedGraceTime
	      ))),
	 @args);
    if ($object)
    {
	$object->activate();
	push(@{$self->{Routes}}, $object);
	$self->{routes}{$object->{Realm}} = $object; # Realm-based lookup
    }
}

#####################################################################
# Does a linear search for a Route that meets the requirements of $result
sub findRouteFor
{
    my ($self, $result) = @_;

    foreach (@{$self->{Routes}})
    {
	return $_ 
	    if $_->isRouteFor($result);
    }
    return; # not there
}

#####################################################################
#####################################################################
#####################################################################
# This is a helper class for holding details about hardwired target hosts
package Radius::AuthDNSROAM::Route;
@Radius::AuthDNSROAM::Route::ISA = qw(Radius::Configurable);
%Radius::AuthDNSROAM::Route::ConfigKeywords = 
('Realm'                      => 
 ['string', 'Specifies the Realm that this Route will apply to. All requests with a User-Name whose Realm component (after applying any RewriteTargetRealm rules) match this realm will by processed using this Route. If the Realm is \`DEFAULT\' then this Route will be used to process requests for which no explicit Route exists, and no route could be discovered through DNS and the <Resolver> clause.', 0],
 'Address'                    => 
 ['string', 'Specifies the name or address of the target server to be used to process requests for this Route.', 0],
 'Transport'                  => 
 ['string', 'Specifies the transport to be used to contact the target server.', 0],
 'Protocol'                   => 
 ['string', 'Specifies the protocol to be used to contact the target server.', 0],
 'Port'                       => 
 ['string', 'Specifies the port number to be used to contact the target server. ', 0],
 'UseTLS'                     => 
 ['flag', 'Specifies whether TLS is to be used to encrypt the connection to the target server. Valid only for Protocol=radsec. Although it is possible to not use TLS for a RadSec connection, it is recommended that RadSec connections always be configured to use TLS. ', 1],
 'SRVName'                     => 
 ['string', 'Specifies a DNS SRV Name that was used to determine the address. Some TLS server certificates require this to be changed against SubjectAltName:SRV extensions to validate the server certificate.', 1],
 'Secret'                     => 
 ['string', 'Shared secret to use for target Realm.', 0],
 );

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
    $self->{Realm} = 'DEFAULT';
    $self->{Address} = 'localhost';
    $self->{Port} = 2083;
    $self->{Transport} = 'tcp';
    $self->{Protocol} = 'radsec';
    $self->{UseTLS} = 1;
}

#####################################################################
sub handle_request
{
    my ($self, $p) = @_;

    if (!defined $self->{target})
    {
	# For historical reasons, Protocol=radius, Transport=tls is the same as Protocol=radsec
	if (lc $self->{Protocol} eq 'radsec'
	    || (lc $self->{Protocol} eq 'radius' && lc $self->{Transport} eq 'tls')
	    || (lc $self->{Protocol} eq 'radius' && (lc $self->{Transport} eq 'tcp' && $self->{UseTLS}) ))
	{
	    # Instantiate an AuthBy RADSEC
	    $self->{target} = Radius::AuthRADSEC->new
		(undef,
		 $self->{Realm},
		 Host => [defined $self->{IPAddress} ? $self->{IPAddress} : $self->{Address}],
		 HostAddress => $self->{IPAddress}, # Maybe force an IP address we already know
		 Protocol => $self->{Transport},
		 TLS_SRVName => $self->{SRVName},
		 # Copy parameters from $self:		 
		 (map {defined $self->{$_} ? ($_ => $self->{$_}) : ()} 
		  (qw(Port Secret
		      StripFromRequest AddToRequest ReplyHook ReplyHook.compiled NoReplyHook NoReplyHook.compiled
                      StripFromReply AllowInReply
		      NoForwardAuthentication NoForwardAccounting AllowInRequest
		      NoreplyTimeout IgnoreReject 
		      IgnoreAccountingResponse MaxBufferSize 
		      ReconnectTimeout ConnectOnDemand UseTLS TLS_CAFile TLS_CAPath 
		      TLS_CertificateFile TLS_CertificateChainFile TLS_CertificateType TLS_PrivateKeyFile 
		      TLS_PrivateKeyPassword TLS_RandomFile TLS_DHFile TLS_CRLCheck TLS_CRLFile 
		      TLS_SessionResumption TLS_SessionResumptionLimit TLS_ExpectedPeerName TLS_SubjectAltNameURI 
                      TLS_CertificateFingerprint
		      FailureBackoffTime MaxFailedRequests MaxFailedGraceTime))),
		 );
	    $self->{target}->activate();
	}
	elsif (lc $self->{Protocol} eq 'radius' && lc $self->{Transport} eq 'udp')
	{
	    # Instantiate an AuthBy RADIUS
	    $self->{target} = Radius::AuthRADIUS->new
		(undef,
		 $self->{Realm},
		 Host => [defined $self->{IPAddress} ? $self->{IPAddress} : $self->{Address}],
		 AuthPort => $self->{Port},
		 AcctPort => $self->{Port},
		 # Copy parameters from $self:		 
		 (map {defined $self->{$_} ? ($_ => $self->{$_}) : ()} 
		  (qw(StripFromRequest AddToRequest ReplyHook ReplyHook.compiled NoReplyHook NoReplyHook.compiled
                      StripFromReply AllowInReply
		      NoForwardAuthentication NoForwardAccounting AllowInRequest
		      AuthPort AcctPort Secret Retries RetryTimeout UseOldAscendPasswords 
		      ServerHasBrokenPortNumbers ServerHasBrokenAddresses IgnoreReplySignature
		      UseExtendedIds FailureBackoffTime MaxFailedRequests MaxFailedGraceTime))),
		 );
	    $self->{target}->activate();
	}
	else
	{
	    $self->log($main::LOG_WARNING, "AuthBy DNSROAM Route doesnt know how to proxy with Protocol $self->{Protocol} and Transport $self->{Transport}. Ignoring", $p);
	    
	}
    }

    return $self->{target}->handle_request($p)
	if $self->{target};


    $self->log($main::LOG_ERR, "AuthBy DNSROAM Route failed to create a target to proxy for realm $self->{Realm}. Ignoring", $p);
    return ($main::IGNORE);
}


#####################################################################
# Tests whether this route is identical to the one needed for the discovered
# address in $result
sub isRouteFor
{
    my ($self, $result) = @_;

    return $self->{Address}      eq $result->{Address}
    && $self->{IPAddress}   eq $result->{IPAddress}
    && (!defined $result->{Port} || $self->{Port} eq $result->{Port})
	&& $self->{Protocol}  eq $result->{Protocol}
    && $self->{Transport} eq $result->{Transport}
    && $self->{UseTLS}    eq $result->{UseTLS};

}

1;



