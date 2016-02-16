# AuthRADIUS.pm
#
# Object for handling Authentication with remote radius servers
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthRADIUS.pm,v 1.150 2014/11/22 01:30:09 hvn Exp $

package Radius::AuthRADIUS;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Radius::Radius;
use Radius::Select;
use Socket;
use Fcntl;
use strict;

# Reusable keyword definitions
@Radius::AuthRADIUS::hostkeywords =
('Secret'                     => 
 ['string', 'Default shared secret to use for target RADIUS Hosts. Radiator acts like a Radius client when it forwards Radius request to another Radius server, and the Secert must match the shared secret configured into the target RADIUS server.', 0],

 'AuthPort'                   => 
 ['string', 'Specifies the default UDP port on the destination Hosts to which Radiator will send RADIUS authentication requests. The argument may be either a numeric port number or an alphanumeric service name as specified in /etc/services (or its moral equivalent on your system). The default port is 1645. Note that the officially assigned port number for Radius accounting has been changed to 1812. Can be overridden for an individual host inside its Host clause.', 0],

 'AcctPort'                   => 
 ['string', 'Specifies the default UDP port on the destination Hosts to which Radiator will send RADIUS accounting requests. The argument may be either a numeric port number or an alphanumeric service name as specified in /etc/services (or its moral equivalent on your system). The default port is 1646. Note that the officially assigned port number for Radius accounting has been changed to 1813. Can be overridden for an individual host inside its Host clause.', 0],

 'Retries'                    => 
 ['integer', 'If Radiator does not get a reply from the destination Radius server within RetryTimeout seconds, it will by default retransmit the request up to this number of retries.', 1],

 'RetryTimeout'               => 
 ['integer', 'Specifies the default number of seconds to wait for a reply before retransmitting if no reply is received froim a proxied RADIUS request. ', 1],

 'BogoMips'                   => 
 ['integer', 'Used by some load balancing modules to determine which target RADIUS server to use.', 1],

 'UseOldAscendPasswords'      => 
 ['flag', 'Deprecated. See "UseExtendedIds" instead. This optional parameter tells Radiator to encode all passwords sent by this AuthBy using the old style (non RFC compliant) method that Ascend used to use on some NASs. The symptom that might indicate a need for this parameter is that passwords longer than 16 characters are not decoded properly. Can be overridden for an individual host inside its Host clause', 1],

 'ServerHasBrokenPortNumbers' => 
 ['flag', 'Deprecated. See "UseExtendedIds" instead. Some Radius servers (GoRemote (GRIC) on NT in particular) exhibit broken behaviour in that the reply does not come from the same UDP port that the request was sent to! This broken behaviour would normally cause Radiator to ignore replies from such broken servers. The optional ServerHasBrokenPortNumbers flag will permit interoperation with such broken servers. Can be overridden for an individual host inside its Host clause.', 1],

 'ServerHasBrokenAddresses'   => 
 ['flag', 'Deprecated. See "UseExtendedIds" instead. Some Radius servers (some rare accounting proxies) exhibit broken behaviour in that the reply does not come from the same address that the request was sent to! This broken behaviour would normally cause Radiator to ignore replies from such broken servers. The optional ServerHasBrokenAddresses flag will permit interoperation with such broken servers. Can be overridden for an individual host inside its Host clause.', 1],

 'IgnoreReplySignature'       => 
 ['flag', 'Deprecated. Normally, if a reply from a remote RADIUS server is received with a bad authenticator, the reply wil be logged and then ignored. This optional parameter tells AuthBy RADIUS to ignore incorrect signatures in replies from remote Radius servers. Some Radius servers implement incorrect signature algorithms, and this flag will prevent problems when interoperating with such servers. Can be overridden for an individual host inside its Host clause. Caution: use of this flag can cause incorrect handling of replies in unusual circumstances.', 1],

 'UseExtendedIds'             => 
 ['flag', 'This optional flag can be used to work around various problem that might arise with remote Radius servers in some circumstances. This flag forces AuthBy RADIUS to use a much larger range of identifiers (at least 32 bits) carried in the Proxy-State attribute, meaning that many more requests can be pending at a given time, and that replies from a remote Radius server are more accurately matched to their original requests.', 1],

 'UseStatusServerForFailureDetect'            => 
 ['flag', 'If this flag is enabled, use only Status-Server requests (if any) to determine that a target server is failed when there is no reply. If not enabled (the default) use no reply to any type of request.', 1],

 'KeepaliveTimeout'             => 
 ['integer', 'This optional integer specifies the maximum time in seconds that a RADIUS connection can be idle before a Status-Server request is sent. Defaults to 0 seconds. If set to 0, keepalives are not used.', 1],

 'MaxFailedRequests'          => 
 ['integer', 'This optional parameter specifies how many requests must fail to receive a reply before the remote radius server is marked as failed, and the FailureBackoffTime will be applied. The default is 1, which means that one ignored request will cause the Host to be marked as failed for FailureBackoffTime seconds.', 1],

 'MaxFailedGraceTime'         => 
 ['integer', 'This optional parameter specifes the time period (in seconds) over which MaxFailedRequests failures will cause the target host to be be assumed to be failed. Defaults to 0. After a host is declared to be failed, no request will be forwarded to it until FailureBackoffTime seconds have elapsed.', 1],

 'FailureBackoffTime'         => 
 ['integer', 'This optional parameter specifies how long a failed remote server will be removed from the forwarding list. If no reply is received from a Host (after all the Retries have expired) for MaxFailedRequests consecutive times, it will be marked as failed for FailureBackoffTime seconds. After that time has expired, it will again be eligible for forwarding. The default is 0, which means that the host is always regarded as working', 1],

 'LocalAddress'               => 
 ['string', 'This optional parameter specifies the local address(es) to bind the proxy forwarding socket. This in turn specifies what the IP source address will be in forwarded requests. Defaults to BindAddress (which defaults to 0.0.0.0, i.e. the default source address).', 1],

 'OutPort'                    => 
 ['string', 'If this optional parameter is set, it forces a particular port number to be used for the forwarding port.', 1],
 );

%Radius::AuthRADIUS::ConfigKeywords = 
('Host'                       => 
 ['stringarray', 'List of target RADIUS server names. This module will try to send requests to each Host in the list in order, until a reply is received.', 1],

 'StripFromRequest'           => 
 ['string', 'Strips the named attributes from the request before forwarding it to any Host. The value is a comma separated list of attribute names. StripFromRequest removes attributes from the request before AddToRequest adds any to the request. ', 1],

 'AddToRequest'               => 
 ['string', 'Adds attributes to the request before forwarding to any Host. Value is a list of comma separated attribute value pairs all on one line, exactly as for any reply item. StripFromRequest removes attributes from the request before AddToRequest adds any to the request. You can use any of the special % formats in the attribute values. ', 1],

 'IgnoreReject'               => 
 ['flag', 'This optional parameter causes Radiator to ignore (i.e. not send back to the original NAS) any Access-Reject messages received from the remote Radius server. This is sometimes useful for authenticating from multiple Radius servers. However, you should note that if all the remote radius servers reject the request, then the NAS will receive no reply at all.', 1],

 'Synchronous'                => 
 ['flag', 'Normally, AuthBy RADIUS will complete as soon as the request has been forwarded to the remote radius server. It will not wait for a reply before moving on to other AuthBy classes, or handling new requests. You can change this behaviour with the Synchronous flag, but make sure you understand what you are doing before enabling the Synchronous flag.
If you enable the Synchronous flag, Radiator will wait for either a reply, or a timeout from the remote radius server before processing any following AuthBy clauses, or before handling any further requests. This means that handling requests will stop until a reply is received or the reply times out (which might take 15 seconds or more, depending on the settings of your RetryTimeout and retries parameters). This can seriously affect the performance of your Radius server, especially if the remote radius server is slow, stopped, or at the end of a slow or unreliable link. ', 1],

 'IgnoreAccountingResponse'   => 
 ['flag', 'This optional flag causes AuthBy RADIUS to ignore replies to accounting requests, instead of forwarding them back to the originating host. This can be used in conjunction with the AccountingHandled flag in a Handler or Realm to ensure that every proxied accounting request is replied to immediately, and the eventual reply from the remote Radius server is dropped.', 1],

 'ReplyHook'                  => 
 ['hook', 'Perl function that will be called after a reply is received from the remote Radius server and before it is relayed back to the original client. ', 1],

 'ReplyTimeoutHook'                => 
 ['hook', 'Perl function that will be called if no reply is received from the currently tried remote Radius server.', 1],

 'NoReplyHook'                => 
 ['hook', 'Perl function that will be called if no reply is received from any remote Radius server. ', 1],

 'NoForwardAuthentication'    => 
 ['flag', 'Stops AuthBy RADIUS forwarding Authentication-Requests. They are ACCEPTED, but no further action is taken with them. This is different in meaning to IgnoreAuthentication, which IGNOREs them.', 1],

 'NoForwardAccounting'        => 
 ['flag', 'Stops AuthBy RADIUS forwarding Accounting-Requests. They are ACCEPTED, but no further action is taken with them. This is different in meaning to IgnoreAccounting, which IGNOREs them. ', 1],

 'Hosts'                      => 
 ['objectlist', 'List of hardwired destination RADIUS Hosts in order of transmission attempts.', 0],

 'CacheOnNoReply'             => 
 ['flag', 'If CacheOnNoReply is set (the default), then the Access-Request will always be proxied to the rmote Radius server, and password cache will only be consulted if there is no reply from of any of the remote Radius servers. If no reply is received from any of the remote Radius servers, and If there is a cached reply that matches the password and has not exceeded the CachePasswordExpiry time limit, then the request will be accepted.
If CacheOnNoReply is not set, then the password cache will consulted before proxying. If there is a cached reply that matches the password and has not exceeded the CachePasswordExpiry time limit, then the request will be accepted immediately without being proxied to any remote Radius server.', 1],

 'AllowInRequest'             => 
 ['string', 'This optional parameter specifies a list of attribute names that are permitted in forwarded requests. Attributes whose names do not apear in this list will be stripped from the request before forwarding.', 1],

 'DisableMTUDiscovery'      => 
 ['flag',
  'Disables MTU discovery on platforms that support that behaviour (currently Linux only). This can be used to prevent discarding of certain large RADIUS packet fragments on supporting operating systems.',
  2],

 'MaxTargetHosts'      => 
 ['integer',
  'Limits the number of different hosts a request will be proxied to in the case of no reply. Defaults to 0 which mean no limit: if the proxy algorithm does not receive a reply from a host, it will keep trying until all hosts are exhausted.',
  2],

 @Radius::AuthRADIUS::hostkeywords
 );

# RCS version number of this module
$Radius::AuthRADIUS::VERSION = '$Revision: 1.150 $';

# This is a hash of requests for which we are awaiting replies
# ie these are the original requests as received from our client
# Each entry is an array of 3 refs to Radius packets. The first element
# is the original packet we received, the second is the packet we
# forwarded, the 3rd is the reply packet we are constructing
# and which was originally passed to handle_request
my %pendingRequests;

# We maintain a separate socket for each distinct LocalAddress. All
# instances of AuthRADIUS with the same LocalAddress share the same
# socket for sending requests.
# Each socket is an instance of FileHandle
my %sockets;

# We maintain an identifer count for each unique port/address 
# combination, so that multiple instances of
# AuthBy RADIUS that all proxy to the
# same remote host all share the same identifier sequence.
my %identifiers;
# Extended Identifiers
my %psIds; 

# List of current AuthBys for reinitialize
my @authbys;

# Make sure we get reinitialized on sighup
push(@main::reinitFns, \&reinitialize);

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    # Check that the failover has a chance to work correctly for each Host.
    map {$self->log($main::LOG_WARNING, "UseStatusServerForFailureDetect enabled with KeepaliveTimeout set to 0 for Host $_->{Name}.")}
        grep { ($_->{UseStatusServerForFailureDetect} && !$_->{KeepaliveTimeout}) } @{$self->{Hosts}};

    $self->SUPER::check_config();
    return;
}

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();
    push @authbys, $self;

    # For backwards compatibility, convert any
    # Host parameters into Host objects
    map {$self->addHosts($_)} @{$self->{Host}};

    # Only validate if configuring from a file. If being constructed
    # by code, we asssume they know what they are doing
    $self->log($main::LOG_WARNING, "No Hosts defined for AuthRADIUS at '$main::config_file' line $.")
	unless defined $self->{Hosts};

    # Start Status-Server polling
    map {$_->set_keepalive_timeout()} @{$self->{Hosts}};

}

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{Secret} = 'mysecret';
    $self->{AuthPort} = 1645;
    $self->{AcctPort} = 1646;
    $self->{OutPort} = 0;
    $self->{Retries} = 3;
    $self->{RetryTimeout} = 5;
    $self->{KeepaliveTimeout} = 0;
    $self->{LocalAddress} = $main::config->{BindAddress} || '0.0.0.0';
    $self->{CacheOnNoReply} = 1; # Historical reasons
    $self->{MaxFailedRequests} = 1;
    $self->{MaxFailedGraceTime} = 0;
}

#####################################################################
# Override the object function in Configurable
sub object
{
    my ($self, $file, $keyword, $name, @args) = @_;

    if ($keyword eq 'Host')
    {
	$self->addHost($name, $file, @args);
	return 1;
    }
    return $self->SUPER::object($file, $keyword, $name, @args);
}

#####################################################################
# Handle a request
sub handle_request
{
    my ($self, $p, $dummy, $extra_checks) = @_;

    $self->log($main::LOG_DEBUG, "Handling with Radius::AuthRADIUS", $p);

    # Now we might fork before processing the request
    # Should only do this for "slow" authentication methods
    return ($main::IGNORE, 'forked')
	if $self->{Fork} && !$self->handlerFork();

    # Trivial handling follows
    if ($p->code eq 'Access-Request')
    {
	return ($main::ACCEPT)
	    if $self->{NoForwardAuthentication};
	return ($main::IGNORE, "Ignored due to IgnoreAuthentication")
	    if $self->{IgnoreAuthentication} ;

	# Handle cached replies
	if ($self->{CachePasswords} && !$self->{CacheOnNoReply})
	{
	    my $cachedreply = $self->cachedReply($p);
	    if ($cachedreply)
	    {
		$self->log($main::LOG_DEBUG, "AuthRADIUS: Using cached reply", $p);	
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
	return ($main::IGNORE, "Ignored due to IgnoreAccounting")
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

    # Forward the request:
    my $fp = Radius::Radius->newCopy($p);
    
    # Tell callers the packet was proxied. Some callers like EAP_21 need to know.
    # Also causes Handler to increment the proxiedRequests stats
    $p->{proxied}++;

    # Remember who this instance of AuthRADIUS is
    $fp->{ThisAuth} = $self;

    # Remove any proxy state 
    $fp->delete_attr('Proxy-State');					# RB 2003-08-07
    # Timestamp on the wire confuses downstream clients
    $fp->delete_attr('Timestamp');

    if ($fp->code eq 'Accounting-Request')
    {
	# Change or set the Acct-Delay. Dont lose delay times from
	# present in the original request
	my $origdelay = $p->getAttrByNum($Radius::Radius::ACCT_DELAY_TIME);
	$fp->changeAttrByNum($Radius::Radius::ACCT_DELAY_TIME, 
			     time - $p->{RecvTime} + $origdelay);
    }
    else
    {
	if ($self->{RejectEmptyPassword} 
	    && $p->decodedPassword() eq ''
	    && !$p->getAttrByNum($Radius::Radius::CHAP_PASSWORD))
	{
	    $self->log($main::LOG_DEBUG, "AuthRADIUS rejected because of an empty password", $p);
	    return ($main::REJECT, 'Empty password');
	}
    }
    
    # Add and strip attributes before forwarding. 
    map {$fp->delete_attr($_)} (split(/\s*,\s*/, $self->{StripFromRequest}))
	if defined $self->{StripFromRequest};
    $fp->delete_attr_fn
	(sub {return $_[0] =~ /^Unknown/; })     # Possibly strip attributes that were not known in dictionary
	    if (!$main::config->{ProxyUnknownAttributes} && $p->{UnknownAttributeCount});
    $fp->delete_attr_fn
	(sub {!grep($_[0] eq $_, 
		    split(/\s*,\s*/, $self->{AllowInRequest}))})
	    if defined $self->{AllowInRequest};

    $fp->parse(&Radius::Util::format_special($self->{AddToRequest}, $p))
	if (defined $self->{AddToRequest});
    
    # Choose a target host and send it:
    delete $p->{RadiusResult};
    $self->forward($fp, $p);

    if ($self->{Synchronous})
    {
	# Here we process replies until the request we are doing
	# has either been replied to or timed out
	# CAUTION: while this is happening, no other incoming requests
	# will be handled: If the remote server is down
	# you may get a serious performance hit
	# Wait for activity on the reply socket or timeouts
	my ($waitfor, $found, $exceptions, $nfound, $timeleft);
	vec($waitfor, fileno($fp->{SendSocket}), 1) = 1;
	while (! defined $p->{RadiusResult})
	{
	    # Wait up to a second for activity on the socket
	    ($nfound, $timeleft) = select($found=$waitfor, undef, $exceptions=$waitfor, 1);
            # ddzeko added error check
            if ($nfound > 0) 
	    {
		if ($found) 
		{
		    &handle_radius_socket_read(fileno($fp->{SendSocket}), $fp->{SendSocket});
		} 
		elsif ($exceptions) 
		{
		    $self->log($main::LOG_DEBUG, "AuthRADIUS: Synchronous network error", $p);
		    return ($main::REJECT, 'Network error');
		}
            }
            &Radius::Select::process_timeouts();
	}
	return ($p->{RadiusResult});
    }
    else
    {
	return (defined $p->{RadiusResult} ? $p->{RadiusResult} : $main::IGNORE); # Dont reply for us
    }
}

#####################################################################
# Finds and returns a socket that can be used to send to the packed address passed in.
# The first suitable address type named in LocalAddress with the same OutPort will be used as the basis
# for the local address, for either ipv4 or ipv6. All
# instances of AuthRADIUS with the same LocalAddress share the 
# same socket.
# If a socket does not exist for the LocalAddress, creates one.
# If a serious error occurs, return undef (no socket found)
sub getSock
{
    my ($self, $dest_addr, $host) = @_;

    # Note: only the first suitable LocalAddress is used if there are multiple comma-sep addresses
    my @bind_address = split(/\s*,\s*/, &Radius::Util::format_special($host->{LocalAddress}));

    my ($localaddr, $bind_address, $thisaddr, $pfamily);
    my $localport = $host->{OutPort};
    my $key;
    if (length($dest_addr) == 16)
    {
	# Want an IPV6 address, find a suitable socket to send from
	foreach (@bind_address)
	{
	    $localaddr = $1, last if /ipv6:(.*)/i;
	}
	$localaddr = '::' unless defined $localaddr; # Fallback to anyhost
	# $localaddr is the name of the local addres, see if it already exists?
	$key = "$localaddr:$localport";
	return  $sockets{$key} if exists $sockets{$key};

	# No, must continue and make one
	($thisaddr, $pfamily) = Radius::Util::pack_sockaddr_pton(Radius::Util::get_port($localport),
								 $localaddr);
    }
    else
    {
	# Want an IPV4 address, find a suitable socket to send from
	foreach (@bind_address)
	{
	    $localaddr = $_, last unless /ipv6:(.*)/i;
	}
	$localaddr = '0.0.0.0' unless defined $localaddr; # Fallback to anyhost
	# $localaddr is the name of the local addres, see if it already exists?
	$key = "$localaddr:$localport";
	return  $sockets{$key} if exists $sockets{$key};

	# No, must continue and make one
	$thisaddr = scalar &Socket::sockaddr_in(&Radius::Util::get_port($localport), Socket::inet_aton($localaddr));
	$pfamily = Socket::PF_INET;
    }

    # Need to make a new one:
    # This could have been done with FileHandle, but this is much
    # more lightweight. It makes a reference to a TYPEGLOB
    # and Perl can use a typeglob ref as an IO handle
    $self->log($main::LOG_DEBUG, "AuthBy RADIUS creates new local socket '$localaddr:$host->{OutPort}' for sending requests");
    my $s = $sockets{$key} = do { local *FH };
    if (!socket($s, $pfamily, Socket::SOCK_DGRAM, scalar getprotobyname('udp')))
    {
	$self->log($main::LOG_ERR, "Could not create Radius forwarding socket in AuthRADIUS: $!");
	return;
    }
    binmode($s); # Make safe in UTF environments
    if (!bind($s, $thisaddr))
    {
	$self->log($main::LOG_ERR, "Could not bind to LocalAddress $bind_address[0] in AuthRADIUS: $!");
	delete $sockets{$key};
	return;
    }

    # On some hosts, select sometimes incorrectly says that there
    # is a reply waiting, even when there isnt. 
    # Set the socket non-blocking to prevent waiting forever
    if ($^O ne 'MSWin32')
    {
	# Win95 does not support fcntl or non-blocking sockets yet.
	fcntl($s, F_SETFL, 
	      fcntl($s, F_GETFL, 0) | O_NONBLOCK)
	    || die "Could not fcntl forwarding socket in AuthRADIUS: $!";
	
	if ($main::config->{SocketQueueLength})
	{
	    # Note: your OS may also need to be configured to allow
	    # you to choose long socket queue lengths.
	    setsockopt($s, 
		       &Socket::SOL_SOCKET, 
		       &Socket::SO_RCVBUF, 
		       $main::config->{SocketQueueLength})
		|| $self->log($main::LOG_WARNING, 
			      "Could not set AuthRADIUS forwarding socket queue length $main::config->{SocketQueueLength}: $!");
	}
	# Maybe disable MTU discovery and enable Dont Frag. Only available on Linux
	if ($^O eq 'linux' && $self->{DisableMTUDiscovery})
	{
	    # Constants from /usr/include/bits/in.h
	    setsockopt($s, 
		       0, # IPPROTO_IP
		       10, # IP_MTU_DISCOVER 
		       0 ) # IP_PMTUDISC_DONT
		|| $self->log($main::LOG_WARNING, "Could not disable MTU discovery for AuthRADIUS forwarding socket: $!");
	}
    }
    &Radius::Select::add_file
	(fileno($s), 1, undef, undef, 
	 \&Radius::AuthRADIUS::handle_radius_socket_read, 
	 $s);
    return $s;
}

#####################################################################
# Reinitialize this instance
sub reinitialize
{
    # Hosts have backpointers to AuthBys. Disconnect the Hosts from
    # the AuthBys to break the circular references.
    map {$_->{Hosts} = ()} @authbys;
    @authbys = ();

    # Since select will have forgotten about our sockets, and in any
    # case, the socket addresses may have changed, we have to
    # recreate our sockets
    %sockets = ();

    # And ignore any bogus replies from requests we have already sent
    %identifiers = ();
    %psIds = ();
}

#####################################################################
# This is called by Select::select whenever our forwarding socket
# becomes readable. Read at most one packet from the socket and
# dispatch it.
# The packets received here will be replies to requests 
# we have forwarded
# to another radius server. We have to forward the 
# reply back to the original
# requester and cross the original request off our timeout list
sub handle_radius_socket_read
{
    my ($fileno, $socket) = @_;

    my $p;   # The reply we just received
    if ($p = Radius::Radius->newRecvFrom($socket, $main::dictionary))
    {
	my $identifier = $p->identifier; 
	my $port = $p->{RecvFromPort};
	my $addr = $p->{RecvFromAddress};
	my $ip = Radius::Util::inet_ntop($addr);
	my $psid = get_psid($p);

	# Any Proxy-State in the reply is ours and must be removed. We
	# do this after logging possible request debug dump.
	$identifier = $psid if $psid;

	my $key = $port.$addr.$identifier;

	# We do this an a longwinded way because some perl 5.003 
	# versions get confused otherwise. First get the ref, 
	# see if its valid, then deref later
	my $ref = $pendingRequests{$key};

	# Maybe its a reply from a server with broken port numbers?
	if (!defined $ref)
	{
	    $key = 'BROKENPORT'.$addr.$identifier;
	    $ref = $pendingRequests{$key};
	}

	# Maybe its a reply from a server with broken addresses?
	if (!defined $ref)
	{
	    $key = $port.'BROKENADDRESS'.$identifier;
	    $ref = $pendingRequests{$key};
	}

	# Maybe its a reply from a server with both
	# broken addresses and broken port numbers?
	if (!defined $ref)
	{
	    $key = 'BROKENPORT'.'BROKENADDRESS'.$identifier;
	    $ref = $pendingRequests{$key};
	}

	if (!defined $ref)
	{
	    &main::log($main::LOG_WARNING, 
		       "Unknown reply received in AuthRADIUS for request $identifier from $ip:$port");
	}
	else
	{
	    # Cross it off our pending list
	    delete $pendingRequests{$key};

	    # sp is the packet we forwarded to the remote radius
	    # op is the original request we received triggered 
	    # this whole thing off
	    my ($op, $sp) = @$ref;
	    # Check out the reply we got
	    my $self = $sp->{ThisAuth};
	    my $host = $sp->{ThisHost};

	    $p->{PacketTrace} = $self->{PacketTrace}
                if defined $self->{PacketTrace}; # Optional extra tracing
	    $self->log($main::LOG_DEBUG,
		       "Received reply in AuthRADIUS for req $identifier from $ip:$port", $p);
	    $self->handleReply($host, $p, $op, $sp);
	}
	return 1; # we got something
    }
}

#####################################################################
# Handle the fact that a reply to a request we are waiting for was 
# received
# $p is the reply packet we just received,
# $op is the original packet from the NAS
# $sp is the request we sent to the remote
sub handleReply
{
    my ($self, $host, $p, $op, $sp) = @_;

    # Cross it of our timeout list
    &Radius::Select::remove_timeout($sp->{TimeoutHandle})
	|| $self->log($main::LOG_ERR, "Timeout $sp->{TimeoutHandle} was not in the timeout list", $p);

    # Drop the reply if it has a bad sig
    # But if IgnoreReplySignature is set, let it through silently
    if ((! $p->check_authenticator($host->{Secret}, $sp->sent_authenticator)) &&
	(! $host->{IgnoreReplySignature}))
    {
	my $identifier = $p->identifier;
	$self->log($main::LOG_WARNING, "Bad authenticator received in reply to ID $identifier. Reply is ignored", $p);
	$op->{RadiusResult} = $main::IGNORE
	    unless defined $op->{RadiusResult};
	return;
    }

    # This host must be OK (again), possible keepalive later
    $host->set_keepalive_timeout();
    $host->{failedRequests} = 0;
    $host->{start_failure_grace_time} = $host->{backoff_until} = time;
    if ($host->{is_failed})
    {
	my ($port, $addr) = Radius::Util::unpack_sockaddr_in($sp->{SendTo});
	my $ip = Radius::Util::inet_ntop($addr);
	$self->log($main::LOG_INFO, "AuthRADIUS $self->{Identifier}: $ip:$port is responding again", $p);
	$host->{is_failed} = 0;
    }

    # Decode and dump the received reply
    $p->decode_attrs($host->{Secret}, $sp, ClearTextTunnelPassword => $self->{ClearTextTunnelPassword});
    $p->recv_debug_dump($self) if (main::willLog($main::LOG_DEBUG, $p));

    # This is a reply to Status-Server probe. It can and should now be discarded.
    return if $op->{is_status_server_probe};

    # Sometimes we use AuthRADIUS as a simple way to send requests to another
    # server. If there is no $p->{rp}, there is no reply to be synthesised, so stop
    return $self->succeeded($host, $p, $op, $sp) unless $op->{rp};

    $p->delete_attr('Proxy-State'); # Any in the reply will be ours. Remove them

    # synthesize a reply 
    # to the original request and send 
    # it back to the original requester. It already has
    # the identifier and authenticator set.
    $op->{rp}->set_code($p->code);
    $op->{rp}->add_attr_list($p);
    $op->{rp}->{UnknownAttributeCount} = $p->{UnknownAttributeCount};
    
    # Add and strip attributes specified in either this AuthRADIUS or the Host before replying
    $self->adjustReply($op), $host->adjustReply($op) if $op->{rp}->code() eq 'Access-Accept';
    
    # Run the reply hook if there is one
    my $redirected;
    $self->runHook('ReplyHook', $p, \$p, \$op->{rp}, \$op, \$sp, $host, \$redirected);
    # If redirected is set, the ReplyHook redirects the request to another AuthBy
    # so we must be sure not to do anything else with this request
    return if $redirected;

    # Maybe cache the results in case we lose contact with 
    # the remote server later
    if ($self->{CachePasswords})
    {
	$self->cacheReply($op, $op->{rp})
	    if $p->code eq 'Access-Accept';
	$self->clearCachedReply($op)
	    if $p->code eq 'Access-Reject';
    }
    
    # RadiusResult tells Synchronous mode that we have
    # finished with this packet and what the result was
    # ReplyHook above could set op->{RadiusResult} to force a 
    # required reponse type
    if (!defined $op->{RadiusResult})
    {
	if ($p->code eq 'Access-Accept'
	    || $p->code eq 'Accounting-Response'
	    || $p->code eq 'Disconnect-Request-ACKed'
	    || $p->code eq 'Change-Filter-Request-ACKed')
	{
	    $op->{RadiusResult} = $main::ACCEPT; 
	}
	elsif ($p->code eq 'Access-Challenge')
	{
	    $op->{RadiusResult} = $main::CHALLENGE; 
	}
	else
	{
	    $op->{RadiusResult} = $main::REJECT; 
	}
    }

    if (! $self->{Synchronous})
    {
	# Send this new reply packet back to wherever the 
	# original packet came from
	my $reason = $p->getAttrByNum($Radius::Radius::REPLY_MESSAGE) || 'Proxied';
	$op->{Handler}->handlerResult
	    ($op, $op->{RadiusResult}, $reason)
               unless (   ($self->{IgnoreReject}
			&& $p->code eq 'Access-Reject')
		       || ($self->{IgnoreAccountingResponse}
			&& $p->code eq 'Accounting-Response'));
    }
    $self->succeeded($host, $p, $op, $sp);
}

#####################################################################
# handle_timeout
# This is called from within Select::process_timeouts for each packet
# we have forwarded but not received a reply within the timeout period
# All we do is call the per-instance method for the instance that
# set the timeout. The args are the same as were passed to add_timeout
# fp is the packet we forwarded, $p is the original request packet, 
sub handle_timeout
{
    my ($handle, $self, $fp, $p) = @_;

    my $host = $fp->{ThisHost};
    my ($port, $addr) = Radius::Util::unpack_sockaddr_in($fp->{SendTo});

    $port = 'BROKENPORT' 
	if $host->{ServerHasBrokenPortNumbers};
    $addr = 'BROKENADDRESS' 
	if $host->{ServerHasBrokenAddresses};
    my $identifier = $fp->identifier;
    my $psid = get_psid($fp); # We may have id in Proxy-State
    $identifier = $psid if $psid;

    my $key = $port.$addr.$identifier;

    if ($fp->{Retries}++ < $host->{Retries})
    {
	# We havent exhausted our retries, retransmit
	my $now = time;

	# REVISIT: need a log message here?

	# Need special treatment for retrans of Accounting-Requests
	# and anything else with Acct-Delay in it. Retransmission
	# requires that Acct-Delay be increased, which requires that
	# the Identifier be changed, which means we have to save
	# a new packet in the PendingRequests list. Gag.
	if (defined $fp->getAttrByNum($Radius::Radius::ACCT_DELAY_TIME))
	{
	    # Remove the old last transmission from our pending list
	    delete $pendingRequests{$key};
	    
	    # Create a new identifier
	    my $identifier = $self->next_identifier($port, $addr);
	    $fp->set_identifier($identifier);

            # If using UseExtendedIds: create a new one!
            if ($host->{UseExtendedIds})
	    {
		my $psid = $self->next_psid($port, $addr);
		$fp->change_attr('Proxy-State', "OSC-Extended-Id=$psid");
		$identifier = $psid;
            }

	    # Change the Acct-Delay Dont lose delay times from
	    # present in the original request
	    my $origdelay = $p->getAttrByNum($Radius::Radius::ACCT_DELAY_TIME);
	    $fp->changeAttrByNum($Radius::Radius::ACCT_DELAY_TIME, 
                $now - $p->{RecvTime} + $origdelay);

	    # Save the new packet in PendingRequests list
	    $pendingRequests{$port.$addr.$identifier} = [$p, $fp];
	}

        $self->log($main::LOG_DEBUG, "Timed out, retransmitting", $p);

	# Now resend it to the same place as before
	$fp->assemble_packet($host->{Secret}, $fp);
	$fp->sendTo($fp->{SendSocket}, $fp->{SendTo}, $p);

	# And register another timeout
	$fp->{TimeoutHandle} = 
	    &Radius::Select::add_timeout($now + $host->{RetryTimeout},
				 \&Radius::AuthRADIUS::handle_timeout,
				 $self, $fp, $p);
    }
    else
    {
	# No reply after all the retries, so 
	# Cross it off our pending list, and try to send
	# it somewhere else
	delete $pendingRequests{$key};
	$self->runHook('ReplyTimeoutHook', $p, \$p, \$fp);
	$self->failed($host, $fp, $p);
    }
}

#####################################################################
# Called after Retries transmissions to a host without
# a response. Decide what to do next.
# Default behaviour is to try to send it to another host
sub failed
{
    my ($self, $host, $fp, $p) = @_;

    my ($port, $addr) = Radius::Util::unpack_sockaddr_in($fp->{SendTo});
    my $ip = Radius::Util::inet_ntop($addr);
    my $delay = time() - $p->{RecvTime};
    my $msg = "AuthRADIUS $self->{Identifier}: No reply after $delay seconds and $host->{Retries} retransmissions to $ip:$port for $p->{OriginalUserName} ($p->{Identifier})";
    # Mark this host down if too many failures over too long a period of time

    if ($host->{UseStatusServerForFailureDetect})
    {
	if ($fp->code() eq 'Status-Server'
	    && ! $host->{is_failed}
	    && ++$host->{failedRequests} >= $host->{MaxFailedRequests}
	    && $host->{start_failure_grace_time} <= time - $host->{MaxFailedGraceTime})
	{
	      $msg .= ". Now have $host->{failedRequests} consecutive failures over $host->{MaxFailedGraceTime} seconds. Backing off until Status-Server gets response";
	      $host->{is_failed} = 1;
	}
    }
    elsif ($host->{FailureBackoffTime} 
	   && ++$host->{failedRequests} >= $host->{MaxFailedRequests} 
	   && $host->{start_failure_grace_time} <= time - $host->{MaxFailedGraceTime})
    {
	$msg .= ". Now have $host->{failedRequests} consecutive failures over $host->{MaxFailedGraceTime} seconds. Backing off for $host->{FailureBackoffTime} seconds";
	$host->{failedRequests} = 0; # For when we restart transmissions
	$host->{backoff_until} = $host->{start_failure_grace_time} = time + $host->{FailureBackoffTime};
	$host->{is_failed} = 1;
    }

    $self->forward($fp, $p) if ($p->code() ne 'Status-Server'); # Try another host if there is one
    $self->log($main::LOG_INFO, $msg, $p);
}

#####################################################################
# Called when a reply is successfully received and after it is relayed
# back to the NAS
# Can be overridden by subclasses
sub succeeded
{
#    my ($self, $host, $p, $op, $sp) = @_;
}

#####################################################################
# Called when no reply is received fromn any of the attempted
# hosts. Default is to run the NoReply hook if there is one
sub noreply
{
    my ($self, $fp, $p) = @_;

    $self->runHook('NoReplyHook', $p, \$p, \$fp, \$p->{rp});
    $self->{Statistics}->{proxiedNoReply}++;
}

#####################################################################
# Look for a previously cached password and reply for this user, and 
# send it back. If not found return undef
sub sendCachedReply
{
    my ($self, $p) = @_;

    my $cachedreply = $self->cachedReply($p);
    if ($cachedreply)
    {
	$self->log($main::LOG_DEBUG, "AuthRADIUS: Using cached reply", $p);	
	$cachedreply->set_identifier($p->identifier());
	$cachedreply->set_authenticator($p->authenticator());
	$p->{rp} = $cachedreply;
	$p->{Handler}->handlerResult($p, $p->{RadiusResult}, 'Proxied');
    }
    return $cachedreply;
}

#####################################################################
# next_identifier
# Return the next identifier to be used 
# Identifiers are in sequence for each unique
# port/address combination
# Identifier 0 is reserved for Status-Server
sub next_identifier
{
    my ($self, $port, $address) = @_;

    return $identifiers{$port.$address} = ($identifiers{$port.$address} % 255) + 1;
}

#####################################################################
# $address is the packed binary address of the dest server
sub next_psid 
{
    my ($self, $port, $address) = @_;
    $psIds{$port.$address}++ if ($psIds{$port.$address} % 256 == 255); # Skip when mod 256 is 0
    return $psIds{$port.$address} = ($psIds{$port.$address} + 1) % 65536;
}

#####################################################################
sub get_psid
{
    my @ps = $_[0]->get_attr("Proxy-State");
    return unless @ps;
    $ps[$#ps] =~ /OSC-Extended-Id=(.*)/;
    return $1;
}

#####################################################################
# forward
# Send the packet to the next host in the list of hosts
# for this RADIUS. We use Retries and hostRetries stored in the 
# forwarded request packet to tell where we are up to in the list
# of hosts and retries for each host
# numTargetHosts allows us to stop forwarding when enough hosts
# have been tried
# $fp is the packet to be sent to the remote server
# $p is the original request packet from the NAS
# Returns true if a target host was found and forwarding occurred
sub forward
{
    my ($self, $fp, $p) = @_;

    my $host;
    $host = $self->chooseHost($fp, $p)
	if (!$self->{MaxTargetHosts} || $fp->{numTargetHosts} < $self->{MaxTargetHosts});

    if ($host)
    {
	# Make sure the host is updated with stats
	push(@{$p->{StatsTrail}}, \%{$host->{Statistics}});

	$fp->{numTargetHosts}++;
	$self->sendHost($host, $fp, $p);
	return 1;
    }
    else
    {
	# Could not find a suitable host, prob because we 
	# exhausted the set of available hosts
	# See if we have a cached reply from before
	if ($self->{CachePasswords})
	{
	    $self->log($main::LOG_INFO, 
		       "AuthRADIUS: No response for $p->{OriginalUserName} ($fp->{Identifier}) from any RADIUS hosts, and no cached password available. Ignoring", $p)
		unless $self->sendCachedReply($p);
	}
	else
	{
             my $delay = time() - $p->{RecvTime}; 
             $self->log($main::LOG_INFO, "AuthRADIUS $self->{Identifier}: Could not find a working host to forward $p->{OriginalUserName} ($fp->{Identifier}) after $delay seconds. Ignoring", $p);
	}

	# See if we are giving up because we have already tried enough Hosts for this request.
	$self->log($main::LOG_INFO, "AuthRADIUS: Request was sent to " . $self->{MaxTargetHosts} . " hosts. MaxTargetHosts reached.")
	    if ($self->{MaxTargetHosts} && $fp->{numTargetHosts} >= $self->{MaxTargetHosts});

	# RadiusResult tells Synchronous mode that we have
	# finished with this packet and what the result was
	$p->{RadiusResult} = $main::IGNORE unless defined $p->{RadiusResult}; 

	# Maybe log failed accounting
	if ($self->{AcctFailedLogFileName}
	    && $p->code eq 'Accounting-Request')
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

	# Run the no-reply hook if there is one
	$self->noreply($fp, $p);

	return;
    }
}

#####################################################################
# chooseHost selects which host to send a packet to.
# Default implementation is to initially choose the first Host named,
# and if that fails, choose the next host in the list
# of Hosts if it is working. Returns a pointer to a Host object if one can be found
# Override this to implement your own host selection algorithm
sub chooseHost
{
    my ($self, $fp, $p) = @_;

    return unless defined $self->{Hosts};
    while ($fp->{hostRetries} < @{$self->{Hosts}})
    {
	my $host = $self->{Hosts}[$fp->{hostRetries}++];
	next unless $host->isWorking();
	return $host;
    }
    return; # None found
}

#####################################################################
# Send $fp to the indicated host for the
# first time. and arrange for retransmit timeouts
sub sendHost
{
    my ($self, $host, $fp, $p) = @_;

    if (!defined $host->{Address})
    {
	$self->log($main::LOG_WARNING, "Host '$host->{Name}' has no IP address. Unable to forward");
	return;
    }

    $fp->{ThisHost} = $host; # Record the Host object we sent it to
    $fp->{Retries} = 0;

    # Choose the "next" address in the round-robin list
    # of addresses within this Host object
    my $addr = @{$host->{Address}}[$host->{roundRobinCounter}++ % @{$host->{Address}}];

    my $port = $fp->code eq 'Accounting-Request' 
	? $host->{AcctPort} : $host->{AuthPort};
    my $destport = &Radius::Util::pack_sockaddr_in($port, $addr);
    
    # Look for tight proxy routing loops
    if ($destport eq $p->{RecvSockname})
    {
	$self->log($main::LOG_WARNING, "RADIUS Proxy to host '$host->{Name}' would create a routing loop. Ignored");
	return;
    }


    # Decode the incoming password and reencode it with the secret
    # for the next hop
    my $password = $p->decodedPassword();
    if (defined $password)
    {
	$fp->changeAttrByNum
	    ($Radius::Radius::USER_PASSWORD, 
	     $fp->encode_password($password, $host->{Secret}, 
				  $host->{UseOldAscendPasswords}));
    }
    
    # Remember it. We keep a hash where the key is the 
    # port and address
    # of the host we sent to, concated with the identifier
    $port = 'BROKENPORT' if $host->{ServerHasBrokenPortNumbers};
    $addr = 'BROKENADDRESS' if $host->{ServerHasBrokenAddresses};

    # Never send Proxy-State from the original request or an earlier Host trasnmission: 
    #$fp->delete_attr('Proxy-State');					# patch RB 2003-08-07

    $fp->delete_attr_fn(
       #sub { my ($name, $value, @args) = @_; return (($name eq 'Proxy-State') && (substr($value, 0, 15) eq 'OSC-Extended-Id')); },
       sub { return ((shift eq 'Proxy-State') && (substr(shift, 0, 15) eq 'OSC-Extended-Id')); },
       undef
    );
    									# end of patch

    # We reserve identifier 0 for Status-Server. Also, no Proxy-State for Status-Server.
    my $identifier = 0;
    if ($fp->code eq 'Status-Server')
    {
	$fp->set_identifier($identifier);
    }
    else
    {
	$identifier = $self->next_identifier($port, $addr);
	$fp->set_identifier($identifier);
	if ($host->{UseExtendedIds}) 
	{
	    my $psid = $self->next_psid($port, $addr);
	    $fp->add_attr("Proxy-State", "OSC-Extended-Id=$psid");
	    $identifier = $psid;
	}
    }

    $pendingRequests{$port.$addr.$identifier} = [$p, $fp];
    
    # and send it
    $fp->assemble_packet($host->{Secret}, $fp);
    $fp->{SendSocket} = $self->getSock($addr, $host);
    if (defined $fp->{SendSocket})
    {
	$fp->sendTo($fp->{SendSocket}, $destport, $p);
    
	# Arrange for retransmission timeout
	# We remember the timeout handle so we can remove 
	# it if we get a reply
	$fp->{TimeoutHandle} = 
	    &Radius::Select::add_timeout
	    (time + $host->{RetryTimeout},
	     \&Radius::AuthRADIUS::handle_timeout,
	     $self, $fp, $p);
    }
}

#####################################################################
# Add a new host to the list of hosts to proxy to.
# The host name is resolved to a list of addresses
# The host name may consist of multiple names separated by 
# commas
# The secret etc default to the ones for the AuthBy RADIUS clause
sub addHost
{
    my ($self, $name, $file, @args) = @_;

    my $object = Radius::Host->new
	($file, $name,
	 'Secret'                     => $self->{Secret},
	 'AuthPort'                   => $self->{AuthPort},
	 'AcctPort'                   => $self->{AcctPort},
	 'Retries'                    => $self->{Retries},
	 'RetryTimeout'               => $self->{RetryTimeout},
	 'UseOldAscendPasswords'      => $self->{UseOldAscendPasswords},
	 'ServerHasBrokenPortNumbers' => $self->{ServerHasBrokenPortNumbers},
	 'ServerHasBrokenAddresses'   => $self->{ServerHasBrokenAddresses},
	 'IgnoreReplySignature'       => $self->{IgnoreReplySignature},
	 'UseExtendedIds'             => $self->{UseExtendedIds},		# RB 2003-08-07
	 'MaxFailedRequests'          => $self->{MaxFailedRequests},
	 'MaxFailedGraceTime'         => $self->{MaxFailedGraceTime},
	 'FailureBackoffTime'         => $self->{FailureBackoffTime},
	 'LocalAddress'               => $self->{LocalAddress},
	 'OutPort'                    => $self->{OutPort},
	 'KeepaliveTimeout'           => $self->{KeepaliveTimeout},
	 'UseStatusServerForFailureDetect' => $self->{UseStatusServerForFailureDetect},
	 'Parent'                     => $self,
	 @args
	 );
    return unless $object;
    $object->activate();
    push(@{$self->{Hosts}}, $object);
    return $object;
}

#####################################################################
# Add new hosts to the list of hosts to proxy to.
# Multiple comma separated names are permitted
# The host name may consist of multiple names separated by 
# commas
# The secret etc default to the ones for the AuthBy RADIUS clause
sub addHosts
{
    my ($self, $name, $file, @args) = @_;

    map {$self->addHost($_, $file, @args)} (split(/\s*,\s*/, &Radius::Util::format_special($name)));
}

#####################################################################
#####################################################################
#####################################################################
# This is where we define the companion class Host
# There is one instance for each <Host> object, and (for backwards
# compatibility) for each comma separated name in a Host parameter
package Radius::Host;
@Radius::Host::ISA = qw(Radius::Configurable);
%Radius::Host::ConfigKeywords = 
(
 @Radius::AuthRADIUS::hostkeywords,
 );

#####################################################################
# Contruct a new Host
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();

    # Permit formatting chars in the host name
    my $name = &Radius::Util::format_special($self->{Name});
    # If there are multiple addresses, remember them 
    # for round-robin
    my ($cname, $aliases, $addrtype, $length, @addrs) = &Radius::Util::gethostbyname($name);

    if (!@addrs)
    {
	# Nothing in the DNS, try to convert from presentation to networkd
	@addrs = Radius::Util::inet_pton($name);
	@addrs = () unless $addrs[0] ne '';
    }
    if (!@addrs)
    {
	# still nothing!
	$self->log($main::LOG_WARNING, "Host '$name' has no IP address at '$main::config_file' line $.");
	return;
    }
    @{$self->{Address}} = @addrs;

    # Permit formatting chars in authn and acct ports
    $self->{AuthPort} = Radius::Util::get_port($self->{AuthPort});
    $self->{AcctPort} = Radius::Util::get_port($self->{AcctPort});

    $self->{start_failure_grace_time} = time;
}

#####################################################################
# Returns true if the host is still deemed to be working
sub isWorking
{
    my ($self) = @_;

    return ! $self->{is_failed} if $self->{UseStatusServerForFailureDetect};

    return time >= $self->{backoff_until};
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
    $self->{Secret} = 'mysecret';
    $self->{AuthPort} = 1645;
    $self->{AcctPort} = 1646;
    $self->{Retries} = 3;    
    $self->{RetryTimeout} = 5;
    $self->{BogoMips} = 1;
    $self->{MaxFailedRequests} = 1;
    $self->{MaxFailedGraceTime} = 0;
    $self->{OutPort} = 0;
}

#####################################################################
# Send a Status-Server as a keepalive
# Set a timeout to make sure it happens again soon
sub send_keepalive
{
    my ($self) = @_;

    # Create and send a Status-Server to this Host
    my $p = Radius::Radius->new($main::dictionary);
    $p->set_code('Status-Server');
    $p->set_authenticator(&Radius::Util::random_string(16));
    $p->{OriginalUserName} = 'Status-Server request';
    $p->add_attr('Message-Authenticator', "\000" x 16); # Will be filled in when proxied
    $p->{RecvTime} = time(); # Creation time in this case
    $p->{is_status_server_probe} = 1;

    my $fp = Radius::Radius->newCopy($p);
    $fp->{ThisAuth} = $self->{Parent}; # The AuthBy that will handle the reply
    $self->{Parent}->sendHost($self, $fp, $p);

    # Cause another one
    $self->set_keepalive_timeout();
}

#####################################################################
# handle_keepalive_timeout
# This is called from within Select::process_timeouts for each packet
# we have forwarded but not received a reply within the timeout period
# All we do is call the per-instance method for the instance that
# set the timeout. The args are the same as were passed to add_timeout
# fp is the packet we forwarded, $p is the original request packet, 
sub handle_keepalive_timeout
{
    my ($handle, $self) = @_;

    $self->log($main::LOG_DEBUG, "Keepalive timeout");
    $self->send_keepalive();
}

#####################################################################
# Set or reset the keepalive timout
sub clear_keepalive_timeout
{
    my ($self) = @_;

    &Radius::Select::remove_timeout($self->{keepaliveTimeoutHandle});
}

#####################################################################
# Set or reset the keepalive timout
sub set_keepalive_timeout
{
    my ($self) = @_;

    # Reset out keepalive timeout
    return unless $self->{KeepaliveTimeout};
    $self->clear_keepalive_timeout();
    $self->{keepaliveTimeoutHandle} =
	&Radius::Select::add_timeout
	(time + $self->{KeepaliveTimeout},
	 \&handle_keepalive_timeout,
	 $self);
}

1;



