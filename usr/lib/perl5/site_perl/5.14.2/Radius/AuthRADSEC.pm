# AuthRADSEC.pm
#
# Object for handling Authentication with remote radius servers
# over a singel TCP stream connection.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997-2005 Open System Consultants
# $Id: AuthRADSEC.pm,v 1.51 2014/11/12 20:53:15 hvn Exp $

package Radius::AuthRADSEC;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Radius::RadSec;
use Radius::Radius;
use Radius::Select;
use Radius::TLSConfig;
use Socket;
use Fcntl;
use strict;

@Radius::AuthRADSEC::hostkeywords =
(
 'Secret'                     => 
 ['string', 'This parameter specifies the shared secret that will be used to encrypt passwords and provide basic RADIUS protocol authentication mechanisms for requests and replies passed over the RadSec connection. It must be the same as the Secret configured into the <ServerRADSEC> this clause connects to. The Secret is used to protect passwords even when TLS is not configured for use. If TLS is used, it is not necessary to change it from the default, since the security of TLS does not depend on the shared secret.', 0],

 'Port'                       => 
 ['string', 'This optional parameter specifies the symbolic service name or port number of the port to connect to on Host. Defaults to 2083, the official IANA port number for RadSec.', 1],

 'LocalAddress'                       => 
 ['string', 'This optional parameter specifies the address to bind to the RadSec client source port. Defaults to 0.0.0.0', 2],

 'LocalPort'                       => 
 ['string', 'If LocalAddress is specified, this optional parameter specifies the symbolic service name or port number of the source port. Defaults to 0, which means to allocate a port number automatically.', 2],

 'NoreplyTimeout'             => 
 ['integer', 'If no reply is received to a proxied request within this number of seconds, the request will be sent to the next Host in the list (if any). If there are no further Hosts, the NoReplyHook will be called for this request. Defaults to 5 seconds.', 1],

 'UseStatusServerForFailureDetect'            => 
 ['flag', 'If this flag is enabled, use only Status-Server requests (if any) to determine that a target server is failed when there is no reply. If not enabled (the default) use no reply to any type of request.', 1],

 'KeepaliveTimeout'             => 
 ['integer', 'This optional integer specifies the maximum time in seconds that any connection can be idle before a Status-Server request is sent to keep the TCP connection alive or to check if the peer is alive when UseStatusServerForFailureDetect is enabled. This helps to keep connections open in the face of "smart" firewalls that might try to close idle connections down. Defaults to 0 seconds. If set to 0, keepalives are not used.', 1],

 'FailureBackoffTime'         => 
 ['integer', 'When the Host is deemed to be failed, AuthBy RADSEC will not attempt to send any requests to it until FailureBackoffTime seconds have elapsed. In the meantime, AuthBy RADSEC will attempt to connect or reconnect to the host according to ReconnectTimeout. It will also skip sending requests to that host, and will instead attempt to send to the next Host in its list of Hosts (if any).', 1],

 'MaxBufferSize'              => 
 ['integer', 'Maximum allowable reply size in octets', 1],

 'ReconnectTimeout'           => 
 ['integer', 'This optional parameter specifies the number of seconds to wait before attempting to reconnected a failed, dropped or disconnected RadSec connection.', 1],

 'ConnectOnDemand'            => 
 ['flag', 'This optional parameter tells AuthBy RADSEC not to connect to the RadSec server as soon as possible, but to wait until a request has been reeceived that must be sent to that server. ', 1],

 'Protocol'                   => 
 ['string', 'This optional parameter specifies which Stream protocol will be used to carry RadSec.', 1],

 'MaxFailedRequests'          => 
 ['integer', 'This optional parameter specifies how many requests must fail to receive a reply before the remote radius server is marked as failed, and the FailureBackoffTime will be applied. The default is 1, which means that one ignored request will cause the Host to be marked as failed for FailureBackoffTime seconds.', 1],

 'MaxFailedGraceTime'         => 
 ['integer', 'This optional parameter specifes the time period (in seconds) over which MaxFailedRequests failures will cause the target host to be be assumed to be failed. Defaults to 0. After a host is declared to be failed, no request will be forwarded to it until FailureBackoffTime seconds have elapsed.', 1],

 'UseTLS'                     => 
 ['flag', 'This optional parameter forces the use of TLS for authentication and encryption of the RadSec connection. Requires Net::SSLeay Perl module from CPAN. When this parameter is enabled, the other TLS_* parameters become available for use. Defaults to disabled.', 1],

 @Radius::TLSConfig::clientkeywords,
 );


%Radius::AuthRADSEC::ConfigKeywords = 
('Host'                       => 
 ['stringarray', 'This parameter specifies the host name or address of a RadSec server (i.e. the instance of Radiator with a Server RADSEC clause) that this AuthBy RADSEC is to connect to. The address may be an IPV4 or IPV6 name or address. Multiple Host lines are supported, which is equivalent to specifying multiple <Host> clauses.', 0],

 'HostAddress'                => 
 ['string', 'Internal use only', 3],

 'Hosts'                      => 
 ['objectlist', 'List of RadSec Hosts that this AuthBy RADSEC is to connect to. ', 0],

 'StripFromRequest'           => 
 ['string', 'Strips the named attributes from the request before forwarding it to any Host. The value is a comma separated list of attribute names. StripFromRequest removes attributes from the request before AddToRequest adds any to the request.', 1],

 'AddToRequest'               => 
 ['string', 'Adds attributes to the request before forwarding to any Host. Value is a list of comma separated attribute value pairs all on one line, exactly as for any reply item. StripFromRequest removes attributes from the request before AddToRequest adds any to the request. You can use any of the special % formats in the attribute values. ', 1],

 'IgnoreReject'               => 
 ['flag', 'This optional parameter causes Radiator to ignore (i.e. not send back to the original NAS) any Access-Reject messages received from the remote RadSec server. This is sometimes useful for authenticating from multiple Radius servers. However, you should note that if all the remote radius servers reject the request, then the NAS will receive no reply at all.', 1],

 'IgnoreAccountingResponse'   => 
 ['flag', 'This optional flag causes AuthBy RADSEC to ignore replies to accounting requests, instead of forwarding them back to the originating host. This can be used in conjunction with the AccountingHandled flag in a Handler or Realm (see Section 5.17.10 on page 60) to ensure that every proxied accounting request is replied to immediately, and the eventual reply from the remote RADSEC server is dropped.', 1],

 'ReplyHook'                  => 
 ['hook', 'Perl function that will be called after a reply is received from a remote RadSec server and before it is relayed back to the original client. ', 2],

 'NoReplyHook'                => 
 ['hook', 'Perl function that will be called if no reply is received from any RadSec server. ', 2],

 'NoForwardAuthentication'    => 
 ['flag', 'Stops AuthBy RADSEC forwarding Authentication-Requests. They are ACCEPTED, but no further action is taken with them. This is different in meaning to IgnoreAuthentication, which IGNOREs them.', 1],

 'NoForwardAccounting'        => 
 ['flag', 'Stops AuthBy RADSEC forwarding Accounting-Requests. They are ACCEPTED, but no further action is taken with them. This is different in meaning to IgnoreAccounting, which IGNOREs them. ', 1],

 'AllowInRequest'             => 
 ['string', 'This optional parameter specifies a list of attribute names that are permitted in forwarded requests. Attributes whose names do not apear in this list will be stripped from the request before forwarding.', 1],

# Host defaults:
 @Radius::AuthRADSEC::hostkeywords,
 );

# RCS version number of this module
$Radius::AuthRADSEC::VERSION = '$Revision: 1.51 $';

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
    $self->log($main::LOG_WARNING, "No Hosts defined for AuthRADSEC at '$main::config_file' line $.")
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
    $self->{Secret} = 'radsec';
    $self->{Port} = 2083; # IANA official for RadSec
    $self->{MaxBufferSize} = 100000;
    $self->{Protocol} = 'tcp';
    $self->{NoreplyTimeout} = 5;
    $self->{KeepaliveTimeout} = 0;
    $self->{MaxFailedRequests} = 1;
    $self->{MaxFailedGraceTime} = 0;
    $self->{UseTLS} = 1;
    $self->{_nextpsid} = 0;
}

#####################################################################
# Reinitialize the AuthBy instances
sub reinitialize
{
    # Hosts have backpointers to AuthBys. Disconnect the Hosts from
    # the AuthBys to break the circular references.
    map {$_->{Hosts} = ()} @authbys;
    @authbys = ();

    return;
}
#####################################################################
# Override the object function in Configurable
# Recognise the Host subobject
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

    $self->log($main::LOG_DEBUG, "Handling with Radius::AuthRADSEC", $p);

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
	if ($self->{CachePasswords})
	{
	    my $cachedreply = $self->cachedReply($p);
	    if ($cachedreply)
	    {
		$self->log($main::LOG_DEBUG, "AuthRADSEC: Using cached reply", $p);	
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
    # UseExtendedIds always, and set the identifier to the LSB
    $fp->delete_attr('Proxy-State');					# RB 2003-08-07
    # Timestamp on the wire confuses downstream clients
    $fp->delete_attr('Timestamp');
    my $psid = $self->next_psid();
    $fp->add_attr("Proxy-State", "OSC-Extended-Id=$psid");
    $fp->set_identifier($psid & 0xff);

    # Tell callers the packet was proxied. Some callers like EAP_21 need to know.
    # This will also cause Handler to increment proxiedRequests statistic
    $p->{proxied}++;

    # Remember who this instance of AuthRADSEC is
    $fp->{ThisAuth} = $self;
    
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
	    $self->log($main::LOG_DEBUG, "AuthRADSEC rejected because of an empty password", $p);
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

    # Queue the message regardless of wheterh there is a current connection
    # it may come up soon, at which time all pending requests wiull be sent
    # Currently connected to the RadSec server
    $self->{pendingRequests}{$psid} = [$p, $fp];

    # Choose a target host and send it:
    delete $p->{RadiusResult};
    $self->forward($fp, $p);
    
    return ($main::IGNORE); # Dont reply for us, we will reply later
}

#####################################################################
# handle_noreply_timeout
# This is called from within Select::process_timeouts for each packet
# we have forwarded but not received a reply within the timeout period
# All we do is call the per-instance method for the instance that
# set the timeout. The args are the same as were passed to add_timeout
# fp is the packet we forwarded, $p is the original request packet, 
sub handle_noreply_timeout
{
    my ($handle, $self, $fp, $p) = @_;

    # Try to send it somewhere else
    my $host = $fp->{ThisHost};
    $self->failed($host, $fp, $p);
}

#####################################################################
# Called after Retries transmissions to a host without
# a response. Decide what to do next.
sub failed
{
    my ($self, $host, $fp, $p) = @_;

    my $msg = "AuthRADSEC: No reply from $host->{Host}:$host->{Port} for $p->{OriginalUserName} ($p->{Identifier})";
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
	      $host->stream_disconnected();
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
	$host->stream_disconnected();
    }

    if ($p->code() ne 'Status-Server')
    {
        $self->forward($fp, $p) # No retries on this host, Try another host if there is one
    }
    else
    {
	$host->keepalive_failed($fp, $p);
    }

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

    delete $self->{pendingRequests}{$self->get_psid($fp)};
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
	$self->log($main::LOG_DEBUG, "AuthRADSEC: Using cached reply", $p);	
	$cachedreply->set_identifier($p->identifier());
	$cachedreply->set_authenticator($p->authenticator());
	$p->{rp} = $cachedreply;
	$p->{Handler}->handlerResult($p, $p->{RadiusResult}, 'Proxied');
    }
    return $cachedreply;
}


#####################################################################
# forward
# Send the packet to the next host in the list of hosts
# for this RADIUS. We use Retries and hostRetries stored in the 
# forwarded request packet to tell where we are up to in the list
# of hosts and retries for each host
# $fp is the packet to be sent to the remote server
# $p is the original request packet from the NAS
# Returns true if a target host was found and forwarding occurred
sub forward
{
    my ($self, $fp, $p) = @_;

    my $host = $self->chooseHost($fp, $p);
    if ($host)
    {
	# Make sure the host is updated with stats
	push(@{$p->{StatsTrail}}, \%{$host->{Statistics}});

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
		       'AuthRADSEC: No response from any RADSEC hosts, and no cached password available. Ignoring', $p)
		unless $self->sendCachedReply($p);
	}
	else
	{
	    $self->log($main::LOG_INFO, 
	       'AuthRADSEC could not find a working host to forward to. Ignoring', $p);
	}

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
# of Hosts. Returns a pointer to a Host object if one can be found
# Override this to implement your own host selection algorithm
sub chooseHost
{
    my ($self, $fp, $p) = @_;

    return unless defined $self->{Hosts};
    while ($fp->{hostRetries} < @{$self->{Hosts}})
    {
	my $host = $self->{Hosts}[$fp->{hostRetries}++];
	# Tight routing loop detection
	if ($p->{RecvSockname} eq $host->{PeerName})
	{
	    $self->log($main::LOG_WARNING, "RADSEC Proxy to host '$host->{Name}' would create a routing loop. Ignored");
	    next;
	}
	next unless $host->isWorking();
	return $host;
    }

    return; # None found
}

#####################################################################
# Send $fp to the indicated host. Arrange for a timeout if we
# dont hear back
sub sendHost
{
    my ($self, $host, $fp, $p) = @_;

    $fp->{ThisHost} = $host; # Record the Host object we sent it to
    $fp->{Retries} = 0;

    # Decode the incoming password and reencode it with the secret
    # for the next hop
    my $password = $p->decodedPassword();
    if (defined $password)
    {
	$fp->changeAttrByNum
	    ($Radius::Radius::USER_PASSWORD, $fp->encode_password($password, $host->{Secret}));
    }
    
    # Make sure the client starts to connect, if not already connected
    $host->stream_connect() unless $host->isconnected();

    # and send it. Format dumps only when they are really logged
    if (main::willLog($main::LOG_DEBUG, $fp))
    {
	my $text = "Packet dump:\n*** Sending request to RadSec $host->{Host}:$host->{Port} ....\n" .
	    $fp->dump;
	$self->log($main::LOG_DEBUG, $text, $fp);
    }
    my $msg = $fp->assemble_packet($host->{Secret}, $fp);
    $host->write($msg);

    # Arrange for retransmission timeout
    # We remember the timeout handle so we can remove 
    # it if we get a reply
    # Arrange for noreply retransmission timeout
    # We remember the timeout handle so we can remove 
    # it if we get a reply
    $fp->{noreplyTimeoutHandle} = 
	&Radius::Select::add_timeout
	(time + $host->{NoreplyTimeout},
	 \&handle_noreply_timeout,
	 $self, $fp, $p);
    
}

#####################################################################
# Called when a complete reply has been received. Despatch it
sub recv
{
    my ($self, $host, $p) = @_;

    $p->{PacketTrace} = $self->{PacketTrace}
        if defined $self->{PacketTrace}; # Optional extra tracing

    my $identifier = $p->identifier; # 0 is special: Status-Server response
    $identifier = $self->get_psid($p) if $identifier; # If not 0, get the extended id
    my $key = ($identifier) ? $identifier : "0:$host";

    # Cross it off our pending list
    my $ref = delete $self->{pendingRequests}{$key};
    if (!defined $ref)
    {
	$self->log($main::LOG_WARNING, "Unknown reply received in AuthRADSEC for request $identifier from $host->{Host}:$host->{Port}", $p);
    }
    else
    {
	$self->log($main::LOG_DEBUG, "Received reply in AuthRADSEC for req $identifier from $host->{Host}:$host->{Port}", $p);

	# sp is the packet we forwarded to the remote radius
	# op is the original request we received triggered 
	# this whole thing off
	my ($op, $sp) = @$ref;
	$self->handleReply($host, $p, $op, $sp);
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
    &Radius::Select::remove_timeout($sp->{noreplyTimeoutHandle})
	|| $self->log($main::LOG_ERR, "Timeout $sp->{noreplyTimeoutHandle} was not in the timeout list", $p);

    # Drop the reply if it has a bad sig
    if (! $p->check_authenticator($host->{Secret}, $sp->sent_authenticator))
    {
	my $identifier = $p->identifier;
	$self->log($main::LOG_WARNING, "Bad authenticator received in reply to ID $identifier. Reply is ignored", $p);
	return;
    }

    # This host must be OK (again), possible keepalive later
    $host->set_keepalive_timeout();
    $host->{failedRequests} = 0;
    $host->{start_failure_grace_time} = $host->{backoff_until} = time;
    if ($host->{is_failed})
    {
	$self->log($main::LOG_INFO, "AuthRADSEC $self->{Identifier}: $host->{Host}:$host->{Port} is responding again", $p);
	$host->{is_failed} = 0;
    }

    # Sometimes we use AuthRADIUS as a simple way to send requests to another
    # server. If there is no $p->{rp}, there is no reply to be synthesised, so stop
    return $self->succeeded($host, $p, $op, $sp) unless $op->{rp};

    # synthesize a reply 
    # to the original request and send 
    # it back to the original requester. It already has
    # the identifier and authenticator set.
    $op->{rp}->set_code($p->code);

    # Decode and dump the received reply
    $p->decode_attrs($host->{Secret}, $sp, ClearTextTunnelPassword => $self->{ClearTextTunnelPassword});
    $p->recv_debug_dump($self) if (main::willLog($main::LOG_DEBUG, $p));

    # This is a reply to Status-Server probe. It can and should now be discarded.
    return if $op->{is_status_server_probe};

    # Add the attributes from the reply
    $op->{rp}->add_attr_list($p);
    $op->{rp}->{UnknownAttributeCount} = $p->{UnknownAttributeCount};
    
    # Add and strip attributes specified in either this AuthRADIUS or the Host before replying
    $self->adjustReply($op), $self->adjustReply($op) if $op->{rp}->code() eq 'Access-Accept';
    
    # Run the reply hook if there is one
    $self->runHook('ReplyHook', $p, \$p, \$op->{rp}, \$op, \$sp, $host);
    
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
	    || $p->code eq 'Disconnect-Request-ACKed')
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

    # Send this new reply packet back to wherever the 
    # original packet came from
    my $reason = $p->getAttrByNum($Radius::Radius::REPLY_MESSAGE) || 'Proxied';
    $op->{Handler}->handlerResult
	($op, $op->{RadiusResult}, $reason)
	unless (   ($self->{IgnoreReject}
		    && $p->code eq 'Access-Reject')
		   || ($self->{IgnoreAccountingResponse}
		       && $p->code eq 'Accounting-Response'));

    $self->succeeded($p, $op, $sp);
}

#####################################################################
# Identifier 0 is reserved for Status-Server messages
sub next_psid 
{
    my ($self) = @_;
    $self->{_nextpsid}++ if ($self->{_nextpsid} % 256 == 255); # Skip when mod 256 is 0
    return $self->{_nextpsid} = ($self->{_nextpsid} + 1) % 65536;
}

#####################################################################
# Returns extended ID value from Proxy-State attribute.
# Returns undef in case of errors.
sub get_psid
{
    my ($self, $p) = @_;

    my @ps = $p->get_attr("Proxy-State");
    unless (@ps)
    {
	$self->log($main::LOG_WARNING, "AuthRADSEC Could not get extended identifier: No Proxy-State attribute found in reply", $p);
	return;
    }
    $ps[$#ps] =~ /OSC-Extended-Id=(.*)/;

    $self->log($main::LOG_WARNING, "AuthRADSEC Could not get extended identifier from Proxy-State value: " . $ps[$#ps], $p)
	unless $1;
    return $1;
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

    my $object = Radius::RadsecHost->new
	($file, $name,
	 'HostAddress'                => $self->{HostAddress},
	 'Secret'                     => $self->{Secret},
	 'Port'                       => $self->{Port},
	 'LocalAddress'               => $self->{LocalAddress},
	 'LocalPort'                  => $self->{LocalPort},
	 'NoreplyTimeout'             => $self->{NoreplyTimeout},
	 'KeepaliveTimeout'           => $self->{KeepaliveTimeout},
	 'UseStatusServerForFailureDetect' => $self->{UseStatusServerForFailureDetect},
	 'FailureBackoffTime'         => $self->{FailureBackoffTime},
	 'MaxBufferSize'              => $self->{MaxBufferSize},
	 'ReconnectTimeout'           => $self->{ReconnectTimeout},
	 'ConnectOnDemand'            => $self->{ConnectOnDemand},
	 'Protocol'                   => $self->{Protocol},
	 'UseTLS'                     => $self->{UseTLS},
	 'TLS_CAFile'                 => $self->{TLS_CAFile},
	 'TLS_CAPath'                 => $self->{TLS_CAPath},
	 'TLS_CertificateFile'        => $self->{TLS_CertificateFile},
	 'TLS_CertificateChainFile'   => $self->{TLS_CertificateChainFile},
	 'TLS_CertificateType'        => $self->{TLS_CertificateType},
	 'TLS_PrivateKeyFile'         => $self->{TLS_PrivateKeyFile},
	 'TLS_PrivateKeyPassword'     => $self->{TLS_PrivateKeyPassword},
	 'TLS_RandomFile'             => $self->{TLS_RandomFile},
	 'TLS_DHFile'                 => $self->{TLS_DHFile},
	 'TLS_ECDH_Curve'             => $self->{TLS_ECDH_Curve},
	 'TLS_CRLCheck'               => $self->{TLS_CRLCheck},
	 'TLS_CRLFile'                => $self->{TLS_CRLFile},
	 'TLS_SessionResumption'      => $self->{TLS_SessionResumption},
	 'TLS_SessionResumptionLimit' => $self->{TLS_SessionResumptionLimit},
	 'TLS_ExpectedPeerName'       => $self->{TLS_ExpectedPeerName},
	 'TLS_SubjectAltNameURI'      => $self->{TLS_SubjectAltNameURI},
	 'TLS_CertificateFingerprint' => $self->{TLS_CertificateFingerprint},
	 'TLS_PolicyOID'              => $self->{TLS_PolicyOID},
	 'TLS_SRVName'                => $self->{TLS_SRVName},
	 'MaxFailedRequests'          => $self->{MaxFailedRequests},
	 'MaxFailedGraceTime'         => $self->{MaxFailedGraceTime},
	 'Parent',                    => $self,
	 @args
	 );
    return unless $object;
    $object->activate();
    push(@{$self->{Hosts}}, $object);
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

    map {$self->addHost($_, $file, @args)} (split(/\s*,\s*/, $name));
}

#####################################################################
#####################################################################
#####################################################################
# This is where we define the companion class Host
# There is one instance for each <Host> object, and (for backwards
# compatibility) for each comma separated name in a Host parameter
package Radius::RadsecHost;
@Radius::RadsecHost::ISA = qw(Radius::Configurable Radius::RadSec);
%Radius::RadsecHost::ConfigKeywords = 
(
 @Radius::AuthRADSEC::hostkeywords
 );

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();
    # Permit formatting chars in the host name
    $self->{Host} = &Radius::Util::format_special($self->{Name});

    if ($self->{UseTLS})
    {
	if (!eval("require Radius::StreamTLS"))
	{
	    $self->log($main::LOG_ERR, "AuthRADSEC $self->{Name} has UseTLS, but could not load required modules: $@");
	}
	else
	{
	    Radius::StreamTLS::init($self);
	}
    }
    $self->stream_connect() unless $self->{ConnectOnDemand};
    $self->{start_failure_grace_time} = time;
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
    $self->{Port} = 2083; # IANA official for RadSec
    $self->{MaxBufferSize} = 100000;
    $self->{Protocol} = 'tcp';
    $self->{NoreplyTimeout} = 5;
    $self->{MaxFailedRequests} = 1;
    $self->{MaxFailedGraceTime} = 0;
}

#####################################################################
# Called when a complete reply octet stream has been received
# unpack it and give it to the parent
sub recv
{
    my ($self, $rec) = @_;

    my $p = Radius::Radius->new($main::dictionary, $rec, $self->{PeerName});
    my $parent = $self->{Parent};
    $parent->recv($self, $p);
}

sub stream_connected
{
    my ($self) = @_;

    # If Status-Server is used for failure detect, we do not need to
    # worry about setting the keep-alive timer. In case we do not use
    # Status-Server for failure detect, we may still be configured to
    # run keep-alives.
    $self->set_keepalive_timeout() unless $self->{UseStatusServerForFailureDetect};
    $self->SUPER::stream_connected()
}

sub stream_disconnected
{
    my ($self) = @_;
    $self->SUPER::stream_disconnected()
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
# Send a Status-Server as a keepalive
# Set a timeout to make sure it happens again soon
sub send_keepalive
{
    my ($self) = @_;

    # Send a Status-Server
    my $p = Radius::Radius->new($main::dictionary);
    $p->set_code('Status-Server');
    $p->set_authenticator(&Radius::Util::random_string(16));
    $p->{OriginalUserName} = 'Status-Server request';
    $p->add_attr('Message-Authenticator', "\000" x 16); # Will be filled in when proxied

    $p->{RecvTime} = time(); # Creation time in this case
    $p->{is_status_server_probe} = 1;

    my $fp = Radius::Radius->newCopy($p);
    $fp->{ThisAuth} = $self->{Parent}; # The AuthBy that will handle the reply

    # We reserve identifier 0 for Status-Server. This also means we
    # need to somehow differentiate between Status-Server messages
    # sent to different hosts. We use stringified $host for this.
    $fp->set_identifier(0);
    $self->{Parent}->{pendingRequests}{"0:$self"} = [$p, $fp];
    $self->{Parent}->sendHost($self, $fp, $p);

    # Cause another one
    $self->set_keepalive_timeout();
}

#####################################################################
# Keepalive failed to get a response after retries
sub keepalive_failed
{
    my ($self, $fp, $p) = @_;

    delete $self->{Parent}->{pendingRequests}{"0:$self"};

    return;
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

sub DESTROY
{
    my ($self) = @_;

    # Decrement the SSL reference counts or otherwise we get a memory
    # leak when reinitialising.
    $self->stream_disconnected();
    Net::SSLeay::CTX_free($self->{ssl_ctx_streamtls}) if $self->{ssl_ctx_streamtls};

    return;
}

1;
