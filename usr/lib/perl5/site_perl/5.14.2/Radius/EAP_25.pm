# EAP_25.pm
#
# Radiator module for  handling Authentication via EAP type 25 (PEAP)
# which uses a server certificates to authenticate a tunnel, over which is carried
# some other authenticaiton protocol
#
# See RFCs 2869 2284 1994 2246 2716 draft-josefsson-pppext-eap-tls-eap-0[35].txt
# Note. There is some confusion about which draft version Microsoft actually
# honours in Windows XP SP1. It reports verion 0, which this code interprets as meaning
# draft-josefsson-pppext-eap-tls-eap-03.txt
# See also http://download.microsoft.com/download/9/5/E/95EF66AF-9026-4BB0-A41D-A4F81802D92C/[MS-PEAP].pdf
#
# In XP SP1, tunnelling TLS through PEAP seems to be broken, but tunnelled EAP MSCHAP-V2
# through PEAP works.
#
# Requires Net_SSLeay.pm-1.20 or later
# Requires openssl 0.9.8 or later
# See example in goodies/eap_peap.cfg
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2002 Open System Consultants
# $Id: EAP_25.pm,v 1.52 2014/03/27 21:29:28 hvn Exp $

package Radius::EAP_25;
use Radius::TLS;
use strict;

# RCS version number of this module
$Radius::EAP_25::VERSION = '$Revision: 1.52 $';

$Radius::EAP_25::PEAPVersion0 = 0;
$Radius::EAP_25::PEAPVersion1 = 1;

$Radius::EAP_25::EAPEXTENSIONS_RESULT         = 3; # EAP Extensions acknowledged result
$Radius::EAP_25::EAPEXTENSIONS_RESULT_SUCCESS = 1;
$Radius::EAP_25::EAPEXTENSIONS_RESULT_FAILURE = 2;

#####################################################################
# Called by EAP.pm when the caller wants to know the EAP type name this class supports
sub type_name
{
    my ($classname) = @_;

    return 'PEAP';
}

#####################################################################
# request
# Called by EAP.pm when a request is received for this protocol type
sub request
{
    my ($classname, $self, $context, $p) = @_;

    return $self->eap_error('Unexpected EAP request');
}

#####################################################################
# Called by EAP.pm when an EAP Response/Identity is received
sub response_identity
{
    my ($classname, $self, $context, $p) = @_;

    # Dont make assumptions about versions based on a previous connection.
    $context->{client_peap_version} = undef;
 
    # Initialise our EAP context for use with TLS
    return ($main::REJECT, 'EAP TLS Could not initialise context')
	unless &Radius::TLS::contextInit($context, $self, $p);

    # Maybe require a valid client certificate
    $context->{ssl_verify_mode} |= (&Net::SSLeay::VERIFY_PEER | &Net::SSLeay::VERIFY_FAIL_IF_NO_PEER_CERT)
	if ($self->{EAPTLS_RequireClientCert});

    # Ready to go: acknowledge with a PEAP Start, default version 0
    my $message = pack('C', $Radius::TLS::FLAG_START | $self->{EAPTLS_PEAPVersion});
    $self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_PEAP, $message);
    return ($main::CHALLENGE, 'EAP PEAP Challenge');
}

#####################################################################
# Called by EAP.pm when an EAP Response (other than Identity)
# is received. Handles defragmenting packets. All the fragments
# are concatenated into $context->{data}, which will end up 
# a number of messages, each precended by a 4 byte length
sub response
{
    my ($classname, $self, $context, $p, $type, $typedata) = @_;

    if (!$context->{ssl})
    {
	# Initialise our EAP context for use with TLS
	return ($main::REJECT, 'PEAP Could not initialise context') 
	    unless &Radius::TLS::contextInit($context, $self, $p);
    }

    # Store outer's frag size. It is later needed by us and inner auth
    # protocols with large messages such as EAP-TLS
    my $framedmtu = $p->get_attr('Framed-MTU'); 
    $p->{EAPOuterFragSize} = $self->{EAPTLS_MaxFragmentSize};
    $p->{EAPOuterFragSize} = $framedmtu if defined $framedmtu && $framedmtu < $p->{EAPOuterFragSize};

    # Decode the typedata to get the TLS flags, 
    # the TLS message length (if present) and TLS data (in TLS record format)
    my ($flags) = unpack('C', $typedata);
    my ($tlsdata, $length, $data);
    if ($flags & $Radius::TLS::FLAG_LENGTH_INCLUDED)
    {
	($flags, $length, $tlsdata) = unpack('C N a*', $typedata);
    }
    else
    {
	($flags, $tlsdata) = unpack('C a*', $typedata);
    }
    # Rememeber which version the client supports.
    # Some clients such as cisco dont set the version flags for every packet
    $context->{client_peap_version} = $flags & 0x3 if ($flags & 0x3);

    # Just finished with this request?
    my $handshake_just_finished; 

    # If we actually received anything
    if (length($tlsdata))
    {
	# TLS data is appended to SSL engine read BIO for processing:
	&Net::SSLeay::BIO_write($context->{rbio}, $tlsdata);
	
	if (!($flags & $Radius::TLS::FLAG_MORE_FRAGMENTS))
	{
	    # We must have all of this message set,
	    # so continue with the accept, or read the application data.
	    # It will go as far as it can
	    # and maybe prompt us for more data
	    if ($context->{handshake_finished})
	    {
		my $data = &Net::SSLeay::read($context->{ssl});
		my $errs = &Net::SSLeay::print_errs();
		if ($errs)
		{
		    peap_contextSessionClear($context);
		    $self->log($main::LOG_ERR, "EAP PEAP TLS read failed: $errs");
		    return($main::REJECT, 'EAP PEAP TLS read failed');
		}
		elsif (length $data)
		{
		    return &handle_tls_data($self, $context, $p, $data);
		}
	    }
	    else
	    {
		# Force the openssl internal verification to run on any
		# client cert that may be presented
		&Radius::TLS::set_verify($self, $context, sub {return 0;});

		my $ret = &Net::SSLeay::accept($context->{ssl});
		my $reason = &Net::SSLeay::get_error($context->{ssl}, $ret);
		my $state = &Net::SSLeay::get_state($context->{ssl});
		&Radius::TLS::reset_verify($self, $context);
		$self->log($main::LOG_DEBUG, "EAP TLS SSL_accept result: $ret, $reason, $state");
		if ($ret == 1)
		{
		    # Success, the SSL accept has completed successfully,
		    # therefore the client has verified our credentials.
		    # However, there may be some more data in the output
		    # BIO to send to the client, so we defer the ACCEPT
		    # until it is acked
		    $handshake_just_finished++;
		    $context->{handshake_finished}++;
		}
		elsif ($ret == 0)
		{
		    # Handshake was not successful
		    my $errs = &Net::SSLeay::print_errs();
		    peap_contextSessionClear($context);
		    $self->log($main::LOG_ERR, "EAP PEAP TLS Handshake unsuccessful: $errs");
		    return ($main::REJECT, 'EAP PEAP TLS Handshake unsuccessful');
		}
		elsif ($reason == Net::SSLeay::ERROR_WANT_READ)
		{
		    # Looking for more data, just ack this
		}
		elsif ($reason == Net::SSLeay::ERROR_WANT_WRITE)
		{
		    # Looking for more data, just ack this
		}
		else
		{
		    # Error
		    my $errs = &Net::SSLeay::print_errs();
		    my $verify_result = &Net::SSLeay::get_verify_result($context->{ssl});
		    if ($verify_result)
		    {
			my $verify_error_string = &Radius::TLS::verify_error_string($verify_result);
			$self->log($main::LOG_ERR, "EAP TLS Certificate verification error: $verify_error_string");
		    }
		    else
		    {
			$self->log($main::LOG_ERR, "EAP TLS error: $ret, $reason, $state, $errs");
		    }
		    $self->eap_failure($p->{rp}, $context);
		    peap_contextSessionClear($context);
		    return ($main::REJECT, "EAP PEAP TLS error");
		}
	    }
	}
    }

    # If there are any bytes to send to the peer, get them and
    # package them, else just acknowledge this packet
    if (&Net::SSLeay::BIO_pending($context->{wbio}))
    {
	# Encrypted data to be sent back to the NAS
	return sendPending($self, $context, $p);
    }
    elsif ($handshake_just_finished 
	   && &Net::SSLeay::session_reused($context->{ssl})
	   && $context->{inner_auth_success})
    {
	# Session resumed/reused
	# Create an EAP extension request, acknowledged success, and tunnel it back
	# Client will ack later with an EAP extension reply, acknowledged success
	# This is the same procedure as when inner authentication succeeds
	$p->{rp}->{inner_identity} = $context->{inner_identity};
	eap_extension($self, $context, $p, $Radius::EAP_25::EAPEXTENSIONS_RESULT_SUCCESS);
	Radius::TLS::contextSessionAllowReuse($context);
	return ($main::CHALLENGE, 'EAP PEAP Session resumed');
    }
    elsif ($handshake_just_finished || ($context->{handshake_finished} && (length($tlsdata) == 0)))
    {
	# Got an empty request (prob an ack) 
	# or a reused session with no inner auth, 
	# so tunnel back an identity request
	my $message;
	if ($flags & $Radius::EAP_25::PEAPVersion1)
	{
	    # Send EAP identity request, ID=0 to kick off the inner auth
	    $message = pack('C C n C', 
			    $Radius::EAP::EAP_CODE_REQUEST, 
			    0, # ID
			    5, # length
			    $Radius::EAP::EAP_TYPE_IDENTITY);
	}
	else
	{
	    # Send an eap identity request, without the code, ID or length
	    # This is broken Microsoft PEAP version 0 behaviour
	    $message = pack('C', $Radius::EAP::EAP_TYPE_IDENTITY);
	}
	&Net::SSLeay::write($context->{ssl}, $message);
	&sendPending($self, $context, $p, 1);
    }
    elsif (length($tlsdata))
    {
	# Reply with an EAP ACK in an Access-Challenge
	my $message = pack('C', 0); # ACK
	$self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_PEAP, $message);
	return ($main::CHALLENGE, 'EAP PEAP Challenge');
    }
    else
    {
	return $self->eap_error('EAP PEAP Nothing to read or write');
    }
}

#####################################################################
# The handshake has successfully completed recently and we have 
# received some TLS application data from the client. It will be an EAP message.
sub handle_tls_data
{
    my ($self, $context, $p, $data) = @_;

    # For tunnelled EAP requests, the
    # first byte is the EAP type (identity etc). No request/response code,
    # ID or length
    # For EAP Extensions reponses, it _does_ include the EAP code, id
    # and length. Sigh
    my ($code, $id, $len, $type) = unpack('C C n C ', $data);
    
    # Maybe an EAP extensions response, acknowledging
    # a previous success or failure
    return &handle_eap_extension($self, $context, $p, $data)
	if ($code == $Radius::EAP::EAP_CODE_RESPONSE 
	    && $type == $Radius::EAP::EAP_TYPE_EXTENSIONS);
    
    # else its a tunnelled EAP request. Make a fake radius request with an
    # EAP-Message and pass it on for inner authentication, possibly
    # by a different Handler.
    my $tp = Radius::Radius->new($main::dictionary);
    my $message;
    if ($context->{client_peap_version})
    {
	# This is the inner EAP request
	$message = $data;
    }
    else
    {
	# Sigh: Broken Microsoft PEAP version 0 does not provide EAP headers in the
	# inner request.
	# Important Note: the ID of the outer auth is propagated to inner auth
	# Unless this is done, Windows XP PEAP-MSCHAPV2 does not work, but it seems a bit
	# screwy to me. 
	$message = pack('C C n a*',
		       $Radius::EAP::EAP_CODE_RESPONSE,
		       $context->{this_id},
		       length $data,
		       $data );
    }
    $tp->add_attr('EAP-Message', $message);
    $tp->add_attr('Message-Authenticator', "\000" x 16); # Will be filled in later if proxied
    # Copy other helpful attributes to the inner request
    # Radiator uses these to disambiguate the Context
    foreach ($Radius::Radius::NAS_IP_ADDRESS, 
	     $Radius::Radius::NAS_IDENTIFIER, 
	     $Radius::Radius::NAS_PORT, 
	     $Radius::Radius::CALLING_STATION_ID)
    {
	my $val = $p->getAttrByNum($_);
	$tp->addAttrByNum($_, $val) if defined $val;
    }
    # Prevent inner requests getting the same context as outers, 
    # and get the correct one independent of changes to User-Name
    $tp->{OuterSSL} = $context->{ssl};
    my $inner_context = $self->getEAPContext($tp);
    # Make a fake username for the inner authentication
    my $userName = &Radius::Util::format_special
	($self->{EAPAnonymous}, $p, undef, $inner_context->{identity});
    $tp->changeUserName($userName);
    $tp->{OriginalUserName} = $userName;
    
    $tp->set_code('Access-Request');
    $tp->{Client} = $p->{Client};
    $tp->{RecvTime} = $p->{RecvTime};
    $tp->{tunnelledByPEAP}++;
    $tp->{StatsTrail} = $p->{StatsTrail};
    $tp->{CachedAttrs}{NasId} = $p->getNasId();
    $tp->set_authenticator(&Radius::Util::random_string(16));
    
    if (defined $context->{inner_auth_state}) {
	$tp->add_attr('State', $context->{inner_auth_state});
	$self->log($main::LOG_DEBUG, "Added State for proxied inner auth: " . $context->{inner_auth_state});
	delete $context->{inner_auth_state};
    }

    # Arrange to call our reply function when we get a reply
    $tp->{replyFn} = [\&Radius::EAP_25::replyFn, $context];
    $tp->{outerRequest} = $p;
    $tp->{OriginalUserName} = $userName;
    
    # Call the PreHandlerHook, if there is one
    $self->runHook('PreHandlerHook', $tp, \$tp);

    my ($user, $realmName) = split(/@/, $userName); 
    $self->log($main::LOG_DEBUG, "EAP PEAP inner authentication request for $userName");
    &main::log($main::LOG_DEBUG,"PEAP Tunnelled request Packet dump:\n" . $tp->dump)
	if (&main::willLog($main::LOG_DEBUG, $self));
    my ($handler, $finder, $handled);
    foreach $finder (@Radius::Client::handlerFindFn)
    {
	if ($handler = &$finder($tp, $user, $realmName))
	{
	    # Make sure the handler is updated with stats
	    push(@{$p->{StatsTrail}}, \%{$handler->{Statistics}});
	    
	    # replyFn will be called from inside the handler when the
	    # reply is available
	    $handled = $handler->handle_request($tp);
	    last;
	}
    }

    return ($main::REJECT, "No Handler for PEAP inner authentication")
	unless $handler;
    
    # Sometimes the inner auth requires this to become
    # a challenge
    $handled = $main::CHALLENGE if $tp->{make_a_challenge};
    
    $tp->{proxied}++ if $handled == $main::IGNORE;
    $p->{proxied} = $tp->{proxied}; # Make sure stats are kept correctevert
    return ($handled, "EAP PEAP inner authentication redispatched to a Handler");
    
}

#####################################################################
# Handle a special type 33 TLS extensions request
sub handle_eap_extension
{
    my ($self, $context, $p, $data) = @_;

    my ($code, $id, $len, $type, $avptype, $avplen, $value) = unpack('C C n C n n n', $data);

    # extensions with acknowledged result?
    if (($avptype & 0x3f) == $Radius::EAP_25::EAPEXTENSIONS_RESULT)
    {
	# Extensions result
	if ($value == $Radius::EAP_25::EAPEXTENSIONS_RESULT_SUCCESS
	    && $context->{inner_auth_success})
	{
	    # Acknowledged success
	    # Client acknowledges the success we sent before
	    # Therefore the entire authentication is successful
	    # Sigh. Microsoft PEAP client version 0 uses the _wrong_ keying material

	    $p->{rp}->{inner_identity} = $context->{inner_identity};
	    # These are the reply attributes from the inner auth
	    $p->{rp}->add_attr_list($context->{last_reply_attrs});
	    $self->adjustReply($p);
	    $self->setTLSMppeKeys($context, $p, 
				  ($context->{client_peap_version} == 0 
				   || $self->{EAPTLS_PEAPBrokenV1Label})
				  ? 'client EAP encryption' 
				  : 'client PEAP encryption');
	    $self->eap_success($p->{rp}, $context);
	    &Radius::TLS::contextSessionAllowReuse($context);
	    return ($main::ACCEPT); # Success, all done
	}
	elsif ($value == $Radius::EAP_25::EAPEXTENSIONS_RESULT_FAILURE)
	{
	    # Acknowledged failure
	    # Client acknowledges the failure we sent before
	    peap_contextSessionClear($context);
	    $self->eap_failure($p->{rp}, $context);
	    return ($main::REJECT, 'PEAP Authentication Failure'); # Failed, all done
	}
    }
    peap_contextSessionClear($context);
    $self->eap_failure($p->{rp}, $context);
    return ($main::REJECT, "Unexpected EAP Extensions result: $type, $avptype, $value");
}

#####################################################################
# This is called when a the inner authentication from
# a tunnelled request is completed. It may have been done locally
# or proxied.
# $tp is the (fake) inner request packet containing the tunnelled request attributes
# $op is the original (outer) request
sub replyFn
{
    my ($tp, $context) = @_;

    my $reply_code = $tp->{rp}->code();  # The result of the inner auth
    my $self = $context->{parent};
    my $op = $tp->{outerRequest};

    # May need to confirm the EAP code so we can detect spoofing of the 
    # Radius packet type.
    # The EAP message may need to be concatenated, but getAttrByNum
    # does not support multiple attributes
    my ($name, $rest) = $tp->{rp}->{Dict}->attrByNum($Radius::Radius::EAP_MESSAGE);
    my $eap_reply = join('', $tp->{rp}->get_attr($name));
    my ($code, $xid, $length, $data) = unpack('C C n a*', $eap_reply);

    &main::log($main::LOG_DEBUG,"Returned PEAP tunnelled packet dump:\n" . $tp->{rp}->dump)
	if (&main::willLog($main::LOG_DEBUG, $self));

    if (!$context->{ssl})
    {
	&main::log($main::LOG_INFO,'Received a reply for a PEAP session that has been closed: ignored');
	return;
    }

    # Make inner identity available via context for e.g., logging
    $context->{inner_identity} = $tp->{EAPIdentity};

    if ($reply_code eq 'Access-Reject' 
	|| $code == $Radius::EAP::EAP_CODE_FAILURE)
    {
	# The inner authentication failed
	# Create an EAP extension request, acknowledged failure, and tunnel it back
	# Client will ack later with an EAP extension reply, acknowledged failure
	&eap_extension($self, $context, $op, $Radius::EAP_25::EAPEXTENSIONS_RESULT_FAILURE);
	# Turn the outer reply into a challenge
	$tp->{make_a_challenge}++;
	$op->{Handler}->handlerResult($op, $main::CHALLENGE, 'EAP PEAP Inner authentication failure')
	    if $tp->{proxied};
    }
    elsif ($reply_code eq 'Access-Challenge')
    {
	# If inner authentication was proxied, remote end may have added State
	my $inner_auth_state = $tp->{rp}->get_attr('State');
	if (defined $inner_auth_state) {
	    $self->log($main::LOG_DEBUG,"Saving State from inner authentication: $inner_auth_state");
	    $context->{inner_auth_state} = $inner_auth_state;
	}

	if ($context->{client_peap_version})
	{
	    # Compliant inner authentication, tunnel it back
	    &Net::SSLeay::write($context->{ssl}, $eap_reply);
	}
	else
	{
	    # Broken Microsoft PEAP client doe not have code, ID or length
	    # Strip the code, id and length from the EAP-Message, and tunnel it
	    # back to the client
	    &Net::SSLeay::write($context->{ssl}, $data);
	}
	&sendPending($self, $context, $op, 1);
	$op->{Handler}->handlerResult($op, $main::CHALLENGE, 'EAP PEAP Inner authentication challenged')
	    if $tp->{proxied};
    }
    elsif ($reply_code eq 'Access-Accept' 
	   && $code == $Radius::EAP::EAP_CODE_SUCCESS)
    {
	# The inner authentication succeeded
	$context->{inner_auth_success}++;

	# Create an EAP extension request, acknowledged success, and tunnel it back
	# Client will ack later with an EAP extension reply, acknowledged success
	&eap_extension($self, $context, $op, $Radius::EAP_25::EAPEXTENSIONS_RESULT_SUCCESS);

	# Keep a copy of the all the reply attributes in case this session will be resumed.
	$context->{last_reply_attrs} = Radius::AttrVal->new();
	$context->{last_reply_attrs}->add_attr_list($tp->{rp});

	# Turn the outer reply into a challenge
	$tp->{make_a_challenge}++;
	$op->{Handler}->handlerResult($op, $main::CHALLENGE, 'EAP PEAP Inner authentication success')
	    if $tp->{proxied};
    }
}

#####################################################################
sub eap_extension
{
    my ($self, $context, $op, $result) = @_;

    my $message = pack('C C n C n n n', 
		       $Radius::EAP::EAP_CODE_REQUEST, 
		       $context->{next_id},
		       11,  # length
		       $Radius::EAP::EAP_TYPE_EXTENSIONS, 
		       3 | 0x8000, 2, $result); # ext avptype|mandatory, avplen, value

    &Net::SSLeay::write($context->{ssl}, $message);
    &sendPending($self, $context, $op, 1);
}

#####################################################################
# Send any pending TLS bytes to be sent back to the NAS
# $nolength falg says not to send the length with this request. IN some
# cases XP SP1 assumes the length is not present, and including it will
# prevent interoperation.
sub sendPending
{
    my ($self, $context, $p, $nolength) = @_;

    my $pending = Net::SSLeay::BIO_pending($context->{wbio});
    my $towrite = &Net::SSLeay::BIO_read($context->{wbio}, $p->{EAPOuterFragSize});
    my $more_pending = &Net::SSLeay::BIO_pending($context->{wbio});
    my $flags = $context->{client_peap_version};

    $flags |= $Radius::TLS::FLAG_MORE_FRAGMENTS if $more_pending;
    my $message;
    if ($context->{first_frag} && !$nolength)
    {
	$flags |= $Radius::TLS::FLAG_LENGTH_INCLUDED;
	$message = pack('C N a*', $flags, $pending, $towrite);
    }
    else
    {
	$message = pack('C a*', $flags, $towrite);
    }
    # This tells us if the next fragment will be the first
    # of a new message set:
    $context->{first_frag} = $more_pending ? 0 : 1;

    $self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_PEAP, $message);
    return ($main::CHALLENGE, 'EAP PEAP Challenge');
}

#####################################################################
# For now do some local cleanup here. Later unify with other EAP methods.
sub peap_contextSessionClear
{
  my ($self, $context) = @_;

  $context->{inner_auth_success} = undef;
  Radius::TLS::contextSessionClear($context);

  return;
}

1;
