# EAP_21.pm
#
# Radiator module for  handling Authentication via EAP type 21 (TTLS)
# which uses a server certificates to authenticate a tunnel, over which is carried
# some other authenticaiton protocol
#
# See RFCs 2869 2284 1994 2246 2716 draft-ietf-pppext-eap-ttls-01.txt
#
# Requires Net_SSLeay.pm-1.20 or later
# Requires openssl 0.9.8 or later
# See example in goodies/eap_ttls.cfg
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2002 Open System Consultants
# $Id: EAP_21.pm,v 1.91 2014/04/04 20:17:37 hvn Exp $

package Radius::EAP_21;
use Radius::TLS;
use strict;

# RCS version number of this module
$Radius::EAP_21::VERSION = '$Revision: 1.91 $';

#####################################################################
# Called by EAP.pm when the caller wants to know the EAP type name this class supports
sub type_name
{
    my ($classname) = @_;

    return 'TTLS';
}

#####################################################################
# request
# Called by EAP.pm when a request is received for this protocol type
sub request
{
    my ($classname, $self, $context, $p, $data) = @_;

    return $self->eap_error('Unexpected EAP request');
}

#####################################################################
# Called by EAP.pm when an EAP Response/Identity is received
sub response_identity
{
    my ($classname, $self, $context, $p) = @_;

    # Initialise our EAP context for use with TLS
    return ($main::REJECT, 'EAP TTLS Could not initialise context') 
	unless &Radius::TLS::contextInit($context, $self, $p);

    if ($self->{UseTNCIMV})
    {
	require Radius::TNC;
	$context->{tnc_recommendation} = $Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_NO_ACCESS;
	$context->{tnc_started} = undef;
    }

    # Maybe require a valid client certificate
    $context->{ssl_verify_mode} |= (&Net::SSLeay::VERIFY_PEER | &Net::SSLeay::VERIFY_FAIL_IF_NO_PEER_CERT)
	if ($self->{EAPTLS_RequireClientCert});

    $context->{last_id} = -1; # Prevent duplicate detection of client-hello
    # Ready to go: acknowledge with a TTLS Start
    my $message = pack('C', $Radius::TLS::FLAG_START);
    $self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_TTLS, $message);
    return ($main::CHALLENGE, 'EAP TTLS Challenge');
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
	return ($main::REJECT, 'TTLS Could not initialise context') 
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

    # If we actually received anything
    if (length($tlsdata))
    {
	# TLS data is appended to SSL engine read BIO for processing
	# but prevent duplicates interfering
	my $state = &Net::SSLeay::get_state($context->{ssl});
	$self->log($main::LOG_DEBUG, "EAP TTLS data, $state, $context->{this_id}, $context->{last_id}");
	&Net::SSLeay::BIO_write($context->{rbio}, $tlsdata) 
	    unless $context->{this_id} == $context->{last_id};
	$context->{last_id} = $context->{this_id};

	if (!($flags & $Radius::TLS::FLAG_MORE_FRAGMENTS))
	{
	    # We must have all of this message set,
	    # so continue with the accept, or read the applicaiotn data.
	    # It will go as far as it can
	    # and maybe prompt us for more data
	    if ($context->{handshake_finished})
	    {
		my $data = &Net::SSLeay::read($context->{ssl});
		if (!defined $data)
		{
		    my $errs = &Net::SSLeay::print_errs();
		    &Radius::TLS::contextSessionClear($context);
		    $context->{inner_auth_success} = undef;
		    $self->eap_failure($p->{rp}, $context);
		    return($main::REJECT, "EAP TTLS read failed: $errs");
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
		$state = &Net::SSLeay::get_state($context->{ssl});
		&Radius::TLS::reset_verify($self, $context);

		$self->log($main::LOG_DEBUG, "EAP TTLS SSL_accept result: $ret, $reason, $state");
		if ($ret == 1)
		{
		    # Success, the SSL accept has completed successfully,
		    # therefore the client has verified credentials.
		    # However, there may be some more data in the output
		    # BIO to send to the client, so we defer the ACCEPT
		    # until it is acked
		    $context->{handshake_finished}++;
		    # We never believe the state of the inner authentication unless
		    # this is a resumed session, and its the same session as last time. We
		    # use pointer comparison of the SSL_SESSION to check if its the same session as before
		    my $this_session = &Net::SSLeay::get_session($context->{ssl});
		    my $session_reused = &Net::SSLeay::session_reused($context->{ssl});
		    if (!$session_reused)
		    {
			$context->{inner_auth_success} = undef;
		    }
		    elsif ($this_session != $context->{last_session})
		    {
			&Radius::TLS::contextSessionClear($context);
			$context->{inner_auth_success} = undef;
			$self->eap_failure($p->{rp}, $context);
			return ($main::REJECT, "EAP TTLS failed session reuse");
		    }
		    $context->{last_session} = $this_session;
		}
		elsif ($ret == 0)
		{
		    # Handshake was not successful
		    my $errs = &Net::SSLeay::print_errs();
		    &Radius::TLS::contextSessionClear($context);
		    return ($main::REJECT, "EAP TTLS Handshake unsuccessful: $errs");
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
			$self->log($main::LOG_ERR, "EAP TTLS Certificate verification error: $verify_error_string");
		    }
		    else
		    {
			$self->log($main::LOG_ERR, "EAP TTLS error: $ret, $reason, $state, $errs");
		    }
		    &Radius::TLS::contextSessionClear($context);
		    $context->{inner_auth_success} = undef;
		    $self->eap_failure($p->{rp}, $context);
		    return ($main::REJECT, "EAP TTLS error");
		}
	    }
	}
    }

    # If there are any bytes to send to the peer, get them and
    # package them, else just acknowledge this packet
    my $message;
    if (&Net::SSLeay::BIO_pending($context->{wbio}))
    {
	# Encrypted data to be sent back to the NAS
	return sendPending($self, $context, $p);
    }
    elsif (   $context->{handshake_finished} 
	   && $context->{inner_auth_success})
    {
	# This is an ack after the tunnelling is complete
	# and we have had a successful inner auth, therefore we have complete sucess
	$p->{rp}->add_attr_list($context->{last_reply_attrs});
	$p->{rp}->{inner_identity} = $context->{inner_identity};
	$self->adjustReply($p);
	$self->setTLSMppeKeys($context, $p, 'ttls keying material');

	# Send the EAP success
	$self->eap_success($p->{rp}, $context);

	&Radius::TLS::contextSessionAllowReuse($context);
	return ($main::ACCEPT); # Success, all done
    }
    elsif (length($tlsdata) && !$self->{EAPTTLS_NoAckRequired})
    {
	# Reply with an EAP ACK in an Access-Challenge
	$message = pack('C', 0); # ACK
	$self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_TTLS, $message);
	return ($main::CHALLENGE, 'EAP TTLS Challenge');
    }
    else
    {
	return $self->eap_error('EAP TTLS Nothing to read or write');
    }
}

#####################################################################
# The handshake has successfully completed recently and we have 
# received some TLS application data.
# In TTLS, this is Diameter encoded
# attributes from the supplicant, so we now have
# some inner authentication data to handle.
sub handle_tls_data
{
    my ($self, $context, $p, $data) = @_;
    

    # Create an empty Diameter object, and unpack the attribute data into it
    my $tp = Radius::Radius->new($main::dictionary);
    $tp->unpackDiameterAttrs($data);
    
    # If there are any challenges sent by the client, we are
    # required to confirm that it is the same as the locally generated
    # keying material
    my ($val, $do_tnc);
    if (($val = $tp->getAttrByNum($Radius::Radius::CHAP_CHALLENGE)))
    {
	# We get 17 bytes of keying material. The client should
	# have done the same to create the CHAP challenge and ID
	my ($correct_challenge, $correct_id) 
	    = unpack('a16 C',
		     &Radius::TLS::PRF($context, 'ttls challenge', 17));
	my ($chap_id, $chap_response) = 
	    unpack('C a*', $tp->getAttrByNum($Radius::Radius::CHAP_PASSWORD));
	return ($main::REJECT, "Incorrect CHAP identifier sent by client")
	    unless $chap_id eq $correct_id;
	return ($main::REJECT, "Incorrect CHAP challenge sent by client")
	    unless $val eq $correct_challenge;
    }
    elsif (($val = $tp->get_attr('MS-CHAP-Challenge')))
    {
	if ($tp->get_attr('MS-CHAP2-Response'))
	{
	    # MSCHAP2: We get 9 bytes of keying material. The client should
	    # have done the same to create the MSCHAP challenge and ID
	    my ($correct_challenge, $correct_id) 
		= unpack('a16 C', &Radius::TLS::PRF($context, 'ttls challenge', 17));
	    return ($main::REJECT, "Incorrect MSCHAPV2 challenge sent by client")
		unless $val eq $correct_challenge;
	}
	elsif ($tp->get_attr('MS-CHAP-Response'))
	{
	    # MSCHAP: We get 9 bytes of keying material. The client should
	    # have done the same to create the MSCHAP challenge and ID
	    my ($correct_challenge, $correct_id) 
		= unpack('a8 C',
			 &Radius::TLS::PRF($context, 'ttls challenge', 9));
	    return ($main::REJECT, "Incorrect MSCHAP challenge sent by client")
		unless $val eq $correct_challenge;
	}
    }
    elsif (($val = $tp->getAttrByNum($Radius::Radius::USER_PASSWORD)))
    {
	# Tunneled passwords are plaintext
	$tp->{DecodedPassword} = $tp->getAttrByNum($Radius::Radius::USER_PASSWORD);
	# Sigh, the incoming password may have trailing NULs, which are not
	# stripped out since User-Password is now of type binary in the dictionary
	$tp->{DecodedPassword} =~ s/\0+$//; # Strip trailing NULs
	$tp->changeAttrByNum($Radius::Radius::USER_PASSWORD, '**obscured**');
    }
    elsif ($self->{UseTNCIMV} && 
	   defined $tp->getAttrByNum($Radius::Radius::EAP_MESSAGE))
    {
	# Make sure TNC uses the context from this packet
	# REVISIT: this breaks TLS-like inner auths, who fail to get 
	# the right context
	$tp->{EAPContext} = $context;
    }
    # If there is an EAP-Message, make sure there is also a message authenticator in case
    # it is proxied to a server that requires a message authenticator 
    $tp->addAttrByNum($Radius::Radius::MESSAGE_AUTHENTICATOR, pack('x16'))
	if defined $tp->getAttrByNum($Radius::Radius::EAP_MESSAGE);

    # Now fake up a new request to redespatch to (possibly a new) handler
    $tp->set_code('Access-Request');
    $tp->{Client} = $p->{Client};
    $tp->{RecvTime} = $p->{RecvTime};
    $tp->{tunnelledByTTLS}++;
    $tp->{StatsTrail} = $p->{StatsTrail};
    $tp->{CachedAttrs}{NasId} = $p->getNasId();
    $tp->set_authenticator(&Radius::Util::random_string(16));
    
    if (defined $context->{inner_auth_state}) {
	$tp->add_attr('State', $context->{inner_auth_state});
	$self->log($main::LOG_DEBUG, "Added State for proxied inner auth: " . $context->{inner_auth_state});
	delete $context->{inner_auth_state};
    }

    # Arrange to call our reply function when we get a reply
    $context->{last_reply_attrs} = Radius::AttrVal->new();
    $tp->{replyFn} = [\&Radius::EAP_21::replyFn, $context];
    $tp->{outerRequest} = $p;
    # Make a fake username for the inner authentication
    my $userName = $context->{inner_identity} = $tp->get_attr('User-Name');
    # Prevent inner requests getting the same context as outers, 
    # and get the correct one independent of changes to User-Name
    $tp->{OuterSSL} = $context->{ssl};
    if (!defined $userName)
    {
	my $inner_context = $self->getEAPContext($tp);
	$context->{inner_identity} = $inner_context->{identity};
	$userName = &Radius::Util::format_special
	    ($self->{EAPAnonymous}, $p, undef, $inner_context->{identity});
	$tp->changeUserName($userName);
    }
    $tp->{OriginalUserName} = $userName;

    my ($user, $realmName) = split(/@/, $userName);
    $self->log($main::LOG_DEBUG, "EAP TTLS inner authentication request for $userName");
    my ($handler, $finder, $result);

    # Call the PreHandlerHook, if there is one
    $self->runHook('PreHandlerHook', $tp, \$tp);

    &main::log($main::LOG_DEBUG,"TTLS Tunnelled Diameter Packet dump:\n" . $tp->dump)
	if (&main::willLog($main::LOG_DEBUG, $self));

    # Despatch to a handler if possible
    foreach $finder (@Radius::Client::handlerFindFn)
    {
	if ($handler = &$finder($tp, $user, $realmName))
	{
	    # Make sure the handler is updated with stats
	    push(@{$p->{StatsTrail}}, \%{$handler->{Statistics}});
	    
	    # replyFn will be called from inside the handler when the
	    # reply is available
	    $result = $handler->handle_request($tp);
	    last;
	}
    }
    $p->{proxied} = $tp->{proxied}; # Make sure stats are kept correct
    return ($main::REJECT, "No Handler for TTLS inner authentication")
	unless $handler;
    return ($result, "EAP TTLS inner authentication redispatched to a Handler");
}

#####################################################################
# This is called when a the inner authentication from
# a tunnelled request is completed. It may have been done locally
# or proxied.
# Access-Challenges are tunnelled back to the TLS client
# Accepts for CHAP requests are converted into Challenges, with the reply attrs tunnelled back
# Access-Accept and Access-Reject for the inner auth 
# result in an Access-Accept or Access-Reject radius reply
# to the original sender, including an EAP Success or EAP fail. Reply attributes
# for the inner authentication are copied to the outer authentication reply.
# Reply attributes from challenges are tunnelled too.
# $tp is the (fake) inner request packet containing the tunnelled request attributes
# $op is the original (outer) request
sub replyFn
{
    my ($tp, $context, $result_ref) = @_;

    my $result = $$result_ref;
    my $reason;
    my $self = $context->{parent};
    my $op = $tp->{outerRequest};

    &main::log($main::LOG_DEBUG,"Returned TTLS tunnelled Diameter Packet dump:\n" . $tp->{rp}->dump)
	if (&main::willLog($main::LOG_DEBUG, $self));

    if (!$context->{ssl})
    {
	&main::log($main::LOG_INFO,'Received a reply for a TTLS session that has been closed: ignored');
	return;
    }

    if ($result == $main::ACCEPT)
    {
	if ($self->{UseTNCIMV} && !$context->{tnc_started})
	{
	    # Start an EAP-TNC conversation by faking a 
	    my $type = $Radius::EAP::EAP_TYPE_TNC;
	    my $class = $self->getEAPClass($type);
	    if ($class)
	    {
		$self->log($main::LOG_DEBUG, 'Starting EAP-TNC');
		# Make sure TNC uses the context from this packet
		($result, $reason) = $class->response_identity($self, $context, $tp);
	    }
	    else
	    {
		($result, $reason) = ($main::REJECT, 'Could not load EAP-TNC support');
	    }
	    $context->{tnc_started}++;
	}
	else
	{
	    $context->{inner_auth_success}++;
	}

	# Also copy the reply attrs from the inner request for use later when the 
	# handshake finishes, but dont reveal any MS-CHAP2-Success
	# Override any attrs that were previously set (eg in the case where 
	# TNC follows authentication, allowing TNC to override tunnels etc
	$context->{last_reply_attrs}->add_attr_list($tp->{rp});
	$context->{last_reply_attrs}->delete_attr('MS-CHAP2-Success');
    }

    # MSCHAPV2 Success must be turned into a challenge for positive ack handshake
    # and also need to tunnel the reply items back to the client in a challenge
    if ($result == $main::ACCEPT && $tp->get_attr('MS-CHAP2-Response'))
    {
	$result = $main::CHALLENGE;
	$tp->{rp}->set_code('Access-Challenge');
    }

    # In the case of CHAP challenge (MS-CHAP-V2 or CHAP), need to tunnel the reply
    # items back to the client in a challenge
    if ($result == $main::CHALLENGE)
    {
	# If inner authentication was proxied, remote end may have added State
	my $inner_auth_state = $tp->{rp}->get_attr('State');
	if (defined $inner_auth_state) {
	    $self->log($main::LOG_DEBUG,"Saving State from inner authentication: $inner_auth_state");
	    $context->{inner_auth_state} = $inner_auth_state;
	}

	# Pack the reply attributes into a diameter data stream
	# and send it back to the client in the tunnelled conection
	&Net::SSLeay::write($context->{ssl}, $tp->{rp}->packDiameterAttrs());
	&sendPending($self, $context, $op);
	$tp->{rp}->set_code('Access-Challenge');
	($result, $reason) = ($main::CHALLENGE, 'EAP TTLS Inner authentication challenged');
    }
    elsif ($result == $main::ACCEPT && $context->{inner_auth_success})
    {
	# Copy the reply attributes from the inner reply to the outer reply
	$op->{rp}->{inner_identity} = $context->{inner_identity};
	$op->{rp}->add_attr_list($context->{last_reply_attrs});

	$self->adjustReply($op);
	$self->setTLSMppeKeys($context, $op, 'ttls keying material');

	# Do this last, in case an EAP-Message was in the copied inner attrs
	$self->eap_success($op->{rp}, $context);
	&Radius::TLS::contextSessionAllowReuse($context);
    }
    else
    {
	&Radius::TLS::contextSessionClear($context);
	$context->{inner_auth_success} = undef;
	$self->eap_failure($op->{rp}, $context);
	($result, $reason) = ($main::REJECT, 'EAP TTLS Inner authentication failed');
    }

    $$result_ref = $result;

    # Asynchronous reply? Send result to originator
    $op->{Handler}->handlerResult($op, $result, $reason)
	if $tp->{proxied};	
}

#####################################################################
# Send any pending TLS bytes to be sent back to the NAS
sub sendPending
{
    my ($self, $context, $p) = @_;

    my $pending = Net::SSLeay::BIO_pending($context->{wbio});
    my $towrite = &Net::SSLeay::BIO_read($context->{wbio}, $p->{EAPOuterFragSize});
    my ($flags, $message);
    my $more_pending = &Net::SSLeay::BIO_pending($context->{wbio});
    $flags |= $Radius::TLS::FLAG_MORE_FRAGMENTS
	if $more_pending;
    if ($context->{first_frag})
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

    $self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_TTLS, $message);
    return ($main::CHALLENGE, 'EAP TTLS Challenge');
}

1;
