# EAP_43.pm
#
# Module for  handling Authentication via EAP type 43
# (EAP-FAST)
# Requires Digest-MD4, Net-SSLeay and OpenSSL (including patches to support 
# SESSION_set_master_key set_session_secret_cb)
#
# See RFCs 4851 and 5422
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001 Open System Consultants
# $Id: EAP_43.pm,v 1.23 2014/04/13 19:13:07 hvn Exp $

package Radius::EAP_43;
use Digest::HMAC_SHA1;
use Radius::TLS;
use strict;

# RCS version number of this module
$Radius::EAP_43::VERSION = '$Revision: 1.23 $';

$Radius::EAP_43::FASTVersion1 = 1;

# Application ID and Application ID info
my ($a_id, $a_id_info);

#####################################################################
# Called by EAP.pm when the caller wants to know the EAP type name this class supports
sub type_name
{
    my ($classname) = @_;

    return 'FAST';
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
# $secret is the current secret, usually all 0s
# $ciphers is ref to an array of peer cipher names
# $pref_cipher is a ref to an index into the list of cipher names of 
#  the preferred cipher. Set it if you want to specify a preferred cipher
# $context is the data passed to set_session_secret_cb
sub session_secret_cb
{
    my ($secret, $ciphers, $pref_cipher, $context) = @_;

    if ($context && $context->{ssl} && defined $context->{pac_key})
    {
	my $client_random = &Net::SSLeay::get_client_random($context->{ssl});
	my $server_random = &Net::SSLeay::get_server_random($context->{ssl});
	my $session = &Net::SSLeay::get_session($context->{ssl});
	my $master_secret = &T_PRF($context->{pac_key}, 
				   'PAC to master secret label hash',
				   $server_random . $client_random, 48);
	&Net::SSLeay::SESSION_set_master_key($session, $master_secret);
	return 1; # Tell OpenSSL we like these ciphers
    }
    return 0; 
}

#####################################################################
# Called by EAP.pm when an EAP Response/Identity is received
sub response_identity
{
    my ($classname, $self, $context, $p) = @_;

    # Initialise our EAP context for use with TLS
    return ($main::REJECT, 'EAP-FAST Could not initialise context') 
	unless &Radius::TLS::contextInit($context, $self, $p);

    return ($main::REJECT, 'EAP-FAST Requires Net::SSLeay::set_session_secret_cb. Upgrade or patch your OpenSSL and/or Net-SSLeay') 
	unless exists &Net::SSLeay::set_session_secret_cb;

    # (re)init state
    delete $context->{inner_identity};
    delete $context->{anonymous_provisioning};
    delete $context->{pac_key};
    delete $context->{inner_auth_success};

    # The default assumption is to provision a PAC unless the client offers a 
    # valid PAC with more than EAPFAST_PAC_Reprovision lifetime left.
    $context->{provisioning} = 1; 

    # Caution, do we need to clear this CB when the session is deleted else get
    # a leak in Net-SSLeay?
    &Net::SSLeay::set_session_secret_cb($context->{ssl}, \&session_secret_cb, $context);
    # Permit the unauthenticated ciphers
    &Net::SSLeay::set_cipher_list($context->{ssl}, 'ADH-AES128-SHA:DHE-RSA-AES128-SHA:AES128-SHA:RC4-SHA');

    $context->{last_reply_attrs} = Radius::AttrVal->new();

    # Determine the application id.
    $a_id_info = $main::hostname unless defined $a_id_info;
    $a_id = Digest::MD5::md5($a_id_info);

    # Send the FAST start: V=1 (EAP-FAST Start, S bit set, A-ID)
    # Odyssey Client Manager likes to see the A_ID_INFO in the start 
    # as well as the required A_ID, 
    # so it can display the server name in the 'Acquire new credentials' dialog
    my $message = pack('C n n a* n n a*', 
		       $Radius::TLS::FLAG_START | $Radius::EAP_43::FASTVersion1,
		       $Radius::EAP_43::PAC::A_ID, 
		       length($a_id), $a_id,
		       $Radius::EAP_43::PAC::A_ID_INFO, 
		       length($a_id_info), $a_id_info);


    $self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_FAST, $message);
    return ($main::CHALLENGE, 'EAP-FAST Challenge');
}

#####################################################################
# Called by EAP.pm when an EAP Response (other than Identity)
# is received
sub response
{
    my ($classname, $self, $context, $p, $type, $typedata) = @_;

    return $self->eap_error('TLS not initialised')
	unless $context->{ssl};

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

    # REVISIT: inspect any ClientHello to see whether we are doing anauthenticated
    # provisioning, and whether the clinet has sent a previously provisioned PAC
    # or not
    &check_client_hello($self, $context, $p, $tlsdata)
	if length($tlsdata);

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
		    $self->log($main::LOG_ERR, "EAP-FAST TLS read failed: $errs");
		    return($main::REJECT, 'EAP-FAST TLS read failed');
		}
		elsif (length $data)
		{
		    return &handle_tls_data($self, $context, $p, $data);
		}
	    }
	    else
	    {
		my $ret = &Net::SSLeay::accept($context->{ssl});
		my $reason = &Net::SSLeay::get_error($context->{ssl}, $ret);
		my $state = &Net::SSLeay::get_state($context->{ssl});
		$self->log($main::LOG_DEBUG, "EAP-FAST SSL_accept result: $ret, $reason, $state");
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
		    &Radius::TLS::contextSessionClear($context);
		    $self->log($main::LOG_ERR, "EAP-FAST TLS Handshake unsuccessful: $errs");
		    return ($main::REJECT, 'EAP-FAST TLS Handshake unsuccessful');
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
			return &fail($self, $context, $p, 
				     'EAP-FAST Certificate verification error: '
				     . &Radius::TLS::verify_error_string($verify_result));
		    }
		    else
		    {
			return &fail($self, $context, $p, "EAP-FAST error: $ret, $reason, $state, $errs");
		    }
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
    elsif ($handshake_just_finished || ($context->{handshake_finished} && (length($tlsdata) == 0)))
    {
	# Handshake just finished and a fast reconnect, or else
	# Got an empty request, prob an ACK, so tunnel back an identity request

	# Generate the session key seed and the MSCHAPV2 challenges 
	# from the TLS master key. Caution, these keys must be extracted 
	# from after the standard TLS keyblocksie for the cipher and hash 
	# currently in use.
	# $server_challenge is the MSCHAPV2 auth_challenge
	# $client_challenge is the MSCHAPV2 peer_challenge
	my $keyblock_size = &Net::SSLeay::get_keyblock_size($context->{ssl});
	my $keys = &PRF($context, 'key expansion', $keyblock_size + 72);

	# Remove the TLS keyblock
	substr($keys, 0, $keyblock_size) = '';
	my ($sks, $server_challenge, $client_challenge) = 
	    unpack('a40 a16 a16', $keys);
	$context->{eap_fast_inner_method_index} = 0;
	$context->{SIMCK}[0] = $sks;
	$context->{server_challenge} = $server_challenge;
	$context->{client_challenge} = $client_challenge;

	# Send EAP identity request, ID=0 to kick off the inner auth,
	# Encapsulated in an EAP-FAST TLV
	my $message = pack('C C n C', 
			   $Radius::EAP::EAP_CODE_REQUEST, 
			   0, # ID
			   5, # length
			   $Radius::EAP::EAP_TYPE_IDENTITY);

	my $reply_tlv = Radius::EAP_43::TLV->new();
	$reply_tlv->add($Radius::EAP_43::TLV::EAP_PAYLOAD, $message);
	&Net::SSLeay::write($context->{ssl}, $reply_tlv->pack());
	&sendPending($self, $context, $p, 1);
    }
    else
    {
	return $self->eap_error('EAP FAST Nothing to read or write');
    }
}

#####################################################################
# Inspect TLS message, to see if its a client_hello that we need to inspect
# We could have done this in a hello_extension callback, but its a bit easier
# to inspect it directly, so we can do logging etc
sub check_client_hello
{
    my ($self, $context, $p, $tlsdata) = @_;

    my ($tlstype, $tlsmajor, $tlsminor, $tlslength, $handshake) = unpack('C C C n a*', $tlsdata);
    if ($tlstype == 22 && $tlsmajor == 3 && $tlsminor == 1)
    {
	my ($typelen, $tlsclientmajor, $tlsclientminor, $client_hello) 
	    = unpack('N C C a*', $handshake);
	if ($typelen >> 24 == 1 && $tlsclientmajor == 3 && $tlsclientminor == 1)
	{
	    my $hellolen = $typelen & 0xffffff;
	    my ($time, $random, $sessionid, $ciphersuites, $compressions, $extensions) 
		= unpack('N a28 C/a n/a C/a a*', $client_hello);
	    
	    my @ciphersuites = unpack('n*', $ciphersuites);
	    # Look for a request for Server-Unauthenticated Provisioning based
	    # on a request for the anonymous provisioning ciphersuite
	    if (grep {$_ == 52} @ciphersuites)
	    {
		# Wants ADH-AES128-SHA, which means 
		$self->log($main::LOG_DEBUG, 'Enable Server-Unauthenticated Provisioning mode');
		$context->{anonymous_provisioning}++;
	    }
	    
	    $extensions = unpack('n/a', $extensions)
		if length($extensions) >= 2;
	    while (length($extensions) >= 4)
	    {
		my ($ext_type, $ext_data) = unpack('n n/a', $extensions);
		if ($ext_type == $Radius::TLS::EXT_TYPE_SESSION_TICKET)
		{
		    my ($esubtype, $length, $pac_opaque) = unpack('n n a*', $ext_data);
		    if ($esubtype == $Radius::EAP_43::PAC::OPAQUE
			&& $length == length($pac_opaque))
		    {
			$self->log($main::LOG_DEBUG, "EAP-FAST received PAC_OPAQUE");
			# Use pac_opaque as a key to find the session master key 
			# to use for this session
			my $pac = $self->get_eapfast_pac($pac_opaque, $p);
			if ($pac)
			{
			    $self->log($main::LOG_DEBUG, "EAP-FAST requested PAC found");
			    $context->{pac_key} = $pac->{pac_key};
			    # Check the lifetime for reprovision
			    $context->{provisioning} = 0
				if $pac->{pac_lifetime} - time() 
				> $self->{EAPFAST_PAC_Reprovision};
			}
			else
			{
			    # Should now fall through to full certificate 
			    # based auth?
			    $self->log($main::LOG_DEBUG, "EAP-FAST requested PAC not found");
			}
		    }
		    
		}
		$extensions = substr($extensions, length($ext_data) + 4);
	    }
	    $self->log($main::LOG_DEBUG, "EAP-FAST a new PAC will be provisioned") 
		if $context->{provisioning};
	}
    }
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
    my $framedmtu = $p->get_attr('Framed-MTU'); 
    my $maxfrag = $self->{EAPTLS_MaxFragmentSize};
    $maxfrag = $framedmtu if defined $framedmtu && $framedmtu < $maxfrag;
    my $towrite = &Net::SSLeay::BIO_read($context->{wbio}, $maxfrag);
    my $more_pending = &Net::SSLeay::BIO_pending($context->{wbio});
    my $flags = $Radius::EAP_43::FASTVersion1 = 1;

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

    $self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_FAST, $message);

    return ($main::CHALLENGE, 'EAP-FAST Challenge');
}

#####################################################################
# The handshake has successfully completed recently and we have 
# received some TLS application data from the client. It will be an EAP message.
sub handle_tls_data
{
    my ($self, $context, $p, $data) = @_;

    $self->log($main::LOG_DEBUG, 'EAP-FAST TLS data: ' . unpack('H*', $data));

    my $tlv = Radius::EAP_43::TLV->new();
    my @errors = $tlv->parse($data);
    if (@errors)
    {
	# There were mandatory TLVs we didnt understand
	my $reply_tlv = Radius::EAP_43::TLV->new();
	foreach (@errors)
	{
	    $reply_tlv->add($Radius::EAP_43::TLV::NAK, pack('N n', 0, $_));
	}
	&Net::SSLeay::write($context->{ssl}, $reply_tlv->pack());
	&sendPending($self, $context, $p);
	return ($main::CHALLENGE, 'EAP-FAST NAK');
    }

    my ($t, @t);
    if (@t = $tlv->get($Radius::EAP_43::TLV::ERROR))
    {
	foreach (@t)
	{
	    my $error_code = unpack('N', $_->[1]);
	    if ($error_code >= 2000 && $error_code <= 2999)
	    {
		return &fail($self, $context, $p, 'EAP-FAST peer ERROR indication');
	    }
	    elsif ($error_code >= 1000 && $error_code <= 1999)
	    {
		$self->log($main::LOG_WARNING, "EAP-FAST peer ERROR indication $error_code");
	    }
	    else
	    {
		$self->log($main::LOG_INFO, "EAP-FAST peer ERROR indication $error_code");
	    }
	}
    }
    elsif ($t = $tlv->get($Radius::EAP_43::TLV::NAK))
    {
	# Got a NAK from the peer
	my ($vendor, $nak_type, $tlvs) = unpack('N n a*', $t->[1]);
	
	return &fail($self, $context, $p, "EAP-FAST Peer NAK received: $vendor, $nak_type");
    }
    
    if (@t = $tlv->get($Radius::EAP_43::TLV::PAC))
    {
	# Cisco SSC can send multiple PACs
	foreach (@t)
	{
	    my $pac = Radius::EAP_43::PAC->new($_->[1]);
	    my ($p, @p);
	    if ($p = $pac->get($Radius::EAP_43::PAC::ACKNOWLEDGEMENT))
	    {
		my $val = unpack('n', $p->[1]);
		$self->log($main::LOG_DEBUG, "EAP-FAST PAC ACK $val");
	    }
	    if (@p = $pac->get($Radius::EAP_43::PAC::TYPE))
	    {
		foreach (@p)
		{
		    my $val = unpack('n', $_->[1]);
		    $self->log($main::LOG_DEBUG, "EAP-FAST PAC request for type $val");
		    $context->{provisioning}++ 
			if $val == $Radius::EAP_43::PAC::TYPE_TUNNEL;
		}
	    }
	    if ($p = $pac->get($Radius::EAP_43::PAC::I_ID))
	    {
		$self->log($main::LOG_DEBUG, "EAP-FAST PAC I_ID $p->[1]");
	    }
	    if ($p = $pac->get($Radius::EAP_43::PAC::SERVER_TRUSTED_ROOT))
	    {
		my ($credential_format, $cred_tlvs) = unpack('n a*', $p->[1]);
		# REVISIT? Could send a a root certificate back to the peer
		$self->log($main::LOG_INFO, "EAP-FAST SERVER_TRUSTED_ROOT request received and ignored");
	    }
	}
    }
    
    if ($t = $tlv->get($Radius::EAP_43::TLV::INTERMEDIATE_RESULT))
    {
	my ($status, $tlvs) = unpack('n a*', $t->[1]);
	if ($status == $Radius::EAP_43::TLV::INTERMEDIATE_RESULT_SUCCESS)
	{
	    # OK, peer finished an inner EAP type
	    # Expect a Crypto-Binding TLV too
	    # And maybe EAP-Payload-TLV(EAP-Response) for the next method 
	    # if one was asked for in the last 
	    # Intermediate Result TLV (Success) that we sent to the peers
	    # Otherwise, if the Crypto-Binding TLV is OK, 
	    # send a Result TLV (Success).
	    return &result_failure($self, $context, $p, 
				   'EAP-FAST Bad Crypto-Binding')
		unless check_crypto_binding($self, $context, $p, $tlv);

	    my $reply_tlv = Radius::EAP_43::TLV->new();
	    # REVISIT: also do this for reprovisioning
	    if ($context->{provisioning})
	    {
		# Client didnt use PAC, or requestsed a new one, 
		# or had an expired/out of date one, so provision one for them
		$self->log($main::LOG_DEBUG, "EAP-FAST Provisioning a new PAC");

		# Build and send a PAC. PAC-Opaque is an identifying string 
		# the client will send
		# to us later. We will use PAC-Opaque as a key to find our cached
		# PAC-Key, which will then be used to create a shared master key 
		# for the new session. 
		my $pac_cache = $self->create_eapfast_pac($p);
		my $pac = Radius::EAP_43::PAC->new();
		$pac->add($Radius::EAP_43::PAC::KEY, $pac_cache->{pac_key});
		$pac->add($Radius::EAP_43::PAC::OPAQUE, $pac_cache->{pac_opaque});
		my $pac_info = Radius::EAP_43::PAC->new();
		$pac_info->add($Radius::EAP_43::PAC::LIFETIME, 
			       pack('N', $pac_cache->{pac_lifetime}));
		$pac_info->add($Radius::EAP_43::PAC::A_ID, $a_id);
		$pac_info->add($Radius::EAP_43::PAC::A_ID_INFO, $a_id_info);
		$pac_info->add($Radius::EAP_43::PAC::TYPE, 
			       pack('n', $Radius::EAP_43::PAC::TYPE_TUNNEL));
		
		# Odyssey likes it if you set the set the I_ID too
		# How can we get it? its the authenticated identity of the inner auth
		$pac_info->add($Radius::EAP_43::PAC::I_ID, 
			       $context->{inner_identity})
		    if defined $context->{inner_identity};

		$pac->add($Radius::EAP_43::PAC::INFO, $pac_info->pack());

		$reply_tlv->add($Radius::EAP_43::TLV::PAC, $pac->pack());
	    }
	    $reply_tlv->add($Radius::EAP_43::TLV::RESULT,
			    pack('n', 
				 $Radius::EAP_43::TLV::RESULT_SUCCESS));

	    &Net::SSLeay::write($context->{ssl}, $reply_tlv->pack());
	    &sendPending($self, $context, $p);
	    return ($main::CHALLENGE, 'EAP-FAST PAC Provision');
	}
	else
	{
	    return &fail($self, $context, $p, 'EAP-FAST Intermediate Result failure from peer');
	
	}
    }

    # Ok, have now checked all the prerequesiste and error conditions. 
    if ($t = $tlv->get($Radius::EAP_43::TLV::EAP_PAYLOAD))
    {
	return &handle_eap_payload($self, $context, $p, $t->[1]);
    }
    elsif ($t = $tlv->get($Radius::EAP_43::TLV::RESULT))
    {
	my ($status, $tlvs) = unpack('n a*', $t->[1]);

	# There may be one or more Request-Action TLVs too:
	if (@t = $tlv->get($Radius::EAP_43::TLV::REQUEST_ACTION))
	{
	    foreach (@t)
	    {
		# Current policy is to ignore these (permitted by RFC 4851
		my $val = unpack('n', $_->[1]);
		$self->log($main::LOG_INFO, "EAP-FAST REQUEST-ACTION for $val ignored");
	    }
	}

	# If we are happy that all inner requests have completed successfully
	# send a success
	# REVISIT: check that is true
	if ($status == $Radius::EAP_43::TLV::RESULT_SUCCESS 
	    && $context->{inner_auth_success})
	{

	    if (!defined $context->{pac_key})
	    {
		# If we didnt get a PAC key, need to send a failure here
		# to provoke the client into do a reauth with the new PAC. 
		# Ref draft-cam-winget-eap-fast-provisioning-04
		&Radius::TLS::contextSessionClear($context);
		$self->eap_failure($p->{rp}, $context);
		return ($main::REJECT, 'EAP-FAST end of Server-Unauthenticated Provisioning mode');
	    }

           # Export the identity and add the reply attributes that were saved from the last inner auth
           $p->{rp}->{inner_identity} = $context->{inner_identity};
           $p->{rp}->add_attr_list($context->{last_reply_attrs});

	    # Send the EAP success	
	    $self->adjustReply($p);
	    
	    my $msk = $p->{rp}->{msk} = &T_PRF($context->{SIMCK}[$context->{eap_fast_inner_method_index}], 'Session Key Generating Function', '', 64);
	    if ($self->{AutoMPPEKeys})
	    {
		my ($send, $recv) = unpack('a32 a32', $msk);
	
		# Note these are swapped for the AP end of the encryption
		$p->{rp}->change_attr('MS-MPPE-Send-Key', $recv);
		$p->{rp}->change_attr('MS-MPPE-Recv-Key', $send);
	    }
	    $self->eap_success($p->{rp}, $context);
	    &Radius::TLS::contextSessionAllowReuse($context);
	    return ($main::ACCEPT); # Success, all done
	}
	else
	{
	    # Peer failed, should have got Error TLVs too.
	    &fail($self, $context, $p, 'EAP-FAST peer RESULT failure');
	    return ($main::REJECT, 'EAP-FAST peer RESULT failure');
	}
    }

    return $self->eap_error('EAP-FAST Nothing to do');
}

#####################################################################
# Check that a CRYPTO_BINDING TLV has the right CMAC in it.
sub check_crypto_binding
{
    my ($self, $context, $p, $tlv) = @_;


    my $t = $tlv->get($Radius::EAP_43::TLV::CRYPTO_BINDING);
    if (!defined $t)
    {
	$self->log($main::LOG_WARNING, 'EAP-FAST required Crypto-Binding TLV not present');
	return;
    }

    my ($reserved, $version, $received_version, $subtype, $nonce, $cmac)
	= unpack('C C C C a32 a20', $t->[1]);
	
    if (   $version != $Radius::EAP_43::FASTVersion1
	|| $received_version != $Radius::EAP_43::FASTVersion1
	|| $subtype != $Radius::EAP_43::TLV::CRYPTO_BINDING_RESPONSE)
    {
	$self->log($main::LOG_WARNING, 'EAP-FAST Incorrect version in Crypto-Binding TLV');
	return;
    }
	
    # Check the received nonce is the same as the last_server_nonce we sent, 
    # except for the last bit, which should be set
    my @nonce = unpack('C32', $nonce);
    if ($nonce[31] & 1 != 1)
    {
	$self->log($main::LOG_WARNING, 'EAP-FAST incorrect nonce bit in Crypto-Binding TLV');
	return;
    }
    $nonce[31] &= 0xfe;
    my $newnonce = pack('C32', @nonce);
    if ($newnonce ne $context->{last_server_nonce})
    {
	$self->log($main::LOG_WARNING, 'EAP-FAST incorrect nonce in Crypto-Binding TLV');
	return;
    }

    # Now check the CMAC
    # First recreate the CBTLV with the cmac set to all 0s
    my $cbtlv_zeroes = Radius::EAP_43::TLV::pack_one
	($Radius::EAP_43::TLV::CRYPTO_BINDING,
	 pack('C C C C a32 a20',
	      $reserved, $version, $received_version, $subtype, $nonce));
    # Compute the cmac over it
    my $correct_cmac = Digest::HMAC_SHA1::hmac_sha1
	($cbtlv_zeroes, 
	 $context->{CMK}[$context->{eap_fast_inner_method_index}]);
    
    if ($cmac ne $correct_cmac)
    {
	$self->log($main::LOG_WARNING, 'EAP-FAST bad CMAC in Crypto-Binding TLV');
	return;
    }
    return 1; # OK
}

#####################################################################
sub fail
{
    my ($self, $context, $p, $reason) = @_;

    $self->log($main::LOG_ERR, $reason);
    &Radius::TLS::contextSessionClear($context);
    $self->eap_failure($p->{rp}, $context);
    return $self->eap_error($reason);
}

#####################################################################
# Start a RESLT=FAILURE dance
sub result_failure
{
    my ($self, $context, $p, $reason) = @_;

    my $reply_tlv = Radius::EAP_43::TLV->new();
    $reply_tlv->add($Radius::EAP_43::TLV::RESULT,
		    pack('n', 
			 $Radius::EAP_43::TLV::RESULT_FAILURE));
    &Net::SSLeay::write($context->{ssl}, $reply_tlv->pack());
    &sendPending($self, $context, $p);
    return ($main::CHALLENGE, 'EAP-FAST Result Failure: ' . $reason);
}

#####################################################################
# This is different to the PRF in RAadius::TLS, 
# the server and client random are reversed
sub PRF
{
    my ($context, $s, $req_len) = @_;

    my $client_random = &Net::SSLeay::get_client_random($context->{ssl});
    my $server_random = &Net::SSLeay::get_server_random($context->{ssl});
    my $session = &Net::SSLeay::get_session($context->{ssl});
    my $master_key = &Net::SSLeay::SESSION_get_master_key($session);
 
    return &Radius::TLS::tls1_PRF($master_key, $s, $server_random . $client_random, $req_len);
}

#####################################################################
# Dispatch an EAP messsage received by TLV to a lower level handler
sub handle_eap_payload
{
    my ($self, $context, $p, $eap_message) = @_;


    # Now fake up a new request to redespatch to (possibly a new) handler
    my $tp = Radius::Radius->new($main::dictionary);
    $tp->add_attr('EAP-Message', $eap_message);
    $tp->add_attr('Message-Authenticator', "\000" x 16); # Will be filled in later if proxied
    # Prevent inner requests getting the same context as outers, 
    # and get the correct one independent of changes to User-Name
    $tp->{OuterSSL} = $context->{ssl};
    my $inner_context = $self->getEAPContext($tp);
    # Make a fake username for the inner authentication
    my $userName = &Radius::Util::format_special
	($self->{EAPAnonymous}, $p, undef, $inner_context->{identity});
    $tp->changeUserName($userName);
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
    
    $tp->set_code('Access-Request');
    $tp->{Client} = $p->{Client};
    $tp->{RecvTime} = $p->{RecvTime};
    $tp->{tunnelledByFAST}++;
    $tp->{StatsTrail} = $p->{StatsTrail};
    $tp->{CachedAttrs}{NasId} = $p->getNasId();
    $tp->set_authenticator(&Radius::Util::random_string(16));
    # Tell EAP.pm to try for inner EAP_MSCHAP-V2 for preference
    $tp->{PreferredEAPType} = 'MSCHAP-V2';

    # Arrange to call our reply function when we get a reply
    $tp->{replyFn} = [\&Radius::EAP_43::replyFn, $context];
    $tp->{outerRequest} = $p;
    $tp->{OriginalUserName} = $userName;
    if ($context->{anonymous_provisioning})
    {
	# When we are doing Server-Unauthenticated Provisioning with MSCHAPV2, 
	# the inner has to use challenges that we contruct
	# As per draft-cam-winget-eap-fast-provisioning-04
	$tp->{FASTServerChallenge} = $context->{server_challenge};
	$tp->{FASTClientChallenge} = $context->{client_challenge};
    }
    my ($user, $realmName) = split(/@/, $userName); 
    $self->log($main::LOG_DEBUG, "EAP-FAST inner authentication request for $userName");
    # Call the PreHandlerHook, if there is one
    $self->runHook('PreHandlerHook', $tp, \$tp);
    &main::log($main::LOG_DEBUG,"EAP-FAST Tunnelled request Packet dump:\n" . $tp->dump)
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
    return ($main::REJECT, "No Handler for FAST inner authentication")
	unless $handler;
    
    # Sometimes the inner auth requires this to become
    # a challenge
    $handled = $main::CHALLENGE if $tp->{make_a_challenge};
    
    $tp->{proxied}++ if $handled == $main::IGNORE;
    return ($handled, "EAP-FAST inner authentication redispatched to a Handler");
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

    &main::log($main::LOG_DEBUG,"Returned FAST inner Packet dump:\n" . $tp->{rp}->dump)
	if (&main::willLog($main::LOG_DEBUG, $self));

    if (!$context->{ssl})
    {
	&main::log($main::LOG_INFO,'Received a reply for a FAST session that has been closed: ignored');
	return;
    }


    # In the case of challenge need to tunnel the EAP back in an EAP-PAYLOAD TLV
    if ($result == $main::CHALLENGE)
    {
	my $reply_tlv = Radius::EAP_43::TLV->new();
	$reply_tlv->add($Radius::EAP_43::TLV::EAP_PAYLOAD, 
			join('', $tp->{rp}->get_attr('EAP-Message')));
	&Net::SSLeay::write($context->{ssl}, $reply_tlv->pack());
	&sendPending($self, $context, $op);
	($result, $reason) = ($main::CHALLENGE, 'EAP-FAST Inner EAP_PAYLOAD challenged');
    }
    elsif ($result == $main::ACCEPT)
    {
	# Inner auth succeeded
	# Generate intermediate result TLV (Success) and
	# Binding-TLV=(Version=1, SNonce, CompoundMAC)
	$context->{inner_auth_success}++;

	# Get the inner session keys padded or truncated to 32 octets, 
	# if there are any, else 32 0s
	my $ISKn = pack('a32', 
			  $tp->{rp}->get_attr('MS-MPPE-Send-Key') 
			. $tp->{rp}->get_attr('MS-MPPE-Recv-Key'));

	# Work out the intermediate compound keys, Section 5.2
	# for this round of inner EAP
	my $index = ++$context->{eap_fast_inner_method_index};
	my $IMCKn = &T_PRF($context->{SIMCK}[$index-1], 
			   'Inner Methods Compound Keys', $ISKn, 60);
	my ($SIMCKn, $CMKn) = unpack('a40 a20',  $IMCKn);

	# Need these later to check the peer's reply CRYPTO_BINDING,
	# and maybe calc the keys for the next inner round
	$context->{CMK}[$index] = $CMKn;
	$context->{SIMCK}[$index] = $SIMCKn;

	# This will be set by EAP.pm in the inner request if it was satisfied
	# internally by Radiator. we can use this to set the I_ID later
	$context->{inner_identity} = $tp->{EAPIdentity};

        # Save a copy of the reply attributes. They will be added to
        # the final outer reply and when session resumption is done
        $context->{last_reply_attrs} = Radius::AttrVal->new();
        $context->{last_reply_attrs}->add_attr_list($tp->{rp});

	# Now build reply TLVs
	my $reply_tlv = Radius::EAP_43::TLV->new();
	# IF we need to run more inner requests, start the next one now
	# and send an INTERMEDIATE_RESULT
	# Odyssey expects RESULT after the GTC INNER accept during reauth
	if ($context->{provisioning})
	{
	    # We are provisioning a PAC
	    $reply_tlv->add($Radius::EAP_43::TLV::INTERMEDIATE_RESULT,
			    pack('n', 
				 $Radius::EAP_43::TLV::INTERMEDIATE_RESULT_SUCCESS));
	}
	else
	{
	    $reply_tlv->add($Radius::EAP_43::TLV::RESULT,
			    pack('n', 
				 $Radius::EAP_43::TLV::RESULT_SUCCESS));
	}

	&add_crypto_binding($self, $context, $tp, $reply_tlv);

	&Net::SSLeay::write($context->{ssl}, $reply_tlv->pack());
	&sendPending($self, $context, $op);
	$tp->{rp}->set_code('Access-Challenge');
	($result, $reason) = ($main::CHALLENGE, 'EAP-FAST Intermediate Result challenge');
    }
    elsif ($result == $main::REJECT)
    {
	# Now build reply TLVs
	my $reply_tlv = Radius::EAP_43::TLV->new();
	$reply_tlv->add($Radius::EAP_43::TLV::RESULT,
			pack('n', 
			     $Radius::EAP_43::TLV::RESULT_FAILURE));
	&Net::SSLeay::write($context->{ssl}, $reply_tlv->pack());
	&sendPending($self, $context, $op);
	$tp->{rp}->set_code('Access-Challenge');
	($result, $reason) = ($main::CHALLENGE, 'EAP-FAST Intermediate Result challenge');
    }
    else
    {
	($result, $reason) = &fail($self, $context, $op, 'EAP-FAST Inner authentication failed')
    }

    $$result_ref = $result;

    # Asynchronous reply? Send result to originator
    $op->{Handler}->handlerResult($op, $result, $reason)
	if $tp->{proxied};	
}

#####################################################################
# Calculate and append a CRYPTO_BINDING to the TLV
sub add_crypto_binding
{
    my ($self, $context, $p, $tlv) = @_;

    # Last bit of 32 octet server nonce must be set to 0
    my @snonce = unpack('C32', Radius::Util::random_string(32));
    $snonce[31] &= 0xfe;
    $context->{last_server_nonce} = pack('C32', @snonce);
    
    # Crypto-Binding TLV with Compound MAC field=zeroes]
    my $cbtlv = Radius::EAP_43::TLV::pack_one
	($Radius::EAP_43::TLV::CRYPTO_BINDING,
	 pack('C C C C a32 a20', 
	      0, 
	      $Radius::EAP_43::FASTVersion1, 
	      $Radius::EAP_43::FASTVersion1, 
	      $Radius::EAP_43::TLV::CRYPTO_BINDING_REQUEST, 
	      $context->{last_server_nonce}));
    
    
    my $cmac = Digest::HMAC_SHA1::hmac_sha1($cbtlv, $context->{CMK}[$context->{eap_fast_inner_method_index}]);

    $tlv->add($Radius::EAP_43::TLV::CRYPTO_BINDING,
	      pack('C C C C a32 a20', 
		   0, 
		   $Radius::EAP_43::FASTVersion1, 
		   $Radius::EAP_43::FASTVersion1, 0, 
		   $context->{last_server_nonce},
		   $cmac));

}

#####################################################################
# Special EAP-FAST PRF from 
# RFC4851 Appendix B: EAP-FAST PRF (T-PRF) 
sub T_PRF
{
    my ($key, $label, $seed, $req_length) = @_;
    
    my $ret = '';
    my $S = $label . "\0" . $seed;
    my $Tn = '';
    my $index = 1;
    while (length $ret < $req_length)
    {
	$Tn = Digest::HMAC_SHA1::hmac_sha1
	    ($Tn . $S . pack('n C', $req_length, $index++), $key);
	$ret .= $Tn;
    }
    return substr($ret, 0, $req_length);
}

#####################################################################
#####################################################################
#####################################################################
# Helper package for handling EAP-FAST TLVs
package Radius::EAP_43::TLV;

$Radius::EAP_43::TLV::MANDATORY                   = 0x8000;

# EAP-FAST TLV types from RFC4851
$Radius::EAP_43::TLV::RESULT                      = 3;
$Radius::EAP_43::TLV::NAK                         = 4;
$Radius::EAP_43::TLV::ERROR                       = 5;
$Radius::EAP_43::TLV::VENDOR_SPECIFIC             = 7;
$Radius::EAP_43::TLV::EAP_PAYLOAD                 = 9;
$Radius::EAP_43::TLV::INTERMEDIATE_RESULT         = 10;
$Radius::EAP_43::TLV::PAC                         = 11;
$Radius::EAP_43::TLV::CRYPTO_BINDING              = 12;
$Radius::EAP_43::TLV::SERVER_TRUSTED_ROOT         = 18;
$Radius::EAP_43::TLV::REQUEST_ACTION              = 19;
$Radius::EAP_43::TLV::PKCS7                       = 20;

$Radius::EAP_43::TLV::RESULT_SUCCESS              = 1;
$Radius::EAP_43::TLV::RESULT_FAILURE              = 2;

$Radius::EAP_43::TLV::INTERMEDIATE_RESULT_SUCCESS = 1;
$Radius::EAP_43::TLV::INTERMEDIATE_RESULT_FAILURE = 2;

$Radius::EAP_43::TLV::ERROR_TUNNEL_COMPROMISE     = 2001;
$Radius::EAP_43::TLV::ERROR_UNEXPECTED_TLV        = 2002;

$Radius::EAP_43::TLV::ACTION_PROCESS_TLV          = 1;
$Radius::EAP_43::TLV::ACTION_NEGOTIATE_EAP        = 2;

$Radius::EAP_43::TLV::CRYPTO_BINDING_REQUEST      = 0;
$Radius::EAP_43::TLV::CRYPTO_BINDING_RESPONSE     = 1;

# Mandatory TLV types we know about
%Radius::EAP_43::TLV::mandatory_tlvs = 
    (
     $Radius::EAP_43::TLV::RESULT              => 1,
     $Radius::EAP_43::TLV::NAK                 => 1,
     $Radius::EAP_43::TLV::ERROR               => 1,
     $Radius::EAP_43::TLV::VENDOR_SPECIFIC     => 1,
     $Radius::EAP_43::TLV::EAP_PAYLOAD         => 1,
     $Radius::EAP_43::TLV::INTERMEDIATE_RESULT => 1,
     $Radius::EAP_43::TLV::PAC                 => 1,
     $Radius::EAP_43::TLV::CRYPTO_BINDING      => 1,
     $Radius::EAP_43::TLV::SERVER_TRUSTED_ROOT => 0,
     $Radius::EAP_43::TLV::REQUEST_ACTION      => 1,
     $Radius::EAP_43::TLV::PKCS7               => 0,
     );

#####################################################################
sub new
{
    my ($class, $s) = @_;

    my $self = {};
    bless $self, $class;

    @{$self->{Attributes}} = (); # Define an empty array
    @{$self->{parse_errors}} = $self->parse($s) if defined $s;

    return $self;
}

#####################################################################
# Returns a list of unknown mandatory attributes that were present
sub parse
{
    my ($self, $data) = @_;

    # Unpack TLV packets
    my @errors;
    while (length $data) 
    {
	my ($type, $length) = unpack 'n n', $data;
	my $flags = $type & 0xc000; # Flags in the top 2 bits of type
	$type &= 0x3fff;           # Type in bottom 14 bits
	my ($val) = unpack("x4 a$length", $data);

	push(@errors, $type)
	    if (   ($flags & $Radius::EAP_43::TLV::MANDATORY)
		   && !$Radius::EAP_43::TLV::mandatory_tlvs{$type});
	$self->add($type, $val);

	# Remove the attribute we just parsed. 
	$data = substr($data, $length + 4);
    }
    return @errors;
}

#####################################################################
sub add
{
    my ($self, $type, $val) = @_;

    push(@{$self->{Attributes}}, [ $type, $val ]);
}

#####################################################################
# Gets the values of the named attribute.
# returns a list of ref(type, vendorid, value, extras)
sub get
{
    my ($self, $type) = @_;

    return map {$_->[0] == $type ? $_ : ()} @{$self->{Attributes}}
        if wantarray;

    map {return $_ if ($_->[0] == $type)} @{$self->{Attributes}};
    return; # Not found
}

#####################################################################
# Pack an EAP request into a FAST TLV
sub pack_one
{
    my ($type, $val) = @_;

    my $flags = $Radius::EAP_43::TLV::mandatory_tlvs{$type} 
                ? $Radius::EAP_43::TLV::MANDATORY : 0;

    return pack('n n a*', $type | $flags, length($val), $val);
}

#####################################################################
sub pack
{
    my ($self) = @_;

    my $ret;
    map {$ret .= pack_one(@$_);} @{$self->{Attributes}};
    return $ret;
}


#####################################################################
#####################################################################
#####################################################################
# Helper package for handling PAC TLVs
package Radius::EAP_43::PAC;

$Radius::EAP_43::PAC::MANDATORY        = 0x8000;

# PAC TLV types from draft-cam-winget-eap-fast-provisioning-04
$Radius::EAP_43::PAC::KEY             = 1;
$Radius::EAP_43::PAC::OPAQUE          = 2;
$Radius::EAP_43::PAC::LIFETIME        = 3;
$Radius::EAP_43::PAC::A_ID            = 4;
$Radius::EAP_43::PAC::I_ID            = 5;
$Radius::EAP_43::PAC::A_ID_INFO       = 7;
$Radius::EAP_43::PAC::ACKNOWLEDGEMENT = 8;
$Radius::EAP_43::PAC::INFO            = 9;
$Radius::EAP_43::PAC::TYPE            = 10;

$Radius::EAP_43::PAC::ACKNOWLEDGEMENT_SUCCESS = 1;
$Radius::EAP_43::PAC::ACKNOWLEDGEMENT_FAILURE = 2;

$Radius::EAP_43::PAC::TYPE_TUNNEL = 1;

# Mandatory PAC types we know about
%Radius::EAP_43::PAC::mandatory_tlvs = 
    (
     );

#####################################################################
sub new
{
    my ($class, $s) = @_;

    my $self = {};
    bless $self, $class;

    @{$self->{Attributes}} = (); # Define an empty array
    @{$self->{parse_errors}} = $self->parse($s) if defined $s;

    return $self;
}

#####################################################################
# Returns a list of unknown mandatory attributes that were present
sub parse
{
    my ($self, $data) = @_;

    # Unpack PAC packets
    my @errors;
    while (length $data) 
    {
	my ($type, $length) = unpack 'n n', $data;
	my $flags = $type & 0xc000; # Flags in the top 2 bits of type
	$type &= 0x3fff;           # Type in bottom 14 bits
	my ($val) = unpack("x4 a$length", $data);

	push(@errors, $type)
	    if (   ($flags & $Radius::EAP_43::PAC::MANDATORY)
		   && !$Radius::EAP_43::PAC::mandatory_tlvs{$type});
	$self->add($type, $val);

	# Remove the attribute we just parsed. 
	$data = substr($data, $length + 4);
    }
    return @errors;
}

#####################################################################
sub add
{
    my ($self, $type, $val) = @_;

    push(@{$self->{Attributes}}, [ $type, $val ]);
}

#####################################################################
# Gets the values of the named attribute.
# returns a list of ref(type, value)
sub get
{
    my ($self, $type) = @_;

    return map {$_->[0] == $type ? $_ : ()} @{$self->{Attributes}}
        if wantarray;

    map {return $_ if ($_->[0] == $type)} @{$self->{Attributes}};
    return; # Not found
}

#####################################################################
# Pack an EAP request into a FAST TLV
sub pack_one
{
    my ($type, $val) = @_;

    my $flags = $Radius::EAP_43::PAC::mandatory_tlvs{$type} 
                ? $Radius::EAP_43::PAC::MANDATORY : 0;

    return pack('n n a*', $type | $flags, length($val), $val);
}

#####################################################################
sub pack
{
    my ($self) = @_;

    my $ret;
    map {$ret .= pack_one(@$_);} @{$self->{Attributes}};
    return $ret;
}


1;
