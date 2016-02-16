# EAP_26.pm
#
# Module for  handling Authentication via EAP type 26: MSCHAP-V2
# Hmmmm, Iana assigned 29 for MSCHAP-V2 and 
# 26 for MS-EAP-Authentication. What gives?
#
# See RFCs 2759 draft-kamath-pppext-eap-mschapv2-00.txt
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001 Open System Consultants
# $Id: EAP_26.pm,v 1.52 2012/11/02 06:18:13 mikem Exp $

package Radius::EAP_26;
use Radius::MSCHAP;
use strict;

# RCS version number of this module
$Radius::EAP_26::VERSION = '$Revision: 1.52 $';

# Definitions for MSCHAP Type
$Radius::EAP_26::MSCHAP_TYPE_CHALLENGE   = 1;
$Radius::EAP_26::MSCHAP_TYPE_RESPONSE    = 2;
$Radius::EAP_26::MSCHAP_TYPE_SUCCESS     = 3;
$Radius::EAP_26::MSCHAP_TYPE_FAILURE     = 4;
$Radius::EAP_26::MSCHAP_TYPE_CHANGE_PASS = 7;

#####################################################################
# Called by EAP.pm when the caller wants to know the EAP type name this class supports
sub type_name
{
    my ($classname) = @_;

    return 'MSCHAP-V2';
}

#####################################################################
# request
# Called by EAP.pm when a rexquest is received for this protocol type
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

    # Generate a MS-CHAP-V2 Challenge packet as per RFC 2759
    # Remember the challenge for later
    $self->mschapv2_challenge($context, $p);

    my $name = $main::hostname; # system name
    my $message = pack('C C n C a16 a*', 
		       $Radius::EAP_26::MSCHAP_TYPE_CHALLENGE,
		       $context->{next_id},    # MS-CHAPv2-ID
		       length($name) + 21, # MS-Length
		       16,     # value-sizelength
		       $context->{mschapv2_challenge},
		       $name);
    $self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_MSCHAPV2, $message);
    return ($main::CHALLENGE, 'EAP MSCHAP-V2 Challenge');
}

#####################################################################
# Called by EAP.pm when an EAP Response (other than Identity)
# is received
sub response
{
    my ($classname, $self, $context, $p, $type, $typedata) = @_;

    # Ignore if this AuthBy is currently ignoring requests
    return ($main::IGNORE, 'Ignored by this AuthBy') if grep {$self == $_} @{$context->{ignoring_auth_bys}};

    my ($mschaptype, $mschapdata) = unpack('C a*', $typedata);
    if ($mschaptype == $Radius::EAP_26::MSCHAP_TYPE_SUCCESS
	&& $context->{success})
    {
	# May have multiple AuthBys in a chain.
	# Reject if the success did not come from this AuthBy
	return ($main::REJECT, 'Not authenticated by this AuthBy') unless $context->{success_auth_by} == $self;
	
	# Client liked our MSCHAP V2 Success Request and sent an ACK,
	# so we reply with an EAP-Success
	$p->{rp}->add_attr_list($context->{last_reply_attrs});
	$self->adjustReply($p);

	if ($self->{AutoMPPEKeys})
	{
	    $p->{rp}->add_attr('MS-MPPE-Send-Key', $context->{send_key});
	    $p->{rp}->add_attr('MS-MPPE-Recv-Key', $context->{recv_key});
	}
	$self->eap_success($p->{rp}, $context);
	return ($main::ACCEPT); # Success, all done
    }
    elsif ($mschaptype == $Radius::EAP_26::MSCHAP_TYPE_FAILURE)
    {
	# Client acknowledges our MSCHAP_TYPE_FAILURE request
	$self->eap_failure($p->{rp}, $context);
	return ($main::REJECT); # Failure, all done
    }
    elsif ($mschaptype == $Radius::EAP_26::MSCHAP_TYPE_RESPONSE)
    {
	# Maybe convert to ordinary Radius-MSCHAPV2 and redespatch
	return &convert_to_mschapv2($self, $context, $mschapdata, $p) 
	    if $self->{EAP_PEAP_MSCHAP_Convert};

	my $identity = $context->{identity};
	$identity =~ s/@[^@]*$//
	    if $self->{UsernameMatchesWithoutRealm};
	if (defined $self->{RewriteUsername})
	{
	    my $rule;
	    foreach $rule (@{$self->{RewriteUsername}})
	    {
		# We use an eval so an error in the pattern wont kill us.
		eval("\$identity =~ $rule");
		&main::log($main::LOG_ERR, "Error while rewriting identity $identity: $@") 
		    if $@;
		&main::log($main::LOG_DEBUG, "Rewrote identity to $identity");
	    }
	}

	$identity = $p->get_attr($self->{AuthenticateAttribute})
            if $self->{AuthenticateAttribute};
	my ($user, $result, $reason) = $self->get_user($identity, $p);
	if ($result == $main::IGNORE)
	{
		push @{$context->{ignoring_auth_bys}}, $self;
		return ($result, "User database access error") if ($result == $main::IGNORE);
	}
	if (!$user || $result != $main::ACCEPT)
	{
	    $self->eap_failure($p->{rp}, $context);
	    return ($main::REJECT, "EAP MSCHAP V2 failed: no such user $identity");
	}

	# Got a user record for this user. Need the plaintext password now
	my $password = $self->get_plaintext_password($user);
	my ($mschapid, $mslength, $valuesize, $peerchallenge, $reserved, $response, $flags, $name) 
	    = unpack('C n C a16 a8 a24 C a*', $mschapdata);

	# This may have come from EAP-FAST, in which case the peer and auth 
	# challenges were derived from the outer TLS session
	$peerchallenge = $p->{FASTClientChallenge} 
	    if defined $p->{FASTClientChallenge};
	$context->{mschapv2_challenge} = $p->{FASTServerChallenge} 
	    if defined $p->{FASTServerChallenge};
	my ($nthash, $authenticator_response, $mppekeys, $check_result); # Returned by check_mschapv2
	if ($password =~ /^{nthash}([0-9a-hA-H]{32})$/)
	{
	    # Password is already NT Hashed
	    $check_result = $self->check_mschapv2
	    ($p, $name, pack('H*', $1), $context->{mschapv2_challenge}, 
	     $peerchallenge, $response, \$mppekeys, \$authenticator_response, undef, $context);
	}
	else
	{
	    # Plaintext password
	    $check_result = $self->check_mschapv2_plaintext
	    ($p, $name, $password, $context->{mschapv2_challenge}, 
	     $peerchallenge, $response, \$mppekeys, \$authenticator_response, 
	     undef, $context);
	}

	if ($check_result)
	{
	    # Password must be right, send back an MSCHAP V2 Success Request
	    if ($self->{AutoMPPEKeys})
	    {
		# Compute and save the MPPE keys for later.
		($context->{send_key}, $context->{recv_key}) = unpack('a16 a16', $mppekeys);
	    }
	    # Save the users reply items for later, when the MSCHAP_TYPE_SUCCESS comes
	    my $temp =  Radius::Radius->new($main::dictionary);
	    $temp->{rp} = Radius::Radius->new($main::dictionary);
	    $context->{last_reply_attrs} = Radius::AttrVal->new();
	    $self->authoriseUser($user, $temp);
	    $context->{last_reply_attrs}->add_attr_list($temp->{rp});

	    # Build a success request packet
	    $authenticator_response .= ' M=success';
	    my $message = pack('C C n a*', 
			       $Radius::EAP_26::MSCHAP_TYPE_SUCCESS,
			       $context->{this_id}, # XP MSCHAP-V2 expects the same as before!
			       length($authenticator_response) + 4,
			       $authenticator_response);
	    $self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_MSCHAPV2, $message);
	    $context->{success}++;
	    $context->{success_auth_by} = $self;
	    # Make sure we dont use this challenge again.
	    $context->{mschapv2_challenge} = undef;
	    return ($main::CHALLENGE, 'EAP MSCHAP V2 Challenge: Success');
	}
	else
	{
	    # Windows XP SP1 via PEAP is much happier with this. The PEAP server
	    # code detects the inner EAP failure and then does an acknowledged
	    # fail handshake
	    $self->eap_failure($p->{rp}, $context);
	    return ($main::REJECT, 'EAP MSCHAP-V2 Authentication failure');

	    # Authentication failed, send an EAP/MSCHAPV2/Fail as per 
	    # draft-kamath-pppext-eap-mschapv2-00.txt
	    # Client will ACK this
#	    my $errormsg = 'E=691 R=0 V=3 M=Authentication Failed';
#	    my $message = pack('C C n a*',
#			       $Radius::EAP_26::MSCHAP_TYPE_FAILURE,
#			       $context->{this_id},
#			       length($errormsg) + 4,
#			       $errormsg);
#	    $self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_MSCHAPV2, $message);
#	    return ($main::CHALLENGE, 'EAP MSCHAP-V2 Challenge: Fail');
	}
    }
    elsif ($mschaptype == $Radius::EAP_26::MSCHAP_TYPE_CHANGE_PASS)
    {
	$self->eap_failure($p->{rp}, $context);
	return ($main::REJECT, 'EAP MSCHAP-V2 Change-Password not suported');
    }
    else
    {
	$self->eap_failure($p->{rp}, $context);
	return $self->eap_error("EAP MSCHAP-V2 unknown mschaptype $mschaptype");
    }
}

#####################################################################
# Convert this inner EAP-MSCHAPV2 into a conventional Radius MSCHAPV2 request
# and redespatch it for proxying (or perhaps local handling)
sub convert_to_mschapv2
{
    my ($self, $context, $mschapdata, $p) = @_;

    my ($mschapid, $mslength, $valuesize, $peerchallenge, $reserved, $response, $flags, $name) 
	= unpack('C n C a16 a8 a24 C a*', $mschapdata);

    # Make a new fake packet that contains something that looks like 
    # an ordinary Radius MSCHAPV2 request
    my $tp = Radius::Radius->new($main::dictionary);
    $tp->set_code('Access-Request');
    $tp->{Client} = $p->{Client};
    $tp->{RecvTime} = $p->{RecvTime};
    $tp->{StatsTrail} = $p->{StatsTrail};
    $tp->{CachedAttrs}{NasId} = $p->getNasId();
    $tp->set_authenticator(&Radius::Util::random_string(16));
    # Arrange to call our reply function when we get a reply
    $tp->{replyFn} = [\&Radius::EAP_26::replyFn, $context];
    $tp->{outerRequest} = $p;

    # Now add the attributes to make it a fake radius request
    $tp->changeUserName($name);
    $tp->add_attr('ConvertedFromEAPMSCHAPV2', 1); # Pseudo attribute to signal dispatcher
    my $responseattr = pack('C C a16 a8 a24', 1, 0, $peerchallenge, undef, $response);
    $tp->add_attr('MS-CHAP2-Response', $responseattr);
    $tp->add_attr('MS-CHAP-Challenge', $context->{mschapv2_challenge});
    
    $tp->{OriginalUserName} = $name;
    $context->{parent} = $self;

    my ($user, $realmName) = split(/@/, $name);
    my ($handler, $finder, $handled);
    # Call the PreHandlerHook, if there is one
    $self->runHook('PreHandlerHook', $tp, \$tp);
    &main::log($main::LOG_DEBUG,"Converted EAP-MSCHAPV2 Packet dump:\n" . $tp->dump)
	if (&main::willLog($main::LOG_DEBUG, $self));
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
    $p->{proxied} = $tp->{proxied};
    return ($main::REJECT, "No Handler for converted EAP-MSCHAPV2 authentication")
	unless $handler;

    # Usually the reply to the converted auth is an accept, which
    # we have to make into a challenge.
    $handled = $main::CHALLENGE if $tp->{make_a_challenge};
    
    return ($handled, "EAP-MSCHAPV2 converted to Radius MSCHAPV2 and redispatched to a Handler");
}

#####################################################################
# This is called when a the EAP-MSCHAPV2 repsonse is converted
# into a conventional Radus MSCHAPV2 request, proxied or handled locally and then completed
# $tp is the (fake) request packet containing the radius MSCHAPV2 request
sub replyFn
{
    my ($tp, $context) = @_;

    my $reply_code = $tp->{rp}->code();  # The result of the inner auth
    my $self = $context->{parent};
    my $op = $tp->{outerRequest}; # This is the EAP 26 request that was converted
    $op->{proxied} = $tp->{proxied};

    &main::log($main::LOG_DEBUG,"Converted EAP-MSCHAPV2 response Packet dump:\n" . $tp->{rp}->dump)
	if (&main::willLog($main::LOG_DEBUG, $self));
    if ($reply_code eq 'Access-Accept')
    {
	my $attr = $tp->{rp}->get_attr('MS-CHAP2-Success');
	if (defined $attr)
	{
	    # This is the MS-CHAP2-Success received from the proxy,
	    # convert it back into a MSCHAP_TYPE_SUCCESS
	    my ($ident, $authenticator_response) = unpack('C a42', $attr);
	    $authenticator_response .= ' M=success';

	    my $message = pack('C C n a*', 
			       $Radius::EAP_26::MSCHAP_TYPE_SUCCESS,
			       $context->{this_id}, # XP MSCHAP-V2 expects the same as before!
			       length($authenticator_response) + 4,
			       $authenticator_response);
	    $self->eap_request($op->{rp}, $context, $Radius::EAP::EAP_TYPE_MSCHAPV2, $message);
	}

	# Copy reply attrs
	$context->{last_reply_attrs} = Radius::AttrVal->new();
	$context->{last_reply_attrs}->add_attr_list($tp->{rp});
	$context->{last_reply_attrs}->delete_attr('MS-CHAP2-Success');

	$tp->{make_a_challenge}++;
	$context->{success}++;
	$context->{success_auth_by} = $self;
	# Make sure we dont use this challenge again.
	$context->{mschapv2_challenge} = undef;

	$op->{Handler}->handlerResult($op, $main::CHALLENGE, 'Converted MSCHAPV2 authentication success')
	    if $tp->{proxied};
    }    
    elsif ($reply_code eq 'Access-Reject')
    {
	$self->eap_failure($op->{rp}, $context);
	$op->{Handler}->handlerResult
	    ($op, $main::REJECT, 'Converted EAP-MSCHAPV2 authentication failed')
	    if $tp->{proxied};	
    }
}


1;
