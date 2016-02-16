# EAP_17.pm
#
# Module for  handling Authentication via EAP type 17 (Cisco LEAP)
# based on LEAP protocol description at
# http://lists.cistron.nl/pipermail/cistron-radius/2001-September/002042.html
# See also a more recent document where Cisco actually provides some documentation of their
# hitherto secret protocol:
# http://www.ciscopress.com/articles/article.asp?p=369223&seqNum=4&rl=1
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2003 Open System Consultants
# $Id: EAP_17.pm,v 1.21 2012/06/28 12:12:35 mikem Exp $
#

package Radius::EAP_17;
use Radius::MSCHAP;
use Radius::Context;
use Digest::MD5;
use strict;

# RCS version number of this module
$Radius::EAP_17::VERSION = '$Revision: 1.21 $';

$Radius::EAP::EAP_17::proto_version = 1;

#####################################################################
# Called by EAP.pm when the caller wants to know the EAP type name this class supports
sub type_name
{
    my ($classname) = @_;

    return 'LEAP';
}

#####################################################################
# request
# Called by EAP.pm when a request is received for this protocol type
sub request
{
    my ($classname, $self, $context, $p, $type, $typedata) = @_;

    # This should be request containing 8 octet peer challenge
    # Generate accept containing peer response and session key
    my ($protocol, $unused, $count) = unpack('C C C', $typedata);
    return ($main::REJECT, 'EAP LEAP unsupport version')
	unless $protocol == $Radius::EAP::EAP_17::proto_version;
    my ($apc, $name) = unpack("x x x a$count a*", $typedata);
    $context->{leap_apc} = $apc;


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

    if (!$self->{EAP_LEAP_MSCHAP_Convert})
    {
	my ($user, $result, $reason) = $self->get_user($identity, $p);
	if (!$user || $result != $main::ACCEPT)
	{
	    $self->eap_failure($p->{rp}, $context);
	    return ($main::REJECT, "EAP LEAP failed: no such user $identity");
	}
    }

    my $apr = &Radius::MSCHAP::ChallengeResponse($apc, $context->{leap_session_key});
    my $message = pack('C C C C a24 a*', 
		       $Radius::EAP::EAP_TYPE_LEAP, 
		       $Radius::EAP::EAP_17::proto_version,
		       0, # Unused
		       24, # response bytecount
		       $apr, # 24 octets
		       $name);

    # session key
    my $md5digest = Digest::MD5::md5
	($context->{leap_session_key} . $apc . $apr . $context->{leap_peer_challenge} . $context->{leap_peer_response});
    my $sk = Radius::Radius::encode_salted($md5digest, $p->{Client}->{Secret}, $p->authenticator);
    $p->{rp}->add_attr('cisco-avpair', "leap:session-key=$sk");
    $p->{rp}->add_attr_list($context->{last_reply_attrs});
    $self->adjustReply($p);
    $self->eap_reply($p->{rp}, $context, $Radius::EAP::EAP_CODE_RESPONSE, $message);

    return ($main::ACCEPT, 'EAP LEAP Accept');
}

#####################################################################
# Called by EAP.pm when an EAP Response/Identity is received
# $self is ref to the current AuthBy
sub response_identity
{
    my ($classname, $self, $context, $p) = @_;

    # Send 8 octet Peer Challenge, should get Response with the Peer response
    # in it next.
    $context->{leap_peer_challenge} = &Radius::Util::random_string(8);
    my $message = pack('C C C a8 a*', 
		       $Radius::EAP::EAP_17::proto_version,
		       0, # Unused
		       8, # challenge bytecount
		       $context->{leap_peer_challenge}, # 8 octets
		       $context->{identity});

    $self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_LEAP, $message);
    return ($main::CHALLENGE, 'EAP LEAP Challenge');
}

#####################################################################
# Called by EAP.pm when an EAP Response (other than Identity)
# is received
sub response
{
    my ($classname, $self, $context, $p, $type, $typedata) = @_;

    # This should be Peer response to Peer Challenge sent before
    # The context hold previous Peer challenge
    my ($protocol, $unused, $count) = unpack('C C C', $typedata);
    return ($main::REJECT, 'EAP LEAP unsupported version')
	unless $protocol == $Radius::EAP::EAP_17::proto_version;
    my ($peer_response, $name) = unpack("x x x a$count a*", $typedata);

    $context->{leap_peer_response} = $peer_response; # Need this later for MPPE keys

    # Maybe convert to ordinary Radius-MSCHAP and redespatch
    return &convert_to_mschap($self, $context, $p, $peer_response, $name) 
	if $self->{EAP_LEAP_MSCHAP_Convert};

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

    my ($user, $result, $reason) = $self->get_user($identity, $p);
    if (!$user || $result != $main::ACCEPT)
    {
	$self->eap_failure($p->{rp}, $context);
	return ($main::REJECT, "EAP LEAP failed: no such user $identity");
    }

    # Got a user record for this user. Need the plaintext password now
    my $password = $self->get_plaintext_password($user);

    my ($usersessionkey, $nthash); # Returned by check_mschap
    if ($password =~ /^{nthash}([0-9a-hA-H]{32})$/)
    {
	# Password is already NT Hashed
	$nthash = pack('H*', $1);
    }
    else
    {
	# Plaintext password
	$nthash = Radius::MSCHAP::NtPasswordHash(Radius::MSCHAP::ASCIItoUnicode($password));
    }
    my $check_result = $self->check_mschap
	($p,  $context->{identity}, $nthash, $context->{leap_peer_challenge}, $peer_response, \$usersessionkey);

    if ($check_result) 
    {
	# AP response is correct, issue accept
	# Should get request with peer challenge next
	$context->{last_reply_attrs} = Radius::AttrVal->new();
	$context->{last_reply_attrs}->add_attr_list($user->get_reply());
	$context->{leap_session_key} = $usersessionkey;      # Need this later for MPPE keys
	$self->eap_success($p->{rp}, $context);
	return ($main::CHALLENGE, 'Wait for peer challenge');
    }
    else 
    {
	# AP Respone is incorrect, issue Reject/EAP Failure
	$self->eap_failure($p->{rp}, $context);
	return ($main::REJECT, 'Bad LEAP Password');
    }
}

#####################################################################
# Convert this inner LEAP into a conventional Radius MSCHAP request
# and redespatch it for proxying (or perhaps local handling)
sub convert_to_mschap
{
    my ($self, $context, $p, $peer_response, $name) = @_;

    # Make a new fake packet that contains something that looks like 
    # an ordinary Radius MSCHAPV2 request
    my $tp = Radius::Radius->new($main::dictionary);
    $tp->set_code('Access-Request');
    $tp->{Client} = $p->{Client};
    $tp->{StatsTrail} = $p->{StatsTrail};
    $tp->{CachedAttrs}{NasId} = $p->getNasId();
    $tp->set_authenticator(&Radius::Util::random_string(16));
    # Arrange to call our reply function when we get a reply
    $tp->{replyFn} = [\&Radius::EAP_17::replyFn, $context];
    $tp->{outerRequest} = $p;

    # Now add the attributes to make it a fake radius request
    $tp->changeUserName($name);
    $tp->add_attr('ConvertedFromLEAP', 1); # Pseudo attribute to signal dispatcher

    $tp->add_attr('MS-CHAP-Response', pack('C C a24 a24', 0, 1, '000000000000000000000000', $peer_response));
    $tp->add_attr('MS-CHAP-Challenge', $context->{leap_peer_challenge});
    
    $tp->{OriginalUserName} = $name;
    $context->{parent} = $self;
    $context->{success} = undef;

    my ($user, $realmName) = split(/@/, $name);
    my ($handler, $finder, $handled);
    # Call the PreHandlerHook, if there is one
    $self->runHook('PreHandlerHook', $tp, \$tp);
    &main::log($main::LOG_DEBUG,"Converted LEAP Packet dump:\n" . $tp->dump)
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
    return ($main::REJECT, "No Handler for converted LEAP authentication")
	unless $handler;

    return ($handled, "LEAP converted to Radius MSCHAP and redispatched to a Handler");
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
    my $op = $tp->{outerRequest}; # This is the EAP 17 request that was converted

    &main::log($main::LOG_DEBUG,"Converted LEAP response Packet dump:\n" . $tp->{rp}->dump)
	if (&main::willLog($main::LOG_DEBUG, $self));
    if ($reply_code eq 'Access-Accept')
    {
	my $keys = $tp->{rp}->get_attr('MS-CHAP-MPPE-Keys');
	if (defined $keys)
	{
	    # Keys have already been decoded
	    my ($lanmansessionkey, $usersessionkey) = unpack('a8, a16', $keys);
	    $context->{leap_session_key} = $usersessionkey;      # Need this later for MPPE keys
	    # Should get a request next
	    $self->eap_success($op->{rp}, $context);
	}
	else
	{
	    &main::log($main::LOG_WARNING, 'Reply to converted LEAP request did not contain MS-CHAP-MPPE-Keys. Cannot generate LEAP encryption keys');
	}

	$context->{success}++;

	$op->{Handler}->handlerResult($op, $main::CHALLENGE, 'Converted MSCHAPV2 authentication success, wait for peer challenge')
	    if $tp->{proxied};
    }    
    elsif ($reply_code eq 'Access-Reject')
    {
	$self->eap_failure($op->{rp}, $context);
	$op->{Handler}->handlerResult
	    ($op, $main::REJECT, 'Converted LEAP authentication failed')
	    if $tp->{proxied};	
    }
}

1;
