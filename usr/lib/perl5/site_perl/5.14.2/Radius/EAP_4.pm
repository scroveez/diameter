# EAP_4.pm
#
# Module for  handling Authentication via EAP type 4 (MD5-Challenge)
#
# See RFCs 2869 2284 1994
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001 Open System Consultants
# $Id: EAP_4.pm,v 1.20 2012/12/21 22:16:35 mikem Exp $

package Radius::EAP_4;
use strict;

# RCS version number of this module
$Radius::EAP_4::VERSION = '$Revision: 1.20 $';

#####################################################################
# Called by EAP.pm when the caller wants to know the EAP type name this class supports
sub type_name
{
    my ($classname) = @_;

    return 'MD5';
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

    # Generate a challnege into $context->{md5_challenge}
    $self->md5_challenge($context);
    my $message = pack('C a16 a*', 
		       16,  # MD5 challenge length
		       $context->{md5_challenge},
		       $main::hostname);
    $self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_MD5_CHALLENGE, $message);
    return ($main::CHALLENGE, 'EAP MD5-Challenge');
}

#####################################################################
# Called by EAP.pm when an EAP Response (other than Identity)
# is received
# $id is the id of the received EAP response
sub response
{
    my ($classname, $self, $context, $p, $type, $typedata) = @_;

    # This should be a response to a challenge
    # we sent previously. The challenge is cached
    # in the challenges array, indexed by
    # challenge_id. The response should be the MD5 hash
    # the challenge_id, the password, the challenge
    my ($length, $response, $username) = unpack('C a16 a*', $typedata);

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

    # OK, now we need the user details to check the password
    my ($user, $result, $reason) = $self->get_user($identity, $p);
    if ($user && $result == $main::ACCEPT)
    {
	my $correct_password = $self->get_plaintext_password($user);
	if ($self->check_md5($context, $p, $identity, $correct_password, chr($context->{this_id}), 
			     $context->{md5_challenge}, $response))
	{
	    $self->eap_success($p->{rp}, $context);
	    $self->authoriseUser($user, $p);
	    $self->adjustReply($p);
	    return ($main::ACCEPT);
	}
	else
	{
	    $self->eap_failure($p->{rp}, $context);
	    return ($main::REJECT, 'EAP MD5-Challenge failed: Bad password');
	}
    }
    else
    {
	$self->eap_failure($p->{rp}, $context);
	return ($main::REJECT, "EAP MD5-Challenge failed: $reason");
    }
}

1;
