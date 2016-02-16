# EAP_6.pm
#
# Module for  handling Authentication via EAP type 6 
# (Generic Token Card)
#
# Requires an AuthBy method that is compatible.
#
# See RFCs 2869 2284 1994
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001 Open System Consultants
# $Id: EAP_6.pm,v 1.8 2014/11/17 21:14:51 hvn Exp $

package Radius::EAP_6;
use strict;

# RCS version number of this module
$Radius::EAP_6::VERSION = '$Revision: 1.8 $';

#####################################################################
# Called by EAP.pm when the caller wants to know the EAP type name this class supports
sub type_name
{
    my ($classname) = @_;

    return 'GTC';
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

    my $identity = $context->{identity};
    $identity =~ s/@[^@]*$//
	if $self->{UsernameMatchesWithoutRealm};
    my ($result, $message) = $self->gtc_start($context, $identity, $p);
    return &gtc_reply($self, $result, $message, $p, $context);
}

#####################################################################
# Called by EAP.pm when an EAP Response (other than Identity)
# is received
sub response
{
    my ($classname, $self, $context, $p, $type, $typedata) = @_;

    my $identity = $context->{identity};
    # Some EAP-GTC clients put the response in this format
    if ($typedata =~ /^RESPONSE=(.*)\0(.*)/)
    {
	$identity = $1;
	$typedata = $2;
    }

    return convert_to_pap($self, $context,$identity,$typedata, $p)
	if $self->{EAP_GTC_PAP_Convert};

    $identity =~ s/@[^@]*$//
	if $self->{UsernameMatchesWithoutRealm};
    my ($result, $message) = $self->gtc_continue($context, $identity, $typedata, $p);
    return &gtc_reply($self, $result, $message, $p, $context);
}

#####################################################################
# Convert this EAP-GTC into a conventional Radius PAP request and
# redispatch it for proxying (or perhaps local handling)
sub convert_to_pap
{
    my ($self, $context, $identity, $typedata, $p) = @_;

    # Make a new fake packet that contains something that looks like
    # an ordinary Radius PAP request
    my $tp = Radius::Radius->new($main::dictionary);

    # Copy other helpful attributes to the inner request
    # Radiator uses these to disambiguate the Context
    foreach ($Radius::Radius::NAS_IP_ADDRESS,
	     $Radius::Radius::NAS_IDENTIFIER,
	     $Radius::Radius::NAS_PORT,
	     $Radius::Radius::CALLING_STATION_ID,
	     $Radius::Radius::STATE,
	     $Radius::Radius::CLASS)
    {
	my $val = $p->getAttrByNum($_);
	$tp->addAttrByNum($_, $val) if defined $val;
    }

    $tp->set_code('Access-Request');

    $tp->{Client} = $p->{Client};
    $tp->{RecvTime} = $p->{RecvTime};
    $tp->{StatsTrail} = $p->{StatsTrail};
    $tp->{CachedAttrs}{NasId} = $p->getNasId();

    $tp->set_authenticator(&Radius::Util::random_string(16));
    # Arrange to call our reply function when we get a reply
    $tp->{replyFn} = [\&Radius::EAP_6::replyFn, $context];
    $tp->{outerRequest} = $p;

    # Now add the attributes to make it a fake radius request
    $tp->changeUserName($identity);
    $tp->add_attr('ConvertedFromGTC', 1); # Pseudo attribute to signal dispatcher

    $tp->{DecodedPassword} = $typedata;
    $tp->changeAttrByNum($Radius::Radius::USER_PASSWORD, '**obscured**');

    $context->{parent} = $self;

    my ($user, $realmName) = split(/@/, $identity);
    my ($handler, $finder, $result);
    # Call the PreHandlerHook, if there is one
    $self->runHook('PreHandlerHook', $tp, \$tp);
    main::log($main::LOG_DEBUG,"Converted EAP-GTC PAP Packet dump:\n" . $tp->dump)
	if (main::willLog($main::LOG_DEBUG, $self));

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
   $tp->{proxied}++ if $result == $main::IGNORE;
   $p->{proxied} = $tp->{proxied};
   return ($main::REJECT, "No Handler for converted EAP-GTC PAP authentication")
		unless $handler;

   return ($result, "EAP-GTC converted to Radius PAP and redispatched to a Handler");
}

#####################################################################
# This is called when a the EAP-GTC repsonse is converted
# into a conventional Radius PAP request, proxied or handled locally and then completed
# $tp is the (fake) request packet containing the Radius PAP request
sub replyFn
{
    my ($tp, $context) = @_;

    my $reply_code = $tp->{rp}->code();	 # The result of the inner auth
    my $self = $context->{parent};
    my $op = $tp->{outerRequest}; # This is the EAP-GTC request that was converted
    $op->{proxied} = $tp->{proxied};

    main::log($main::LOG_DEBUG,"Returned converted EAP-GTC PAP Packet dump:\n" . $tp->{rp}->dump)
	if (main::willLog($main::LOG_DEBUG, $self));
    if ($reply_code eq 'Access-Accept')
    {
	my $identity = $context->{identity};
	# copy reply attributes to outer reply
	$op->{rp}->add_attr_list($tp->{rp});

	$self->gtc_end($context, $identity, $op);
	$self->eap_success($op->{rp}, $context);
	$self->adjustReply($op);

	$op->{Handler}->handlerResult
	    ($op, $main::ACCEPT, 'Converted EAP-GTP PAP authentication success')
	    if $tp->{proxied};
    }
    elsif ($reply_code eq 'Access-Reject')
    {
	my $identity = $context->{identity};
	$self->gtc_end($context, $identity, $op);
	$self->eap_failure($op->{rp}, $context);

	$op->{Handler}->handlerResult
	    ($op, $main::REJECT, 'Converted EAP-GTP PAP authentication failed')
	    if $tp->{proxied};
    }
    elsif ($reply_code eq 'Access-Challenge')
    {
	my $message = $tp->{rp}->get_attr ('Reply-Message');
	# copy reply attributes to outer reply
	$op->{rp}->add_attr_list($tp->{rp});
	$self->eap_request($op->{rp}, $context, $Radius::EAP::EAP_TYPE_TOKEN, $message);

	$op->{Handler}->handlerResult
	    ($op, $main::CHALLENGE, 'Converted EAP-GTP PAP authentication challenge')
	    if $tp->{proxied};
    }
}

#####################################################################
# Handle the result of a gtc_start or gtc_continue
sub gtc_reply
{
    my ($self, $result, $message, $p, $context) = @_;

    my $identity = $context->{identity};
    $identity =~ s/@[^@]*$//
	if $self->{UsernameMatchesWithoutRealm};
    if ($result == 2)
    {
	$self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_TOKEN, $message);
	return ($main::CHALLENGE, 'EAP Generic Token Card Challenge');
    }
    elsif ($result == 1)
    {
	$self->gtc_end($context, $identity, $p);
	$self->eap_success($p->{rp}, $context);
	$self->adjustReply($p);
	return ($main::ACCEPT);
    }
    else
    {
	$self->gtc_end($context, $identity, $p);
	$self->eap_failure($p->{rp}, $context);
	return ($main::REJECT, "EAP Generic Token Card failed: $message");
    }
}

1;
