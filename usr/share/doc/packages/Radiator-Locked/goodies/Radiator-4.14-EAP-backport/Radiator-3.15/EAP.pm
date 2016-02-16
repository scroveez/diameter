# EAP.pm
#
# Code for handling Authentication via EAP.
# We automatically keep a Context object for each current EAP conversation.
# The key to finding the context is "eap:$nas_id:$nas_port:$calling_station$rad_user_name"
# which relies on the NAS-Id, NAS-Port and Calling-Station-ID being present
# in the Radius request to be sure of uniquely determining the context.
#
# See RFCs 2869 2284 1994
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001 Open System Consultants
# $Backport-Id: EAP.pm,v 1.33 2006/04/18 06:02:35 mikem Exp $
# $Id: EAP.pm,v 1.1 2014/12/03 07:11:47 hvn Exp $

# Extends AuthGeneric
package Radius::AuthGeneric;
use Radius::Context;
use strict;

# Some constants from the EAP protocol
$Radius::EAP::EAP_CODE_REQUEST = 1;
$Radius::EAP::EAP_CODE_RESPONSE = 2;
$Radius::EAP::EAP_CODE_SUCCESS = 3;
$Radius::EAP::EAP_CODE_FAILURE = 4;

# EAP types, see http://www.iana.org/assignments/ppp-numbers
$Radius::EAP::EAP_TYPE_IDENTITY = 1;
$Radius::EAP::EAP_TYPE_NOTIFICATION = 2;
$Radius::EAP::EAP_TYPE_NAK = 3;
$Radius::EAP::EAP_TYPE_MD5_CHALLENGE = 4;
$Radius::EAP::EAP_TYPE_OTP = 5;
$Radius::EAP::EAP_TYPE_TOKEN = 6;
$Radius::EAP::EAP_TYPE_TLS = 13;
$Radius::EAP::EAP_TYPE_SECURID = 15;
$Radius::EAP::EAP_TYPE_LEAP = 17;
$Radius::EAP::EAP_TYPE_SIM = 18;
$Radius::EAP::EAP_TYPE_TTLS = 21;
$Radius::EAP::EAP_TYPE_AKA = 23;
$Radius::EAP::EAP_TYPE_PEAP = 25;
$Radius::EAP::EAP_TYPE_MSCHAPV2 = 26;
$Radius::EAP::EAP_TYPE_EXTENSIONS = 33;

# Maps our EAPType names to EAP type numbers
my %eap_name_to_type = 
(
 'MD5'               => $Radius::EAP::EAP_TYPE_MD5_CHALLENGE,
 'MD5-Challenge'     => $Radius::EAP::EAP_TYPE_MD5_CHALLENGE,
 'One-Time-Password' => $Radius::EAP::EAP_TYPE_OTP,
 'Generic-Token'     => $Radius::EAP::EAP_TYPE_TOKEN,
 'TLS'               => $Radius::EAP::EAP_TYPE_TLS,
 'SecurID'           => $Radius::EAP::EAP_TYPE_SECURID,
 'LEAP'              => $Radius::EAP::EAP_TYPE_LEAP,
 'SIM'               => $Radius::EAP::EAP_TYPE_SIM,
 'TTLS'              => $Radius::EAP::EAP_TYPE_TTLS,
 'AKA'               => $Radius::EAP::EAP_TYPE_AKA,
 'PEAP'              => $Radius::EAP::EAP_TYPE_PEAP,
 'MSCHAP-V2'         => $Radius::EAP::EAP_TYPE_MSCHAPV2,
 );
# Reverse hash of %eap_name_to_type
my %eap_type_to_name = reverse(%eap_name_to_type);

# A hash of EAP type classes we have already loaded
my %typeClasses;

#####################################################################
# authenticateUserEAP
# Called by AuthGeneric
# $self is a ref to the current AuthBy
# $user is Radius::User record for the user being authenticated
# $p is the current request
sub authenticateUserEAP
{
    my ($self, $p) = @_;

    # Must have at least one EAPType configured to continue
    return ($main::REJECT, "EAP authentication is not permitted.") 
	unless ($self->{EAPType} && @{$self->{EAPType}});

    # The EAP message may need to be concatenated, but getAttrByNum
    # does not support multiple attributes
    my ($name, $rest) = $p->{Dict}->attrByNum($Radius::Radius::EAP_MESSAGE);
    my $message = join('', $p->get_attr($name));

    return ($main::REJECT, 'Missing EAP-Message') 
	unless defined $message;

    # Form up a unique key, so we can find a preexisting EAP context for this authenticatio
    # conversation.
    my $nas_id = $p->getNasId();
    my $rad_user_name = $p->getUserName();
    my $nas_port = $p->getAttrByNum($Radius::Radius::NAS_PORT);
    my $calling_station = $p->getAttrByNum($Radius::Radius::CALLING_STATION_ID);
    # Key for finding the same context for the same user. Allow user to roam
    # from AP to AP if  $calling_station is available
    my $key = defined $calling_station 
	? "eap:$calling_station:$rad_user_name"
	: "eap:$nas_id:$nas_port:$rad_user_name";
    my $context = &Radius::Context::get($key, $self->{EAPContextTimeout});
    # print "FIXME: key $key, context $context\n";
    my ($code, $identifier, $length, $data) = unpack('C C n a*', $message);
    $self->log($main::LOG_DEBUG, "Handling with EAP: code $code, $identifier, $length", $p);
    $context->{this_eap_message} = $message;
    $context->{this_id} = $identifier;
    $context->{next_id} = ($context->{this_id} + 1) % 256; # May need this before the reply
    $p->{EAPIdentity} = $context->{identity}; # Sometimes useful for hooks, also %x special character
    if (!defined $code)
    {
	# Its an EAP start, send an Access-Challenge/
	# EAP-Message/Identity
	$self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_IDENTITY);
	return ($main::CHALLENGE, 'EAP Identity Request Challenge');
    }
    elsif ($code == $Radius::EAP::EAP_CODE_REQUEST)
    {
	# Request
	my ($type, $typedata) = unpack('C a*', $data);
	$self->log($main::LOG_DEBUG, "EAP Request $type", $p);
	if ($type == $Radius::EAP::EAP_TYPE_NOTIFICATION)
	{
	    $self->log($main::LOG_INFO, "EAP Notification: $typedata", $p);
	    $self->eap_success($p->{rp}, $identifier);
	    return ($main::ACCEPT);
	}
	else
	{
	    return ($main::REJECT, "EAP Request type $type, but no expected type known")
		unless (defined $context->{eap_type});

	    return ($main::REJECT, "Mismatching EAP Request type $type, expected type $context->{eap_type}")
		unless ($context->{eap_type} == $type);

	    my $class = $self->getEAPClass($type)
		|| return ($main::REJECT, "Unsupported EAP Request $type");
	    $p->{EAPType} = $type;
	    $p->{EAPTypeName} = $eap_type_to_name{$type};
	    return $class->request($self, $context, $p, $type, $typedata);
	}
    }
    elsif ($code == $Radius::EAP::EAP_CODE_RESPONSE)
    {
	# Response
	my ($type, $typedata) = unpack('C a*', $data);
	$self->log($main::LOG_DEBUG, "Response type $type", $p);
	if ($type == $Radius::EAP::EAP_TYPE_IDENTITY)
	{
	    # OK, now have the identity of the supplicant,
	    # send a challenge depending
	    # on the type of the most preferred EAP protocol
	    # we are configured to use
	    my $defaulttype = $eap_name_to_type{$self->{EAPType}[0]}
	       || return ($main::REJECT, "Unknown default EAP type $self->{EAPType}[0]");
	    my $class = $self->getEAPClass($defaulttype)
		|| return ($main::REJECT, "Unsupported default EAP Response/Identity $defaulttype");
	    $p->{EAPType} = $type;
	    $p->{EAPTypeName} = $eap_type_to_name{$type};
	    $context->{eap_type} = $defaulttype;
	    $context->{identity} = $typedata;
	    return $class->response_identity($self, $context, $p, $typedata);
	}
	elsif ($type == $Radius::EAP::EAP_TYPE_NAK)
	{
	    # NAK (Response only). NAS requests a different EAP type.
	    # The type data should indicate the type
	    # of authentication desired by the supplicant
	    my ($desired) = unpack('C', $typedata);
	    # If the type is in our list of permitted types, use it, else reject
	    $self->log($main::LOG_INFO, "EAP Nak desires type $desired", $p);
	    if (grep $eap_name_to_type{$_} == $desired, @{$self->{EAPType}})
	    {
		my $class = $self->getEAPClass($desired)
		    || return ($main::IGNORE, "Desired EAP type $desired not supported");
		$p->{EAPType} = $type;
		$context->{eap_type} = $desired;
		$p->{EAPTypeName} = $eap_type_to_name{$type};
		return $class->response_identity($self, $context, $p);
	    }
	    else
	    {
		return ($main::REJECT, "Desired EAP type $desired not permitted");
	    }
	}
	elsif ($type)
	{
	    return ($main::REJECT, "EAP Response type $type, but no expected type known")
		unless (defined $context->{eap_type});

	    return ($main::REJECT, "Mismatching EAP Response type $type, expected type $context->{eap_type}")
		unless ($context->{eap_type} == $type);

	    my $class = $self->getEAPClass($type)
		|| return ($main::REJECT, "Unsupported EAP Response $type");
	    $p->{EAPType} = $type;
	    $p->{EAPTypeName} = $eap_type_to_name{$type};
	    return $class->response($self, $context, $p, $type, $typedata);
	}
	# Anything else is a runt EAP-Message
    }
    else
    {
	return ($main::IGNORE, "Unknown EAP code from client: $code");
    }
}

#####################################################################
# Set up EAP fields in a reply packet $p
# $code is one of EAP_CODE_*
# $message is the EAP message (if any)
sub eap_reply
{
    my ($self, $p, $context, $code, $message) = @_;

    $p->changeAttrByNum($Radius::Radius::EAP_MESSAGE, 
		      pack
		      ('C C n a*', 
		       $code,
		       $context->{this_id},
		       length($message) + 4,
		       $message));
    # The MESSAGE_AUTHENTICATOR will be filled in 
    # correctly during message packing, we just make space for it
    # here, and alert the packer to its required presence
    $p->changeAttrByNum($Radius::Radius::MESSAGE_AUTHENTICATOR, "\000" x 16);
}

#####################################################################
# Build an EAP Request field in a reply packet $p
# $message is the EAP message (if any)
# Handle long messages by dividing into multiple EAP_MESSAGE
# attributes
sub eap_request
{
    my ($self, $p, $context, $type, $message, $msg_proc) = @_;

    my $m = pack
	('C C n C a*', 
	 $Radius::EAP::EAP_CODE_REQUEST,
	 $context->{next_id},
	 length($message) + 5,
	 $type,
	 $message);

    # Maybe call a processing function on the fully assembled message.
    # Useful for in-band MACs etc
    &$msg_proc($self, $p, $context, $m) if $msg_proc;

    # Divide into multiple instances of EAP-Message, leave enough
    # room in each in each one for the radius attribute id and length
#    my $x = unpack('H*', $m);
#    print "eap_request: $x\n";
    $p->deleteAttrByNum($Radius::Radius::EAP_MESSAGE); # Make sure there is not an old one there
    my $mpart;
    while (length($mpart = substr($m, 0, 253, '')))
    {
	$p->addAttrByNum($Radius::Radius::EAP_MESSAGE, $mpart);
    }
    # The MESSAGE_AUTHENTICATOR will be filled in 
    # correctly during message packing, we just make space for it
    # here, and alert the packer to its required presence
    $p->changeAttrByNum($Radius::Radius::MESSAGE_AUTHENTICATOR, "\000" x 16);
}

#####################################################################
# Build an EAP success packet
# $p is the reply packet we are building
sub eap_success
{
    my ($self, $p, $context) = @_;
    $self->eap_reply($p, $context, $Radius::EAP::EAP_CODE_SUCCESS);
}

#####################################################################
# Build an EAP failure packet
# $p is the reply packet we are building
sub eap_failure
{
    my ($self, $p, $context) = @_;
    $self->eap_reply($p, $context, $Radius::EAP::EAP_CODE_FAILURE);
}

#####################################################################
# Given an EAP protocol type number, load the appropriate 
# Radiator module, and return the class name of the module
sub getEAPClass
{
    my ($self, $type) = @_;

    return $typeClasses{$type} if exists $typeClasses{$type};
    my $class = "Radius::EAP_$type";
    if (eval("require $class"))
    {
	$typeClasses{$type} = $class;
    }
    else
    {
	$self->log($main::LOG_ERR, "Could not load EAP module $class: $@");
    }
    return $typeClasses{$type};
}

#####################################################################
# Possibly calculate and set the MPPE send and recv keys in the reply
# Using the TLS master secret, work out the asymmetrical master keys
# and return them. See rfc2716 for details.
sub setTLSMppeKeys
{
    my ($self, $context, $p, $key) = @_;

    if ($self->{AutoMPPEKeys})
    {
	my ($send, $recv) = unpack('a32 a32', &Radius::TLS::PRF($context, $key, 64));
	
	# Note these are swapped because its for the AP end of the encryption
	$p->{rp}->change_attr('MS-MPPE-Send-Key', $recv);
	$p->{rp}->change_attr('MS-MPPE-Recv-Key', $send);
    }
}

1;
