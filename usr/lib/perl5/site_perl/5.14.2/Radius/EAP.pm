# EAP.pm
#
# Code for handling Authentication via EAP.
# We automatically keep a Context object for each current EAP conversation.
# The key to finding the context is "eap:$nas_id:$nas_port:$calling_station$rad_user_name"
# which relies on the NAS-Id, NAS-Port and Calling-Station-ID being present
# in the Radius request to be sure of uniquely determining the context.
#
# See RFCs 2869 2284 1994
# Supports multiple types in NAK as per RFC 3748
# Supports expanded types as per RFC 3748
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001 Open System Consultants
# $Id: EAP.pm,v 1.61 2014/12/02 21:23:40 hvn Exp $

# Extends AuthGeneric
package Radius::AuthGeneric;
use Radius::Context;
use strict;

# RCS version number of this module
$Radius::EAP::VERSION = '$Revision: 1.61 $';

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
$Radius::EAP::EAP_TYPE_TNC = 38;
$Radius::EAP::EAP_TYPE_FAST = 43;
$Radius::EAP::EAP_TYPE_PAX = 46;
$Radius::EAP::EAP_TYPE_PSK = 47;
$Radius::EAP::EAP_TYPE_AKA_PRIME = 50;
$Radius::EAP::EAP_TYPE_PWD = 52;

$Radius::EAP::EAP_TYPE_EXPANDED_TYPE = 254;

# Maps our EAPType names to EAP type numbers
# Handle a few common aliases too
%Radius::EAP::eap_name_to_type = 
(
 'MD5'               => $Radius::EAP::EAP_TYPE_MD5_CHALLENGE,
 'MD5-Challenge'     => $Radius::EAP::EAP_TYPE_MD5_CHALLENGE,
 'OTP'               => $Radius::EAP::EAP_TYPE_OTP,
 'One-Time-Password' => $Radius::EAP::EAP_TYPE_OTP,
 'GTC'               => $Radius::EAP::EAP_TYPE_TOKEN,
 'Generic-Token'     => $Radius::EAP::EAP_TYPE_TOKEN,
 'TLS'               => $Radius::EAP::EAP_TYPE_TLS,
 'SecurID'           => $Radius::EAP::EAP_TYPE_SECURID,
 'LEAP'              => $Radius::EAP::EAP_TYPE_LEAP,
 'SIM'               => $Radius::EAP::EAP_TYPE_SIM,
 'TTLS'              => $Radius::EAP::EAP_TYPE_TTLS,
 'AKA'               => $Radius::EAP::EAP_TYPE_AKA,
 'PEAP'              => $Radius::EAP::EAP_TYPE_PEAP,
 'MSCHAP-V2'         => $Radius::EAP::EAP_TYPE_MSCHAPV2,
 'TNC'               => $Radius::EAP::EAP_TYPE_TNC,
 'FAST'              => $Radius::EAP::EAP_TYPE_FAST,
 'PAX'               => $Radius::EAP::EAP_TYPE_PAX,
 'PSK'               => $Radius::EAP::EAP_TYPE_PSK,
 'AKA-PRIME'         => $Radius::EAP::EAP_TYPE_AKA_PRIME,
 'PWD'               => $Radius::EAP::EAP_TYPE_PWD,
 );
# Reverse hash of %eap_name_to_type
%Radius::EAP::eap_type_to_name = reverse(%Radius::EAP::eap_name_to_type);

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

    my $context = $self->getEAPContext($p);
    $p->{EAPContext} = $context;
    if (!length($message))
    {
	# Its an EAP start, send an Access-Challenge/
	# EAP-Message/Identity
	$context->{next_id} = 1;
	$self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_IDENTITY, '');
	return ($main::CHALLENGE, 'EAP Identity Request Challenge');
    }

    my ($code, $identifier, $length, $type, $typedata) = unpack('C C n C a*', $message);
    $self->log($main::LOG_DEBUG, "Handling with EAP: code $code, $identifier, $length, $type", $p);
    $context->{this_eap_message} = $message;
    $context->{this_id} = $identifier;
    $context->{next_id} = ($identifier + 1) % 256; # May need this before the reply
    $p->{EAPIdentity} = $context->{identity}; # Sometimes useful for hooks, also %x special character
    $p->{EAPType} = $type;

    if ($code == $Radius::EAP::EAP_CODE_REQUEST)
    {
	# Request
	$self->log($main::LOG_DEBUG, "EAP Request $type", $p);
	if ($type == $Radius::EAP::EAP_TYPE_NOTIFICATION)
	{
	    $self->log($main::LOG_INFO, "EAP Notification: $typedata", $p);
	    $self->eap_failure($p->{rp}, $context);
	    return ($main::REJECT, 'Unexpected EAP Notification');
	}
	elsif ($type)
	{
	    return ($main::REJECT, "EAP Request type $type, but no expected type known")
		unless (defined $context->{eap_type});

	    return ($main::REJECT, "Mismatching EAP Request type $type, expected type $context->{eap_type}")
		unless ($context->{eap_type} == $type);

	    my $class = $self->getEAPClass($type)
		|| return ($main::REJECT, "Unsupported EAP Request $type");
	    $p->{EAPType} = $type;
	    $p->{EAPTypeName} = $Radius::EAP::eap_type_to_name{$type};
	    return $class->request($self, $context, $p, $type, $typedata);
	}
	# Anything else is a runt EAP-Message
	else
	{
	    $self->log($main::LOG_INFO, 'Invalid EAP type in EAP request', $p);
	    $self->eap_failure($p->{rp}, $context);
	    return ($main::REJECT, 'Invalid EAP type in EAP request');
	}
    }
    elsif ($code == $Radius::EAP::EAP_CODE_RESPONSE)
    {
	# Response
	$self->log($main::LOG_DEBUG, "Response type $type", $p);
	if ($type == $Radius::EAP::EAP_TYPE_IDENTITY)
	{
	    # OK, now have the identity of the supplicant,
	    # send a challenge depending
	    # on the type of the most preferred EAP protocol
	    # we are configured to use

	    my $typename = $self->{EAPType}[0]; # Default preferred
	    # Allow an outer to enforce a preferred type
	    $typename = $p->{PreferredEAPType}
	        if    defined $p->{PreferredEAPType}
	           && grep $_ eq $p->{PreferredEAPType}, @{$self->{EAPType}};


	    $p->{EAPType} = $Radius::EAP::eap_name_to_type{$typename};
	    $p->{EAPTypeName} = $typename;
	    my $class = $self->getEAPClass($p->{EAPType})
		|| return ($main::REJECT, "Unsupported default EAP Response/Identity $typename");
	    $context->{eap_type} = $Radius::EAP::eap_name_to_type{$typename};
	    $context->{eap_vendor} = $context->{eap_vendor_type} = undef;
	    $context->{identity} = $typedata;
	    @{$context->{start_time}} = Radius::Util::getTimeHires();
	    return $class->response_identity($self, $context, $p, $typedata);
	}
	elsif ($type == $Radius::EAP::EAP_TYPE_NAK)
	{
	    # Legacy NAK (Response only). NAS requests a different EAP type.
	    # The type data should indicate the type
	    # of authentication desired by the supplicant

	    # If the type is in our list of permitted types, use it, else reject
	    my @desired = unpack('C*', $typedata);
	    foreach (@desired)
	    {
		my $desired = $_;
		$self->log($main::LOG_DEBUG, "EAP Nak desires type $desired", $p);
		if ($desired == $Radius::EAP::EAP_TYPE_EXPANDED_TYPE)
		{
		    # RFC 3748 5.3.1: Legacy Nak. Client indicates desire for an Expanded authentication Type
		    # Send expanded type request (Type 254). Clniet will reply
		    # with Expanded NAK and list of desired types in expanded format (see below).
		    $self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_EXPANDED_TYPE);
		    
		    return ($main::CHALLENGE, 'EAP Expanded Type Request Challenge');
		}
		elsif ($self->eap_type_permitted($desired))
		{
		    my $class = $self->getEAPClass($desired);
		    if ($class)
		    {
			$p->{EAPType} = $desired;
			$context->{eap_type} = $desired;
			$context->{eap_vendor} = $context->{eap_vendor_type} = undef;
			$p->{EAPTypeName} = $Radius::EAP::eap_type_to_name{$desired};
			return $class->response_identity($self, $context, $p);
		    }
		    $self->log($main::LOG_DEBUG, "Desired EAP type $desired not supported. This may be due to a broken client, or a problem loading the required EAP module", $p);
		}
		$self->log($main::LOG_DEBUG, "Desired EAP type $Radius::EAP::eap_type_to_name{$desired} ($desired) not permitted", $p);
		
	    }
	    return ($main::REJECT, "None of the desired EAP types (@desired) are available");
	}
	elsif ($type == $Radius::EAP::EAP_TYPE_EXPANDED_TYPE)
	{
	    my ($vendor_high, $vendor_low, $vendor_type, $rest) = unpack('CnNa*', $typedata);
	    my $vendor = ($vendor_high << 16) | $vendor_low;
	    if ($vendor == 0 && $vendor_type == $Radius::EAP::EAP_TYPE_NAK)
	    {
		# Expanded NAK response with a list of acceptable types in expanded format
		# Look for types we can support, and if found one, send its identity response
		while (length($rest) >= 8)
		{
		    my $dummy;
		    ($dummy, $vendor_high, $vendor_low, $vendor_type, $rest) = unpack('CCnNa*', $rest);
		    my $vendor = ($vendor_high << 16) | $vendor_low;
		    if ($self->eap_type_permitted($vendor_type, $vendor))
		    {
			my $class = $self->getEAPClass($vendor_type, $vendor);
			if ($class)
			{
			    $p->{EAPType} = $vendor_type; # Not very helpful
			    # Until all classes have type_name present
			    $p->{EAPTypeName} = $vendor ? $class->type_name() 
				: $Radius::EAP::eap_type_to_name{$vendor_type};
			    $context->{eap_type} = $Radius::EAP::EAP_TYPE_EXPANDED_TYPE;
			    $context->{eap_vendor} = $vendor;
			    $context->{eap_vendor_type} = $vendor_type;
			    return $class->response_identity($self, $context, $p);
			}
			$self->log($main::LOG_DEBUG, "Desired EAP extended type $vendor_type, vendor $vendor not supported. This may be due to a broken client, or a problem loading the required EAP module", $p);
		    }
		}
		return ($main::REJECT, "None of the desired EAP extended types are available");
	    }
	    else
	    {
		# Expanded type response
		return ($main::REJECT, "EAP Response extended vendor type $vendor_type and vendor $vendor, but no expected vendor type and vendor known")
		    unless (defined $context->{eap_vendor_type} &&
			    defined $context->{eap_vendor});

		return ($main::REJECT, "Mismatching EAP Response extended type $vendor_type and vendor $vendor, expected type $context->{eap_vendor_type} vendor $context->{eap_vendor}")
		    unless ($context->{eap_vendor_type} == $vendor_type &&
			    $context->{eap_vendor} == $vendor);

		my $class = $self->getEAPClass($vendor_type, $vendor)
		    || return ($main::REJECT, "Unsupported EAP Extended type $type");
		$p->{EAPTypeName} = $class->type_name();
		return $class->response($self, $context, $p, $vendor_type, $rest);
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
	    $p->{EAPTypeName} = $Radius::EAP::eap_type_to_name{$type};
	    return $class->response($self, $context, $p, $type, $typedata);
	}
	# Anything else is a runt EAP-Message
	else
	{
	    return ($main::IGNORE, "Bad EAP-Message");
	}
    }
    else
    {
	return ($main::IGNORE, "Unknown EAP code from client: $code");
    }
}

#####################################################################
# Return true if the specified eap type number and vendor is permitted
sub eap_type_permitted
{
    my ($self, $type, $vendor) = @_;

    $vendor = 0 unless defined $vendor;
    my $name;
    foreach $name (@{$self->{EAPType}})
    {
	return 1 if $name =~ /^(\d+):(\d+)$/ && $1 == $vendor && $2 == $type; # vendornumber:typenumber
	return 1 if $name =~ /^(\d+)$/ && $vendor == 0 && $1 == $type;    # typenumber
	return 1 if $Radius::EAP::eap_name_to_type{$name} == $type;       # typename
    }
    return; # Not permitted
}

#####################################################################
# Find a context for this request, in such a way that we always find the same 
# context for requests originating from the same user, unless its the inner request tunnelled from an outer
sub getEAPContext
{
    my ($self, $p) = @_;

    # Form up a unique key, so we can find a preexisting EAP context for this authenticatio
    # conversation.
    return $p->{EAPContext} if defined $p->{EAPContext};
    my $nas_id = $p->getNasId();
    my $rad_user_name = $p->getUserName();
    # Prevent inner requests getting the same context as outers, 
    # and get the correct one independent of changes to User-Name
    $rad_user_name = $p->{OuterSSL} if defined $p->{OuterSSL};
    my $nas_port = $p->getAttrByNum($Radius::Radius::NAS_PORT);
    my $calling_station = $p->getAttrByNum($Radius::Radius::CALLING_STATION_ID);
    # Key for finding the same context for the same user. Allow user to roam
    # from AP to AP if  $calling_station is available
    # The $p->{OuterEAPType prevents inner requests getting the same context as outers
    # even if they have the same User-Name
    my $key = defined $calling_station 
	? "eap:$calling_station:$rad_user_name"
	: "eap:$nas_id:$nas_port:$rad_user_name";
    return &Radius::Context::get($key, $self->{EAPContextTimeout});
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
# Build an EAP expanded type Request field in a reply packet $p
# $message is the EAP message (if any)
# Handle long messages by dividing into multiple EAP_MESSAGE
# attributes
sub eap_request_expanded
{
    my ($self, $p, $context, $type, $vendor, $message, $msg_proc) = @_;

    my $m = pack
	('C C n N N a*', 
	 $Radius::EAP::EAP_CODE_REQUEST,
	 $context->{next_id},
	 length($message) + 12,
	 $vendor | ($Radius::EAP::EAP_TYPE_EXPANDED_TYPE << 24),
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

    my $interval = Radius::Util::timeInterval(@{$context->{start_time}}, Radius::Util::getTimeHires());
    $self->log($main::LOG_DEBUG, "EAP Success, elapsed time $interval", $p);
    $self->eap_reply($p, $context, $Radius::EAP::EAP_CODE_SUCCESS);
}

#####################################################################
# Build an EAP failure packet
# $p is the reply packet we are building
sub eap_failure
{
    my ($self, $p, $context) = @_;

    my $interval = Radius::Util::timeInterval(@{$context->{start_time}}, Radius::Util::getTimeHires());
    $self->log($main::LOG_DEBUG, "EAP Failure, elapsed time $interval", $p);
    $self->eap_reply($p, $context, $Radius::EAP::EAP_CODE_FAILURE, '');
}

#####################################################################
# Call this when an EAP TLS handshake fails. Normally such a failure would 
# result in IGNORE, but in some circumstances we want to REJECT instead
sub eap_error
{
    my ($self, $message) = @_;

    return ($self->{EAPErrorReject} ? $main::REJECT : $main::IGNORE, $message);
}

#####################################################################
# Given an EAP protocol type number and perhaps type vendor, load the appropriate 
# Radiator module, and return the class name of the module
# If the vendor is undefined, assume IETF vendor 0
sub getEAPClass
{
    my ($self, $type, $vendor) = @_;

    $vendor = 0 unless defined $vendor;
    return $typeClasses{$vendor}{$type} if exists $typeClasses{$vendor}{$type};
    my $class = $vendor ? "Radius::EAP_${vendor}_${type}" : "Radius::EAP_${type}";
    if (eval("require $class"))
    {
	$typeClasses{$vendor}{$type} = $class;
    }
    else
    {
	$self->log($main::LOG_ERR, "Could not load EAP module $class: $@");
    }
    return $typeClasses{$vendor}{$type};
}

#####################################################################
# Calculate the MSK using the TLS PRF and the TLS master secret
# Possibly set the MPPE send and recv keys in the reply
# Using the TLS master secret, work out the asymmetrical master keys
# and set them in the reply packet.
# Also export the MSK and EMSK if required
sub setTLSMppeKeys
{
    my ($self, $context, $p, $key) = @_;

    my ($msk, $emsk);
    if ($self->{ExportEMSK})
    {
	# Need to do more work
	($msk, $emsk) = unpack('a64 a64', &Radius::TLS::PRF($context, $key, 128));
	$p->{rp}->{msk} = $msk;
	$p->{rp}->{emsk} = $emsk;
    }
    else
    {
	$msk = $p->{rp}->{msk} = &Radius::TLS::PRF($context, $key, 64);
    }
    if ($self->{AutoMPPEKeys})
    {
	my ($send, $recv) = unpack('a32 a32', $msk);
	# Note these are swapped because its for the AP end of the encryption
	$p->{rp}->change_attr('MS-MPPE-Send-Key', $recv);
	$p->{rp}->change_attr('MS-MPPE-Recv-Key', $send);
    }
}

1;
