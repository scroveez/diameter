# ServerDIAMETER.pm
#
# Object for receiving Diameter requests and satisfying them
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2003-2005 Open System Consultants
# $Id: ServerDIAMETER.pm,v 1.38 2014/11/27 20:57:06 hvn Exp $

package Radius::ServerDIAMETER;
@ISA = qw(Radius::Configurable Radius::StreamServer);
use Radius::Configurable;
use Radius::StreamServer;
use Radius::Diameter;
use Radius::DiaPeer;
use Radius::DiaMsg;
use Radius::DiaDict;
use Radius::DiaUtil;
use Radius::Radius;
use Math::BigInt;
use strict;

#####################################################################
# This hash describes all the standards types of keywords understood by this
# class. If a keyword is not present in ConfigKeywords for this
# class, or any of its superclasses, Configurable will call sub keyword
# to parse the keyword
# See Configurable.pm for the list of permitted keywordtype
%Radius::ServerDIAMETER::ConfigKeywords = 
(
 'ReadTimeout'                => 
 ['integer', 'This optional parameter specifies the maximum time to wait for incoming Diameter connections to complete their initial handshaking. Defaults to 10 seconds. If a Diameter CER message is not received from the peer by ServerDIAMETER within this time period, the connection will be shut down.', 1],

 'OriginHost'                 => 
 ['string', 'This parameter specifies the name that ServerDIAMETER will use to identify itself to any connecting Diameter peers. It is sent to the peer in the Diameter CER message. It is not optional an must be specified in the ServerDIAMETER clause. Diameter peers may use OriginHost to determine whether they have connected to the correct peer, so it may be critical that it be configured correctly.', 1],

 'OriginRealm'                => 
 ['string', 'This parameter specifies the name of the user Realm that ServerDIAMETER is willing to handle. It is sent to connecting Diameter peers in the CER message, and the peer will use it to determine which requests are to be routed to this ServerDIAMETER. It is not optional an must be specified in the ServerDIAMETER clause.', 1],

 'ProductName'                => 
 ['string', 'This optional parameter is used to identify the product name of this Diameter peer. It is sent to connecting Diameter peers in the CER message. It defaults to "Radiator".', 1],

 'AddToRequest'               => 
 ['string', 'This optional parameter is used to add extra RADIUS attributes to the RADIUS request generated from each incoming Diameter request. It can be used to tag requests arriving from ServerDIAMETER for special handling within Radiator or in remote RADIUS servers.', 1],

 'DefaultRealm'               => 
 ['string', 'This optional parameter can be used to specify a default realm to use for received Diameter requests that have a username that does not include a realm. If the incoming user name does not have a realm (i.e. there is no @something following the user name) and if DefaultRealm is specified, the User-Name in the resulting RADIUS request will have @defaultrealm appended to it. The realm can then be used to trigger a specific <Realm> or <Handler> clause. This is useful if you operate a number of Diameter peers for different customer groups and where some or all of your customers log in without specifying a realm.', 1],

 'PreHandlerHook'             => 
 ['hook', 'This optional parameter allows you to define a Perl function that will be called during packet processing. PreHandlerHook is called for each request received by this ServerDIAMETER before it is passed to a Realm or Handler clause. A reference to the current request is passed as the only argument.', 1],

 'UseSSL'             => 
 ['flag', 'Not supported', 3],

 'AuthApplicationIds'             => 
 ['string', 'This optional parameter allows you to define the Auth Application Ids anounced in CER. Defaults to DIAMETER BASE, NASREQ and Diameter-EAP', 1],

 'AcctApplicationIds'             => 
 ['string', 'This optional parameter allows you to define the Acct Application Ids anounced in CER. Defaults to BASE_ACCOUNTING', 1],

 'SupportedVendorIds'             => 
 ['string', 'This optional parameter allows you to define the Supported Vendor Ids anounced in CER. There is no default and no Supported-Vendor-Id is announced by default. Keyword "DictVendors" is an alias group for all vendors in the default dictionary and the dictionary file configured with DiameterDictionaryFile.', 1],

 'PacketTrace'                 => 
 ['flag', 
  'Forces all packets that pass through this module to be logged at trace level 4. This is useful for logging packets that pass through this clause in more detail than other clauses during testing or debugging. The packet tracing  will stay in effect until it passes through another clause with PacketTrace set to off or 0.', 
  1],

 'PostDiaToRadiusConversionHook'             => 
 ['hook', 'This optional parameter allows you to define a Perl function that will be called during packet processing. PostDiaToRadiusConversionHook is called after an incoming Diameter request has been converted to its equivalent RADIUS request, allowing you to alter or ad to attritbute conversions etc. It is passed references to the incoming Diameter reqest and the converted RADIUS request.', 2],

 'PostRadiusToDiaConversionHook'             => 
 ['hook', 'This optional parameter allows you to define a Perl function that will be called during packet processing. PostDiaToRadiusConversionHook is called after an RADIUS reply has been converted to its equivalent Diameter reply, prior to being sent back to the Diameter client. It is passed references to the RADIUS reply and the converted Diameter reply.', 2],


 );

# RCS version number of this module
$Radius::ServerDIAMETER::VERSION = '$Revision: 1.38 $';

$Radius::ServerDIAMETER::dictionary = Radius::DiaDict->new
    (Filename => &Radius::Util::format_special($main::config->{DiameterDictionaryFile}));
$Radius::ServerDIAMETER::dictionary->activate();

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->Radius::Configurable::activate();
    $self->Radius::StreamServer::activate();

    # Resolve the application names in SupportedAuth- and
    # SupportedVendorAuth and -AcctApplicationIds to numeric
    # values. Load any dictionaries the applications need. Then
    # resolve the supported vendors and vendor parts in supported
    # vendor apps.
    Radius::DiaUtil::resolve_application_ids($self);
    Radius::DiaUtil::load_dictionaries($self);
    Radius::DiaUtil::resolve_vendor_ids($self);
}


#####################################################################
# Do per-instance default initialization
# This is called by Configurable during Configurable::new before
# the config file is parsed. Its a good place initialize instance 
# variables
# that might get overridden when the config file is parsed.
# Do per-instance default initialization. This is called after
# construction is complete
sub initialize
{
    my ($self) = @_;

    $self->Radius::Configurable::initialize();
    $self->Radius::StreamServer::initialize();

    $self->{ProductName} = 'Radiator';

    $self->{Dictionary} = $Radius::ServerDIAMETER::dictionary;
    $self->{SupportedVendorIds} = "";
    $self->{AuthApplicationIds} = "$Radius::DiaMsg::APPID_BASE, $Radius::DiaMsg::APPID_NASREQ, $Radius::DiaMsg::APPID_DIAMETER_EAP";
    $self->{AcctApplicationIds} = "$Radius::DiaMsg::APPID_BASE_ACCOUNTING";
    $self->{VendorAuthApplicationIds} = undef;
    $self->{VendorAcctApplicationIds} = undef;
    $self->{Port} = 3868; # IANA official for Diameter
    $self->{ReadTimeout} = 10;
}

#####################################################################
# This is called by StreamServer when a new connetion has been made
sub handle_new_connection
{
    my ($self, $newsocket) = @_;

    Radius::DiameterConnection->new
	($self, $newsocket,
	 ReadTimeout               => $self->{ReadTimeout},
	 ProductName               => $self->{ProductName},
	 OriginHost                => $self->{OriginHost},
	 OriginRealm               => $self->{OriginRealm},
	 AddToRequest              => $self->{AddToRequest},
	 Identifier                => $self->{Identifier},
	 Dictionary                => $self->{Dictionary},
	 MaxBufferSize             => $self->{MaxBufferSize},
	 UseTLS                    => $self->{UseTLS},
	 SupportedVendorIds	   => $self->{Ids}{SupportedVendorIds},
	 AuthApplicationIds	   => $self->{Ids}{AuthApplicationIds},
	 AcctApplicationIds	   => $self->{Ids}{AcctApplicationIds},
	 VendorAuthApplicationIds  => $self->{Ids}{VendorAuthApplicationIds},
	 VendorAcctApplicationIds  => $self->{Ids}{VendorAcctApplicationIds},
	 TLS_ExpectedPeerName      => $self->{TLS_ExpectedPeerName},
	 TLS_SubjectAltNameURI     => $self->{TLS_SubjectAltNameURI},
	 TLS_CertificateFingerprint=> $self->{TLS_CertificateFingerprint},
	 TLS_PrivateKeyPassword    => $self->{TLS_PrivateKeyPassword},
	 TLS_CertificateType       => $self->{TLS_CertificateType},
	 TLS_CertificateFile       => $self->{TLS_CertificateFile},
	 TLS_CertificateChainFile  => $self->{TLS_CertificateChainFile},
	 TLS_PrivateKeyFile        => $self->{TLS_PrivateKeyFile},
	 );
}

#####################################################################
# Remove various circular references that would prevent automatic destruction
# of ServerDIAMETER and DiameterConnection objects
sub destroy
{
    my ($self) = @_;

    $self->Radius::StreamServer::destroy();
}

#####################################################################
# Called by the connection if un unknown request type is received.
# Subclass and override this if you want handle this Diameter request type in a special way
sub handle_other_request
{
    my ($self, $connection, $dia_request, $radius_request) = @_;
	
    $self->log($main::LOG_WARNING, "DiameterConnection $connection->{OriginHost} Diameter request from $connection->{Host}:$connection->{Port} was not a known type of request. Ignored.");
}

#####################################################################
#####################################################################
#####################################################################
package Radius::DiameterConnection;
use vars qw(@ISA);
@ISA = qw(Radius::StreamServer::Connection Radius::Diameter);

#####################################################################
sub new
{
    my ($class, $parent, $socket, @args) = @_;

    my $self = $class->SUPER::new($parent, $socket, @args);
    # Constructor can fail
    if ($self)
    {
	# Make sure we close down if we dont get a diameter connection soon
	$self->{read_timer} = Radius::Select::add_timeout
	    (time + $self->{ReadTimeout}, 
	     sub { $self->read_timeout()});
	
	$self->log($main::LOG_DEBUG,  "New DiameterConnection created for $self->{Host}:$self->{Port}");
    }
    return $self;
}

#####################################################################
# This is called when an the ReadTimeout expires, indicating that we did not get a
# sensible Diameter CER message from this connection.
sub read_timeout
{
    my ($self) = @_;
    
    $self->log($main::LOG_ERR, "DiameterConnection $self->{OriginHost} read_timeout from $self->{Host}:$self->{Port}. Closing");
    # The connection should disappear about now
    $self->stream_disconnected();
}

#####################################################################
# Called when a complete request has been received
# Parse and process it
# Version has been checked
sub recv_diameter
{
    my ($self, $rec) = @_;

    # If we have already got our peer, use it.
    return $self->{DiaPeer}->r_recv_callback($self, $rec) if $self->{DiaPeer};

    # Else find or create a DiaPeer to handle this peer
    my $p = Radius::DiaMsg->new(Data => $rec);
    
    $self->log($main::LOG_EXTRA_DEBUG, "Received initial Diameter request raw data: " . unpack('H*', $rec));
    $self->log($main::LOG_DEBUG, "Packet dump:\n*** Received initial Diameter request ....\n" . $p->format);
    
    # If its a CER, then its the start of a new incoming Diameter connection
    # So either make a new Peer, or despatch it to an existing peer, possibly
    # for an election
    if (   $p->version() == 1
	&& $p->code() == $Radius::DiaMsg::CODE_CER
	&& $p->flags() & $Radius::DiaMsg::FLAG_REQUEST)
    {
	# Dont need this read timer, since we have received a CER from the peer
	&Radius::Select::remove_timeout($self->{read_timer});
	
	# REVISIT: Should instead discard and recreate peers?
	my $peeroriginhost = $p->get($Radius::DiaAttrList::ACODE_ORIGIN_HOST);
	$self->{DiaPeer} = Radius::DiaPeer::find($peeroriginhost);
	if ($self->{DiaPeer} && $self->{DiaPeer}->state() ne 'Closed')
	{
	    $self->log($main::LOG_ERR, "DiameterConnection $self->{OriginHost} received a connection attempt for a peer that is already connected $self->{Host}:$self->{Port}. Closing");
	    $self->stream_disconnected();
	    return;
	}
	
	$self->{DiaPeer} = Radius::DiaPeer->new
	    (Identifier             => $peeroriginhost,
	     OriginHost             => $self->{OriginHost},
	     OriginRealm            => $self->{OriginRealm},
	     ProductName            => $self->{ProductName},
#	     TransportUpCallback    => $self->{TransportUpCallback},
#	     TransportDownCallback  => $self->{TransportDownCallback},
#	     RecvMessageCallback    => sub {$self->recv_message_callback(@_)},
	     LogStdout              => $self->{LogStdout},
	     Trace                  => $self->{Trace},
	     UseTLS                 => $self->{UseTLS},
	     Protocol               => $self->{Protocol},
	     RConn                  => $self,
	     SupportedVendorIds     => $self->{SupportedVendorIds},
	     AuthApplicationIds     => $self->{AuthApplicationIds},
	     AcctApplicationIds     => $self->{AcctApplicationIds},
	     VendorAuthApplicationIds => $self->{VendorAuthApplicationIds},
	     VendorAcctApplicationIds => $self->{VendorAcctApplicationIds},
	     InbandSecurityIds      => [($self->{UseTLS} ?
					$Radius::DiaAttrList::INBAND_SECURITY_ID_TLS :
					$Radius::DiaAttrList::INBAND_SECURITY_ID_NO_INBAND_SECURITY  )],
	     Dictionary             => $self->{Dictionary},
	     ) unless $self->{DiaPeer};
    
	# Register the peer so we can find it later
	$self->{DiaPeer}->registerAs($self->{DiaPeer}->{ObjType}, $self->{DiaPeer}->{Identifier});

	# Tell the peer about this new responder connection
	$self->{DiaPeer}->setRConn($self);
	$self->{DiaPeer}->{RecvMessageCallback} = sub {$self->recv_message_callback(@_)};
	$self->{DiaPeer}->activate();

	# And get it to receive and process it
	$self->{DiaPeer}->{current_message} = $p;
	$self->{DiaPeer}->event('R-Conn-CER');
    }
    else
    {
	$self->log($main::LOG_ERR, "DiameterConnection $self->{OriginHost} did not receive a Version 1 CER from $self->{Host}:$self->{Port}. Closing");
	$self->stream_disconnected();
    }
}

#####################################################################
# Copy and convert all diameter attribtutes in $msg to Radius attributes
# in $tp. Recursive so we can deal with grouped attrs
sub copy_dia_to_radius_attrs
{
    my ($self, $msg, $tp) = @_;

    # This violates the encapsulation of AttrList, but its good for performance
    foreach (@{$msg->{Attributes}})
    {
	# [attrnum, vendornum, flags, value]
	my ($attrnum, $vendornum, $flags, $rvalue) = @$_;
	my $value = $msg->decode($attrnum, $vendornum, $flags, $rvalue);

	my ($dname, $dtype) = $self->{Dictionary}->attrByNum($attrnum, $vendornum);
	if ($dtype eq 'Grouped')
	{
	    # Recurse into the group
	    $self->copy_dia_to_radius_attrs($value, $tp)
	}
	elsif ($vendornum != 0 && $attrnum <= 255)
	{
	    # VSA, as per RFC 4005 sect 9.6.1
	    my ($name, $dummy) = $tp->{Dict}->attrByNum($attrnum & 0xff, $vendornum);
	    $tp->add_attr($name, $value);
	}
	elsif ($attrnum == $Radius::DiaAttrList::ACODE_CHAP_AUTH)
	{
	    # $value should be a ref to a Radius::DiaAttrList
	    # The CHAP-Challenge that should acoompmany this CHAP-Auth
	    # will be converted as a standard Radius attribute
	    my $chap_id = $value->get_attr($Radius::DiaAttrList::ACODE_CHAP_IDENT);
	    my $chap_response = $value->get_attr($Radius::DiaAttrList::ACODE_CHAP_RESPONSE);
	    $tp->changeAttrByNum($Radius::Radius::CHAP_PASSWORD, 
				 $chap_id . $chap_response);
	}
	elsif ($attrnum == $Radius::DiaAttrList::ACODE_ACCOUNTING_INPUT_OCTETS)
	{
	    # Convert to gigawords?
	    my $n = Math::BigInt->new($value);
	    my $max = Math::BigInt->new('268435456');
	    my ($gigawords, $octets) = $n->bdiv($max);
	    $tp->addAttrByNum($Radius::Radius::ACCT_INPUT_GIGAWORDS, $gigawords) 
		if $gigawords;
	    $tp->addAttrByNum($Radius::Radius::ACCT_INPUT_OCTETS, $octets);
	}
	elsif ($attrnum == $Radius::DiaAttrList::ACODE_ACCOUNTING_OUTPUT_OCTETS)
	{
	    # Convert to gigawords?
	    my $n = Math::BigInt->new($value);
	    my $max = Math::BigInt->new('268435456');
	    my ($gigawords, $octets) = $n->bdiv($max);
	    $tp->addAttrByNum($Radius::Radius::ACCT_OUTPUT_GIGAWORDS, $gigawords) 
		if $gigawords;
	    $tp->addAttrByNum($Radius::Radius::ACCT_OUTPUT_OCTETS, $octets);
	}
	elsif ($attrnum == $Radius::DiaAttrList::ACODE_ACCOUNTING_INPUT_PACKETS)
	{
	    $tp->addAttrByNum($Radius::Radius::ACCT_INPUT_PACKETS, $value);
	}
	elsif ($attrnum == $Radius::DiaAttrList::ACODE_ACCOUNTING_OUTPUT_PACKETS)
	{
	    $tp->addAttrByNum($Radius::Radius::ACCT_OUTPUT_PACKETS, $value);
	}
	elsif ($attrnum == $Radius::DiaAttrList::ACODE_ACCOUNTING_RECORD_TYPE)
	{
	    $tp->addAttrByNum($Radius::Radius::ACCT_STATUS_TYPE, 
			      ($value eq 'EVENT_RECORD')
			      ? $Radius::Radius::ACCT_STATUS_TYPE_STOP
			      : ($value eq 'START_RECORD')
			      ? $Radius::Radius::ACCT_STATUS_TYPE_START
			      : ($value eq 'STOP_RECORD')
			      ? $Radius::Radius::ACCT_STATUS_TYPE_STOP
			      : ($value eq 'INTERIM_RECORD')
			      ? $Radius::Radius::ACCT_STATUS_TYPE_ALIVE
			      : $Radius::Radius::ACCT_STATUS_TYPE_START);
	}
	elsif ($attrnum == $Radius::DiaAttrList::ACODE_USER_PASSWORD)
	{
	    $tp->addAttrByNum($Radius::Radius::USER_PASSWORD, $value);
	    $tp->{DecodedPassword} = $value;
	}
	elsif ($attrnum == $Radius::DiaAttrList::ACODE_EAP_PAYLOAD)
	{
	    # May need to split
	    my $substr;
	    do
	    {
		$substr = substr($value, 0, 254, '');
		$tp->addAttrByNum($Radius::Radius::EAP_MESSAGE, $substr);
	    } while (length($value));
	}
	elsif ($attrnum < 256)
	{
	    $tp->addAttrByNum($attrnum, $value);
	}
	elsif ($attrnum == $Radius::DiaAttrList::ACODE_ORIGIN_HOST)
	{
	    # Last in case there is a Nas-Identifier in the incoming
	    $tp->changeAttrByNum($Radius::Radius::NAS_IDENTIFIER, $value);
	}

    }
}

#####################################################################
# Copy and convert all RADIUS attribtutes in $p to Diameter attributes
# in $dia_reply. Recursive so we can deal with grouped attrs
sub copy_radius_to_dia_attrs
{
    my ($self, $p, $dia_reply) = @_;

    my $code = $p->{rp}->code;
    my ($mppe_send_key, $mppe_recv_key);
    foreach (@{$p->{rp}->{Attributes}})
    {
	# Get the Radius attribute number from the name
	my ($attrname, $attrval) = @$_;
	my ($name, $number, $type, $vendorid) 
	    = $main::dictionary->attrByName($attrname); # The RADIUS dictionary

	if (defined $name)
	{
	    if ($number == $Radius::Radius::EAP_MESSAGE)
	    {
		# Do not copy EAP-Message now but create EAP-Payload later
	    }
	    elsif ($code eq 'Access-Challenge'
		   && $number == $Radius::Radius::SESSION_TIMEOUT)
	    {
		$dia_reply->add_attr($Radius::DiaAttrList::ACODE_MULTI_ROUND_TIMEOUT, 0, 
				     $Radius::DiaAttrList::AFLAG_MANDATORY, 
				     $attrval);
	    }
	    elsif ($number == $Radius::Radius::MS_MPPE_SEND_KEY)
	    {
		$mppe_send_key = $attrval;
	    }
	    elsif ($number == $Radius::Radius::MS_MPPE_RECV_KEY)
	    {
		$mppe_recv_key = $attrval;
	    }
	    elsif ($number == $Radius::Radius::MESSAGE_AUTHENTICATOR)
	    {
		# Drop this: it was already checked on receipt and not
		# used in Diameter.
	    }
	    else
	    {
		# May need to parse Grouped attributes
		# Get the diameter dictionary entry
		my ($dname, $dtype) = $self->{Dictionary}->attrByNum($number, $vendorid);
		if ($dtype eq 'Grouped')
		{
		    # Parse string from RADIUS attribute into a Grouped Diameter attribute
		    my $dlist = Radius::DiaAttrList->new();
		    $dlist->parse($attrval);
		    $attrval = $dlist;
		}
		$dia_reply->add_attr($number, $vendorid, 0, $attrval);
	    }
	}
	else
	{
	    # Pseudo Diameter Attribute with no RADIUS equivalent ?
	    $self->log($main::LOG_WARNING, "Radius reply attribute $attrname is not found in the Radius dictionary and cannot be converted to Diameter attribute" , $p);
	}
    }

    if ($dia_reply->code() == $Radius::DiaMsg::CODE_DER)
    {
	# RFC 4072 section 6.2:
	if ($p->{rp}->getAttrByNum($Radius::Radius::ERROR_CAUSE) == 202)
	{
	    # 202 is "Invalid EAP Packet (Ignored)"
	    $dia_reply->add_attr($Radius::DiaAttrList::ACODE_EAP_REISSUED_PAYLOAD, 0,
			 $Radius::DiaAttrList::AFLAG_MANDATORY,
			 join('', $p->{rp}->get_attr('EAP-Message')));
	}
	else
	{
	    $dia_reply->add_attr($Radius::DiaAttrList::ACODE_EAP_PAYLOAD, 0,
			 $Radius::DiaAttrList::AFLAG_MANDATORY,
			 join('', $p->{rp}->get_attr('EAP-Message')));
	}

	# Get the EAP method from the request if the reply is Access-Accept
	if ($code eq 'Access-Accept')
	{
	    my $eap_message = $p->get_attr('EAP-Message');
	    $dia_reply->add_attr($Radius::DiaAttrList::ACODE_ACCOUNTING_EAP_AUTH_METHOD, 0,
				 $Radius::DiaAttrList::AFLAG_MANDATORY,
				 unpack('x x x x C', $eap_message))
		if (length($eap_message) >= 5);
	}
    }

    if (defined $mppe_send_key && defined $mppe_recv_key)
    {
	    $dia_reply->add_attr($Radius::DiaAttrList::ACODE_EAP_MASTER_SESSION_KEY, 0, 
			 $Radius::DiaAttrList::AFLAG_MANDATORY,
			 $mppe_recv_key . $mppe_send_key);
    }
}

#####################################################################
# Copy Diameter attrs to RADIUS attrs
# and despatch the resulting RADIUS request
sub despatch_request
{
    my ($self, $dia_request, $radius_request) = @_;

    # Now copy all the Radius-like attributes from the incoming request to the 
    # new Radius request
    $self->copy_dia_to_radius_attrs($dia_request, $radius_request);

    $radius_request->{OriginalUserName} = $radius_request->getAttrByNum($Radius::Radius::USER_NAME);
    $radius_request->{diameter_request} = $dia_request; # Need it during the reply

    # Arrange to call our reply function when we get a reply
    $radius_request->{replyFn} = [\&Radius::DiameterConnection::replyFn, $self];

    # Call the PostDiaToRadiusConversionHook, if there is one
    $self->{parent}->runHook('PostDiaToRadiusConversionHook', $radius_request, \$dia_request, \$radius_request);

    my $text = "Packet dump:\n*** Diameter request converted to Radius request ....\n" . $radius_request->dump;
    $self->log($main::LOG_DEBUG, $text, $radius_request);

    $main::statistics{total_packets}++; $main::statistics{packets_this_sec}++;

    $self->dispatch_radius_request($radius_request);
}

#####################################################################
# Copy and convert a specific type of Diameter request to RADIUS request
# Subclass and override this if you want handle this Diameter request type in a special way
sub handle_aa_request
{
    my ($self, $dia_request, $radius_request) = @_;

    $radius_request->set_code('Access-Request');
    $self->despatch_request($dia_request, $radius_request);
}

#####################################################################
# Copy and convert a specific type of Diameter request to RADIUS request
# Subclass and override this if you want handle this Diameter request type in a special way
sub handle_accounting_request
{
    my ($self, $dia_request, $radius_request) = @_;

    $radius_request->set_code('Accounting-Request');
    $self->despatch_request($dia_request, $radius_request);
}

#####################################################################
# Copy and convert a specific type of Diameter request to RADIUS request
# Subclass and override this if you want handle this Diameter request type in a special way
sub handle_der_request
{
    my ($self, $dia_request, $radius_request) = @_;

    $radius_request->set_code('Access-Request');
    $self->despatch_request($dia_request, $radius_request);
}

#####################################################################
# Copy and convert a specific type of Diameter request to RADIUS request
# Subclass and override this if you want handle this Diameter request type in a special way
sub handle_cc_request
{
    my ($self, $dia_request, $radius_request) = @_;

    $radius_request->set_code('Access-Request');
    $self->despatch_request($dia_request, $radius_request);
}

#####################################################################
# Copy and convert any other type of Diameter request to RADIUS request
# Subclass and override this if you want handle this Diameter request type in a special way
sub handle_other_request
{
    my ($self, $dia_request, $radius_request) = @_;
	
    $self->{parent}->handle_other_request($self, $dia_request, $radius_request);
}

#####################################################################
# Copy and convert Diameter request to RADIUS request in a request-specific fashion
# Default behaviour is to convert everyting into RADIUS and despatch it
# Subclass and override this if you want handle all Diameter requests in a special way
sub handle_request
{
    my ($self, $dia_request, $radius_request) = @_;

    # Now look at the type of Diameter request and handle it with 
    # a type-specific method that can be overridden if required
    if ($dia_request->code() == $Radius::DiaMsg::CODE_AA)
    {
	$self->handle_aa_request($dia_request, $radius_request);
    }
    elsif ($dia_request->code() == $Radius::DiaMsg::CODE_ACCOUNTING)
    {
	$self->handle_accounting_request($dia_request, $radius_request);
    }
    elsif ($dia_request->code() == $Radius::DiaMsg::CODE_DER)
    {
	$self->handle_der_request($dia_request, $radius_request);
    }
    elsif ($dia_request->code() == $Radius::DiaMsg::CODE_CREDIT_CONTROL)
    {
	$self->handle_cc_request($dia_request, $radius_request);
    }
    else
    {
	$self->handle_other_request($dia_request, $radius_request);
    }
}

#####################################################################
# This is called by DiaPeer when a complete application message is received
# and is ready to be processed by an applicaiton
sub recv_message_callback
{
    my ($self, $peer, $msg) = @_;

    # Convert the diameter request into a Radius request
    my $tp = Radius::Radius->new($main::dictionary);
    $tp->{RecvFrom} = $self->{peer};
    $tp->{RecvFromPort} = $self->{Port};
    $tp->{RecvFromAddress} = $self->{Peeraddr};
    ($tp->{RecvTime}, $tp->{RecvTimeMicros}) = &Radius::Util::getTimeHires;
    $tp->{Client} = $self; # So you can use Client-Identifier check items
    $tp->set_authenticator(&Radius::Util::random_string(16));
    # Add arbitrary data to every request
    $tp->parse(&Radius::Util::format_special($self->{AddToRequest}))
	if (defined $self->{AddToRequest});

    $self->handle_request($msg, $tp);
}

#####################################################################
# Dispatch a fake Radius request to the appropriate Handler
sub dispatch_radius_request
{
    my ($self, $tp) = @_;

    # Make sure top level config is updated with stats
    push(@{$tp->{StatsTrail}}, \%{$main::config->{Statistics}});

    $tp->{PacketTrace} = $self->{parent}->{PacketTrace} 
        if defined $self->{parent}->{PacketTrace}; # Optional extra tracing

    # Now arrange for this fake radius request to be handled and find out the result
    my ($userName, $realmName) = split(/@/, $tp->get_attr('User-Name'));
    # Maybe set a default realm
    no warnings qw(uninitialized);
    if (defined $userName
	&& $realmName eq '' 
	&& defined $self->{'DefaultRealm'})
    {
	$realmName = $self->{'DefaultRealm'};
	$tp->changeUserName("$userName\@$realmName");
    }

    my ($handler, $finder, $handled);
    # Call the PreHandlerHook, if there is one
    $self->{parent}->runHook('PreHandlerHook', $tp, \$tp);
    foreach $finder (@Radius::Client::handlerFindFn)
    {
	if ($handler = &$finder($tp, $userName, $realmName))
	{
	    # Make sure the handler is updated with stats
	    push(@{$tp->{StatsTrail}}, \%{$handler->{Statistics}});
	    
	    # replyFn will be called from inside the handler when the
	    # reply is available
	    $handled = $handler->handle_request($tp);
	    last;
	}
    }
    $self->log($main::LOG_WARNING, "DiameterConnection could not find a Handler")
	if !$handler;

    # Adjust statistics
    my $code = $tp->code();
    $tp->statsIncrement('requests');
    $tp->statsIncrement('accessRequests') 
	if $code eq 'Access-Request';
    $tp->statsIncrement('accountingRequests') 
	if $code eq 'Accounting-Request';
    
}


#####################################################################
# This function is called automatically when an authentication request
# has been serviced. $p->{rp} will have been set to the reply message
sub replyTo
{
    my ($self, $p) = @_;

    my $code = $p->{rp}->code;
    $p->statsIncrement('accessAccepts')
	if $code eq 'Access-Accept';
    $p->statsIncrement('accessRejects')
	if $code eq 'Access-Reject';
    $p->statsIncrement('accessChallenges')
	if $code eq 'Access-Challenge';
    $p->statsIncrement('accountingResponses')
	if $code eq 'Accounting-Response';
    my $response_time = &Radius::Util::timeInterval($p->{RecvTime}, $p->{RecvTimeMicros}, &Radius::Util::getTimeHires);
    $p->statsAverage($response_time, 'responseTime');

    my $text = "Packet dump:\n*** Sending reply to Diameter $self->{Host}:$self->{Port} ....\n" . $p->{rp}->dump;
    $self->log($main::LOG_DEBUG, $text, $p);

    # The original incoming Diameter request
    my $diameter_request = $p->{diameter_request};

    # Convert Radius reply back into Diameter
    my $dia_reply = $diameter_request->new_reply();
    # Copy various interesting attributes back to the reply if present
    foreach ($Radius::DiaAttrList::ACODE_ORIGIN_REALM,
	     $Radius::DiaAttrList::ACODE_AUTH_APPLICATION_ID,
	     $Radius::DiaAttrList::ACODE_AUTH_REQUEST_TYPE,
	     $Radius::DiaAttrList::ACODE_ACCOUNTING_RECORD_TYPE,
	     $Radius::DiaAttrList::ACODE_ACCOUNTING_RECORD_NUMBER)
    {
	my $v = $diameter_request->get_attr($_);
	$dia_reply->add_attr($_, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, $v) if defined $v;
    }
    $dia_reply->add_attr($Radius::DiaAttrList::ACODE_ORIGIN_HOST, 0,
		 $Radius::DiaAttrList::AFLAG_MANDATORY, $self->{OriginHost});

    my $result_code;
    if ($code eq 'Access-Accept')
    {
	$result_code = $Radius::DiaAttrList::RESULT_CODE_DIAMETER_SUCCESS;
    }
    elsif ($code eq 'Access-Reject')
    {
	$result_code = $Radius::DiaAttrList::RESULT_CODE_DIAMETER_AUTHENTICATION_REJECTED;
    }
    elsif ($code eq 'Access-Challenge')
    {
	$result_code = $Radius::DiaAttrList::RESULT_CODE_DIAMETER_MULTI_ROUND_AUTH;
    }
    elsif ($code eq 'Accounting-Response')
    {
	$result_code = $Radius::DiaAttrList::RESULT_CODE_DIAMETER_SUCCESS;
    }
    else
    {
	# Dont understand any other types (yet)
	$self->log($main::LOG_WARNING, "Radius reply code $code cannot be converted to Diameter reply" , $p);
	return;
    }

    $dia_reply->add_attr($Radius::DiaAttrList::ACODE_RESULT_CODE, 0, 
		 $Radius::DiaAttrList::AFLAG_MANDATORY, 
		 $result_code);

    $self->copy_radius_to_dia_attrs($p, $dia_reply);

    # Call the PostRadiusToDiaConversionHook, if there is one
    $self->{parent}->runHook('PostRadiusToDiaConversionHook', $p, \$p, \$dia_reply);

    my $msg = $dia_reply->assemble();
    if (main::willLog($main::LOG_DEBUG, $p))
    {
	$self->log($main::LOG_DEBUG, "Packet dump:\n*** Radius reply converted into Diameter reply ....\n" . $dia_reply->format, $dia_reply);
	$self->log($main::LOG_EXTRA_DEBUG, "Sending Diameter raw packet dump:\n" . unpack('H*', $msg))
	    if main::willLog($main::LOG_EXTRA_DEBUG, $p);
    }
    $self->send($msg);
}

#####################################################################
# This fn is called by Handler when the reply to the request is ready to go back
# This works even for delayed or asynch replies.
sub replyFn
{
    my ($p, $self) = @_;
    $self->replyTo($p);
}


#####################################################################
# Push log messages from Diameter up to the parent
sub log
{
    my ($self, @args) = @_;
    $self->{parent}->log(@args);
}

#####################################################################
# Return the IP address of our socket
sub hostipaddress
{
    my ($self) = @_;
    my ($port, $addr) = Radius::Util::unpack_sockaddr_in(getsockname($self->{socket}));
    return ($addr);
}

#####################################################################
# Called by DiaPeer when the connection is to be closed
sub close
{
    my ($self) = @_;

    $self->stream_disconnected();
}

#####################################################################
# Called by DiaPeer when an assembled message is to be sent
sub send
{
    my ($self, $msg) = @_;

    $self->write($msg);
}

#####################################################################
# A serious stream error has occurred, log it and disconnect
sub stream_error
{
    my ($self, $msg) = @_;

    $self->{DiaPeer}->r_error_callback($self, $msg) if $self->{DiaPeer};
    $self->SUPER::stream_error($msg);
}

#####################################################################
# Reset Peer state after disconnect
sub stream_disconnected
{
    my ($self, @args) = @_;

    $self->SUPER::stream_disconnected(@args);
    $self->{DiaPeer}->reset() if $self->{DiaPeer};
}

1;

