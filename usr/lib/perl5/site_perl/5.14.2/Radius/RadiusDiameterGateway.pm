# RadiusDiameterGateway.pm
#
# Converts Radius requests into Diameter requests.
#
# Part of the Radius project.
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2013 Open System Consultants
# $Id: RadiusDiameterGateway.pm,v 1.5 2014/11/27 20:57:06 hvn Exp $
package Radius::RadiusDiameterGateway;
use Radius::DiaMsg;
use Radius::BigInt;
use Socket;
use strict;


#####################################################################
# Receive a Radius request and convert it into a Diameter request,
# based on RFC 4005 Diameter Network Access Server Application.
sub handle_request
{
    my ($self, $m) = @_;

    $self->log($main::LOG_DEBUG, "Radius::RadiusDiameterGateway handle_request");

    $m->{RecvFromName} = Radius::Util::inet_ntop($m->{RecvFromAddress}); # Dotted quad
    my $rcode = $m->code(); # Radius message type name
    my ($dcode, $aid);
    if ($rcode eq 'Access-Request')
    {
	$dcode = $Radius::DiaMsg::CODE_AA;
	$aid = $Radius::DiaMsg::APPID_NASREQ;
    }
    elsif ($rcode eq 'Accounting-Request')
    {
	$dcode = $Radius::DiaMsg::CODE_ACCOUNTING;
	$aid = $Radius::DiaMsg::APPID_BASE_ACCOUNTING;
    }
    else
    {
	$self->log($main::LOG_WARNING, "Received Radius $rcode request, which cant be converted to an equivalent Diameter request. Ignoring");
	return;
    }

    # The new Diameter request
    my $d = Radius::DiaMsg->new_request(Aid => $aid,
					Code => $dcode,
					Flags => ($Radius::DiaMsg::FLAG_REQUEST|$Radius::DiaMsg::FLAG_PROXIABLE));

    my $origin; # Will be split to create Origin-Host and Origin-Realm
    my ($have_session_id, $session_id_value, $origin_is_nas_ip_address, $destination_realm);
    my %tunnel_group; # Hash of tunnel groups indexed by tunnel tag
    my $do_diameap;

    # The transport address of the sender MUST be checked against the
    # NAS identifying attributes. See the description of NAS-
    # Identifier and NAS-IP-Address below.

    # Now we traverse the entire list of incoming Radius attributes, converting, copying or dropping them 
    # as required by draft-ietf-aaa-diameter-nasreq-14.txt
    # This violates the encapsulation of AttrList, but its good for performance
    foreach (@{$m->{Attributes}})
    {
	# [aname, avalue]
	next if $$_[0] eq 'Timestamp'; # Not a real attribute, added by Radiator.
	my ($aname, $attrnum, $atype, $vendornum, $flags) = $m->{Dict}->attrByName($$_[0]);
	my $value = $$_[1];

	if ($vendornum != 0)
	{
	    # Speedup, allows us to assume $vendornum == 0 in following tests
	    # Its an AVP, just copy it
	    $d->add_attr($attrnum, $vendornum, 0, $value);
	}
	elsif ($attrnum == $Radius::RadiusAttrList::ACODE_NAS_IP_ADDRESS)
	{
	    # clause 9.3.2:
	    my $nian = Radius::Util::gethostbyaddr(Radius::Util::inet_pton($value));

	    $d->add_attr($Radius::DiaAttrList::ACODE_NAS_IP_ADDRESS, 0,
			 $Radius::DiaAttrList::AFLAG_MANDATORY, Radius::Util::inet_pton($value));
	    next unless $nian; # Can't add DiameterIdentities if there is no name.

	    $origin = $nian;
	    $origin_is_nas_ip_address++;
	    if ($value eq $m->{RecvFromName})
	    {
		# origin address and Nas-IP-Address match, so the request
		# came direct from the NAS
	    }
	    else
	    {
		# The request must have come through a Radius proxy (REVISIT: can we check this?)
		# Add Route-Record entries for the source address and the Nas-IP-Address 
		$d->add_attr($Radius::DiaAttrList::ACODE_ROUTE_RECORD, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, $nian);
		$d->add_attr($Radius::DiaAttrList::ACODE_ROUTE_RECORD, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, 
			     gethostbyaddr($m->{RecvFromAddress}, Socket::AF_INET));
	    }
	}
	elsif ($attrnum == $Radius::RadiusAttrList::ACODE_NAS_IPV6_ADDRESS)
	{
	    # clause 9.3.3:
	    my $ni6an = Radius::Util::gethostbyaddr(Radius::Util::inet_pton($value));
	    $d->add_attr($Radius::DiaAttrList::ACODE_NAS_IP_ADDRESS, 0,
			 $Radius::DiaAttrList::AFLAG_MANDATORY, Radius::Util::inet_pton($value));
	    next unless $ni6an; # Can't add DiameterIdentities if there is no name.

	    $origin = $ni6an;
	    $origin_is_nas_ip_address++;
	    if ($value eq $m->{RecvFromName})
	    {
		# origin address and Nas-IP-Address match, so the request
		# came direct from the NAS
	    }
	    else
	    {
		# The request must have come through a Radius proxy (REVISIT: can we check this?)
		# Add Route-Record entries for the source address and the Nas-IP-Address 
		$d->add_attr($Radius::DiaAttrList::ACODE_ROUTE_RECORD, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, $ni6an);
		$d->add_attr($Radius::DiaAttrList::ACODE_ROUTE_RECORD, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, 
			     gethostbyaddr($m->{RecvFromAddress}, Socket::AF_INET));
	    }
	}
	elsif ($attrnum == $Radius::RadiusAttrList::ACODE_NAS_IDENTIFIER)
	{
	    # clause 9.3.1:
	    # Whether it looks like a FQDN or not we do a name lookup
	    my ($cname, $aliases, $addrtype, $length, @addrs) = Radius::Util::gethostbyname($value);

	    $d->add_attr($Radius::DiaAttrList::ACODE_NAS_IDENTIFIER, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, $value);

	    # Should we add NAS-Identifier in Diameter in all cases?
	    $self->log($main::LOG_WARNING, "Radius NAS-Identifier $value resolves to multiple addresses")
	        if @addrs > 1;

	    $self->log($main::LOG_WARNING, "Radius NAS-Identifier $value did not resolve to any address")
	        unless @addrs;

	    # See below: what if NAS-Identifier is not RADIUS request source address?
	    $origin = $value unless $origin_is_nas_ip_address;

	    foreach my $nia (@addrs)
	    {
		if (defined $nia
		    && $nia eq $m->{RecvFromAddress})
		{
		      # origin address and Nas-Identifier match, so the request
		      # came direct from the NAS
		}
		else
		{
		      # Should we still use NAS-Identifier for Origin-Host and Origin-Realm?
		      my $source = gethostbyaddr($m->{RecvFromAddress}, Socket::AF_INET);
		      $self->log($main::LOG_ERR, "Radius NAS-Identifier $value does not resolve to the source address $m->{RecvFromName}");
		      $d->add_attr($Radius::DiaAttrList::ACODE_ROUTE_RECORD, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, $value);
		      $d->add_attr($Radius::DiaAttrList::ACODE_ROUTE_RECORD, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, $source);
		}
		last; # Currently we use just the first address
	    }
	}
	elsif ($attrnum == $Radius::RadiusAttrList::ACODE_ACCT_TERMINATE_CAUSE)
	{
	    # Clause 9.3.5
	    # This relies on the dictionaries VALUE entries to be the same to map from value to value
	    $d->add_attr($Radius::DiaAttrList::ACODE_TERMINATION_CAUSE, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, $value);
	}
	elsif ($attrnum == $Radius::RadiusAttrList::ACODE_USER_NAME)
	{
	    # The Destination-Realm AVP is created from the
	    # information found in the RADIUS User-Name attribute. It
	    # can be overridden if required. We save it here so we can
	    # later insert it close to the Diameter header.
	    (undef, $destination_realm) = split(/@/, $value);
	    $d->add_attr($Radius::DiaAttrList::ACODE_USER_NAME, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, $value);
	}
	elsif ($attrnum == $Radius::RadiusAttrList::ACODE_STATE)
	{
	    # If the RADIUS request contained a State attribute, and the
	    # prefix of the data is "Diameter/", the data following the prefix
	    # contains the Diameter Session-Id. If no such attributes are
	    # present, and the RADIUS command is an Access-Request, a new
	    # Session-Id is created. The Session-Id is included in the
	    # Session-Id AVP.
	    if ($value =~ /^Diameter\/(.*)/)
	    {
		# We do not add it here so that we can insert it as the first AVP
		$session_id_value = $1;
		$have_session_id++;
	    }
	}
	elsif ($rcode eq 'Accounting-Request' && $attrnum == $Radius::RadiusAttrList::ACODE_CLASS)
        {
	    # If the Command-Code is set to AA-Answer, the Diameter
	    # Session-Id AVP is saved in a new RADIUS Class attribute
	    # whose format consists of the string "Diameter/" followed
	    # by the Diameter Session Identifier.  This will ensure
	    # that the subsequent Accounting messages, which could be
	    # received by any Translation Agent, would have access to
	    # the original Diameter Session Identifier.
	    # So here we recover the state from the received Class
	    if ($value =~ /^Diameter\/(.*)/)
	    {
		# We do not add it here so that we can insert it as the first AVP
		$session_id_value = $1;
		$have_session_id++;
	    }
	}
	elsif ($attrnum == $Radius::RadiusAttrList::ACODE_USER_PASSWORD)
	{
	    # If the RADIUS User-Password attribute is present, the password
	    # must be unencrypted using the link's RADIUS shared secret. And
	    # forwarded using Diameter security.
	    my $pw = $m->decodedPassword();
	    $d->add_attr($Radius::DiaAttrList::ACODE_USER_PASSWORD, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, $pw);
	}
	elsif ($attrnum == $Radius::RadiusAttrList::ACODE_CHAP_PASSWORD)
	{
	    # If the RADIUS CHAP-Password attribute is present, the Ident and
	    # Data portion of the attribute are used to create the CHAP-Auth
	    # grouped AVP.
	    my ($chap_id, $chap_response) = unpack('Ca*', $value);
	    my $ca = Radius::DiaAttrList->new(Dictionary => $d->{Dictionary});
	    $ca->add_attr($Radius::DiaAttrList::ACODE_CHAP_ALGORITHM, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, 
			  $Radius::DiaAttrList::CHAP_ALGORITHM_CHAP_WITH_MD5);
	    $ca->add_attr($Radius::DiaAttrList::ACODE_CHAP_IDENT, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, 
			  $chap_id);
	    $ca->add_attr($Radius::DiaAttrList::ACODE_CHAP_RESPONSE, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, 
			  $chap_response);
	    $d->add_attr($Radius::DiaAttrList::ACODE_CHAP_AUTH, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, $ca);
	    
	    my $chap_challenge = $m->getAttrByNum($Radius::RadiusAttrList::ACODE_CHAP_CHALLENGE);
	    $chap_challenge = $m->authenticator() unless defined $chap_challenge;
	    $d->add_attr($Radius::DiaAttrList::ACODE_CHAP_CHALLENGE, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, $chap_challenge);
	}
	elsif ($attrnum == $Radius::RadiusAttrList::ACODE_TUNNEL_TYPE
	       || $attrnum == $Radius::RadiusAttrList::ACODE_TUNNEL_MEDIUM_TYPE
	       || $attrnum == $Radius::RadiusAttrList::ACODE_TUNNEL_CLIENT_ENDPOINT
	       || $attrnum == $Radius::RadiusAttrList::ACODE_TUNNEL_SERVER_ENDPOINT
	       || $attrnum == $Radius::RadiusAttrList::ACODE_TUNNEL_ID
	       || $attrnum == $Radius::RadiusAttrList::ACODE_TUNNEL_PASSWORD
	       || $attrnum == $Radius::RadiusAttrList::ACODE_TUNNEL_PRIVATE_GROUP_ID
	       || $attrnum == $Radius::RadiusAttrList::ACODE_TUNNEL_ASSIGNMENT_ID
	       || $attrnum == $Radius::RadiusAttrList::ACODE_TUNNEL_PREFERENCE
	       || $attrnum == $Radius::RadiusAttrList::ACODE_TUNNEL_CLIENT_AUTH_ID
	       || $attrnum == $Radius::RadiusAttrList::ACODE_TUNNEL_SERVER_AUTH_ID)
	{
	    # If the RADIUS message contains Tunnel information [RFC2868],
	    # the attributes or tagged groups should each be converted to a
	    # Diameter Tunneling  Grouped AVP set. If the tunnel information
	    # contains a Tunnel-Password attribute, the RADIUS encryption must
	    # be resolved, and the password forwarded using Diameter security
	    # methods.
	    # Affects Tunnel-Type, Tunnel-Medium-Type, Tunnel-Client-Endpoint
	    # Tunnel-Server-Endpoint, Tunnel-Password, Tunnel-Private-Group-ID,
	    # Tunnel-Assignment-ID, Tunnel-Preference, Tunnel-Client-Auth-ID,
	    # Tunnel-Server-Auth-ID
	    my ($tag, $tunnel_val) = split(/:/, $value, 2);
	    # Make a tunnel group attribute for each tag
	    $tunnel_group{$tag} = Radius::DiaAttrList->new(Dictionary => $d->{Dictionary})
		unless exists $tunnel_group{$tag};
	    $tunnel_group{$tag}->add_attr($attrnum, $vendornum, 0, $tunnel_val);
	}
	elsif ($attrnum == $Radius::RadiusAttrList::ACODE_ACCT_STATUS_TYPE
	       && $rcode eq 'Accounting-Request')
	{
	    # If the RADIUS message received is an Accounting-Request, the
	    # Acct-Status-Type attribute value must be converted to a
	    # Accounting-Record-Type AVP value.  If the Acct-Status-Type
	    # attribute value is STOP, the local server MUST issue a Session-
	    # Termination-Request message once the Diameter Accounting-Answer
	    # message has been received.
	    my $record_type;
	    if ($value eq 'Start')
	    {
		$record_type = $Radius::DiaAttrList::ACCOUNTING_RECORD_TYPE_START_RECORD;
	    }
	    elsif ($value eq 'Alive')
	    {
		$record_type = $Radius::DiaAttrList::ACCOUNTING_RECORD_TYPE_INTERIM_RECORD;
	    }
	    elsif ($value eq 'Stop')
	    {
		$record_type = $Radius::DiaAttrList::ACCOUNTING_RECORD_TYPE_STOP_RECORD;
	    }
	    else
	    {
		$record_type = $Radius::DiaAttrList::ACCOUNTING_RECORD_TYPE_EVENT_RECORD;
	    }
	    $d->add_attr($Radius::DiaAttrList::ACODE_ACCOUNTING_RECORD_TYPE, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, $record_type);
	}
	# If the RADIUS message contains the Accounting-Input-Octets,
	# Accounting-Input-Packets, Accounting-Output-Octets or
	# Accounting-Output-Packets, these attributes must be converted to
	# the Diameter equivalent ones. Further, if the Acct-Input-
	# Gigawords or Acct-Output-Gigawords attributes are present, these
	# must be used to properly compute the Diameter accounting AVPs.
	elsif ($attrnum == $Radius::RadiusAttrList::ACODE_ACCT_INPUT_OCTETS)
	{
	    my $gw = $m->getAttrByNum($Radius::RadiusAttrList::ACODE_ACCT_INPUT_GIGAWORDS);
	    $value = convert_gigawords($value, $gw)
		if defined $gw;
	    $d->add_attr($Radius::DiaAttrList::ACODE_ACCOUNTING_INPUT_OCTETS, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, $value);
	}
	elsif ($attrnum == $Radius::RadiusAttrList::ACODE_ACCT_OUTPUT_OCTETS)
	{
	    my $gw = $m->getAttrByNum($Radius::RadiusAttrList::ACODE_ACCT_OUTPUT_GIGAWORDS);
	    $value = convert_gigawords($value, $gw)
		if defined $gw;
	    $d->add_attr($Radius::DiaAttrList::ACODE_ACCOUNTING_OUTPUT_OCTETS, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, $value);
	}
	elsif ($attrnum == $Radius::RadiusAttrList::ACODE_ACCT_INPUT_PACKETS)
	{
	    $d->add_attr($Radius::DiaAttrList::ACODE_ACCOUNTING_INPUT_PACKETS, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, $value);
	}
	elsif ($attrnum == $Radius::RadiusAttrList::ACODE_ACCT_OUTPUT_PACKETS)
	{
	    $d->add_attr($Radius::DiaAttrList::ACODE_ACCOUNTING_OUTPUT_PACKETS, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, $value);
	}
	elsif ($attrnum == $Radius::RadiusAttrList::ACODE_CHAP_CHALLENGE
	       || $attrnum == $Radius::RadiusAttrList::ACODE_ACCT_INPUT_GIGAWORDS
	       || $attrnum == $Radius::RadiusAttrList::ACODE_ACCT_OUTPUT_GIGAWORDS)
	{
	    # Drop this: it was handled in a previous clause
	}
	elsif ($attrnum == $Radius::RadiusAttrList::ACODE_EAP_MESSAGE)
	{
	    # Drop individual EAP-Message attributes. We do conversion
	    # to EAP-Payload later.
	    $do_diameap++;
	}

	elsif ($attrnum == $Radius::RadiusAttrList::ACODE_MESSAGE_AUTHENTICATOR)
	{
	    # Drop this: it was already checked on receipt and not
	    # used in Diameter.
	}
	else
	{
	    # If the RADIUS message contains an address attribute, it MUST be
	    # converted to the appropriate Diameter AVP and type.
	    # Anything else gets copied
	    $d->add_attr($attrnum, $vendornum, $Radius::DiaAttrList::AFLAG_MANDATORY, $value);
	}
    }

    if ($rcode eq 'Accounting-Request')
    {
	$d->add_attr($Radius::DiaAttrList::ACODE_ACCT_APPLICATION_ID, 0,
		     $Radius::DiaAttrList::AFLAG_MANDATORY, 'BASE_ACCOUNTING');
    }

    if ($rcode eq 'Access-Request')
    {
	$d->add_attr($Radius::DiaAttrList::ACODE_AUTH_APPLICATION_ID, 0,
		     $Radius::DiaAttrList::AFLAG_MANDATORY, 'NASREQ');
	$d->add_attr($Radius::DiaAttrList::ACODE_AUTH_REQUEST_TYPE, 0,
		     $Radius::DiaAttrList::AFLAG_MANDATORY, 'AUTHORIZE_AUTHENTICATE');
	$d->add_attr($Radius::DiaAttrList::ACODE_ORIGIN_AAA_PROTOCOL, 0,
		     $Radius::DiaAttrList::AFLAG_MANDATORY, 'RADIUS');
    }

    # At this point $destination_realm may have been set when User-Name was processed
    $destination_realm = $self->{DestinationRealm} if defined $self->{DestinationRealm};
    $destination_realm = '' unless defined $destination_realm;
    $d->insert_attr($Radius::DiaAttrList::ACODE_DESTINATION_REALM, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, $destination_realm);
    $d->insert_attr($Radius::DiaAttrList::ACODE_DESTINATION_HOST, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, $self->{DestinationHost})
      if defined $self->{DestinationHost};

    # The Diameter Origin-Host and Origin-Realm AVPs MUST be created
    # and added using the information from an FQDN corresponding to
    # the NAS-IP-Address attribute (preferred if available), and/or
    # the NAS-Identifier attribute. (Note that the RADIUS NAS-
    # Identifier is not required to be an FQDN) The AAA protocol
    # specified in the identity would be set to "RADIUS".
    my ($oh, $or) = split(/\./, $origin, 2);
    $d->insert_attr($Radius::DiaAttrList::ACODE_ORIGIN_HOST, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, $origin);
    $d->insert_attr($Radius::DiaAttrList::ACODE_ORIGIN_REALM, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, $or)
	if defined $or;

    if (!$have_session_id && $rcode eq 'Access-Request')
    {
	# Create a new Session-Id. Subsequent messages will carry it with RADIUS Class attribute
	my ($sec, $usec) = Radius::Util::getTimeHires;
	$session_id_value = $self->{OriginHost} . ";$sec;$usec;$main::farmInstance";
    }

    # The Proxy-Info group SHOULD be added with the local server's
    # identity being specified in the Proxy-Host AVP.  This should
    # ensure that the response is returned to this system.
#    my $pi = Radius::DiaAttrList->new();
#    $pi->add_attr($Radius::DiaAttrList::ACODE_PROXY_HOST, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, $self->{OriginHost});
#    $d->add_attr($Radius::DiaAttrList::ACODE_PROXY_INFO, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, $pi);

    # Add each of the tunnel groups that we collected above
    foreach (sort keys %tunnel_group)
    {
	$d->add_attr($Radius::DiaAttrList::ACODE_TUNNELING, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, $tunnel_group{$_});
    }

    # Possibly create EAP-Payload from EAP-Message(s). Empty payload is valid.
    if ($do_diameap)
    {
	$d->set_aid($Radius::DiaMsg::APPID_DIAMETER_EAP);
	$d->set_code($Radius::DiaMsg::CODE_DER);

	# All EAP-Message attributes are translated to a single EAP-Payload AVP
	$d->add_attr($Radius::DiaAttrList::ACODE_EAP_PAYLOAD, 0,
		     $Radius::DiaAttrList::AFLAG_MANDATORY, join('', $m->get_attr('EAP-Message')));

	# Switch Auth-Application-Id to EAP
	$d->delete($Radius::DiaAttrList::ACODE_AUTH_APPLICATION_ID);
	$d->add_attr($Radius::DiaAttrList::ACODE_AUTH_APPLICATION_ID, 0,
		     $Radius::DiaAttrList::AFLAG_MANDATORY, 'DIAMETER_EAP');
    }

    # Finally insert Session-Id as the first AVP
    $d->insert_attr($Radius::DiaAttrList::ACODE_SESSION_ID, 0, $Radius::DiaAttrList::AFLAG_MANDATORY, $session_id_value);

    # The Translation Agent must maintain transaction state
    # information relevant to the RADIUS request, such as the
    # Identifier field in the RADIUS header, any existing RADIUS
    # Proxy-State attribute as well as the source IP address and port
    # number of the UDP packet. These may be maintained locally in a
    # state table, or may be saved in a Proxy-Info AVP group.

    # Call the PostRadiusToDiaConversionHook, if there is one
    $self->runHook('PostRadiusToDiaConversionHook', $m, \$m, \$d);

    return $d;
}

#####################################################################
# Called when a Diameter reply is received to the diameter request.
# Convert it into a Radius reply to the Radius $orig_request
sub handle_reply
{
    my ($self, $diareply, $diasp, $op) = @_;

    $self->log($main::LOG_DEBUG, "Radius::RadiusDiameterGateway handle_reply");
    my $reason;
    my $result_code = $diareply->get_attr($Radius::DiaAttrList::ACODE_RESULT_CODE);

    # Ensure reply has a Message-Authenticator (recommended by the RFC)
    $op->{rp}->add_attr('Message-Authenticator', "\000" x 16);

    # Convert and possibly split EAP-Payload. Empty payload is valid.
    my $eap_payload = $diareply->get_attr($Radius::DiaAttrList::ACODE_EAP_PAYLOAD);
    if (defined $eap_payload)
    {
	my $substr;
	do
	{
	    $substr = substr($eap_payload, 0, 253, '');
	    $op->{rp}->addAttrByNum($Radius::Radius::EAP_MESSAGE, $substr);
	} while (length($eap_payload));
    }

    my $master_session_key = $diareply->get_attr($Radius::DiaAttrList::ACODE_EAP_MASTER_SESSION_KEY);
    if ($master_session_key)
    {
	$op->{rp}->add_attr('MS-MPPE-Send-Key', substr($master_session_key, -length($master_session_key)/2, length($master_session_key)/2));
	$op->{rp}->add_attr('MS-MPPE-Recv-Key', substr($master_session_key, 0, length($master_session_key)/2));
    }

    if ($result_code eq 'DIAMETER_SUCCESS')
    {
	# The subsequent RADIUS accounting requests, if any, will use the same Class
	$op->{rp}->add_attr('Class', 'Diameter/' . $diareply->get_attr($Radius::DiaAttrList::ACODE_SESSION_ID));

	$op->{RadiusResult} = $main::ACCEPT;
	$reason = 'Accepted by DIAMETER';
    }
    elsif ($result_code eq 'DIAMETER_MULTI_ROUND_AUTH')
    {
	# The subsequent RADIUS access request, if any, will use the same State
	$op->{rp}->add_attr('State', 'Diameter/' . $diareply->get_attr($Radius::DiaAttrList::ACODE_SESSION_ID));

	$op->{RadiusResult} = $main::CHALLENGE;
	$reason = 'Multi round auth by DIAMETER';
    }
    else
    {
	$op->{RadiusResult} = $main::REJECT;
	$reason = 'Rejected by DIAMETER';
    }

    # Call the PostDiaToRadiusConversionHook, if there is one
    $self->runHook('PostDiaToRadiusConversionHook', $op, \$diareply, \$op);

    # Now send it back to the original Radius requester
    $op->{Handler}->handlerResult
            ($op, $op->{RadiusResult}, $reason);

    return;
}

#####################################################################
# Convert octets and gigawords into a single (large) octet count
sub convert_gigawords
{
    my ($octets, $gigawords) = @_;

    my @a = Radius::BigInt::from_str($octets);
    my @b = Radius::BigInt::from_str($gigawords);
    my @c = Radius::BigInt::from_str('2147483648'); # 2 << 31
    my @d = Radius::BigInt::mul(\@b, \@c);

    return Radius::BigInt::str(Radius::BigInt::add(\@a, \@d));
}


#####################################################################
#####################################################################
#####################################################################
package Radius::RadiusAttrList;

# Attribute codes
# These are the well known radius attribute numbers that we use
# We have these here so we can change the dictionary to 
# be anything we like
# Only well-known attributes codes used in the code are listed here
$Radius::RadiusAttrList::ACODE_USER_NAME                    = 1;
$Radius::RadiusAttrList::ACODE_USER_PASSWORD                = 2;
$Radius::RadiusAttrList::ACODE_CHAP_PASSWORD                = 3;
$Radius::RadiusAttrList::ACODE_NAS_IP_ADDRESS               = 4;
$Radius::RadiusAttrList::ACODE_NAS_PORT                     = 5;
$Radius::RadiusAttrList::ACODE_SERVICE_TYPE                 = 6;
$Radius::RadiusAttrList::ACODE_FRAMED_PROTOCOL              = 7;
$Radius::RadiusAttrList::ACODE_FRAMED_IP_ADDRESS            = 8;
$Radius::RadiusAttrList::ACODE_FRAMED_IP_NETMASK            = 9;
$Radius::RadiusAttrList::ACODE_LOGIN_IP_HOST                = 14;
$Radius::RadiusAttrList::ACODE_LOGIN_SERVICE                = 15;
$Radius::RadiusAttrList::ACODE_LOGIN_TCP_PORT               = 16;
$Radius::RadiusAttrList::ACODE_REPLY_MESSAGE                = 18;
$Radius::RadiusAttrList::ACODE_STATE                        = 24;
$Radius::RadiusAttrList::ACODE_CLASS                        = 25;
$Radius::RadiusAttrList::ACODE_SESSION_TIMEOUT              = 27;
$Radius::RadiusAttrList::ACODE_CALLED_STATION_ID            = 30;
$Radius::RadiusAttrList::ACODE_CALLING_STATION_ID           = 31;
$Radius::RadiusAttrList::ACODE_NAS_IDENTIFIER               = 32;
$Radius::RadiusAttrList::ACODE_PROXY_STATE                  = 33;
$Radius::RadiusAttrList::ACODE_ACCT_STATUS_TYPE             = 40;
$Radius::RadiusAttrList::ACODE_ACCT_DELAY_TIME              = 41;
$Radius::RadiusAttrList::ACODE_ACCT_INPUT_OCTETS            = 42;
$Radius::RadiusAttrList::ACODE_ACCT_OUTPUT_OCTETS           = 43;
$Radius::RadiusAttrList::ACODE_ACCT_SESSION_ID              = 44;
$Radius::RadiusAttrList::ACODE_ACCT_SESSION_TIME            = 46;
$Radius::RadiusAttrList::ACODE_ACCT_INPUT_PACKETS           = 47;
$Radius::RadiusAttrList::ACODE_ACCT_OUTPUT_PACKETS          = 48;
$Radius::RadiusAttrList::ACODE_ACCT_TERMINATE_CAUSE         = 49;
$Radius::RadiusAttrList::ACODE_ACCT_INPUT_GIGAWORDS         = 52;
$Radius::RadiusAttrList::ACODE_ACCT_OUTPUT_GIGAWORDS        = 53;
$Radius::RadiusAttrList::ACODE_CHAP_CHALLENGE               = 60;
$Radius::RadiusAttrList::ACODE_NAS_PORT_TYPE                = 61;
$Radius::RadiusAttrList::ACODE_TUNNEL_TYPE                  = 64;
$Radius::RadiusAttrList::ACODE_TUNNEL_MEDIUM_TYPE           = 65;
$Radius::RadiusAttrList::ACODE_TUNNEL_CLIENT_ENDPOINT       = 66;
$Radius::RadiusAttrList::ACODE_TUNNEL_SERVER_ENDPOINT       = 67;
$Radius::RadiusAttrList::ACODE_TUNNEL_ID                    = 68;
$Radius::RadiusAttrList::ACODE_TUNNEL_PASSWORD              = 69;
$Radius::RadiusAttrList::ACODE_CONNECT_INFO                 = 77;
$Radius::RadiusAttrList::ACODE_EAP_MESSAGE                  = 79;
$Radius::RadiusAttrList::ACODE_MESSAGE_AUTHENTICATOR        = 80;
$Radius::RadiusAttrList::ACODE_TUNNEL_PRIVATE_GROUP_ID      = 81;
$Radius::RadiusAttrList::ACODE_TUNNEL_ASSIGNMENT_ID         = 82;
$Radius::RadiusAttrList::ACODE_TUNNEL_PREFERENCE            = 83;
$Radius::RadiusAttrList::ACODE_TUNNEL_CLIENT_AUTH_ID        = 90;
$Radius::RadiusAttrList::ACODE_TUNNEL_SERVER_AUTH_ID        = 91;
$Radius::RadiusAttrList::ACODE_NAS_IPV6_ADDRESS             = 95;
$Radius::RadiusAttrList::ACODE_PROXY_ACTION                 = 211;
$Radius::RadiusAttrList::ACODE_ASCEND_SEND_SECRET           = 214;

# Some hardwired numbers required by the code
$Radius::RadiusAttrList::VENDORCODE_MICROSOFT               = 311;
$Radius::RadiusAttrList::MS_CHAP_MPPE_KEYS                  = 12;
$Radius::RadiusAttrList::MS_MPPE_SEND_KEY                   = 16;
$Radius::RadiusAttrList::MS_MPPE_RECV_KEY                   = 17;

1;
