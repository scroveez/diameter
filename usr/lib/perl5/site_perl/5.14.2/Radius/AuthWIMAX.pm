# AuthWIMAX.pm
#
# Object for handling Authentication and Accounting from a WiMAX network
# Acts as a Home AAA (HAAA) as per 
# WiMAX End-to-End Network Systems Architecture Stage 2-3 Release 1.1.0, 
# NWG_R1.1.0-Stage-3.pdf
# Answers requests from NAS, HA and DHCP servers
# All WiMAX docs are at http://www.wimaxforum.org/resources/documents/technical/release
#
# Provides:
#  Authentication of users and devices from SQL database. Most EAP types supported
#  Generation and caching (in SQL) of MIP-RK, MIP-SPI and FA-RK for each 
#   device session.
#  Generation of mobility keys for both NAS and HA requests
#  Generation, caching (in memory) and refreshing of HA-RK, HA-SPI for each HA.
#  Generation, caching (in memory) and supplying DHCP-RK and Key-Id for 
#   NAS and DHCP requests
#  Hotlining profiles
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2007 Open System Consultants
# $Id: AuthWIMAX.pm,v 1.21 2012/12/13 20:19:47 mikem Exp $

package Radius::AuthWIMAX;
@ISA = qw(Radius::AuthSQL);
use Radius::AuthSQL;
use Radius::WiMAX;
use Radius::WiMAXTLV;
use strict;

%Radius::AuthWIMAX::ConfigKeywords = 
('KeyLifetime'                 => 
 ['integer', 
  'Lifetime for all mobility keys in seconds', 
  1],

'HAPassword'                 => 
 ['string', 
  'PAP password required for access by a WiMAX HA (Home Agent). If not defined, HA does not have to present a password before its requsts are satisfied. If HAPassword is defined, the HA must present a PAP password with an exact match, and the HA must be configured to send this password, otherwise its requests will be REJECTed. Not all HAs are able to send a password with requests to the HAAA, so use of this parameter depends on your HA', 
  1],

'ProfileHotlining'                 => 
 ['flag', 
  'Indicates whether to provide profile-based hotlining. If set, and the user has a Hotline Profile ID, the SQL database will be consulted for the Hotline profile, and the contents of the hotline profile id will be returned', 
  1],

'RulebasedHotlining'                 => 
 ['flag', 
  'Indicates whether to provide rule-based hotlining. If set, and the user has a Hotline Profile ID, the SQL database will be consulted for the Hotline profile, and the contents of the hotline NAS-Filter-Rule will be returned', 
  1],

'HTTPRedirectionHotlining'                 => 
 ['flag', 
  'Indicates whether to provide HTTP Redirection-based hotlining. If set, and the user has a Hotline Profile ID, the SQL database will be consulted for the Hotline profile, and the contents of the hotline HTTP-Redirection-Rule will be returned', 
  1],

'IPRedirectionHotlining'                 => 
 ['flag', 
  'Indicates whether to provide IP Redirection-based hotlining. If set, and the user has a Hotline Profile ID, the SQL database will be consulted for the Hotline profile, and the contents of the hotline IP-Redirection-Rule will be returned', 
  1],

'MSKInMPPEKeys'                 => 
 ['flag', 
  'Forces the MSK to be encoded in MS-MPPE-Send-Key and MS-MPPE-Recv-Key, as well as the usual WiMAX-MSK reply attributes. This is required by some non-compliant clients, such as some Alcatel-Lucent devices.', 
  2],

 'GetCachedKeyQuery'             => 
 ['string', 'SQL query to get the cached keys for a given AAA-Session-ID', 1],

 'InsertSessionQuery'             => 
 ['string', 'SQL query to get create a new session for a given AAA-Session-ID', 1],

 'UpdateSessionQuery'             => 
 ['string', 'SQL query to get update a session for a given AAA-Session-ID', 1],

 'GetHotlineProfileQuery'             => 
 ['string', 'SQL query to get hotlining parameters', 1],

 'GetQosProfileQuery'             => 
 ['string', 'SQL query to get QOS parameters', 1],

);

# The version of WiMAX this code supports
my $wimax_release = '1.0';
my $wimax_recommended_mtu = 1400;

# HA-RK keys issued by this AAA, keyed by authenticator binary IP address
# Each entry is [HA-RK, HA-RK-SPI, EXPIRY]
my %ha_rk_keys = ();

# Hash of keys. Each entry is keyed by the IP address of the DHCP server
# Each value is an array of [key, id, expiry] in order of increasing expiry 
# (and id), most recent key last
my %dhcp_keys = ();

#####################################################################
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{ExportEMSK} = 1;
    $self->{NoDefault} = 1;
    $self->{KeyLifetime} = 3600;
    $self->{HARKLifetime} = 10000;
    $self->{HARKGraceTime} = 1000;
    $self->{DHCPRKLifetime} = 10000;
    $self->{DHCPRKGraceTime} = 1000;
    $self->{SupportPseudoId} = 1;
    $self->{AuthSelect} = 'select psk, cui, hotlineprofile from subscription where nai=?';
    $self->{InsertSessionQuery} = 'insert into device_session (outer_nai, sessionid, napid, bsid, nspid, msid, capabilities, timezoneoffset, nai, cui, mip_rk, mip_spi, fa_rk, key_expires) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
    $self->{UpdateSessionQuery} = 'update device_session set outer_nai=?, nai=?, cui=?, mip_rk=?, mip_spi=?, fa_rk=?, key_expires=? where sessionid=?';
    $self->{GetCachedKeyQuery} = 'select sessionid, mip_rk, mip_spi, fa_rk from device_session where sessionid=?';
    $self->{GetHotlineProfileQuery} = 'select profileid, httpredirectionrule, ipredirectionrule, nasfilterrule, sessiontimer from hotlineprofile where id=?';
    $self->{GetQosProfileQuery} = 'select globalscname, scname, scheduletype, priority, maxsusrate, minresrate, maxburst, jitter, maxlatency, reducedresources, flowtype, grantinterval, sdusize, unsolpollinginterval from qosprofile where id=?';
}

#####################################################################
sub handle_request
{
    my ($self, $p, $dummy, $extra_checks) = @_;

    if ($p->code eq 'Access-Request')
    {
	my $nas_identifier = $p->get_attr('NAS-Identifier');
	my $nas_port_type = $p->get_attr('NAS-Port-Type');
	my $service_type = $p->get_attr('Service-Type');

	# Here we distinguish between a variety of request types based
	# on some required WiMAX attributes
	if (defined $p->{outerRequest})
	{
	    # Dont fiddle with inner requests
	    return $self->SUPER::handle_request($p);
	}
	elsif (!defined $nas_port_type)
	{
	    # REVISIT:
	    # Is it from the HA or a DHCP server?
	    if (defined $p->get_attr('WiMAX-HA-IP-MIP4')
		|| defined $p->get_attr('WiMAX-HA-IP-MIP6'))
	    {
		return $self->handle_ha_request($p);
	    }
	    elsif (defined $p->get_attr('WiMAX-DHCP-RK-Key-ID'))
	    {
		return $self->handle_dhcp_request($p);
	    }
	    else
	    {
		return ($main::REJECT, 'Unknown request without NAS-Port-Type');
	    }
	}
	elsif ($service_type eq 'Framed-User' || $service_type eq 'Authenticate-Only')
	{
	    # Authentication request from NAS
	    return $self->handle_authentication_request($p);
	}
	elsif ($service_type eq 'Authorize-Only')
	{
	    # Authorization request
	    return $self->handle_authorization_request($p);
	}
	else
	{
	    return ($main::REJECT, 'Unknown WiMAX request type');
	}
    }
    else
    {
	return $self->handle_accounting($p); # in AuthSQL superclass
    }
    return ($main::REJECT, 'Unsupported RADIUS request type in AuthBy WIMAX');
}

#####################################################################
sub handle_authentication_request
{
    my ($self, $p) = @_;

    # Make sure the lower levels see the user name as the Calling-Station-Id
    # this allows us to do TLS session reuse, since the lowere levels will 
    # see the same outer user name in the reused session
    my $outer_nai = $p->getUserName; # This will prob be a pseudo id
    my $msid = $p->get_attr('Calling-Station-Id');
    $p->changeUserName($msid) if defined $msid;

    # Do the lower level authentication
    my ($result, $reason) = $self->SUPER::handle_request($p);
    
    # Only need further processing of ACCEPT or a CHALLENGE requests
    return ($result, $reason) 
	unless ($result == $main::ACCEPT || $result == $main::CHALLENGE);
    
    # Have an ACCEPT or a CHALLENGE
    my $sessionid = $p->get_attr('WiMAX-AAA-Session-ID');
    my $reply = $p->{rp}; # Speedup
    my $napid = $p->get_attr('WiMAX-NAP-ID');
    my $bsid = $p->get_attr('WiMAX-BS-ID');
    ($napid, $bsid) = unpack('a3 a3', $bsid)
	if (defined $bsid);
    my $nspid = $p->get_attr('WiMAX-NSP-ID');
    
    # Only need further processing of ACCEPT
    return ($result, $reason) unless $result == $main::ACCEPT;
    return ($main::REJECT, 'EAP keys were not exported')
	unless defined $reply->{msk} && defined $reply->{emsk};
    
    # Need the inner user name that was authenticated by EAP.
    return ($main::IGNORE, 'No identity exported by inner authenticator')
	unless defined $p->{rp}->{inner_identity};
    
    # Set the WiMAX-Capability
    my $hotline_capability = 0;
    $hotline_capability |= $Radius::WiMAXTLV::CAPABILITY_HOTLINE_PROFILE
	if $self->{ProfileHotlining};
    $hotline_capability |= $Radius::WiMAXTLV::CAPABILITY_HOTLINE_RULE
	if $self->{RulebasedHotlining};
    $hotline_capability |= $Radius::WiMAXTLV::CAPABILITY_HOTLINE_HTTP_REDIRECTION
	if $self->{HTTPRedirectionHotlining};
    $hotline_capability |= $Radius::WiMAXTLV::CAPABILITY_HOTLINE_IP_REDIRECTION
	if $self->{IPRedirectionHotlining};
    $reply->add_attr('WiMAX-Capability', "Release=$wimax_release,Accounting-Capabilities=1,Hotlining-Capabilities=$hotline_capability,Idle-Mode-Notification-Capabilities=0");
    
    # Have MSK and EMSK from the EAP authentication. 
    # Can now compute various keys for this session
    my $mip_rk = Radius::WiMAX::mip_rk($reply->{emsk});
    my $mip_spi = Radius::WiMAX::mip_spi($mip_rk);
    my $fa_rk  = Radius::WiMAX::fa_rk($mip_rk);
    my $expires = time+ $self->{KeyLifetime};
    my $cui = $p->get_attr('Chargeable-User-Identity');

    if (!defined $sessionid)
    {
	# Need to create a new Device Session
	# First try to find an unused session id
	my $i = 10;
	while ($i-- > 0)
	{
	    # New random session id
	    $sessionid = unpack('H*', Radius::Util::random_string(16));
	    my ($dummysi) =  $self->get_cached_keys($sessionid);
	    last unless defined $dummysi;
	}
	return ($main::REJECT, 'Could not find an unused session id. Database problem?')
	    if ($i <= 0);

	my $timezoneoffset = $p->get_attr('WiMAX-GMT-Timezone-Offset');
	my $capabilities = unpack('H*', $p->get_attr('WiMAX-Capability'));

	# and save it to the database
	return ($main::IGNORE, 'Failed to create new device_session')
	    unless $self->do($self->{InsertSessionQuery}, 
			     $outer_nai, 
			     $sessionid, 
			     $napid, 
			     $bsid, 
			     $nspid, 
			     $msid,
			     $capabilities,
			     $timezoneoffset,
			     $p->{rp}->{inner_identity},
			     $cui,
			     unpack('H*', $mip_rk), 
			     $mip_spi,
			     unpack('H*', $fa_rk), 
			     $expires);
	$reply->add_attr('WiMAX-AAA-Session-ID', $sessionid);
    }
    else
    {
	return ($main::IGNORE, 'Failed to update device_session')
	    unless $self->set_cached_keys
	    ($sessionid, 
	     $outer_nai,
	     $p->{rp}->{inner_identity},
	     $cui,
	     unpack('H*', $mip_rk),
	     $mip_spi,
	     unpack('H*', $fa_rk),
	     $expires);
    }

    $reply->add_attr('WiMAX-MSK', $reply->{msk});
    # Some APs (eg Alcatel-Lucent) require the MSK in MS-MPPE-Send-Key
    # and MS-MPPE-Recv-Key
    if ($self->{MSKInMPPEKeys})
    {
	my ($send, $recv) = unpack('a32 a32', $reply->{msk});
	# Note these are swapped because its for the AP end of the encryption
	$reply->add_attr('MS-MPPE-Send-Key', $recv);
	$reply->add_attr('MS-MPPE-Recv-Key', $send);
    }
    $reply->add_attr('Session-Timeout', $self->{KeyLifetime});

    # Set the Framed-MTU to the recommended value unless the NAS asks
    # for something less
    my $framed_mtu = $p->get_attr('Framed-MTU');
    $framed_mtu = $wimax_recommended_mtu 
	if !defined $framed_mtu || ($framed_mtu > $wimax_recommended_mtu);
    $reply->add_attr('Framed-MTU', $framed_mtu);

    # REVISIT
    # Prepaid quotas?
    my $ppac = $p->get_attr('WiMAX-PPAC');
    if (defined $ppac)
    {
	# Maybe set PPAQ and Prepaid-Tariff-Switching
    }

    # REVISIT:
    # QoS?

    # Maybe generate DHCP key for an allcoated DHCP server
    ($result, $reason) = $self->handle_dhcp_allocation($p);
    return ($result, $reason) unless $result == $main::ACCEPT;

    return $self->handle_mip_keys($p, $outer_nai, $mip_rk, $mip_spi, $fa_rk);
}

#####################################################################
sub handle_ha_request
{
    my ($self, $p) = @_;


    return ($main::REJECT, 'Bad HAPassword')
	if defined $self->{HAPassword} 
    && !$self->check_plain_password('HA', $p->decodedPassword(),
				    $self->{HAPassword}, $p);

    my $sessionid = $p->get_attr('WiMAX-AAA-Session-ID');
    my $outer_nai = $p->getUserName; # This will prob be a pseudo id
    my $reply = $p->{rp}; # Speedup

    # Get keys from the database
    my ($dummysi, $mip_rk, $mip_spi, $fa_rk) = $self->get_cached_keys($sessionid);
    return ($main::REJECT, 'No WiMAX session found')
	unless defined $mip_rk;
    $reply->add_attr('Message-Authenticator', "\0" x 16);
    $reply->add_attr('WiMAX-AAA-Session-ID', $sessionid)
	unless defined $p->get_attr('WiMAX-AAA-Session-ID');

    return $self->handle_mip_keys($p, $outer_nai, pack('H*', $mip_rk), 
				  $mip_spi, pack('H*', $fa_rk));
}

#####################################################################
# Get cached ($sessionid, $mip_rk, $mip_spi, $fa_rk) from the database,
# given the outer NAI
sub get_cached_keys
{
    my ($self, $sessionid) = @_;

    return $self->queryOneRow($self->{GetCachedKeyQuery}, $sessionid);
}

#####################################################################
# Save keys and other interesting information
sub set_cached_keys
{
    my ($self, $sessionid, $outer_nai, $nai, $cui, $mip_rk, $mip_spi, $fa_rk, $expires) = @_;

    return $self->do($self->{UpdateSessionQuery},
		     $outer_nai,
		     $nai,
		     $cui,
		     unpack('H*', $mip_rk), 
		     $mip_spi,
		     unpack('H*', $fa_rk), 
		     $expires,
		     $sessionid);
}

#####################################################################
# Set up reply attributes for various MIP keys that may be required 
# by this request
# It might be a NAS authentication request or HA MIP request
sub handle_mip_keys
{
    my ($self, $p, $outer_nai, $mip_rk, $mip_spi, $fa_rk) = @_;

    my $reply = $p->{rp}; # Speedup

    $reply->add_attr('WiMAX-FA-RK-KEY', $fa_rk);
    
    # If WiMAX-RRQ-HA-IP is present, generate WiMAX-RRQ-MN-HA-KEY
    # Hmmm, can this happen independently of authentication?
    # So may need to get keys back from database
    my $rrq_ha_ip = $p->get_attr('WiMAX-RRQ-HA-IP');
    if (defined $rrq_ha_ip)
    {
	# Need to generate WiMAX-RRQ-MN-HA-KEY, see 4.8.3.1.4
	my $rrq_mn_ha_key = Radius::WiMAX::mn_ha_cmip4
	    ($mip_rk, $rrq_ha_ip, $outer_nai);
	
	$reply->add_attr('WiMAX-RRQ-MN-HA-KEY', $rrq_mn_ha_key);
    }
    
    # If WiMAX-HA-IP-MIP4 is present, generate WiMAX-MN-HA-MIP4-KEY
    my $ha_ip_mip4 = $p->get_attr('WiMAX-HA-IP-MIP4');
    if (defined $ha_ip_mip4)
    {
	# Requires CMIP4 keys
	my $mn_ha_mip4_key = Radius::WiMAX::mn_ha_cmip4
	    ($mip_rk, $ha_ip_mip4, $outer_nai);

	$reply->add_attr('WiMAX-MN-HA-MIP4-KEY', $mn_ha_mip4_key);
	$reply->add_attr('WiMAX-MN-HA-MIP4-SPI', $mip_spi);
    }

    # If WiMAX-HA-IP-MIP6 is present, generate WiMAX-MN-HA-MIP6-KEY
    my $ha_ip_mip6 = $p->get_attr('WiMAX-HA-IP-MIP6');
    if (defined $ha_ip_mip6)
    {
	# Requires CMIP6 keys
	my $mn_ha_mip6_key = Radius::WiMAX::mn_ha_cmip6
	    ($mip_rk, $ha_ip_mip6, $outer_nai);

	$reply->add_attr('WiMAX-MN-HA-MIP6-KEY', $mn_ha_mip6_key);
	$reply->add_attr('WiMAX-MN-HA-MIP6-SPI', $mip_spi + 2);
    }
    
    return $self->check_ha_rk($p);
}

#####################################################################
# Maybe generate DHCP keys required. This happens during an authentication 
# request, and the serer alloation and jkeys are piggybacked on the reply
# The DHCP key must be cached until later when the DHCP server will ask
# for it, see handle_dhcp_request
sub handle_dhcp_allocation
{
    my ($self, $p) = @_;

    # IF a DHCP server has been assigned, find its latest key, and 
    # generate a new key if necessary.

    # The address of the DHCP server being allocated to this user
    my $dhcp_server = $p->{rp}->get_attr('WiMAX-DHCPv4-Server');
    $dhcp_server = $p->{rp}->get_attr('WiMAX-DHCPv6-Server')
	unless defined $dhcp_server;

    # ONly need to genertae keys if a DHCP server is allocated in the reply
    return ($main::ACCEPT) unless defined $dhcp_server;

    # Revisit: During authentication, may need to generate and cache the key
    # Recover the key later when the DHCP 
    # server asks for it

    my $reply = $p->{rp}; # Speedup

    my ($dhcp_rk, $dhcp_rk_key_id, $dhcp_rk_lifetime, $key_expires);

    # Make sure it exists
    @{$dhcp_keys{$dhcp_server}} = () unless defined $dhcp_keys{$dhcp_server};

    my $keys = @{$dhcp_keys{$dhcp_server}}; # Number of keys
    # Get the last (newest) key in the array
    ($dhcp_rk, $dhcp_rk_key_id, $key_expires) = @{${$dhcp_keys{$dhcp_server}}[$keys-1]} if $keys;
    if ($keys == 0 || time > $key_expires - $self->{DHCPRKGraceTime})
    { 
	# Generate a new key and push it to the end
	$dhcp_rk = Radius::Util::random_string(20);
	$dhcp_rk_key_id++;
	$key_expires = time + $self->{DHCPRKLifetime};
	push (@{$dhcp_keys{$dhcp_server}}, [$dhcp_rk, $dhcp_rk_key_id, $key_expires]);

	$dhcp_rk_lifetime = $self->{DHCPRKLifetime};

	# Delete any expired keys
	while (@{$dhcp_keys{$dhcp_server}}
	       && ${$dhcp_keys{$dhcp_server}}[0]->[2] < time)
	{
	    shift(@{$dhcp_keys{$dhcp_server}});
	}
    }
    else
    {
	# Use the latest keys
	$dhcp_rk_lifetime = $key_expires - time;
    }
    $reply->add_attr('WiMAX-DHCP-RK', $dhcp_rk);
    $reply->add_attr('WiMAX-DHCP-RK-Key-ID', $dhcp_rk_key_id+0);
    $reply->add_attr('WiMAX-DHCP-RK-Lifetime', $dhcp_rk_lifetime);

    return ($main::ACCEPT);
}

#####################################################################
# DHCP server is asking for its DHCP key, given the address and key id.
# We return the key that was previously generated by handle_dhcp_allocation
sub handle_dhcp_request
{
    my ($self, $p) = @_;

    # Its a DHCP request
    my $dhcp_rk_key_id = $p->get_attr('WiMAX-DHCP-RK-Key-ID');
    my $dhcp_server = $p->get_attr('NAS-IP-Address');
    $dhcp_server = $p->get_attr('NAS-IPv6-Address')
	unless defined $dhcp_server;
    $dhcp_server = $p->get_attr('WiMAX-DHCPMSG-Server-IP')
	unless defined $dhcp_server;

    # Make sure it exists
    @{$dhcp_keys{$dhcp_server}} = () unless scalar @{$dhcp_keys{$dhcp_server}};

    # Scan the list looking for this ID
    my $key;
    foreach $key (@{$dhcp_keys{$dhcp_server}})
    {
	if ($$key[1] == $dhcp_rk_key_id)
	{
	    my $reply = $p->{rp}; # Speedup
	    $reply->add_attr('WiMAX-DHCP-RK', $$key[0]);
	    $reply->add_attr('WiMAX-DHCP-RK-Key-ID', $$key[1]);
	    $reply->add_attr('WiMAX-DHCP-RK-Lifetime', $$key[2] - time);
	    $reply->add_attr('Message-Authenticator', "\0" x 16);
	    return ($main::ACCEPT);
	}
    }
    # Request key not found or maybe expired
    return ($main::REJECT, 'Requested DHCP key not found');
}

#####################################################################
# Check the HA-RK for this authenticator
# if it does not exist or is due to expire soon, create a new
# one and reply with it
# We dont keep the key in SQL, since the keys are _Always_ only relevant
# to a particular instrance of HAAA server, and never need to be shared 
# with other HAAA instances. So we keep them in memory and (re) generate them
# after restarting.
#  $session_expires is the expiry time (Unix epoch) of an associated session
sub check_ha_rk
{
    my ($self, $p, $session_expires) = @_;

    my $reply = $p->{rp}; # Speedup

    my $authenticator = $p->get_attr('WiMAX-HA-IP-MIP4');
    $authenticator = $p->get_attr('WiMAX-HA-IP-MIP6') 
	unless defined $authenticator;

    my $ha_rk_spi = $p->get_attr('WiMAX-HA-RK-SPI');
    my ($ha_rk, $key_expires);

    # Look for existing HA-RK
    ($ha_rk, $ha_rk_spi, $key_expires) = @{$ha_rk_keys{$authenticator}} 
        if exists $ha_rk_keys{$authenticator};

    # If the key doesnt exist or expires soon, create a new one
    if (!defined $ha_rk
	|| (time >= ($key_expires - $self->{HARKGraceTime}))
	|| ($session_expires && ($key_expires < $session_expires)))
    {
	# Create and return new keys
	my $ha_rk  = Radius::Util::random_string(64);
	$ha_rk_spi = Radius::WiMAX::mip_spi($ha_rk)
	    unless defined $ha_rk_spi;
	$key_expires = time + $self->{HARKLifetime};
	$ha_rk_keys{$authenticator} = [$ha_rk, $ha_rk_spi, $key_expires];

	$reply->add_attr('WiMAX-HA-RK-KEY', $ha_rk);
	$reply->add_attr('WiMAX-HA-RK-SPI', $ha_rk_spi);
	$reply->add_attr('WiMAX-HA-RK-Lifetime', $key_expires - time);
    }
    elsif ($p->get_attr('WiMAX-HA-RK-Key-Requested'))
    {
	# Return existing keys
	$reply->add_attr('WiMAX-HA-RK-KEY', $ha_rk);
	$reply->add_attr('WiMAX-HA-RK-SPI', $ha_rk_spi);
	$reply->add_attr('WiMAX-HA-RK-Lifetime', $key_expires - time);
    }
    # else do nothing

    return ($main::ACCEPT);
}

#####################################################################
sub handle_authorization_request
{
    my ($self, $p) = @_;
    # REVISIT: asking for a prepaid quota?

    return ($main::REJECT, 'not supported yet');
#    $reply->add_attr('Message-Authenticator', "\0" x 16);
}

#####################################################################
# Find a the named user by looking in the database, and constructing
# User object if we found the named user
# $name is the user name we want
# $p is the current request we are handling
sub findUser
{
    my ($self, $name, $p) = @_;

    # (Re)-connect to the database if necessary, 
    return (undef, 1) unless $self->reconnect;
    my $user_name = $p->getUserName();

    # Recurse upwards to find the original outer request
    my $outerRequest = $p;
    while ($outerRequest->{outerRequest})
    {
	$outerRequest = $outerRequest->{outerRequest};
    }

    my ($user, @row);
    if (@row = $self->queryOneRow($self->{AuthSelect}, $user_name))
    {
	$user = new Radius::User $name;
	$user->get_check->add_attr('User-Password', $row[0]);

	# if the CUI is an empty string, it means the NAS wants the real CUI
	my $cui = $outerRequest->get_attr('Chargeable-User-Identity');
	$user->get_reply->add_attr('Chargeable-User-Identity', $row[1])
	    if (defined $cui && $cui eq '');

#print "FIXME test AuthWIMAX attrs\n";
#$user->get_reply->add_attr('WiMAX-QoS-Descriptor', "QoS-ID=1,Media-Flow-Type=Robust-Browser,Schedule-Type=BEST-EFFORT,Traffic-Priority=0,Maximum-Sustained-Traffic-Rate=128000");
#$user->get_reply->add_attr('WiMAX-Packet-Flow-Descriptor', "Packet-Data-Flow-ID=01,Service-Data-Flow-ID=1,Direction=Bi-Directional,Transport-Type=IPv4-CS,Activation-Trigger=\"Activate\",Uplink-QoS-ID=1,Downlink-QoS-ID=2");

	# Maybe process extra columns
	$self->getAuthColumns($user, $p, @row)
	    if defined $self->{AuthColumnDef};

	# See if we need to start hotlining (ie limit the user to a hotline
	# session which limits them to recharging their account.
	if (defined $row[2]
	    && ($self->{ProfileHotlining}
		|| $self->{RulebasedHotlining}
		|| $self->{HTTPRedirectionHotlining}
		|| $self->{IPRedirectionHotlining}))
	{
	    my $hotlineid = $row[2];
	    if (@row = $self->queryOneRow($self->{GetHotlineProfileQuery}, $hotlineid))
	    {
		# Must set the WiMAX-Hotline-Indicator. It can be any string,
		# but here we set it to 
		# the hotlineprofile.id of the profile. We would expect to see 
		# this back in subsequent accounting messages for this session
		$user->get_reply->add_attr('WiMAX-Hotline-Indicator', $hotlineid);
		$user->get_reply->add_attr('WiMAX-Hotline-Profile-ID', $row[0])
		    if ($self->{ProfileHotlining} && defined $row[0]);
		$user->get_reply->add_attr('WiMAX-TBD-TBD-TBD-TBD', $row[3])
		    if ($self->{RulebasedHotlining} && defined $row[3]);
		$user->get_reply->add_attr('WiMAX-HTTP-Redirection-Rule', $row[1])
		    if ($self->{HTTPRedirectionHotlining} && defined $row[1]);
		$user->get_reply->add_attr('WiMAX-IP-Redirection-Rule', $row[2])
		    if ($self->{IPRedirectionHotlining} && defined $row[2]);
		$user->get_reply->add_attr('WiMAX-Hotline-Session-Timer', $row[4])
		    if (defined $row[4]);
	    }
	}

	# Array of QOS Profile IDs we have to get and include in this reply
	my @requiredqos = ();
#	my @requiredqos = (1, 2); # TEST

	# Get each QoS record required by previous attributes that reference QoS
	# profiles
	# REVISIT: IS THIS REALLY NECESSARY? Can set qos using ascii in a reply attr
	my $index = 0; # Counter for relative qos number within this reply
	foreach (@requiredqos)
	{
	    if (@row = $self->queryOneRow($self->{GetQosProfileQuery}, $_))
	    {
		my $qosdstring = "QoS-Id=" . $index++;
		$qosdstring .= ",Global-Service-Class-Name=$row[0]"
		    if defined $row[0];
		$qosdstring .= ",Service-Class-Name=$row[1]"
		    if defined $row[1];
		$qosdstring .= ",Schedule-Type=$row[2]"
		    if defined $row[2];
		$qosdstring .= ",Traffic-Priority=$row[3]"
		    if defined $row[3];
		$qosdstring .= ",Maximum-Sustained-Traffic-Rate=$row[4]"
		    if defined $row[4];
		$qosdstring .= ",Minimum-Reserved-Traffic-Rate=$row[5]"
		    if defined $row[5];
		$qosdstring .= ",Maximum-Traffic-Burst=$row[6]"
		    if defined $row[6];
		$qosdstring .= ",Tolerated-Jitter=$row[7]"
		    if defined $row[7];
		$qosdstring .= ",Maximum-Latency=$row[8]"
		    if defined $row[8];
		$qosdstring .= ",Reduced-Resources-Code=$row[9]"
		    if defined $row[9];
		$qosdstring .= ",Media-Flow-Type=$row[10]"
		    if defined $row[10];
		$qosdstring .= ",Unsolicited-Grant-Interval=$row[11]"
		    if defined $row[11];
		$qosdstring .= ",SDU-Size=$row[12]"
		    if defined $row[12];
		$qosdstring .= ",Unsolicited-Polling-Interval=$row[13]"
		    if defined $row[13];
		$qosdstring .= ",Media-Flow-Description-SDP=$row[14]"
		    if defined $row[14];
		$qosdstring .= ",Transmission Policy=$row[15]"
		    if defined $row[15];
		$qosdstring .= ",DCSP=$row[16]"
		    if defined $row[16];
		$user->get_reply->add_attr('WiMAX-QoS-Descriptor', $qosdstring);
	    }
	    # If a referenced QoSprofile isnt found, the client will fail the auth
	}

    }
    return $user;
}

1;
