# DHCP.pm
# Implements DHCP package
#
# These routines do the low-level assembling
# and dis-assembling of DHCP packets for 
# AddressAllocatorDHCP.pm.
#
# Contains the following: 
#  build_dhcpdiscover
#  build_dhcprequest
#  build_dhcprelease
#  assemble_packet
#  disassemble_packet
#
# Author: Hugh Irvine (hugh@open.com.au) 
# Copyright (C) 2000 Open System Consultants

package Radius::DHCP;
use Socket;
use strict;

# RCS version number of this module
$Radius::DHCP::VERSION = '$Revision: 1.9 $';

# These are the well known DHCP constants that we use

$Radius::DHCP::SERVER_PORT = 67;
$Radius::DHCP::CLIENT_PORT = 68;

$Radius::DHCP::NO = 0;
$Radius::DHCP::YES = 1;

$Radius::DHCP::CLIENT_OPCODE = 1;
$Radius::DHCP::SERVER_OPCODE = 2;

$Radius::DHCP::BOOTREQUEST = 1;
$Radius::DHCP::BOOTREPLY = 2;

# DHCP option codes

$Radius::DHCP::PAD = 0;
$Radius::DHCP::SUBNET_MASK = 1;
$Radius::DHCP::TIME_OFFSET = 2;
$Radius::DHCP::ROUTER = 3;
$Radius::DHCP::TIME_SERVER = 4;
$Radius::DHCP::IEN116_NAME_SERVER = 5;
$Radius::DHCP::DNS_SERVER = 6;
$Radius::DHCP::LOG_SERVER = 7;
$Radius::DHCP::COOKIE_SERVER = 8;
$Radius::DHCP::LPR_SERVER = 9;
$Radius::DHCP::IMPRESS_SERVER = 10;
$Radius::DHCP::RESOURCE_LOCATION_SERVER = 11;
$Radius::DHCP::HOST_NAME = 12;
$Radius::DHCP::BOOT_FILE_SIZE = 13;
$Radius::DHCP::MERIT_DUMP_FILE = 14;
$Radius::DHCP::DOMAIN_NAME = 15;
$Radius::DHCP::SWAP_SERVER = 16;
$Radius::DHCP::ROOT_PATH = 17;
$Radius::DHCP::EXTENSIONS_PATH = 18;
$Radius::DHCP::IP_FORWARDING = 19;
$Radius::DHCP::SOURCE_ROUTING = 20;
$Radius::DHCP::POLICY_FILTERS = 21;
$Radius::DHCP::MAXIMUM_DATAGRAM_SIZE = 22;
$Radius::DHCP::DEFAULT_TTL = 23;
$Radius::DHCP::PATH_MTU_TIMEOUT = 24;
$Radius::DHCP::PATH_MTU_TABLE = 25;
$Radius::DHCP::INTERFACE_MTU = 26;
$Radius::DHCP::ALL_SUBNETS_LOCAL = 27;
$Radius::DHCP::BROADCAST_ADDRESS = 28;
$Radius::DHCP::PERFORM_MASK_DISCOVERY = 29;
$Radius::DHCP::MASK_SUPPLIER = 30;
$Radius::DHCP::PERFORM_ROUTER_DISCOVERY = 31;
$Radius::DHCP::ROUTER_SOLICITATION_ADDRESS = 32;
$Radius::DHCP::STATIC_ROUTE = 33;
$Radius::DHCP::TRAILER_ENCAPSULATION = 34;
$Radius::DHCP::ARP_CACHE_TIMEOUT = 35;
$Radius::DHCP::ETHERNET_ENCAPSULATION = 36;
$Radius::DHCP::TCP_DEFAULT_TTL = 37;
$Radius::DHCP::TCP_KEEPALIVE_INTERVAL = 38;
$Radius::DHCP::TCP_KEEPALIVE_GARBAGE = 39;
$Radius::DHCP::NIS_DOMAIN = 40;
$Radius::DHCP::NIS_SERVER = 41;
$Radius::DHCP::NTP_SERVER = 42;
$Radius::DHCP::VENDOR_SPECIFIC = 43;
$Radius::DHCP::NETBIOS_NAMESERVER = 44;
$Radius::DHCP::NETBIOS_NBDD_SERVER = 45;
$Radius::DHCP::NETBIOS_NODE_TYPE = 46;
$Radius::DHCP::NETBIOS_SCOPE = 47;
$Radius::DHCP::X_FONT_SERVER = 48;
$Radius::DHCP::X_DISPLAY_MANAGER = 49;
$Radius::DHCP::REQUESTED_IP_ADDRESS = 50;
$Radius::DHCP::IP_ADDRESS_LEASE_TIME = 51;
$Radius::DHCP::OPTION_OVERLOAD = 52;
$Radius::DHCP::MESSAGE_TYPE = 53;
$Radius::DHCP::SERVER_IDENTIFIER = 54;
$Radius::DHCP::PARAMETR_REQUEST_LIST = 55;
$Radius::DHCP::MESSAGE = 56;
$Radius::DHCP::MAXIMUM_MESSAGE_SIZE = 57;
$Radius::DHCP::RENEWAL_TIME = 58;
$Radius::DHCP::REBINDING_TIME = 59;
$Radius::DHCP::VENDOR_CLASS_IDENTIFIER = 60;
$Radius::DHCP::CLIENT_IDENTIFIER = 61;
$Radius::DHCP::NIS_PLUS_DOMAIN = 64;
$Radius::DHCP::NIS_PLUS_SERVER = 65;
$Radius::DHCP::TFTP_SERVER = 66;
$Radius::DHCP::BOOTFILE_NAME = 67;
$Radius::DHCP::MOBILE_IP_HOME_AGENT = 68;
$Radius::DHCP::SMTP_SERVER = 69;
$Radius::DHCP::POP3_SERVER = 70;
$Radius::DHCP::NNTP_SERVER = 71;
$Radius::DHCP::DEFAULT_WWW_SERVER = 72;
$Radius::DHCP::DEFAULT_FINGER_SERVER = 73;
$Radius::DHCP::DEFAULT_IRC_SERVER = 74;
$Radius::DHCP::STREETTALK_SERVER = 75;
$Radius::DHCP::STREETTALK_STDA_SERVER = 76;
$Radius::DHCP::USER_CLASS = 77;
$Radius::DHCP::FQDN = 81;
$Radius::DHCP::AGENT_OPTIONS = 82;

# The Subnet Selection Option has now been
# defined in RFC 3011 (www.ietf.org). 

$Radius::DHCP::SUBNET_SELECTION = 118;

# Keep the old Subnet Selection Option for now as
# some customers may be running the old DHCP code
# in the earlier versions of the ISC DHCP server

$Radius::DHCP::OLD_SUBNET_SELECTION = 211;

$Radius::DHCP::AUTHENTICATE = 210;

$Radius::DHCP::END_OF_OPTIONS = 255;

# DHCP ETHERNET_ENCAPSULATION values

$Radius::DHCP::RFC_894 = 0;
$Radius::DHCP::RFC_1042 = 1;

# DHCP NETBIOS_NODE_TYPE values

$Radius::DHCP::B_NODE = 0x1;
$Radius::DHCP::P_NODE = 0x2;
$Radius::DHCP::M_NODE = 0x4;
$Radius::DHCP::H_NODE = 0x8;

# DHCP OPTION_OVERLOAD values

$Radius::DHCP::USE_FILE = 1;
$Radius::DHCP::USE_SNAME = 2;
$Radius::DHCP::USE_BOTH = 3;

# DHCP MESSAGE_TYPE values

$Radius::DHCP::DHCPDISCOVER = 1;
$Radius::DHCP::DHCPOFFER = 2;
$Radius::DHCP::DHCPREQUEST = 3;
$Radius::DHCP::DHCPDECLINE = 4;
$Radius::DHCP::DHCPACK = 5;
$Radius::DHCP::DHCPNAK = 6;
$Radius::DHCP::DHCPRELEASE = 7;
$Radius::DHCP::DHCPINFORM = 8;

$Radius::DHCP::RAI_CIRCUIT_ID = 1;
$Radius::DHCP::RAI_REMOTE_ID = 2;
$Radius::DHCP::RAI_AGENT_ID = 3;          

$Radius::DHCP::FQDN_NO_CLIENT_UPDATE = 1;
$Radius::DHCP::FQDN_SERVER_UPDATE = 2;
$Radius::DHCP::FQDN_ENCODED = 3;
$Radius::DHCP::FQDN_RCODE1 = 4;
$Radius::DHCP::FQDN_RCODE2 = 5;
$Radius::DHCP::FQDN_NAME = 6;
$Radius::DHCP::FQDN_SUBOPTION_COUNT = 6;              

$Radius::DHCP::ETHERNET = 1;

$Radius::DHCP::MAGIC_COOKIE = pack 'C4', 99, 130, 83, 99;

####################################################################
# Build a DHCPDISCOVER packet.
sub build_dhcpdiscover
{
    my ($values) = @_;

    my $ret = assemble_packet
	($Radius::DHCP::DHCPDISCOVER, $values); 

    return $ret;
}

####################################################################
# Build a DHCPREQUEST packet.
sub build_dhcprequest
{
    my ($values) = @_;

    my $ret = assemble_packet
	($Radius::DHCP::DHCPREQUEST, $values);

    return $ret;
}

####################################################################
# Build a DHCPRELEASE packet.
sub build_dhcprelease
{
    my ($values) = @_;

    my $ret = assemble_packet
	($Radius::DHCP::DHCPRELEASE, $values);

    return $ret;
}

#####################################################################
# Assemble a packet in binary form.
sub assemble_packet 
{
    my ($message_type, $values) = @_;
 
    # Define the header values
    my $op = $Radius::DHCP::CLIENT_OPCODE;
    my $htype = $Radius::DHCP::ETHERNET;
    my $hlen = 6;
    my $hops = 1;
    my $xid = $$values{xid} || 0;
    my $secs = $$values{secs} || 0;
    my $flags = 0;
    my $ciaddr = pack 'C4', 0, 0, 0, 0;
    $ciaddr = $$values{ciaddr}
        if defined $$values{ciaddr};
    my $yiaddr = 0;
    my $siaddr = 0;

    # The giaddr is our local address by default
    my $giaddr = $$values{local_address};

    # If we aren't using the Subnet Selection Option,
    # then the giaddr is set to the subnet value which 
    # must be a secondary address on our interface
    $giaddr = $$values{subnet}
	if ((defined $$values{subnet}) &&
	    (!defined $$values{sso}));

    my $chaddr = $$values{chaddr};
    my $sname = 0;
    my $file = 0;

    # Pack the header
    my $packet = pack 'C4', $op, $htype, $hlen, $hops;    
    $packet .= pack 'N', $xid;
    $packet .= pack 'n2', $secs, $flags;
    $packet .= $ciaddr;
    $packet .= pack 'N2', $yiaddr, $siaddr;
    $packet .= $giaddr;
    $packet .= $chaddr;
    $packet .= pack 'C64', $sname;
    $packet .= pack 'C128', $file;

    # Define the options
    my $client_identifier = $$values{client_identifier};
    my $clidlen = length($client_identifier);
    my $user_class = $$values{user_class}
        if (defined $$values{user_class});
    my $uclen = length($user_class)
	if (defined $user_class);

    # Pack the options
    # First the Magic Cookie,
    # then the Message Type.
    $packet .= $Radius::DHCP::MAGIC_COOKIE;
    $packet .= pack 'C3', $Radius::DHCP::MESSAGE_TYPE, 1, $message_type;

    # Pack the Client Identifier.
    # Use the convention of a leading "0" to indicate a string.
    $packet .= pack 'C3', $Radius::DHCP::CLIENT_IDENTIFIER, $clidlen + 1, 0; 
    $packet .= $client_identifier;

    if ($message_type == $Radius::DHCP::DHCPDISCOVER)
    {
	$packet .= pack 'C C N', 
		$Radius::DHCP::IP_ADDRESS_LEASE_TIME, 4, 
		    $$values{default_lease};
    }
    elsif ($message_type == $Radius::DHCP::DHCPREQUEST)
    {
	if (defined $$values{server_identifier})
	{
	    $packet .= pack 'C C', $Radius::DHCP::SERVER_IDENTIFIER, 4;
	    $packet .= $$values{server_identifier};
	}
	if (defined $$values{requested_ip_address})
	{
	    $packet .= pack 'C C', $Radius::DHCP::REQUESTED_IP_ADDRESS, 4;
	    $packet .= $$values{requested_ip_address};
	}
    }
    elsif ($message_type == $Radius::DHCP::DHCPRELEASE)
    {
	# add anything needed here  
    }

    # Use Subnet Selection Option if it has been defined.
    if ((defined $$values{sso}) && (defined $$values{subnet}))
    {
	$packet .= pack 'C C', $$values{sso}, 4;
	$packet .= $$values{subnet};
    }

    # Add the User Class if it has been defined.
    if (defined $user_class)
    {
	$packet .= pack 'C C', $Radius::DHCP::USER_CLASS, $uclen;
	$packet .= $user_class;
    }

    # Add the End of Options tag.
    $packet .= pack 'C', $Radius::DHCP::END_OF_OPTIONS;
    
    # Pack the packet out to 300 bytes.
    # SUN in.dhcpd will not respond otherwise.
    my $pad = 300 - length($packet);

    $packet .= pack "C$pad", 0 if $pad > 0;

    return $packet;
}

#####################################################################
# Disassemble the binary packet into useable form.
sub disassemble_packet 
{
    my ($data) = @_;

    my %reply;

    # Decode the header
    my ($op, $htype, $hlen, $hops) = unpack('C4', $data);
    $data = substr($data, 4);
    my ($xid) = unpack('N', $data);
    $data = substr($data, 4);
    my ($secs, $flags) = unpack('n2', $data);
    $data = substr($data, 4);
    my ($ciaddr) = substr($data, 0, 4);
    $data = substr($data, 4);
    my ($yiaddr) = substr($data, 0, 4);
    $data = substr($data, 4);
    my ($siaddr) = substr($data, 0, 4);
    $data = substr($data, 4);
    my ($giaddr) = substr($data, 0, 4);
    $data = substr($data, 4);
    my ($chaddr) = substr($data, 0, 16);
    $data = substr($data, 16);
    my ($sname) = substr($data, 0, 64);
    $data = substr($data, 64);
    my ($file) = ($data, 0, 128);
    $data = substr($data, 128);
    my ($magic_cookie) = substr($data, 0, 4);
    $data = substr($data, 4);

    $reply{op_code} = $op;
    $reply{xid} = $xid;
    $reply{yiaddr} = $yiaddr;
    $reply{sname} = $sname;
    $reply{magic_cookie} = $magic_cookie;

    # Unpack the options
    while (length($data) > 1) 
    {
	my ($type, $length) = unpack 'C C', $data;

	$data = substr($data, 2);

	# Stop processing when we reach the end
	last if ($type == $Radius::DHCP::END_OF_OPTIONS);

	# We currently only handle the following attributes
	# (additional attribute processing may be required).

	if ($type == $Radius::DHCP::MESSAGE_TYPE)
	{
	    $reply{message_type} = unpack 'C', substr($data, 0, $length);
	}
	elsif ($type == $Radius::DHCP::SUBNET_MASK)
	{
	    $reply{subnet_mask} = substr($data, 0, $length);
	}
	elsif ($type == $Radius::DHCP::DNS_SERVER)
	{
	    # This may contain a list - only return the first one
	    $reply{dns_server} = substr($data, 0, 4);
	}
	elsif ($type == $Radius::DHCP::SERVER_IDENTIFIER)
	{
	    $reply{server_identifier} = substr($data, 0, $length);
	}
	elsif (($type == $Radius::DHCP::SUBNET_SELECTION) ||
	       ($type == $Radius::DHCP::OLD_SUBNET_SELECTION))
	{
	    $reply{sso} = $type;
	    $reply{subnet} = substr($data, 0, $length);
	}

	# Remove the option we just parsed
	$data = substr($data, $length);
    }

    return \%reply;
}


#####################################################################
# Format data in a values hash derived from a DHCP request/reply
sub dump
{
    my ($data) = @_;

no warnings qw(uninitialized);

    my $yiaddr = unpack('H*', $$data{yiaddr});
    my $sname = $$data{sname};
    $sname =~ s/\0*//g;
    my $magic_cookie = unpack('H*', $$data{magic_cookie});
    my $subnet_mask = unpack('H*', $$data{subnet_mask});
    my $dns_server = unpack('H*', $$data{dns_server});
    my $server_identifier = unpack('H*', $$data{server_identifier});
    my $subnet = unpack('H*', $$data{subnet});
    my $ret = " OPCODE: $$data{op_code}\n MESSAGE_TYPE: $$data{message_type}\n XID: $$data{xid}\n YIADDR: $yiaddr\n SNAME: $sname\n MAGIC_COOKIE: $magic_cookie\n SUBNET_MASK: $subnet_mask\n DNS_SERVER: $dns_server\n SERVER_IDENTIFIER: $server_identifier\n SSO: $$data{sso}\n SUBNET: $subnet";

    return $ret;
}

1;
