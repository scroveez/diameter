# Radius.pm
# Implements Radius message packet object
#
# Contains the following additional attributes
#  SendTo
#  StatsTrail, array or refs to statistics hashes
#
# Handles multiple instances of the same attribute
# Handles accounting packets, and authentication of same
# Handles EAP
#
# Author: Mike McCauley (mikem@open.com.au),
# Copyright (C) Open System Consultants
# $Id: Radius.pm,v 1.176 2014/11/27 20:57:06 hvn Exp $

package Radius::Radius;
@ISA = qw(Radius::AttrVal);
use Radius::AttrVal;
use Radius::BigInt;
use Socket;
use Digest::MD5;
use Radius::Util;
use strict;

# RCS version number of this module
$Radius::Radius::VERSION = '$Revision: 1.176 $';

# These map request names into request types. Some are from RFC 2882
my %codes  = ( 
        'Access-Request'                     => 1,
        'Access-Accept'                      => 2,
        'Access-Reject'                      => 3,
        'Accounting-Request'                 => 4,
        'Accounting-Response'                => 5,
        'Accounting-Status'                  => 6,
        'Access-Password-Request'            => 7,
        'Access-Password-Ack'                => 8,
        'Access-Password-Reject'             => 9,
        'Accounting-Message'                 => 10,
        'Access-Challenge'                   => 11,
        'Status-Server'                      => 12,
        'Status-Client'                      => 13,
	'Resource-Free-Request'              => 21,
	'Resource-Free-Response'             => 22,
	'Resource-Query-Request'             => 23,
	'Resource-Query-Response'            => 24,
	'Alternate-Resource-Reclaim-Request' => 25,
	'NAS-Reboot-Request'                 => 26,
	'NAS-Reboot-Response'                => 27,
        'Ascend-Access-Next-Code'            => 29,
        'Ascend-Access-New-Pin'              => 30,
        'Ascend-Terminate-Session'           => 31,
        'Ascend-Password-Expired'            => 32,
        'Ascend-Access-Event-Request'        => 33,
        'Ascend-Access-Event-Response'       => 34,
        'Disconnect-Request'                 => 40,
        'Disconnect-Request-ACKed'           => 41,
        'Disconnect-Request-NAKed'           => 42,
        'Change-Filter-Request'              => 43,
        'Change-Filter-Request-ACKed'        => 44,
        'Change-Filter-Request-NAKed'        => 45,
	'IP-Address-Allocate'                => 50,
	'IP-Address-Release'                 => 51,
);

# These map request types into request names
my %rcodes  = ( 
        1 => 'Access-Request',
        2 => 'Access-Accept',
        3 => 'Access-Reject',
        4 => 'Accounting-Request',
        5 => 'Accounting-Response',
        7 => 'Access-Password-Request',
        8 => 'Access-Password-Ack',
        9 => 'Access-Password-Reject',
        11 => 'Access-Challenge',
        12 => 'Status-Server',
        13 => 'Status-Client',
        29 => 'Ascend-Access-Next-Code',
        30 => 'Ascend-Access-New-Pin',
        31 => 'Ascend-Terminate-Session',
        32 => 'Ascend-Password-Expired',
        33 => 'Ascend-Access-Event-Request',
        34 => 'Ascend-Access-Event-Response',
        40 => 'Disconnect-Request',
        41 => 'Disconnect-Request-ACKed',
        42 => 'Disconnect-Request-NAKed',
        43 => 'Change-Filter-Request',
        44 => 'Change-Filter-Request-ACKed',
        45 => 'Change-Filter-Request-NAKed',
);

# Specifies what request codes get an authenticator calculated
my %authenticator_codes =
(
 'Access-Accept'               => 1,
 'Access-Reject'               => 1,
 'Accounting-Request'          => 1,
 'Accounting-Response'         => 1,
 'Access-Challenge'            => 1,
 'Disconnect-Request'          => 1,
 'Disconnect-Request-ACKed'    => 1,
 'Disconnect-Request-NAKed'    => 1,
 'Change-Filter-Request'       => 1,
 'Change-Filter-Request-ACKed' => 1,
 'Change-Filter-Request-NAKed' => 1,
 );

# Attribute names that are required to be encoded with salt
# This is a speedup to prevent multiple tests in decode_attrs and encode_attrs
# Remove when everybody has dictionaries with encryption flags
my %salted =
(
 'MS-MPPE-Send-Key'          => 1,
 'MS-MPPE-Recv-Key'          => 1,
 'Motorola-WiMAX-MIP-KEY'    => 1,
 '3GPP2-MN-HA-Shared-Key'    => 1,
 'Unisphere-Med-Dev-Handle'  => 1,
 'cisco-li-configuration'    => 1,
 'LI-Profile'                => 1,
 );
my %ascended =
(
 'Ascend-Send-Secret'        => 1,
 'Ascend-Receive-Secret'     => 1,
 );
my %salted_integer = 
(
 'Unisphere-LI-Action'       => 1,
 'Unisphere-Med-Port-Number' => 1,
 'LI-Action'                 => 1,
 'LI-Md-Port'                => 1,
 );
my %salted_ipaddr =
(
 'Unisphere-Med-Ip-Address'  => 1,
 'LI-Md-Address'             => 1,
 );
my %salted_long =
(
 'LI-Id' => 1,
 );


# These are the well known radius attribute numbers that we use
# We have these here so we can change the dictioanry to 
# be anything we like
$Radius::Radius::USER_NAME = 1;
$Radius::Radius::USER_PASSWORD = 2;
$Radius::Radius::CHAP_PASSWORD = 3;
$Radius::Radius::NAS_IP_ADDRESS = 4;
$Radius::Radius::NAS_PORT = 5;
$Radius::Radius::SERVICE_TYPE = 6;
$Radius::Radius::FRAMED_PROTOCOL = 7;
$Radius::Radius::FRAMED_IP_ADDRESS = 8;
$Radius::Radius::FRAMED_IP_NETMASK = 9;
$Radius::Radius::LOGIN_IP_HOST = 14;
$Radius::Radius::LOGIN_TCP_PORT = 16;
$Radius::Radius::REPLY_MESSAGE = 18;
$Radius::Radius::STATE = 24;
$Radius::Radius::CLASS = 25;
$Radius::Radius::SESSION_TIMEOUT = 27;
$Radius::Radius::CALLED_STATION_ID = 30;
$Radius::Radius::CALLING_STATION_ID = 31;
$Radius::Radius::NAS_IDENTIFIER = 32;
$Radius::Radius::PROXY_STATE = 33;
$Radius::Radius::ACCT_STATUS_TYPE = 40;
$Radius::Radius::ACCT_DELAY_TIME = 41;
$Radius::Radius::ACCT_INPUT_OCTETS = 42;
$Radius::Radius::ACCT_OUTPUT_OCTETS = 43;
$Radius::Radius::ACCT_SESSION_ID = 44;
$Radius::Radius::ACCT_SESSION_TIME = 46;
$Radius::Radius::ACCT_INPUT_PACKETS = 47;
$Radius::Radius::ACCT_OUTPUT_PACKETS = 48;
$Radius::Radius::ACCT_TERMINATE_CAUSE = 49;
$Radius::Radius::ACCT_INPUT_GIGAWORDS = 52;
$Radius::Radius::ACCT_OUTPUT_GIGAWORDS = 53;
$Radius::Radius::CHAP_CHALLENGE = 60;
$Radius::Radius::NAS_PORT_TYPE = 61;
$Radius::Radius::EAP_MESSAGE = 79;
$Radius::Radius::MESSAGE_AUTHENTICATOR = 80;
$Radius::Radius::CONNECT_INFO = 77;
$Radius::Radius::ERROR_CAUSE = 101;
$Radius::Radius::PROXY_ACTION = 211;

$Radius::Radius::ACCT_STATUS_TYPE_START = 1;
$Radius::Radius::ACCT_STATUS_TYPE_STOP  = 2;
$Radius::Radius::ACCT_STATUS_TYPE_ALIVE = 3;

$Radius::Radius::VENDOR_MICROSOFT = 311;
$Radius::Radius::MS_CHAP_RESPONSE = 1;
$Radius::Radius::MS_CHAP_CHALLENGE = 11;
$Radius::Radius::MS_MPPE_SEND_KEY = 16;
$Radius::Radius::MS_MPPE_RECV_KEY = 17;
$Radius::Radius::MS_CHAP2_RESPONSE = 25;

# SIP
$Radius::Radius::SIP_DIGEST_RESPONSE = 206;
$Radius::Radius::SIP_DIGEST_ATTRIBUTES = 207;

# Functions for unpacking the various data types
# The arguments passed to the unpacker functions are:
# $_[0] The raw bytes of the value in binary format
# $_[1] The atribute number, an integer
# $_[2] The attribute name, a string
# $_[3] The pointer to the RDict dictionary to use
# Attribute types not mentioned here are packed verbatim
my %unpacker = 
    (
     'text' => sub {
	 # 'C' code out there would chop trailing
	 # nulls, so we will too.  <shawni@teleport.com>
	 $_[0] =~ s/\0+$//;
	 return $_[0];
     },
# now done by unpackRadiusAttrs
#     'string' => sub {
#	 # 'C' code out there would chop trailing
#	 # nulls, so we will too.  <shawni@teleport.com>
#	 $_[0] =~ s/\0+$//;
#	 return $_[0];
#     },
     'tagged-string' => sub {
	 # 'C' code out there would chop trailing
	 # nulls, so we will too.  <shawni@teleport.com>
	 $_[0] =~ s/\0+$//;
	 my ($tag, $string) = unpack 'C a*', $_[0];
	 # Tag greater than 1F is really first octet of a string
	 return $tag <= 0x1f ? $tag . ':' . $string : $_[0];
     },
     'hexadecimal' => sub {
	 return unpack 'H*', $_[0];
     },
     'integer' => sub {
	 my $value = unpack 'N', $_[0];
	 my $ret = $_[3]->valNumToName($_[2], $value);
	 return defined $ret ? $ret : $value;
     },
     'signed-integer' => sub {
	 # Gymnastics to make sure we use network byte order
	 my $value = unpack('l', pack('L', unpack('N', $_[0])));
     },
     'tagged-integer' => sub {
	 # Top byte is tag integer
	 my $value = unpack 'N', $_[0];
	 my $tag = ($value & 0xff000000) >> 24;
	 $value &= 0xffffff;
	 my $ret = $_[3]->valNumToName($_[2], $value);
	 return $tag . ':' . (defined $ret ? $ret : $value);
     },
     'integer8' => sub {
	 my $value = unpack 'C', $_[0];
	 my $ret = $_[3]->valNumToName($_[2], $value);
	 return defined $ret ? $ret : $value;
     },
     'integer16' => sub {
	 my $value = unpack 'n', $_[0];
	 my $ret = $_[3]->valNumToName($_[2], $value);
	 return defined $ret ? $ret : $value;
     },
     'integer64' => sub {
#	 require Math::BigInt;
	 my ($v1, $v2) = unpack 'NN', $_[0];
#	 my $value = Math::BigInt->new($v1);
#	 $value = $value << 32;
#	 $value = $value + $v2;
#	 return $value->stringify();
	 return $v1 ? sprintf("0x%x%08x", $v1, $v2) : sprintf("0x%x", $v2);
     },
     'boolean' => sub {
	 return unpack 'C', $_[0];
     },
     'ipaddr' => sub {
	 return length($_[0]) == 4 ? Socket::inet_ntoa($_[0]) : 'UNKNOWN';
     },
     'ipaddrv4v6' => sub {
	 return &Radius::Util::inet_ntop($_[0]);
     },
     'ipaddrv6' => sub {
	 return &Radius::Util::inet_ntop($_[0]);
     },
     'date' => sub {
	 return unpack 'N', $_[0];
	 
     },		    
     'abinary' => \&unpackAbinary,
     'ipv4prefix' => \&unpackIpv4prefix,
     'ipv6prefix' => \&unpackIpv6prefix,
     'ifid' => \&unpackIfid,
     'tlv' => \&unpackTLV,
     );
$unpacker{integer1} = $unpacker{integer8}; # Backwards compatibility

# We treat the following as binary if we can not unpack them.
if (Radius::Util::get_ipv6_capability() eq 'none')
{
  $unpacker{ipaddrv4v6} = sub {return $_[0]};
  $unpacker{ipaddrv6}   = sub {return $_[0]};
  $unpacker{ipv6prefix} = sub {return $_[0]};
}

# Define a hash of subroutine references to pack the various data types
# The arguments passed to the packer functions are:
# $_[0] The string representation of the value to be packed
# $_[1] The attribute name, a string
# $_[2] The pointer to the RDict dictionary to use
# Attribute types not mentioned here are packed verbatim
my %packer = 
    (
     'string' => sub {
	 # Zero-length strings are never sent
	 return unless length($_[0]);
	 return $_[0];
     },
     'tagged-string' => sub {
	 if ($_[0] =~ /^(\d+):(.*)/)
	 {
	     # Tagged
	     return pack 'ca*', $1, $2;
	 }
	 else
	 {
	     # Not tagged, implicit 0 tag
	     return pack 'ca*', 0, $_[0];
	 }
     },
     'hexadecimal' => sub {
	 return pack 'H*', $_[0];
     },
     'integer' => sub {
	 return pack 'N', $_[2]->valNameToNum(@_[1, 0]);
     },
     'signed-integer' => sub {
	 # Gymnastics to make sure we use network byte order
	 return pack('N', unpack('L', pack('l', $_[0])));
     },
     'integer8' => sub {
	 return pack 'C', $_[2]->valNameToNum(@_[1, 0]);
     },
     'integer16' => sub {
	 return pack 'n', $_[2]->valNameToNum(@_[1, 0]);
     },
     'tagged-integer' => sub {
	 if ($_[0] =~ /^(\d+):(.*)/)
	 {
	     # Tagged
	     return pack 'N', $_[2]->valNameToNum($_[1], $2) | $1 << 24;
	 }
	 else
	 {
	     # Not tagged
	     return pack 'N', $_[2]->valNameToNum(@_[1, 0]);
	 }
     },
     'integer64' => sub {
	 if ($_[0] =~ /^0x([0-9a-fA-F]{1,16})$/)
	 {
	     my $pad = 16 - length($1);
	     return pack("H*", '0' x $pad . $1);
	 }
	 return &Radius::BigInt::pack64u($_[0]);
     },
     'boolean' => sub {
	 return pack 'C', $_[0];
     },
     'ipaddr' => sub {
	 # Allow binary addresses
	 return length($_[0]) == 4 ? $_[0] : Socket::inet_aton($_[0]);
     },
     'ipaddrv4v6' => sub {
	 return &Radius::Util::inet_pton($_[0]);
     },
     'ipaddrv6' => sub {
	 return &Radius::Util::inet_pton($_[0]);
     },
     'date' => sub {
	 return pack 'N', $_[0];
     },
     'abinary' => \&packAbinary,
     'ipv4prefix' => \&packIpv4prefix,
     'ipv6prefix' => \&packIpv6prefix,
     'ifid' => \&packIfid,
     'tlv' => \&packTLV,
     );
$packer{integer1} = $packer{integer8}; # Backwards compatibility

# We treat the following as binary if we can not pack them.
if (Radius::Util::get_ipv6_capability() eq 'none')
{
  $packer{ipaddrv4v6} = sub {return $_[0]};
  $packer{ipaddrv6}   = sub {return $_[0]};
  $packer{ipv6prefix} = sub {return $_[0]};
}

# Allow encoders and decoders to be accessed by an encryption algorithm number,
# permitting support for dictionary-based encryption specifications
my %encoders = 
(
 '1' => \&encode_password2,
 '2' => \&encode_salted,
 '3' => \&encode_ascend_secret,
 );
my %decoders = 
(
 '1' => \&decode_password2,
 '2' => \&decode_salted,
 '3' => \&encode_ascend_secret, # Symmetric
 );

# We keep counts of unknown attributes sent by different sources.
%main::unknown_attr_counts = ();

# Make sure we get reinitialized on sighup
push(@main::reinitFns, \&reinitialize);

#####################################################################
sub reinitialize
{
    %main::unknown_attr_counts = ();
}

#####################################################################
sub new
{
    my ($class, $dict, $data, $whence) = @_;
    my $self = $class->SUPER::new;

    $self->{RecData} = $data; # Keep a copy of the original packet if possible
    $self->{Dict} = $dict;
    if ($whence)
    {
	$self->{RecvFrom} = $whence;
	($self->{RecvFromPort}, $self->{RecvFromAddress}) = Radius::Util::unpack_sockaddr_in($whence);
    }
    $self->unpackRadiusAttrs($data) if defined($data);

    return $self;
}

#####################################################################
# Construct a new request which is a copy of the old one
sub newCopy
{
    my ($class, $old) = @_;

    my $self = $class->new();
    $self->{Code} = $old->{Code};
    $self->{Authenticator} = $old->{Authenticator};
    $self->{Dict} = $old->{Dict};
    $self->add_attr_list($old);
    return $self;
}

#####################################################################
# Get the next radius packet from $socket and disassemble it
# into a new Radius object
sub newRecvFrom
{
    my ($class, $socket, $dictionary) = @_;
    my ($rec, $self, $whence);
    if ($whence = recv($socket, $rec, 65535, 0))
    {
	$self = Radius::Radius->new($dictionary, $rec, $whence);
	$self->{RecvSocket} = $socket;
	$self->{RecvSockname} = getsockname($socket);

	($self->{RecvTime}, $self->{RecvTimeMicros}) = &Radius::Util::getTimeHires;
	# Packet dumping moved to decode_attrs where the decrypted 
	# and translated attrs are available
    }
    return $self;
}

# Functions for accessing data structures
sub code          { $_[0]->{Code};          }
sub code_int      { $codes{$_[0]->{Code}};  } # As an integer
sub identifier    { $_[0]->{Identifier};    }
sub authenticator { $_[0]->{Authenticator}; }

sub set_code          { $_[0]->{Code} = $_[1];          }
sub set_identifier    { $_[0]->{Identifier} = $_[1];    }
sub set_authenticator { $_[0]->{Authenticator} = $_[1]; }

#####################################################################
# Send it to $paddr via $socket
# returns true on success
# $p is the original request that caused this, might be needed for
# context in logging etc
sub sendTo
{
    my ($self, $socket, $paddr, $p) = @_;

    &main::log($main::LOG_ERR, "in sendTo, assemble_packet has not been called", $p)
	unless defined $self->{Packet};
    $self->{SendTo} = $paddr;
    
    if (&main::willLog($main::LOG_DEBUG, $p))
    {
	my @l = Radius::Util::unpack_sockaddr_in($paddr); 
	my $addr = Radius::Util::inet_ntop($l[1]); 
	my $text = "Packet dump:\n*** Sending to $addr port $l[0] ....\n";

	# Packet dump for debugging
	# Courtesy Aaron Nabil (nabil@spiritone.com)
	if (&main::willLog(5, $p)) 
	{
	    my $rec = $self->{Packet};
	    $text .= "\nPacket length = " . length($rec) . "\n";
	    my $i;
	    for ($i = 0; $i < length($rec); $i += 16)
	    {
		$text .= join ' ', map {sprintf "%02x", $_} unpack('C16', substr($rec, $i, 16));
		$text .= "\n";
	    }
	}

	$text .= $self->dump;
	&main::log($main::LOG_DEBUG, $text, $p)
    }

    # Some platforms (eg Linux) will produce "Connection refused" if the dest
    # does not have a port open, so ignore those kinds of errors
    if (!send($socket, $self->{Packet}, 0, $self->{SendTo})
	&& $! =~ /^Connection refused/)
    {
	&main::log($main::LOG_ERROR, "sendTo: send failed: $!", $p);
	return;
    }
    return 1;
}

#####################################################################
# Send it to $paddr via $socket
sub sendReplyTo
{
    my ($self, $request) = @_;
    
    $self->sendTo($request->{RecvSocket}, $request->{RecvFrom}, $request);
}

#####################################################################
# Low level RADIUS compliant password encryption decryption
# Encode a password
# if $oldascendalgorithm is set, we dont pad to 16 bytes, and we dont
# do cipher block chaining in order to be compliant with the old
# Ascend password encryption algorithm
sub encode_password2
{
  my ($pwdin, $secret, $iv, $oldascendalgorithm) = @_;

  # Pad the input to a multiple of 16 bytes with NULs
  # Although the RFC says not to append any NULs if its already 16 
  # bytes, we always add at least one NUL, since some C servers
  # assume that the password will be NUL terminated!
  $pwdin .= "\000" x (16 - (length($pwdin) % 16))
      unless $oldascendalgorithm;

  my $lastround = $iv;
  my ($pwdout, $i);
  for ($i = 0; $i < length($pwdin); $i += 16) 
  {
      $pwdout .= substr($pwdin, $i, 16) ^ Digest::MD5::md5($secret . $lastround);
      $lastround = substr($pwdout, $i, 16)
	  unless $oldascendalgorithm;
  }
  return $pwdout;
}

#####################################################################
# Low level RADIUS compliant password encryption decryption
sub decode_password2
{
    my ($pwdin, $secret, $iv, $oldascendalgorithm) = @_;

    my $lastround = $iv;
    return unless defined $pwdin;

    my ($pwdout, $i, $remaining);
    for ($i = 0; $i < length($pwdin); $i += $remaining) 
    {
	# Some NAS's dont pad the password to 16 bytes
	# as per RFC 2138
	$remaining = length($pwdin) - $i;
	$remaining = 16 if $remaining > 16;
	my $chunk = substr($pwdin, $i, $remaining) ^ Digest::MD5::md5($secret . $lastround); 
	$pwdout .= substr($chunk, 0, $remaining);
	# If the client has the UseOldAscendPasswords flag set
	# then we dont implement cipher block chaining, in order
	# to be compatible withthe old Ascend algorithm
	
	$lastround = substr($pwdin, $i, $remaining)
	    unless $oldascendalgorithm
    }
    # GAG: some NAS's notably Cisco only have a single trailing NULL
    # folloed by junk. The Radius spec says it should be passed with 
    # NULLs all the way out to a 16 byte boundary. Other servers
    # use strcmp so, we wount strictly check against the Radius
    # spec: strip after the first NULL. 
    my $index = index($pwdout, "\000");
    substr($pwdout, $index) = '' if $index != -1;

    return $pwdout;
}

#####################################################################
# Decode a password
sub decode_password 
{
    my ($self, $pwdin, $secret, $oldascendalgorithm) = @_;

    my $pwdout = &decode_password2($pwdin, $secret, $self->authenticator, 
				   $oldascendalgorithm);

    # Uncomment this if you really want to see whats really 
    # in the password. Useful for finding obscure bugs
#    my $pwdump = Radius::AttrVal::pclean($pwdout);
#    &main::log($main::LOG_DEBUG, "Decoded password is $pwdump");
    
    return $pwdout;
}

#####################################################################
# Encode a password
# if $oldascendalgorithm is set, we dont pad to 16 bytes, and we dont
# do cipher block chaining in order to be compliant with the old
# Ascend password encryption algorithm
sub encode_password 
{
  my ($self, $pwdin, $secret, $oldascendalgorithm) = @_;

  return &encode_password2($pwdin, $secret, $self->authenticator, $oldascendalgorithm);
}

#####################################################################
# Encode/Decode a secret, suitable for use with Ascend-Send-Secret
# Symmetric
sub encode_ascend_secret
{
    my ($pwdin, $secret, $iv) = @_;

    my $digest = Digest::MD5::md5($iv . $secret);
    my $pwdout;
    while (length($pwdin))
    {
	$pwdout .= substr($pwdin, 0, 16, '') ^ $digest;
    }
    return $pwdout;
}

#####################################################################
# Encode with the SALT algorithm as described by as per RFC 2548
# and Siemens for Juniper ERX LI attributes. Used for MPPE keys. 
# replaces encode_mppe_key and decode_mppe_keys. Also used for Tunnel Passwords etc.
sub encode_salted
{
    my ($pwdin, $secret, $iv) = @_;

    my $P = pack('C',  length($pwdin)) . $pwdin;
    my $A = pack('n', &Radius::Util::rand(65535) | 0x8000); # salt
    my $c_i = $iv . $A;     # Ciphertext blocks
    my $C;                                   # Encrypted result
    while (length($P))
    {
	$c_i = substr($P, 0, 16, '') ^ Digest::MD5::md5($secret . $c_i);
	$C .= $c_i;
    }
    return $A . $C; # salt . rest
}

sub decode_salted
{
    my ($encoded, $secret, $iv) = @_;

    my ($A, $S) = unpack('a2a*', $encoded); # salt, rest

    my ($p, $c_i, $b_i);
    $b_i = Digest::MD5::md5($secret . $iv . $A);
    while (length($S))
    {
	$c_i = substr($S, 0, 16, '');
	$p .= $c_i ^ $b_i;
	$b_i = Digest::MD5::md5($secret . $c_i);
    }
    # Decode the length and strip off the padding NULs
    my ($len, $password) = unpack('Ca*', $p);
    substr($password, $len) = '' if ($len < length($password));
    return $password;
}

#####################################################################
# Encode with the SALT algorithm as described by as per RFC 2548
# but without an encoded string length.
# Used by Cisco.
# Used in Cisco EAP SIM module
sub encode_salted_nolength
{
    my ($pwdin, $secret, $iv) = @_;

    my $P = $pwdin;
    my $A = pack('n', &Radius::Util::rand(65535) | 0x8000); # salt
    my $c_i = $iv . $A;     # Ciphertext blocks
    my $C;                                   # Encrypted result
    while (length($P))
    {
	$c_i = substr($P, 0, 16, '') ^ Digest::MD5::md5($secret . $c_i);
	$C .= $c_i;
    }
    return $A . $C; # salt . rest
}

sub decode_salted_nolength
{
    my ($encoded, $secret, $iv) = @_;

    my ($A, $S) = unpack('a2a*', $encoded); # salt, rest

    my ($p, $c_i, $b_i);
    $b_i = Digest::MD5::md5($secret . $iv . $A);
    while (length($S))
    {
	$c_i = substr($S, 0, 16, '');
	$p .= $c_i ^ $b_i;
	$b_i = Digest::MD5::md5($secret . $c_i);
    }
    return $p;
}

#####################################################################
# At this stage the attributes are raw data straight off the wire
# Decode/decrypt any attributes that require it. 
# Unpack any attrs that require it
# $op contains the original Radius request 
# containing the authenticator used as an IV to decrypt
sub decode_attrs
{
    my ($self, $secret, $op, %flags) = @_;

    my $dict = $self->{Dict};
    foreach (@{$self->{Attributes}})
    {
	my ($name, $value) = @$_;

	my ($aname, $anum, $atype, $avendor, $dflags) = $self->{Dict}->attrByName($name);

	# First decrypt anything that needs it:
	# REVISIT: Remove these explicit tests when everybody has dictionaries with
	# encryption flags
	if ($name eq 'Tunnel-Password' && !$flags{ClearTextTunnelPassword})
	{
	    # Encode a Tunnel-Password according to
	    # http://ftp.ietf.org/internet-drafts/draft-ietf-radius-tunnel-auth-06.txt
	    # or ftp://ftp.isi.edu/in-notes/rfc2868.txt
	    my ($tag, $encoded) = unpack('Ca*', $value);
	    $value = $tag . ':' . &decode_salted($encoded, $secret, $op->authenticator);
	}
	elsif ($name eq 'MS-CHAP-MPPE-Keys')
	{
	    $value = $op->decode_password($value, $secret);
	}
	elsif (exists $ascended{$name})
	{
	    $value = &encode_ascend_secret($value, $secret, $op->authenticator);
	}
	elsif (exists $salted{$name})
	{
	    # binary
	    $value = &decode_salted($value, $secret, $op->authenticator);
	}
	# Unisphere Jupiter ERX attributes get special type of encryption,
	# described to us by Siemens. This should really be done as a special
	# type of dictionary item in the packer and unpacker, the secret is
	# not available there.
	elsif (exists $salted_integer{$name})
	{
	    # integer
	    $value = unpack('N', &decode_salted($value, $secret, $op->authenticator));
	}
	elsif (exists $salted_ipaddr{$name})
	{
	    # ipaddr
	    my $a = &decode_salted($value, $secret, $op->authenticator);
	    $value = length($a) == 4 ? Socket::inet_ntoa($a) : 'UNKNOWN';
	}
	# Some redback LI salt encrypted attrs
	elsif (exists $salted_long{$name})
        {
            # binary
            $value = &Radius::BigInt::unpack64u(&decode_salted($value, $secret, $op->authenticator));
        }
	else
	{
	    # Look for dictionary flags based encryption:
	    if (defined $dflags)
	    {
		# See if there is a tag required and get it if present
		# Tag defaults to 0 if no explicit tag
		my $tag = 0;
		my $has_tag;
		if ($dflags =~/has_tag/)
		{
		    my ($xtag, $xvalue) = unpack('Ca*', $value);
		    # Tag greater than 1F is really first octet of a string
		    if ($xtag <= 0x1f)
		    {
			$tag = $xtag;
			$value = $xvalue;
			$has_tag++;
		    }
	        }

		# Maybe  decrypt
		$value = &{$decoders{$1}}($value, $secret, $op->authenticator)
		    if ($dflags =~ /encrypt=(\d)/
			&& exists $decoders{$1});

		# Maybe prepend the tag
		$value = $tag . ':' . $value
		    if ($has_tag);
	    }
	}

	# Then unpack and translate integers
	$value = &{$unpacker{$atype}}($value, $atype, $aname, $dict)
	    if exists $unpacker{$atype};
	$_->[1] = $value;
    }

}

#####################################################################
# Dump the received request using the logger of the calling module
# such as Client, AuthBy RADIUS, etc.
sub recv_debug_dump
{
    my ($self, $module) = @_;

    my $addr = Radius::Util::inet_ntop($self->{RecvFromAddress}); 
    my $text = "Packet dump:\n*** Received from $addr port $self->{RecvFromPort} ....\n";
	
    # Packet dump for debugging.
    # Courtesy Aaron Nabil (nabil@spiritone.com)
    if (main::willLog(5, $self))
    {
	my $rec = $self->{RecData};

	$text .= "\nPacket length = " . length($rec) . "\n";
	my $i;
	for ($i = 0; $i < length($rec); $i += 16)
	{
	    $text .= join ' ', map {sprintf "%02x", $_} unpack('C16', substr($rec, $i, 16));
	    $text .= "\n";
	}
    }
    $text .= $self->dump;
    $module->log($main::LOG_DEBUG, $text, $self);
}

#####################################################################
sub dump
{
    my $self = shift;

    no warnings "uninitialized";
    sprintf("Code:       %s
Identifier: %s
Authentic:  %s
Attributes:
", 
	  Radius::AttrVal::pdef($self->{Code}),
	  Radius::AttrVal::pdef($self->{Identifier}),
	  Radius::AttrVal::pclean(Radius::AttrVal::pdef($self->{Authenticator}))) . $self->format();   
}

#####################################################################
sub packRadiusAttrs 
{
    my ($self, $secret, $op, %flags) = @_;

    my $dict = $self->{Dict};

    # Pack the attributes
    my ($attstr, $name, $value, $vlen, $aname, $anum, $atype, $avendor, $dflags, $attr);

    foreach (@{$self->{Attributes}})
    {
	($name, $value) = @$_;

	# Unknown-nn-mm are received attributes that have no entry in
	# our dictionary. Vendor and number are stored in the name.
	if ($name =~ /^Unknown-(\d+)-(\d+)$/)
	{
	    $avendor = $1;
	    $anum = $2;
	}
	else
	{
	    ($aname, $anum, $atype, $avendor, $dflags) = $dict->attrByName($name);
	    &main::log($main::LOG_WARNING, "No such attribute $name", $self), next
		unless defined $aname;
	}

	# Translate integers and pack them
	# Only call packers that actually change something
	$value = &{$packer{$atype}}($value, $name, $dict) 
	    if exists $packer{$atype};


	# Do any encryption required
	# REVISIT: Remove these explicit tesets when everybody has dictionaries with
	# encryption flags
	if ($name eq 'Tunnel-Password' && !$flags{ClearTextTunnelPassword})
	{
	    # Encode a Tunnel-Password according to
	    # http://ftp.ietf.org/internet-drafts/draft-ietf-radius-tunnel-auth-06.txt
	    # or ftp://ftp.isi.edu/in-notes/rfc2868.txt
	    if ($value =~ /^(\d+):(.*)/)
	    {
		# Explicit tag syntax
		$value = pack('Ca*', $1, &encode_salted($2, $secret, 
							 $op->authenticator));
	    }
	    else
	    {
		# Implicit tag of 0
		$value = pack('Ca*', 0, &encode_salted($value, $secret, 
							$op->authenticator));
	    }
	}
	elsif ($name eq 'MS-CHAP-MPPE-Keys')
	{
	    $value = $op->encode_password($value, $secret);
	}
	elsif (exists $ascended{$name})
	{
	    $value = &encode_ascend_secret($value, $secret, $op->authenticator);
	}
	elsif (exists $salted{$name})
	{
	    $value = &encode_salted($value, $secret, $op->authenticator);
	}
	# Unisphere Jupiter ERX attributes get special type of encryption,
	# described to us by Siemens. This should really be done as a special
	# type of dictionary item in the packer and unpacker, but the secret
	# is not available there.
	elsif (exists $salted_integer{$name})
	{
	    # integer
	    $value = &encode_salted(pack('N', $value), $secret, $op->authenticator);
	}
	elsif (exists $salted_ipaddr{$name})
	{
	    # ipaddr
	    my $a = (length($value) == 4) ? $value : Socket::inet_aton($value);
	    $value  = &encode_salted($a, $secret, $op->authenticator);
	}
	elsif (exists $salted_long{$name})
        {
            # binary
            $value = &encode_salted(&Radius::BigInt::pack64u($value), $secret, $op->authenticator);
        }
	else
	{
	    # Look for dictionary flags based encryption:
	    if (defined $dflags)
	    {
		# See if there is a tag required and get it if present
		# Tag defaults to 0 if no explicit tag
		my $tag = 0;
		my $has_tag;
		if ($dflags =~/has_tag/)
		{
		    $has_tag++;
		    $tag = $1, $value=$2 if ($value =~ /^(\d+):(.*)/);
	        }

		# Maybe  encrypt
		$value = &{$encoders{$1}}($value, $secret, $op->authenticator)
		    if ($dflags =~ /encrypt=(\d)/
			&& exists $encoders{$1});

		# Maybe prepend the tag
		$value = pack('Ca*', $tag, $value)
		    if ($has_tag);
	    }
	}


	$vlen = length($value) + 0; # +0 works around a problem in some versions of perl 5.12.1 where $vlen is not changed
	# Some attributes can be ignored
#	&main::log($main::LOG_WARNING, "Empty string attribute $name will be ignored", $self),next
#	    unless defined $value;
	if ($avendor)
	{
	    # This is a vendor attr, pack it in a Vendor-Specific
	    if ($avendor == 429)
	    {
		# USR / 3COM vendor-specific is a special 
		# format
		$attr = pack 'C C N n n a*', 
                              26, $vlen + 10, $avendor, 0, $anum, $value;
		
	    }
	    elsif (   $avendor == 2637 
		   && $anum >= 0x84000000
		   && $anum <= 0x85FFFFFF)
	    {
		# Sigh, Nortel/Aptis CVX has VSAs with
		# 4-byte attribute numbers
		$attr = pack 'C C N N C a*', 
		              26, $vlen + 11, $avendor, $anum, $vlen + 5, $value;
	    }
	    elsif ($avendor == 4846 || $avendor == 637)
	    {
		# Silly Ascend/Lucent TAOS VSA format or Alcatel ESAM, 
		# 16 bit VS attribute num
		$attr = pack 'C C N n C a*', 
		              26, $vlen + 9, $avendor, $anum, $vlen + 3, $value;
	    }
	    elsif ($avendor == 24757)
	    {
		# WiMAX have special format, including continuations
		$attr = '';
		while (length($value))
		{
		    my $frag = substr($value, 0, 246, '');
		    my $fraglen = length($frag);
		    my $continuation = length($value) ? 0x80 : 0;
		    $attr .= pack('C C N C C C a*',
				  26, $fraglen + 9, $avendor, $anum, $fraglen + 3,
				  $continuation, $frag);
		}
	    }
	    elsif ($avendor == 25622 && $anum == 132)
	    {
		# UKERNA SAML-AAA-Assertion
		# Split into multiple attrs
		$attr = '';
		while (length($value))
		{
		    my $frag = substr($value, 0, 246, '');
		    my $fraglen = length($frag);
		    $attr .= pack 'C C N C C a*', 
		    26, $fraglen + 8, $avendor, $anum, $fraglen + 2, $frag;
		}
	    }
	    elsif ($avendor == 8164)
	    {
		my ($name, $number, $extras) = $dict->vendorByNum($avendor);
		if ($extras eq 'format=2,2')
		{
		    # Silly Starent VSA format, 16 bit VS attribute/length
		    $attr = pack 'C C N n n a*',
		    26, $vlen + 10, $avendor, $anum, $vlen + 4, $value;
		}
		else
		{
		    $attr = pack 'C C N C C a*', 
		    26, $vlen + 8, $avendor, $anum, $vlen + 2, $value;
		}
	    }
	    else
	    {
		# Other vendor-specific
		$attr = pack 'C C N C C a*', 
		             26, $vlen + 8, $avendor, $anum, $vlen + 2, $value;
	    }
	}
	else
	{
	    # Dont do anything with native attributes with attribute
	    # numbers greater than 255, since they are prob
	    # pseudo-attributes that cant be translated to the wire
	    &main::log($main::LOG_WARNING, "Invalid reply item $name ignored", $self),next
		if $anum > 255;
	    $attr = pack 'C C a*', $anum, $vlen + 2, $value;


	    # If there is a Message-Authenticator, remember the offset 
	    # to it so we can compute its correct value after the
	    # entire packet is assembled
	    $self->{EAPMessageAuthenticator} = length($attstr) + 20 
		if $anum == $Radius::Radius::MESSAGE_AUTHENTICATOR;
	}

	$attstr .= $attr; # Append the packed and encoded attribute
    }

    # Prepend the header and return the complete binary packet
    return pack 'C C n a16 a*', 
        $codes{$self->code}, $self->identifier,
        length($attstr) + 20, $self->authenticator,
        $attstr;
}

#####################################################################
# For testing packers, should not need to use this in production code.
sub packRadiusAttr
{
    my ($atype, $value, $name, $dict) = @_;

    $value = &{$packer{$atype}}($value, $name, $dict) 
	if exists $packer{$atype};
    return $value;
}

sub unpackRadiusAttr
{
    my ($atype, $value, $vtype, $aname, $dict) = @_;

    $value = &{$unpacker{$atype}}($value, $vtype, $aname, $dict)
	if exists $unpacker{$atype};
    return $value;
}


#####################################################################
sub unpackRadiusAttrs 
{
    my ($self, $data) = @_;
    my $dict = $self->{Dict};

    # Decode the header
    my ($code, $id, $len, $auth) = unpack 'C C n a16', $data;
    my $attrdat = substr($data, 20);
    my $offset = 20; # Where we are up to in decoding

    # Generate a skeleton data structure to be filled in
    $self->set_code($rcodes{$code});
    $self->set_identifier($id);
    $self->set_authenticator($auth);
    
    my ($type, $length, $value, $vendor, $dummy, $is_unknown,
	$aname, $anum, $atype, $avendor, $subvendor, $breezeid);
    # Unpack the attributes up to the end of the data or the end of the claimed length,
    my $wimaxbuf = '';
    while ($offset < $len && length $attrdat) 
    {
	($type, $length) = unpack 'C C', $attrdat;
	$vendor = undef;
        $subvendor = 0;
	
	# Look for bogus or malformed packets according to RFC2138
	if ($length < 2)
	{
	    # Gasp a malformed packet, bomb out now, lest we stay forever
	    &main::log($main::LOG_WARNING, "Malformed request packet: Attribute $type with length $length: ignored", $self);
	    return;
	}
	if ($type == 26)
	{
	    if ($length < 7)
	    {
		# Broken vendor specific attribute, skip it
		&main::log($main::LOG_WARNING, "Malformed Vendor Specific Attribute with length $length: ignored", $self);
		return;
	    }
	    
	    # Its a vendor specific, length is OK, decode it
	    my ($vlength, $vtype);
	    ($vendor, $type, $vlength) = unpack 'x x N C C', $attrdat;
	    
	    if ($vendor == 429)
	    {
		# USR / 3COM vendor-specific is a special 
		# format. We dont know what the dummy short is for yet
		if ($length < 10)
		{
		    # Gasp a malformed packet, bomb out now, lest we stay forever
		    &main::log($main::LOG_WARNING, "Malformed USR / 3COM  VSA attribute: length $length too small.", $self);
		    return;
		}
		($dummy, $type, $value) 
		    = unpack "x x x x x x n n a${\($length-10)}", 
		    $attrdat;
	    }
	    elsif ($vendor == 2637 
		   && $type >= 0x84 
		   && $type <= 0x85)
	    {
		# Sigh, Nortel/Aptis CVX supports VSAs with
		# 4-byte attribute numbers, so unpack again
		# with 4 byte attribute number
		# REVISIT?: looks like there can be multiple
		# sub-attrs within one VSA.
		if ($length < 11)
		{
		    # Gasp a malformed packet, bomb out now, lest we stay forever
		    &main::log($main::LOG_WARNING, "Malformed Nortel/Aptis CVX VSA attribute: length $length too small.", $self);
		    return;
		}
		($type, $vlength, $value) 
		    = unpack "x x x x x x N C a${\($length-11)}", 
		    $attrdat;
	    }	
	    elsif ($vendor == 4846 || $vendor == 637)
	    {
		# Silly Ascend/Lucent TAOS VSA format or Alcatel ESAM, 
		# 16 bit VS attribute num
		if ($length < 9)
		{
		    # Gasp a malformed packet, bomb out now, lest we stay forever
		    &main::log($main::LOG_WARNING, "Malformed Ascend/Lucent TAOS VSA attribute: length $length too small.", $self);
		    return;
		}
		($type, $vlength, $value) 
		    = unpack "x x x x x x n C a${\($length-9)}", 
		    $attrdat;
	    }
	    elsif ($vendor == 8164)
	    {
		my ($name, $number, $extras) = $dict->vendorByNum($vendor);
		if (($length < 10 && $extras eq 'format=2,2') ||
		     $length < 8)
		{
		    # Gasp a malformed packet, bomb out now, lest we stay forever
		    &main::log($main::LOG_WARNING, "Malformed Starent VSA attribute: length $length too small.", $self);
		    return;
		}
		if ($extras eq 'format=2,2')
		{
		    # Silly Starent VSA format, 16 bit VS attribute/length
		    ($type, $vlength, $value)
			= unpack "x x x x x x n n a${\($length-10)}",
			$attrdat;
		}
		else
		{
		    ($type, $vlength, $value)
			= unpack "x x x x x x C C a${\($length-8)}",
			$attrdat;
		}
	    }	
	    elsif ($vendor == 24757)
	    {
		# WiMAX have special format, including continuations
		if ($length < 9)
		{
		    # Gasp a malformed packet, bomb out now, lest we stay forever
		    &main::log($main::LOG_WARNING, "Malformed WiMAX VSA attribute: length $length too small.", $self);
		    return;
		}
		my ($continuation, $wimaxdata) = unpack("x8 C a${\($length-9)}", 
							$attrdat);
		$wimaxbuf .= $wimaxdata;
		if ($continuation & 0x80)
		{
		    # Remove the attribute we just parsed and get the next frag
		    $attrdat = substr($attrdat, $length);
		    $offset += $length;
		    next;
		}
		$value = $wimaxbuf; # Last frag, use all the frags
		$wimaxbuf = ''; # Clear it for next time
	    }
	    else
	    {
		# Other vendor-specific
		# first strip of vendor header:
		my $vattrdat = substr($attrdat, 6, $length-6);
		while (length $vattrdat)
		{
		    ($vtype, $vlength) = unpack 'C C', $vattrdat;
		    if ($vendor == 710)
		    {
			# Stupid Breezenet/Breezecom/Alvarion
			# These NASs send Ethernet port data in VSAs (up to 11 per accounting request)
			# but unfortunately dont use
			# the same attribute numbers each time. Instead, the attribute number increments
			# each time, then wraps at 256. Radiator automatically maps the fist one
			# to Breezecom-Attr1, the second to Breezecom-Attr2 etc.
			$vtype = $breezeid++ + 1;
			
			# Sigh. Some early Breezecom have broken VSA's: 
			# The vendor length part
			# is brokenly fixed at 2. Repair by using the
			# adjusted total VSA length
			$vlength = length $vattrdat
			    if $vlength == 2;
			
		    }
		    if ($vlength < 2)
		    {
			# Gasp a malformed packet, bomb out now, lest we stay forever
			&main::log($main::LOG_WARNING, "Malformed request packet: Vendor $vendor Attribute $vtype with length $vlength: ignored", $self);
			return;
		    }
		    ($aname, $anum, $atype, $avendor, undef, $is_unknown) = $dict->attrOrUnknownByNum($vtype, $vendor);
		    $value = substr($vattrdat, 2, $vlength - 2);
		    if (defined $atype)
		    {
			$value =~ s/\0+$// if $atype eq 'string';
			$self->add_attr($aname, $value);
		    }
		    $vattrdat = substr($vattrdat, $vlength);
		    $subvendor++;
		}
	    }
	}
	else
	{
	    $value = substr($attrdat, 2, $length - 2);
	    # We remember if/where there is a MessageAuthenticator
	    # attribute because EAP processing needs to 
	    # muck around with it when verifying it.
	    $self->{EAPMessageAuthenticator} = $offset 
		if $type == $Radius::Radius::MESSAGE_AUTHENTICATOR;
	}
	if (! $subvendor)
	{
	    ($aname, $anum, $atype, $avendor, undef, $is_unknown) = $dict->attrOrUnknownByNum($type, $vendor);
	    if (defined $atype)
	    {
		$value =~ s/\0+$// if $atype eq 'string';
		$self->add_attr($aname, $value);
	    }
	}

	# Log each unknown attribute only once per sender. 
	if (   $is_unknown
	    && !$main::unknown_attr_counts{$aname}{$self->{RecvFromAddress}}++)
	{
	    my ($vendor, $number) = ($aname =~ /^Unknown-(\d+)-(\d+)$/);
	    my $msg = '';
	    $msg = " (vendor $vendor)" if $vendor;
	    main::log($main::LOG_WARNING, "Attribute number $number$msg from " .
		      Radius::Util::inet_ntop($self->{RecvFromAddress}) . ":".
		      $self->{RecvFromPort} . " is not defined in your dictionary", $self);
	}

	# Count the unknown attributes the request or reply has for later use
	$self->{UnknownAttributeCount} += $is_unknown;

	# Remove the attribute we just parsed
	$attrdat = substr($attrdat, $length);
	$offset += $length;
    }
    $self->{OriginalUserName} = $self->getUserName();
}

#####################################################################
# Pack up the attributes into a packed diameter attribute data stream
sub packDiameterAttrs
{
    my $self = shift;
    my $dict = $self->{Dict};

    # Pack the attributes
    my ($attstr, $r, $name, $value, $aname, $anum, $atype, $avendor,
	$attr, $length, $paddatalen);

    foreach $r (@{$self->{Attributes}})
    {
	($name, $value) = @$r;

	($aname, $anum, $atype, $avendor) = $dict->attrByName($name);
	&main::log($main::LOG_WARNING, "No such attribute $name", $self),next
	    unless defined $aname;
	# Dont do anything with native attributes with attribute
	# numbers greater than 255, since they are prob
	# pseudo-attributes that cant be translated to the wire
	&main::log($main::LOG_WARNING, "Invalid reply item $name ignored", $self),next
	    if $anum > 255;

	$value = &{$packer{$atype}}($value, $name, $dict)
	    if exists $packer{$atype};
	# Pad to a 4 byte boundary
	$length = length($value);
	$paddatalen = ($length + 3) & 0xfffffffc;
	if ($avendor)
	{
	    # Pack it up including the vendor number
	    $length += 12;
	    $length |= 0x80000000; # V flag, vendor number is present
	    $attr = pack "N N N a$paddatalen", $anum, $length, $avendor, $value;
	}
	else
	{
	    # Pack it up without the vendor number
	    $length += 8;
	    $attr = pack "N N a$paddatalen", $anum, $length, $value;
	}

	# If there is a Message-Authenticator, remember the offset 
	# to it so we can compute its correct value after the
	# entire packet is assembled
	$self->{EAPMessageAuthenticator} = length($attstr) + 20 
	    if $anum == $Radius::Radius::MESSAGE_AUTHENTICATOR
		&& $avendor == 0;
	$attstr .= $attr; # Append the whole attribute
    }

    return $attstr;
}

#####################################################################
# Unpack some Diameter attributes as per draft-ietf-pppext-eap-ttls-01.txt
sub unpackDiameterAttrs
{
    my ($self, $attrdat) = @_;
    my $dict = $self->{Dict};

    my $offset = 0; # Where we are up to in decoding
    my ($type, $length, $flags, $value, $vendor, $datalen, $aname, $anum, $atype, $avendor);
    # Unpack the attributes
    while (length $attrdat) 
    {
	($type, $length) = unpack 'N N', $attrdat;
	$flags = $length >> 24; # Flags in the top byte of length
	$length &= 0xffffff;

	if ($flags & 0x80)
	{
	    # V flag set, there is a vendor ID
	    $datalen = $length - 12;
	    ($vendor, $value) = unpack "x8 N a$datalen", $attrdat;
	}
	else
	{
	    $datalen = $length - 8;
	    $vendor = 0;
	    $value = unpack "x8 a$datalen", $attrdat;
	}
	# Look for bogus or malformed packets.
	if ($length < 4)
	{
	    # Gasp a malformed packet, bomb out now, lest we stay forever
	    &main::log($main::LOG_WARNING, "Malformed Diameter attribute: type $type with length $length: ignored", $self);
	    return;
	}

	# We remember if/where there is a MessageAuthenticator
	# attribute because EAP processing needs to 
	# muck around with it when verifying it.
	$self->{EAPMessageAuthenticator} = $offset 
	    if $type == $Radius::Radius::MESSAGE_AUTHENTICATOR && $vendor == 0;

	($aname, $anum, $atype, $avendor) = $dict->attrByNum($type, $vendor);
	if (! defined($atype) && $flags & 0x40)
	{
	    &main::log($main::LOG_WARNING, "Mandatory Diameter attribute not in dictionary: Attribute $type with length $length: request ignored", $self);
	    return;
	}
	$value = &{$unpacker{$atype}}($value, $type, $aname, $dict)
	    if exists $unpacker{$atype};
	$self->add_attr($aname, $value)
	    if defined $atype;

	# Remove the attribute we just parsed. 
	# Note the length does not agree with the
	# TTLS spec length is padded to a 4 octet boundary
	$length += 3;
	$length &= 0xfffffffc;
	$attrdat = substr($attrdat, $length);
	$offset += $length;
    }

}

#####################################################################
# If $p is defined it is the original packet that this is a reply to
sub assemble_packet
{
    my ($self, $secret, $p, %flags) = @_;

    my $code = $self->code; # speedup
    $self->set_authenticator("\000" x 16)
	if $code eq 'Accounting-Request' 
	|| $code eq 'Disconnect-Request'
	|| $code eq 'Change-Filter-Request';
    my $rec = $self->packRadiusAttrs($secret, $p, %flags);
    $self->{Packet} = $rec;

    # May need to handle an EAP Message-Authenticator
    # If $p is set, it is the original request
    # that this is a reply to. If the reply also has a 
    # Message-Authenticator, then need to recompute its correct
    # value. The current value should be the Radius Authenticator
    # of the original request, which is required to compute
    # the Message-Authenticator in the reply
    if ($self->{EAPMessageAuthenticator})
    {
	# Need to compute the correct EAP Message-Authenticator
	# in this reply. See RFC 2869
	# If this is a reply to an AccessREquest, then need to
	# Copy ythe Radius Authenticator into this packet in order
	# to compute the Message-Authenticator
	substr($rec, 4, 16) = $p->authenticator
	    if $p && $p->code eq 'Access-Request';

	# Clear the current Message-Authenticator
	substr($rec, $self->{EAPMessageAuthenticator} + 2, 
	       16) = "\000" x 16;
	# so now we we just need to hash the entire packet
	substr($self->{Packet}, $self->{EAPMessageAuthenticator} + 2, 
	       16) = &Radius::Util::hmac_md5($secret, $rec);
    }

    # Construct the Radius authenticator for the whole packet
    # For certain types of packet
    if ($authenticator_codes{$code}) 
    {
	$self->set_authenticator(Digest::MD5::md5($self->{Packet} . $secret));
	substr($self->{Packet}, 4, 16) = $self->authenticator;
    }

    return $self->{Packet};
}


#####################################################################
# Returns the authenticator that was sent with the packet
sub sent_authenticator
{
    my ($self) = @_;

    &main::log($main::LOG_ERR, "sent_authenticator called without sent packet data", $self)
	unless defined $self->{Packet};
    return substr($self->{Packet}, 4, 16);
}

#####################################################################
# Checks that the authenticator in this packet agrees with what it
# should be
sub check_authenticator
{
    my ($self, $secret, $orig_authenticator, $require_message_authenticator) = @_;

    # Get the original received packet
    my $data = $self->{RecData};
    if (length($data) < 20)
    {
	&main::log($main::LOG_WARNING, "Malformed request", $self);
	return;
    }
    my $code = $self->code; # Speedup
    if (   $code eq 'Accounting-Request' 
	|| $code eq 'Disconnect-Request'
	|| $code eq 'Change-Filter-Request')
    {
	substr($data, 4, 16) = "\000" x 16;
	# Check the RADIUS authenticator
	return unless $self->authenticator 
	    eq Digest::MD5::md5($data . $secret);
    }
    elsif ($authenticator_codes{$code})
    {
	# We temp change the authenticator to the one we sent so we can
	# recalculate what the sender should have sent us
	substr($data, 4, 16) = $orig_authenticator;
	# Check the RADIUS authenticator
	return unless $self->authenticator 
	    eq Digest::MD5::md5($data . $secret);
    }
    # Else No authenticator to check
    # REVISIT: is this really true for Status-Server?

    # Also check EAP Message-Authenticator, if present
    if ($self->{EAPMessageAuthenticator})
    {
	# Here we zero the original MessageAuthenticator
	# Attribute in order to check it. Radius::unpack sets
	# EAPMessageAuthenticator to the offset of the
	# start of the attribute
	my $sig = substr($data, $self->{EAPMessageAuthenticator} + 2, 16);
	substr($data, $self->{EAPMessageAuthenticator} + 2, 16) 
	    = "\000" x 16;
	if (&Radius::Util::hmac_md5($secret, $data) ne $sig)
	{
	    &main::log($main::LOG_WARNING, "Bad EAP Message-Authenticator", $self);
	    return;
	}
    }
    elsif ($require_message_authenticator)
    {
	&main::log($main::LOG_WARNING, "Message-Authenticator required but not present", $self);
	return;
    }
    return 1;
}

#####################################################################
# Override format in AttrVal, to provide slightly cleverer
# formatting that quotes strings
# Format the list in a pretty way and return it
sub format
{
    my ($self) = @_;

    my ($ret, $r, @attr);
    foreach $r (@{$self->{Attributes}})
    {
	next if grep {$_ eq $r->[0]} @{$main::config->{PacketDumpOmitAttributes}};
	@attr = $self->{Dict}->attrByName($r->[0]);
	if ($attr[2] eq 'string')
	{
	    $ret .= "\t$r->[0] = \"" . Radius::AttrVal::pclean($r->[1]) . "\"\n";
	}
	else
	{
	    $ret .= "\t$r->[0] = " . Radius::AttrVal::pclean($r->[1]) . "\n";
	}
    }
    return $ret;
}

# Variables for Ascend filter binaries
my $RAD_FILTER_GENERIC = 0;
my $RAD_FILTER_IP = 1;
my $RAD_FILTER_IPX = 2;

my $RAD_NO_COMPARE = 0;
my $RAD_COMPARE_LESS = 1;
my $RAD_COMPARE_EQUAL = 2;
my $RAD_COMPARE_GREATER = 3;
my $RAD_COMPARE_NOT_EQUAL = 4;
my %ascendPortComparisons = 
    (
     '<',  $RAD_COMPARE_LESS,
     '=',  $RAD_COMPARE_EQUAL,
     '>',  $RAD_COMPARE_GREATER,
     '!=', $RAD_COMPARE_NOT_EQUAL,
     );
my %ascendPortComparisonsR = 
    (
     $RAD_COMPARE_LESS,      '<',  
     $RAD_COMPARE_EQUAL,     '=',  
     $RAD_COMPARE_GREATER,   '>',  
     $RAD_COMPARE_NOT_EQUAL, '!=', 
     );

my %ascendServiceNameToNumber =
    (
     'ftp-data', 20,
     'ftp', 21,
     'telnet', 23,
     'smtp', 25,
     'nameserver', 42,
     'domain', 53,
     'tftp', 69,
     'gopher', 70,
     'finger', 79,
     'www', 80,
     'kerberos', 88,
     'hostname', 101,
     'nntp', 119,
     'ntp', 123,
     'exec', 512,
     'login', 513,
     'cmd', 514,
     'talk', 517,
     );

my %ascendServiceNumberToName =
    (
     20, 'ftp-data',
     21, 'ftp', 
     23, 'telnet', 
     25, 'smtp', 
     42, 'nameserver', 
     53, 'domain', 
     69, 'tftp', 
     70, 'gopher', 
     79, 'finger', 
     80, 'www', 
     88, 'kerberos', 
     101, 'hostname', 
     119, 'nntp', 
     123, 'ntp', 
     512, 'exec', 
     513, 'login', 
     514, 'cmd', 
     517,'talk', 
     );

my %ascendProtoNameToNumber =
    (
     'ip',   0,
     'icmp', 1,
     'ggp',  3,
     'tcp',  6,
     'egp',  8,
     'pup', 12,
     'udp', 17,
     'hmp', 20,
     'xns-idp', 22,
     'rdp', 27,
     );

my %ascendProtoNumberToName =
    (
     0,  'ip',
     1,  'icmp',
     3,  'ggp',
     6,  'tcp',
     8,  'egp',
     12, 'pup',
     17, 'udp',
     20, 'hmp',
     22, 'xns-idp',
     27, 'rdp',
     );

my %ascendFilterTypes =
    (
     $RAD_FILTER_GENERIC, 'generic',
     $RAD_FILTER_IP,      'ip',
     $RAD_FILTER_IPX,     'ipx',
     );


#####################################################################
# pack an string into ascend binary filter format
# The following syntaxes are supported:
# ip dir action [dstip n.n.n.n/nn] [srcip n.n.n.n/nn]
#     [proto [dstport cmp value] [srcport cmd value] [est]
# generic dir action offset mask value [== | != ] [more]
# ipx dir action [srcipxnet nnnn srcipxnode mmmmm [srcipxsoc cmd value]]
#     [dstipxnet nnnn dstipxnode mmmmm [dstipxsoc cmd value]]
# As at Jul 2001, the only offical refernce for this stuff is
# http://support.baynetworks.com/library/tpubs/pdf/remote/bsac22/BSAC22RN.PDF
# although cistron understands the IPX extensions
sub packAbinary
{
    my ($value, $name, $dict) = @_;

    no warnings "uninitialized";

    if ($value =~ /^ip\s+(IN|OUT)\s+(FORWARD|DROP)
	(\s+dstip\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\/(\d{1,2}))?)?
	(\s+srcip\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\/(\d{1,2}))?)?
	(\s+(\S+)(\s+dstport\s*(>|=|<|!=)\s*(\S+))?
	 (\s+srcport\s*(>|=|<|!=)\s*(\S+))?
	 (\s+(est))?)?$/ix)
    {
	# Its an IP filter

	my $direction = $1;
	my $forward = $2;
	my $srcip = pack 'C C C C', split(/\./, $8);
	my $srcmask = $10;
	$srcmask = 32 if $srcmask eq '' && $8;
	my $dstip = pack 'C C C C', split(/\./, $4);
	my $dstmask = $6;
	$dstmask = 32 if $dstmask eq '' && $4;
	my $proto = $ascendProtoNameToNumber{$12};
	$proto = $12 unless $proto;
	my $established = $20;
        my $dstport = $ascendServiceNameToNumber{$15};
	$dstport = $15 unless $dstport;
        my $srcport = $ascendServiceNameToNumber{$18};
	$srcport = $18 unless $srcport;
	my $dstportcomp = $ascendPortComparisons{$14};
	my $srcportcomp = $ascendPortComparisons{$17};

	return pack 'C C C C a4 a4 C C C C n n C C x x',
	$RAD_FILTER_IP,      # type
	$forward =~ /^f/i ? 1 : 0,   # forward
	$direction =~ /^i/i ? 1 : 0, # indirection
	0,                   # fill
	# Start of the union
	$srcip,
	$dstip,
	$srcmask,
	$dstmask,
	$proto,
	defined $established,
	$srcport,
	$dstport,
	$srcportcomp,
	$dstportcomp,
	0,
	0,
	;
    }
# generic dir action offset mask value [== | != ] [more]
    elsif ($value =~ /^generic\s+(IN|OUT)\s+(FORWARD|DROP)
	   \s+(\d+)
	   \s+([0-9a-f]+)
	   \s+([0-9a-f]+)
	   \s*(==|!=)?
	   (\s*more)?
	   /ix)
    {
	# Its a generic filter

	my $direction = $1;
	my $forward = $2;
	my $offset = $3;
	my $mask = $4;
	my $mvalue = $5;
	my $comparison = $6;
	my $more = $7;
	&main::log($main::LOG_WARNING, "Mask and value are not the same length in $name: $value")
	    if length $mask != length $mvalue;
	&main::log($main::LOG_WARNING, "Mask is too long in $name: $value")
	    if length $mask > 6;
	
	return pack 'C C C C n n n a6 a6 C x',
	$RAD_FILTER_GENERIC, # type
	$forward =~ /^f/i ? 1 : 0,   # forward
	$direction =~ /^i/i ? 1 : 0, # indirection
	0,                   # fill
	# Start of the union
	$offset,
	length $mask,
	defined $more,
	$mask,
	$mvalue,
	$comparison eq '!=',
	;
    }
    elsif ($value =~ /^ipx\s+(IN|OUT)\s+(FORWARD|DROP)
	   (\s+srcipxnet\s+(\d+)\s+srcipxnode\s+(0x)?([0-9a-f]{12})
	    (\s+srcipxsoc\s*(>|=|<|!=)\s*([0-9a-f]+))?)?
	   (\s+dstipxnet\s+(\d+)\s+dstipxnode\s+(0x)?([0-9a-f]{12})
	    (\s+dstipxsoc\s*(>|=|<|!=)\s*([0-9a-f]+))?)?
	   /ix)
    {
	# Its an IPX filter

	my $direction = $1;
	my $forward = $2;
	my $srcIpxNet = $4;
	my $srcIpxNode = $6;
	my $srcIpxSoc = $9;
	my $srcSocComp = $ascendPortComparisons{$8};
	my $dstIpxNet = $11;
	my $dstIpxNode = $13;
	my $dstIpxSoc = $16;
	my $dstSocComp = $ascendPortComparisons{$15};

	return pack 'C C C C N H12 H4 N H12 H4 C C',
	$RAD_FILTER_IPX,      # type
	$forward =~ /^f/i ? 1 : 0,   # forward
	$direction =~ /^i/i ? 1 : 0, # indirection
	0,                   # fill
	# Start of the union
	$srcIpxNet,
	$srcIpxNode,
	$srcIpxSoc,
	$dstIpxNet,
	$dstIpxNode,
	$dstIpxSoc,
	$srcSocComp,
	$dstSocComp,
	;
    }
    else
    {
	&main::log($main::LOG_WARNING, "Could not parse $name: $value");
    }
}

#####################################################################
# unpack ascend binary filter format into a string
sub unpackAbinary
{
    my ($value, $type, $name, $dict) = @_;
    my $ret;

    my ($ftype, $forward, $input, $fill) = unpack 'C C C C', $value;

    $ret = $ascendFilterTypes{$ftype};
    $ret .= $input ? ' in' : ' out';
    $ret .= $forward ? ' forward' : ' drop';

    if ($ftype == $RAD_FILTER_GENERIC)
    {
	my ($dummy, $offset, $len, $more, $mask, $mvalue, $compNeq)
	    = unpack 'N n n n a6 a6 C', $value;
	# Mask and value might be null padded
	$mask =~ s/\000//g;
	$mvalue =~ s/\000//g;
	$ret .= " $offset $mask $mvalue";
	$ret .= $compNeq ? " !=" : " ==";
	$ret .= " more" if $more;
    }
    elsif ($ftype == $RAD_FILTER_IP)
    {
	my ($dummy, $srcip, $dstip, $srcmask, $dstmask, $proto, $established,
	    $srcport, $dstport, $srcportcomp, $dstportcomp) =
		unpack 'N a4 a4 C C C C n n C C C', $value;
	if ($dstip ne "\000\000\000\000")
	{
	    $ret .= ' dstip ';
	    $ret .= join('.', unpack 'C C C C', $dstip);
	    $ret .= "/$dstmask" if $dstmask;
	}
	if ($srcip ne "\000\000\000\000")
	{
	    $ret .= ' srcip ';
	    $ret .= join('.', unpack 'C C C C', $srcip);
	    $ret .= "/$srcmask" if $srcmask;
	}
	if ($proto)
	{
	    my $pname = $ascendProtoNumberToName{$proto};
	    $ret .= ' ';
	    $ret .= $pname ? $pname : $proto;
	}
	if ($dstport)
	{
	    $ret .= " dstport $ascendPortComparisonsR{$dstportcomp} $dstport";
	}
	if ($srcport)
	{
	    $ret .= " srcport $ascendPortComparisonsR{$srcportcomp} $srcport";
	}
	$ret .= " est" if $established;
    }
    elsif ($ftype == $RAD_FILTER_IPX)
    {
	my ($dummy, $srcIpxNet, $srcIpxNode, $srcIpxSoc, 
	    $dstIpxNet, $dstIpxNode, $dstIpxSoc,
	    $srcSocComp, $dstSocComp) 
	    = unpack 'N N H12 H4 N H12 H4 C C', $value;
	if ($srcIpxNet)
	{
	    $ret .= " srcipxnet $srcIpxNet srcipxnode 0x$srcIpxNode";
	    $ret .= " srcipxsoc $ascendPortComparisonsR{$srcSocComp} $srcIpxSoc";
	}
	if ($dstIpxNet)
	{
	    $ret .= " dstipxnet $dstIpxNet dstipxnode 0x$dstIpxNode";
	    $ret .= " dstipxsoc $ascendPortComparisonsR{$dstSocComp} $dstIpxSoc";
	}
    }
    else
    {
	&main::log($main::LOG_WARNING, "Unknown ascend filter type: $ftype");
    }
    return $ret;
}

#####################################################################
# Packs a string in the form attr=value,attr=value,... into binary TLV format
sub packTLV
{
    my ($value, $name, $dict) = @_;

    $value =~ s/\s*$//; # Strip trailing white space
    my $subdict = $dict->dictForTLV($name);
    return unless $subdict;
    my $result = '';
    while ($value ne '')
    {
	$value =~ s/^[\s,]*//; # Strip leading white space & commas
	if (   $value =~ /^([^ =]+) *= *"((\\"|[^"])*)",*/g
	    || $value =~ /^([^ =]+) *= *([^,]*),*/g)
	{
	    my ($attr, $val) = ($1, $2);

	    # Find the TLV subdictionary entry for this tlv subattr name
	    # Translate integers and pack them
	    # Only call packers that actually change something
	    my ($aname, $anum, $atype, $avendor, $dflags) = $subdict->attrByName($attr);
	    $val = &{$packer{$atype}}($val, $attr, $subdict) 
		if exists $packer{$atype};
	    $result .= pack('C C a*', $anum, length($val)+2, $val);

	    # Remove the one we just processed
	    $value = substr($value, pos $value);
	}
	else
	{
	    # Silly trailing data, abort
	    last;
	}
    }
    return $result;
}

#####################################################################
sub unpackTLV
{
    my ($value, $type, $name, $dict) = @_;

    return unless defined $value;
    my ($aname, $anum, $atype, $avendor, $dflags) = $dict->attrByName($name);
    my $subdict = $dict->dictForTLV($name);
    return unless $subdict;
    my @result;
    while ($value ne '')
    {
	my ($type, $length) = unpack 'C C', $value;
	return unless defined $length;
	return if $length < 2 || $length > length($value);
	my $val = unpack("x x a${\($length-2)}", $value);
	$value = substr($value, $length);
	($aname, $anum, $atype, $avendor, $dflags) = $subdict->attrByNum($type);
	next unless defined $atype;
	$val = &{$unpacker{$atype}}($val, $atype, $aname, $subdict)
	    if exists $unpacker{$atype};

	if (defined $val)
	{
	    # Quote SUBTLVs
	    $val = '"' . $val . '"'
		if ($val =~ /=/);

	    push (@result, "$aname=$val");
	}
    }
    return join(',', @result);
}

#####################################################################
# Pack an IPv4 prefix from the form '192.168.1.0/24' to binary
sub packIpv4prefix
{
    my ($value, $name, $dict) = @_;

    if ($value =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})/ && $2 <= 32)
    {
	my ($address, $length) = ($1, $2);
	my $addr = Socket::inet_aton($address);
	return pack('x C', $length) . $addr;
    }

    # Fail
    main::log($main::LOG_WARNING, "Attribute $name: Failed to parse ipv4prefix: $value");
    return;
}

#####################################################################
# Unpack IPv4 prefix into string form '192.168.1.0/24'
sub unpackIpv4prefix
{
    my ($value, $type, $name, $dict) = @_;

    if (length($value) == 6)
    {
	my ($length, $addr) = unpack('x C a4', $value);
	if ($length <= 32)
	{
	    my $address = Socket::inet_ntoa($addr);
	    return $address . '/' . $length;
	}
    }

    # Fail
    main::log($main::LOG_WARNING, "Attribute $name: Failed to decode ipv4prefix: $value");
    return;
}

#####################################################################
sub packIpv6prefix
{
    my ($value, $name, $dict) = @_;

    my $ret;
    if ($value =~ /^([0-9a-fA-F:]+)\/(\d{1,3})/ && $2 <= 128)
    {
	my ($address, $length) = ($1, $2);
	my $colons = $address;
	$colons =~ s/[^:]//g;
	$address .= '::' unless length $colons == 7 || $address =~ /::/;
	my $addr = Radius::Util::inet_pton($address);
	return pack('x C', $length) . $addr;
    }
    else
    {
	&main::log($main::LOG_WARNING, "Failed to parse ipv6prefix: $value");
    }
    return $ret;
}

#####################################################################
# unpack ascend binary filter format into a string
sub unpackIpv6prefix
{
    my ($value, $type, $name, $dict) = @_;
    
    if (length($value) > 2)
    {
	my ($length, $addr) = unpack('x C a*', $value);
	if ($length <= 128 && length($addr) <= 16)
	{
	    $addr .= "\0" x (16 - length($addr));
	    my $address = Radius::Util::inet_ntop($addr);
	    return $address . '/' . $length;
	}
    }

    # Fail
    &main::log($main::LOG_WARNING, "Failed to decode ipv6prefix: $value");
    return;
}

#####################################################################
# Pack an IPV6 interface ID from the form 'aaaa:bbbb:cccc:dddd' to binary
# RFC 3162
sub packIfid
{
    my ($value, $name, $dict) = @_;

    my $ret;
    if ($value =~ /^([0-9a-fA-F]{4}):([0-9a-fA-F]{4}):([0-9a-fA-F]{4}):([0-9a-fA-F]{4})$/)
    {
	$ret = pack('H4 H4 H4 H4', $1, $2, $3, $4);
    }
    else
    {
	&main::log($main::LOG_WARNING, "Failed to parse ifid: $value");
    }
    return $ret;
}

#####################################################################
sub unpackIfid
{
    my ($value, $type, $name, $dict) = @_;

    my $ret;
    if (length($value) == 8)
    {
	$ret = join(':', unpack('H4 H4 H4 H4', $value));
    }
    else
    {
	&main::log($main::LOG_WARNING, "Failed to decode ifid: $value");
    }
    return $ret;
}

#####################################################################
# Get the user name from the packet, with some caching
sub getUserName
{
    my ($self) = @_;

    return $self->getAttrByNum($Radius::Radius::USER_NAME);
}

#####################################################################
# Change the cached user name, and the version in the database
sub changeUserName
{
    my ($self, $name) = @_;

    $self->{CachedAttrs}{$Radius::Radius::USER_NAME} = $name;
    $self->change_attr('User-Name', $name);
}

#####################################################################
# Get the Nas ID from the packet. 
# Radius says that it might be in NAS-IP-Address, or NAS-Identifier
sub getNasId
{
    my ($self) = @_;

    if (!exists $self->{CachedAttrs}{NasId})
    {
	$self->{CachedAttrs}{NasId} = 
	    $self->getAttrByNum($Radius::Radius::NAS_IP_ADDRESS);
	if (!defined $self->{CachedAttrs}{NasId})
	{
	    # Theres no Nas-IP-Address, so try for NAS-Identifier
	    my $nas_id = $self->getAttrByNum
		($Radius::Radius::NAS_IDENTIFIER);
	    if ($nas_id =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)
	    {
		$self->{CachedAttrs}{NasId} = $1;
	    }
	    elsif (defined($self->{RecvFrom}))
	    {
		# Could not deduce an IP address from NAS-Identifier
		# so try the IP address of the sender
		my ($port, $addr) = Radius::Util::unpack_sockaddr_in($self->{RecvFrom});
		$self->{CachedAttrs}{NasId} = Radius::Util::inet_ntop($addr);
	    }
	    else
	    {
		$self->{CachedAttrs}{NasId} = 'unknown';
	    }
	}
    }
    return $self->{CachedAttrs}{NasId};
}

#####################################################################
# Get an attribute from the packet, with some caching
# The attribute number is the "well known" radius attribute number
# One day, AttrVal will store the attribute number too, so we wont need
# these gymnastics. Only non-vendor specifics are supported
sub getAttrByNum
{
    my ($self, $num) = @_;

    unless (exists $self->{CachedAttrs}{$num})
    {
	# Get the attribute name from our dictionary
	# RDict will complain if its never heard of the attr before
	my ($name, $rest) = $self->{Dict}->attrByNum($num);
	$self->{CachedAttrs}{$num} = $self->get_attr($name);
    }
    return $self->{CachedAttrs}{$num};
}

#####################################################################
# Add a "well-known" attribute type given its attribute number
# This is slow, and should not really be necessary. One day we will fix it
sub addAttrByNum
{
    my ($self, $num, $value) = @_;

    my ($name, $rest) = $self->{Dict}->attrByNum($num);
    $self->{CachedAttrs}{$num} = $value;
    $self->add_attr($name, $value);
}

#####################################################################
# Delete a "well-known" attribute type given its attribute number
# This is slow, and should not really be necessary. One day we will fix it
sub deleteAttrByNum
{
    my ($self, $num) = @_;

    my ($name, $rest) = $self->{Dict}->attrByNum($num);
    delete $self->{CachedAttrs}{$num};
    $self->delete_attr($name);
}

#####################################################################
# Change a "well-known" attribute type given its attribute number
# This is slow, and should not really be necessary. One day we will fix it
sub changeAttrByNum
{
    my ($self, $num, $value) = @_;

    my ($name, $rest) = $self->{Dict}->attrByNum($num);
    $self->{CachedAttrs}{$num} = $value;
    $self->change_attr($name, $value);
}

#####################################################################
# Apply 0 or more RewriteUsername to the username in this request
# (if there is one). returns the rewritten name
sub rewriteUsername
{
    my ($self, $rules) = @_;

    my $name;
    if (defined($name = $self->getUserName))
    {
	my $rule;
	foreach $rule (@$rules)
	{
	    next unless length $rule;
	    # We use an eval so an error in the pattern wont kill us.
	    eval("\$name =~ $rule");
	    &main::log($main::LOG_ERR, "Error while rewriting username $name: $@", $self) 
		if $@;
	    
	    &main::log($main::LOG_DEBUG, "Rewrote user name to $name", $self);
	}
	$self->changeUserName($name);
    }
    return $name;
}

#####################################################################
# Return the decoded password. Cache it for next time.
# returns undef if thre is no password in the packet
# REVISIT: make sure all other code uses this entry point after next release
sub decodedPassword
{
    my ($self) = @_;

    return $self->{DecodedPassword} if defined $self->{DecodedPassword};

    # Have not cached it yet, so cache and return it
    return $self->{DecodedPassword} = $self->decode_password
	($self->getAttrByNum($Radius::Radius::USER_PASSWORD), 
	 $self->{Client}->{Secret},
	 $self->{Client}->{UseOldAscendPasswords});
}

#####################################################################
# Add one to each key specified in @names in each hash in StatsTrail
sub statsIncrement
{
    my ($self, @names) = @_;

    my $s;
    foreach $s (@{$self->{StatsTrail}})
    {
	map {$s->{$_}++} @names;
    }
}

#####################################################################
# Upadate a moving window average
# on each key specified in @names in each hash in StatsTrail
# Average is over 100 samples
sub statsAverage
{
    my ($self, $sample, @names) = @_;

    no warnings "uninitialized";
    my $s;
    foreach $s (@{$self->{StatsTrail}})
    {
	# http://en.wikipedia.org/wiki/Moving_average
	map {$s->{$_} += (($sample - $s->{$_}) / 100);} @names;
    }
}

#sub DESTROY
#{
#    my ($self) = @_;
#    print "packet @_ destroyed\nVVVVVVVVVVVVVVVVV\n" . $self->dump . "^^^^^^^^^^^^^^^^^\n";
#}

1;

