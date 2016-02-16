# EAP_46.pm
#
# Radiator module for  handling Authentication via EAP type 46 (PAX)
# EAP Password Authenticated Exchange
#
# based on RFC 4746
# Tested against wpa_supplicant-0.6-2006-12-05 and later
#
# Only PAX STD is currently supported
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2006 Open System Consultants
# $Id: EAP_46.pm,v 1.6 2014/11/22 01:30:09 hvn Exp $

package Radius::EAP_46;
use Digest::HMAC_SHA1;
use strict;

# RCS version number of this module
$Radius::EAP_46::VERSION = '$Revision: 1.6 $';

# OP Codes
$Radius::EAP_46::OP_STD_1 = 0x01;
$Radius::EAP_46::OP_STD_2 = 0x02;
$Radius::EAP_46::OP_STD_3 = 0x03;
$Radius::EAP_46::OP_SEC_1 = 0x11;
$Radius::EAP_46::OP_SEC_2 = 0x12;
$Radius::EAP_46::OP_SEC_3 = 0x13;
$Radius::EAP_46::OP_SEC_4 = 0x14;
$Radius::EAP_46::OP_SEC_5 = 0x15;
$Radius::EAP_46::OP_ACK   = 0x21;

# Flags values
$Radius::EAP_46::F_NONE = 0x00;
$Radius::EAP_46::F_MF   = 0x01; # More Fragments
$Radius::EAP_46::F_CE   = 0x02; # Certificate Enabled
$Radius::EAP_46::F_AI   = 0x04; # ADE Included

# MAC types
$Radius::EAP_46::MAC_HMAC_SHA1_128   = 0x01;
$Radius::EAP_46::MAC_HMAC_SHA256_128 = 0x02;

# DH Group ID types
$Radius::EAP_46::DHG_NONE = 0x00;
$Radius::EAP_46::DHG_2048 = 0x01; # 2048-bit MODP Group (IANA DH Group 14) [RFC3526]
$Radius::EAP_46::DHG_3072 = 0x02; # 3072-bit MODP Group (IANA DH Group 15) [RFC3526]
$Radius::EAP_46::DHG_NIST = 0x03; # NIST ECC Group P-256 [FIPS186]

# Public Key Cipher types
$Radius::EAP_46::PK_NONE           = 0x00;
$Radius::EAP_46::PK_RSAES_OAEP     = 0x01; # RSAES-OAEP [RFC3447]
$Radius::EAP_46::PK_RSA_PKCS1_V1_5 = 0x02; # RSA-PKCS1-V1_5 [RFC3447]
$Radius::EAP_46::PK_EL_GAMAL       = 0x03;   # El-Gamal Over NIST ECC Group P-256 [FIPS186]


#####################################################################
# Called by EAP.pm when the caller wants to know the EAP type name this class supports
sub type_name
{
    my ($classname) = @_;

    return 'PAX';
}

#####################################################################
# request
# Called by EAP.pm when a request is received for this protocol type
sub request
{
    my ($classname, $self, $context, $p) = @_;

    return $self->eap_error('Unexpected EAP request');
}

#####################################################################
# Called by EAP.pm when an EAP Response/Identity is received
sub response_identity
{
    my ($classname, $self, $context, $p) = @_;

    my $X = $context->{X} = &Radius::Util::random_string(32); # server_rand

    # Ready to go: acknowledge with a STD-1 message
    my $message = pack('C C C C C a*', 
		       $Radius::EAP_46::OP_STD_1, 
		       $Radius::EAP_46::F_NONE,
		       $Radius::EAP_46::MAC_HMAC_SHA1_128,
		       $Radius::EAP_46::DHG_NONE,
		       $Radius::EAP_46::PK_NONE,
		       &encode_payload($X) # ICV will be filled in by pax_request_icv
		       );

    &pax_request_icv($self, $p, $context, $message, '');
    $context->{last_sent_opcode} = $Radius::EAP_46::OP_STD_1;
    return ($main::CHALLENGE, 'EAP PAX Challenge STD-1');
}

#####################################################################
# Build a PAX request and ensure the ICV is calculated in the last 16 octets
sub pax_request_icv
{
    my ($self, $p, $context, $message, $key) = @_;

    # The msg_proc calculates the ICV and overwrites it in the last 16 octets
    $self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_PAX, 
		       $message . pack('x16'), # Append a dummy ICV
		       sub
		       {
			   substr($_[3], -16) = eap_pax_mac
			       ($Radius::EAP_46::MAC_HMAC_SHA1_128,
				$key,
				substr($_[3], 0, -16));
		       });
}

#####################################################################
# pack 0 or more payload items. Each is prepended with a 2 octet length count
sub encode_payload
{
    join('', map {pack('n/a*', $_)} @_);
}

#####################################################################
# unpack 0 or more payload items. Each is prepended with a 2 octet length count
# Return an array of decoded items
sub decode_payload
{
    my ($payload) = @_;

    my @payload;
    while (length($payload) >= 2)
    {
	my $item = unpack('n/a*', $payload);
	push(@payload, $item);
	substr($payload, 0, length($item) + 2) = '';
    }
    return @payload;
}

#####################################################################
# 128 bit HMAC SHA1 (ie the first 128 bits of Digest::HMAC_SHA1::hmac_sha1)
# $key and $text are binary strings
# returns a binary string
sub hmac_sha1_128
{
    my ($key, $text) = @_;
    return substr(Digest::HMAC_SHA1::hmac_sha1($text, $key), 0, 16);
}

#####################################################################
# Compute the MAC using the designated MAC type
sub eap_pax_mac
{
    my ($type, $key, $text) = @_;

    # Only know how to do HMAC_SHA1_128 for now
    return &hmac_sha1_128($key, $text) if $type == $Radius::EAP_46::MAC_HMAC_SHA1_128;
    return;
}

#####################################################################
# Called by EAP.pm when an EAP Response (other than Identity)
# is received. Handles defragmenting packets. All the fragments
# are concatenated into $context->{data}, which will end up 
# a number of messages, each precended by a 4 byte length
sub response
{
    my ($classname, $self, $context, $p, $type, $typedata) = @_;

    my ($opcode, $flags, $mac_id, $dhgroup_id, $pk_id, $payload_icv) 
	= unpack('C C C C C a*', $typedata);
    $self->log($main::LOG_DEBUG, "EAP PAX message: $opcode, $flags, $mac_id, $dhgroup_id, $pk_id");

    if ($opcode == $Radius::EAP_46::OP_STD_2)
    {
	$self->log($main::LOG_DEBUG, "EAP PAX STD-2 message");

	return $self->eap_error('EAP PAX received STD-2 in incorrect state')
	    if $context->{last_sent_opcode} != $Radius::EAP_46::OP_STD_1;

	return $self->eap_error('EAP PAX message too short')
	    if length($payload_icv) < 16 + 2 + 2 + 2;

	# Get the ICV
	my $icv = substr($payload_icv, -16);
	
	# Decode the payload (need Y from the peer to generate keys)
	my @payload = &decode_payload(substr($payload_icv, 0, -16));
	return $self->eap_error('EAP PAX incorrect payload size')
	    if @payload < 3;

	$context->{Y} = $payload[0];
	$context->{CID} = $payload[1];
	my $mac_ck = $payload[2]; # Check this later

	# Need to get the AK Authentication Key here based on the user name
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
	    return ($main::REJECT, "EAP PAX failed: no such user $identity");
	}
	$context->{user} = $user;

	# Got a user record for this user. Need the plaintext password now
	# use it as the HEX value of the AK (Authentication Key)
	$context->{ak} = pack('H*', $self->get_plaintext_password($user));

	# Initial key derivation
	key_setup($context, $mac_id, $context->{ak}, $context->{X} . $context->{Y});

	# Check the MAC_CK in the payload
	my $correct_mac_ck = eap_pax_mac($mac_id, $context->{ck}, 
					 $context->{X} . $context->{Y} . $context->{CID});
	if ($mac_ck ne $correct_mac_ck)
	{
	    $self->eap_failure($p->{rp}, $context);
	    return ($main::REJECT, "EAP PAX failed: bad MAC in STD-2. Incorrect User-Password?");
	}

	# Check the ICV
	my $correct_icv = &eap_pax_mac($mac_id, $context->{ick}, 
				       substr($context->{this_eap_message}, 0, -16));

	return $self->eap_error('EAP PAX bad ICV')
	    if $icv ne $correct_icv;

	# OK, so now we have all the keys and data we need and the STD-2 looks good,
	# so build an STD-3 in reply
	$mac_ck = eap_pax_mac($Radius::EAP_46::MAC_HMAC_SHA1_128, $context->{ck}, 
			      $context->{Y} . $context->{CID});
	my $message = pack('C C C C C a*', 
			   $Radius::EAP_46::OP_STD_3, 
			   $Radius::EAP_46::F_NONE,
			   $Radius::EAP_46::MAC_HMAC_SHA1_128,
			   $Radius::EAP_46::DHG_NONE,
			   $Radius::EAP_46::PK_NONE,
			   &encode_payload($mac_ck) # ICV will be filled in by pax_request
			   );
	&pax_request_icv($self, $p, $context, $message, $context->{ick});
	$context->{last_sent_opcode} = $Radius::EAP_46::OP_STD_3;
	return ($main::CHALLENGE, 'EAP PAX Challenge');
    }
    elsif ($opcode == $Radius::EAP_46::OP_ACK)
    {
	# ACK, the client like us!
	$self->log($main::LOG_DEBUG, 'EAP PAX ACK message');

	return $self->eap_error('EAP PAX received ACK in incorrect state')
	    if $context->{last_sent_opcode} != $Radius::EAP_46::OP_STD_3;

	$self->authoriseUser($context->{user}, $p);
	$self->adjustReply($p);
	$p->{rp}->{msk} = $context->{msk};
	my ($send, $recv) = unpack('a32 a32', $context->{msk});
	# Note these are swapped because its for the AP end of the encryption
	$p->{rp}->change_attr('MS-MPPE-Send-Key', $recv);
	$p->{rp}->change_attr('MS-MPPE-Recv-Key', $send);
	$self->eap_success($p->{rp}, $context);
	return ($main::ACCEPT); # Success, all done
    }
    else
    {
	return $self->eap_error("EAP PAX Unexpected opcode $opcode");
    }
}

#####################################################################
# Key Derivation Function as per clancy
sub eap_pax_kdf
{
    my ($mac_id, $key, $entropy, $identifier, $length) = @_;

    # Only know how to do HMAC_SHA1_128 for now
    return unless $mac_id == $Radius::EAP_46::MAC_HMAC_SHA1_128;

    my $num_blocks = int(($length + 15) / 16);
    return if $num_blocks >= 255;
    my ($counter, $result);
    for ($counter = 1; $counter <= $num_blocks; $counter++)
    {
	$result .= &hmac_sha1_128($key, $identifier . $entropy . pack('C', $counter));
    }

    return substr($result, 0, $length);
}

#####################################################################
# Compute keys based on Authenticaiton Key and exchamged entropy
sub key_setup
{
    my ($context, $mac_id, $ak, $entropy) = @_;

    $context->{mk}  = eap_pax_kdf($mac_id, $ak, $entropy, 'Master Key', 16);
    $context->{ck}  = eap_pax_kdf($mac_id, $context->{mk}, $entropy, 'Confirmation Key', 16);
    $context->{ick} = eap_pax_kdf($mac_id, $context->{mk}, $entropy, 'Integrity Check Key', 16);
    $context->{msk} = eap_pax_kdf($mac_id, $context->{mk}, $entropy, 'Master Session Key', 64);

}

1;
