# EAP_47.pm
#
# Radiator module for  handling Authentication via EAP type 47 (PSK)
# Crypt::Rijndael is used for AES encryption
# Extensions are not yet handled, nor is CONT
#
# based on RFC 4764
# Tested against wpa_supplicant-0.6-2006-12-05 and later
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2006 Open System Consultants
# $Id: EAP_47.pm,v 1.8 2014/11/22 01:30:09 hvn Exp $

package Radius::EAP_47;
use Radius::AES;
use Radius::PBKDF;
use strict;

# RCS version number of this module
$Radius::EAP_47::VERSION = '$Revision: 1.8 $';

$Radius::EAP_47::R_CONT         = 1;
$Radius::EAP_47::R_DONE_SUCCESS = 2;
$Radius::EAP_47::R_DONE_FAILURE = 3;

#####################################################################
# Called by EAP.pm when the caller wants to know the EAP type name this class supports
sub type_name
{
    my ($classname) = @_;

    return 'PSK';
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

    $context->{nonce} = 0;
    $context->{sent_r_flag} = 0;
    $context->{recv_r_flag} = 0;
    $context->{id_s} = $main::hostname;
    $context->{rand_s} = &Radius::Util::random_string(16);

    # Ready to go: acknowledge with a PSK First Message
    my $message = pack('C a16 a*', 0, $context->{rand_s}, $context->{id_s});
    $self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_PSK, $message);
    return ($main::CHALLENGE, 'EAP PSK Challenge');
}

#####################################################################
# Compute AK and KDK from users PSK
sub key_setup
{
    my ($context) = @_;

    my $cipher = new Crypt::Rijndael $context->{psk}, Crypt::Rijndael::MODE_ECB;

    my $k = $cipher->encrypt(pack('x16'));
    $context->{ak}  = $cipher->encrypt($k ^ pack('x15 C', 0x01));
    $context->{kdk} = $cipher->encrypt($k ^ pack('x15 C', 0x02));
}

#####################################################################
# Called by EAP.pm when an EAP Response (other than Identity)
# is received. Handles defragmenting packets. All the fragments
# are concatenated into $context->{data}, which will end up 
# a number of messages, each precended by a 4 byte length
sub response
{
    my ($classname, $self, $context, $p, $type, $typedata) = @_;

    my ($flags) = unpack('C', $typedata);
    my $T = ($flags >> 6) & 0x3;

    if ($T == 1)
    {
	# Received EAP-PSK Second Message
	my ($rand_s, $rand_p, $mac_p, $id_p) = unpack('x a16 a16 a16 a*', $typedata);
	$self->log($main::LOG_DEBUG, "EAP PSK Second Message from $id_p");
	$context->{id_p} = $id_p;

	# Check rand_s is the same as we sent?

	# Need to get the PSK here based on the user name
	my $identity = $id_p;
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
	    return ($main::REJECT, "EAP PSK failed: no such user $identity");
	}
	$context->{user} = $user;

	# Got a user record for this user. Need the plaintext password now
	my $password = $self->get_plaintext_password($user);
	if ($password =~ /^[0-9a-fA-F]{32}$/)
	{
	    # HEX PSK of 32 digits (16 octets)
	    $context->{psk} = pack('H*', $password);
	}
	else
	{
	    # simple password, convert to a PSK according to RFC 4764 Appendix A
	    $context->{psk} = &password_to_psk($context, $password);
	}
	$self->log($main::LOG_DEBUG, "EAP PSK user $identity has PSK of " . unpack('H*', $context->{psk}));
	&key_setup($context);

	# Now we have keys, check the MAC_P from the peer
	# If the password or PSK is wrong, it wil show up here
	my $correct_mac_p = &Radius::AES::omac1_aes_128
	    ($context->{ak}, 
	     $id_p . $context->{id_s} . $context->{rand_s} . $rand_p);
	if ($correct_mac_p ne $mac_p)
	{
	    $self->eap_failure($p->{rp}, $context);
	    return ($main::REJECT, "EAP PSK failed: bad MAC_P from peer. Incorrect User-Password?)");
	}

	# Receipt of Second message was good, Construct EAP-PSK Third Message
	my $mac_s = &Radius::AES::omac1_aes_128($context->{ak}, $context->{id_s} . $rand_p);
	($context->{tek}, $context->{msk}) = &derive_keys($context->{kdk}, $rand_p);

	# The PCHANNEL
	my $nonce = $context->{nonce}++;
	$context->{sent_r_flag} = $Radius::EAP_47::R_DONE_SUCCESS;
	my $pchannelflag = $context->{sent_r_flag} << 6;
	my $plaintext = pack('C', $pchannelflag);

	# plaintext will be encrypted below and tag filled in
	my $pchannel = pack('N x16 a*', $nonce, $plaintext);
	
	$flags = 2 << 6;
	my $message = pack('C a16 a16 a*', $flags, $context->{rand_s}, $mac_s, $pchannel);

	# The msg_proc here calculates the tag and encryption (need the entire
	# EAP header for this calculation)
	$self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_PSK, $message,
			   sub 
			   {
			       my $context = $_[2]; 
			       my ($encrypted, $tag) = &Radius::AES::aes_128_eax_encrypt
				   ($context->{tek}, pack('x12 N', $nonce), 
				    substr($_[3], 0, 22), $plaintext);
			       substr($_[3], 42, 16 + length($encrypted)) = $tag . $encrypted;
			   });
        return ($main::CHALLENGE, 'EAP PSK Challenge');

    }
    elsif ($T == 3)
    {
	# EAP-PSK Fourth Message
	$self->log($main::LOG_DEBUG, 'EAP PSK Fourth Message');
        my $hdr = substr($context->{this_eap_message}, 0, 22);
        my ($rand_s, $nonce, $tag, $encrypted) = unpack('x a16 N a16 a*', $typedata);
	my ($decrypted, $dtag) = &Radius::AES::aes_128_eax_decrypt
                 ($context->{tek}, pack('x12 N', $nonce), $hdr, $encrypted);
	if ($tag != $dtag)
	{
            # Bad tag in PCHANNEL, pull out
	    return $self->eap_error('EAP PSK bad tag received in PCHANNEL in Fourth Message');
	}
	
	# New nonce for the next round if any
	$context->{nonce} = $nonce; 

	# decrypted now holds the decrypted PCHANNEL data from the peer
	$self->log($main::LOG_DEBUG, 'EAP PSK decrypted PCHANNEL: ' . unpack('H*', $decrypted));

	my ($pchannelflag, $extensions) = unpack('C a*', $decrypted);
	if ($pchannelflag & 0x20)
	{
	    # REVISIT:
	    $self->log($main::LOG_ERR, 'EAP PSK does not understand PSK extensions yet');
	}
	$context->{recv_r_flag} = ($pchannelflag >> 6) & 0x3;
	if ($context->{recv_r_flag} == $Radius::EAP_47::R_CONT)
	{
	    # CONT
	    # REVISIT
	    $self->log($main::LOG_ERR, 'EAP PSK does not understand how to do CONT yet');
	}
	elsif ($context->{recv_r_flag} == $Radius::EAP_47::R_DONE_SUCCESS)
	{
	    # DONE_SUCCESS
            
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
	elsif ($context->{recv_r_flag} == $Radius::EAP_47::R_DONE_FAILURE)
	{
	    # DONE_FAILURE
	    return $self->eap_error('EAP PSK received DONE_FAILURE');
	}
	else
	{
	    return $self->eap_error("EAP PSK bad result indicator from peer: $context->{recv_r_flag}");
	}
    }
    else
    {
	return $self->eap_error("EAP PSK Unexpected message type $T");
    }
}

#####################################################################
# Work out the users TEK and MSK from the KDK and RAND_P
sub derive_keys
{
    my ($kdk, $rand_p) = @_;

    my $cipher = new Crypt::Rijndael $kdk, Crypt::Rijndael::MODE_ECB;
    
    my $counter = 1;
    my $hash = $cipher->encrypt($rand_p);
    $hash ^= pack('x15 C', $counter);
    my $tek = $cipher->encrypt($hash);
    $hash ^= pack('x15 C', $counter);
    $counter++;
    my ($i, $msk);

    for ($i = 0; $i < 8; $i++, $counter++)
    {
	$hash ^= pack('x15 C', $counter);
	$msk .= $cipher->encrypt($hash);
	$hash ^= pack('x15 C', $counter);
    }

    return ($tek, $msk);
}

#####################################################################
# Turn a password into a PSK according to RFC 4764 Appendix A
sub password_to_psk
{
    my ($context, $password) = @_;

    my $p16;
    if (length($password) < 16)
    {
	# Pad up to 16
	$p16 = $password | pack('x16');
    }
    else
    {
	# Hash down to 16 octets using Matyas-Meyer-Oseas hash
	my $hash = pack('H*', '0123456789ABCDEFFEDCBA9876543210'); # The IV
	while (length($password))
	{
	    my $cipher = new Crypt::Rijndael $hash, Crypt::Rijndael::MODE_ECB;
	    $hash ^= $cipher->encrypt(substr($password, 0, 16, '') | pack('x16'));
	}
	$p16 = $hash;
    }

    # Now use PBKDF2 from RFC 2898
    my $salt = substr($context->{id_s}, 0, 12) ^ substr($context->{id_p}, 0, 12) ^ pack('x12');
    return &Radius::PBKDF::pbkdf2_hmac_sha1($p16, $salt, 5000, 16);
}

1;
