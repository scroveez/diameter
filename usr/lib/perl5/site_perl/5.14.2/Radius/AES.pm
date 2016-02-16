# AES.pm
#
# Radiator module implementing various AES encryption functions
# Crypt::Rijndael is used for AES encryption
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2006 Open System Consultants
# $Id: EAP_25.pm,v 1.26 2006/11/21 07:06:28 mikem Exp 

package Radius::AES;
use Crypt::Rijndael;
use strict;

# RCS version number of this module
$Radius::AES::VERSION = '$Revision: 1.3 $';

#####################################################################
sub gf_mulx
{
    my ($pad) = @_;

    my @pad = unpack('C16', $pad);
    my $carry = $pad[0] & 0x80;
    my $i;
    for ($i = 0; $i < 15; $i++)
    {
	$pad[$i] = (($pad[$i] << 1) | ($pad[$i+1] >> 7)) & 0xff;
    }
    $pad[15] = ($pad[15] << 1) & 0xff;
    $pad[15] ^= 0x87 if $carry;
    return pack('C16', @pad);
}


#####################################################################
# One-Key CBC MAC (OMAC1) hash with AES-128
# returns MAC
sub omac1_aes_128
{
    my ($key, $data) = @_;

    my $cipher = new Crypt::Rijndael $key, Crypt::Rijndael::MODE_ECB;
    my ($cbc, $pad, $pos, $left);
    $cbc = $pad = pack('x16');
    for ($pos = 0, $left = length($data); $left >= 16; $pos += 16, $left -= 16)
    {
	$cbc ^= substr($data, $pos, 16);
	$cbc = $cipher->encrypt($cbc) if $left > 16;
    }

    $pad = $cipher->encrypt($pad);
    $pad = &gf_mulx($pad);

    if ($left || length($data) == 0)
    {
	$cbc ^= substr($data, $pos) . pack('C', 0x80); # Last part of the string
	$pad = &gf_mulx($pad);
    }

    return $cipher->encrypt($pad ^ $cbc);
}

#####################################################################
# AES-128 CTR mode encryption
sub aes_128_ctr_encrypt
{
    my ($key, $nonce, $data) = @_;

    my $cipher = new Crypt::Rijndael $key, Crypt::Rijndael::MODE_ECB;
    my @counter = unpack('C16', $nonce);
    my ($buf, $block, $i);
    my $encrypted = '';
    while (length($data))
    {
	$buf = $cipher->encrypt(pack('C16', @counter));
	$block = substr($data, 0, 16, '');
	$encrypted .= substr($block ^ $buf, 0, length($block));
	for ($i = 15; $i >= 0; $i--)
	{
	    $counter[$i] = ($counter[$i] + 1) & 0xff;
	    last if $counter[$i];
	}
    }
    return $encrypted;
}

#####################################################################
# Tek is 16 bytes
# Nonce is 16 bytes
# Hdr is 22 bytes
# Data is variable len
# Returns (encrypteddata, tag)
sub aes_128_eax_encrypt
{
    my ($key, $nonce, $hdr, $data) = @_;

    my $nonce_mac = omac1_aes_128($key, pack('x16') . $nonce);
    my $hdr_mac   = omac1_aes_128($key, pack('x15 C', 1) . $hdr);

    my $encrypted = aes_128_ctr_encrypt($key, $nonce_mac, $data);
    my $data_mac  = omac1_aes_128($key, pack('x15 C', 2) . $encrypted);

    return ($encrypted, $nonce_mac ^ $data_mac ^ $hdr_mac);
}

#####################################################################
# Tek is 16 bytes
# Nonce is 16 bytes
# Hdr is 22 bytes
# Data is variable len
# Returns (decrypteddata, tag)
sub aes_128_eax_decrypt
{
    my ($key, $nonce, $hdr, $data) = @_;

    my $nonce_mac = omac1_aes_128($key, pack('x16') . $nonce);
    my $hdr_mac   = omac1_aes_128($key, pack('x15 C', 1) . $hdr);

    my $decrypted = aes_128_ctr_encrypt($key, $nonce_mac, $data);
    my $data_mac  = omac1_aes_128($key, pack('x15 C', 2) . $data);

    return ($decrypted, $nonce_mac ^ $data_mac ^ $hdr_mac);
}

1;
