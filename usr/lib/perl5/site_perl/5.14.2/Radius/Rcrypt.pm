# Rcrypt.pm
#
# Routines for reversible encryption-decryption
#
# Rcrypt (for radiator-crypt) is a reversible password
# encryption scheme that is implemented by Radiator and Radmin.
#
# Rcrypt uses a secret key to encrypt and decrypt the 
# plaintext. The plaintext is padded to a multiple of 16 bytes
# and then xored with a pseudo-random string. The pseudo-random string
# is generated from the salt and the shared secret, hashed with
# MD5. The MD5 hash is replicated to be the length of the padded
# plaintext. The salt and the result of the xor are concatenated 
# the whole string Base64 encoded (minus any trailing newline). 
# Something like:
#
# base64(salt . md5hash(salt . secret) ^ paddedplaintext)
# 
# Examples:
# Using as the secret key the string    mysecret
# plaintext          ciphertext
# a                  pp4TNZzikPcFCNDf0xbd5Gsv
# 12345678           tZcRat4egwByBk84BqRjeY
# 1234567890123456   PeISDNSOE8zB2ahSAJ41crgEIz7nuib69uGRYjGsBkaNMg==
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: Rcrypt.pm,v 1.5 2008/04/16 01:21:00 mikem Exp $

package Radius::Rcrypt;
use Radius::Util;
use Digest::MD5;
use MIME::Base64;
use strict;

# RCS version number of this module
$Radius::Rcrypt::VERSION = '$Revision: 1.5 $';

# Test code
#my $secret = 'mysecret';
#foreach ('', 'a', 'fred', '12345678', '123456789012345', 
#         '1234567890123456', '12345678901234567', 
#         'jkdfhlukashfouashdfuiahf')
#{
#    my $cipher = &encrypt($_, $secret);
#    my $plain = &decrypt($cipher, $secret);
#    print "cipher $cipher, plain $plain\n";
#    print "decode error for $_\n" unless $_ eq $plain;
#}

#####################################################################
# Encode plaintext with a random salt and the secret key
# Plaintext may not contain NULs
# Returns the base 64 encoded ciphertext (with no embedded newlines)
sub encrypt
{
    my ($plaintext, $secret) = @_;

    my $salt = pack('n', &Radius::Util::rand(65535)); # 2 bytes of salt
    my $hash = Digest::MD5::md5($salt . $secret);
    # Replicate the hash until its longer than the plaintext.
    my $hashrep = $hash x int((length($plaintext) + 16) / 16);
    my $encoded = MIME::Base64::encode_base64($salt . ($plaintext ^ $hashrep), '');
    chomp $encoded; # Strip off trailing newline
    return $encoded;
}

#####################################################################
# Decode the Base64 ciphertext according to the secret key
# Returns the plaintext
sub decrypt
{
    my ($cipher, $secret) = @_;

    my ($salt, $xor) = unpack('a2 a*', MIME::Base64::decode_base64($cipher));
    my $hash = Digest::MD5::md5($salt . $secret);
    # Replicate the hash until its same length as the xored cipher
    # which should be a multiple of 16 bytes
    my $hashrep = $hash x int((length($xor) + 15) / 16);
    my $plaintext = $xor ^ $hashrep;
    # Strip off any NUL padding
    $plaintext =~ s/\000*$//;
    return $plaintext;
}

1;
