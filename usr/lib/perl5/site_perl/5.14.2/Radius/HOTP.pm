# HOTP.pm
# 

# (RFC 6238)
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2009 Open System Consultants
# $Id: HOTP.pm,v 1.4 2014/11/13 20:31:27 hvn Exp $

package Radius::HOTP;
use strict;
use warnings;

#####################################################################
# Return the HOTP using SHA1, truncated to $digits as per RFC
# $K is the secret
# $C is an 8 byte counter
# $digits is the number of digits required in the HOTP
sub hotp_sha1
{
    my ($K, $C, $digits) = @_;

    return Radius::HOTP::truncate(Digest::SHA::hmac_sha1($C, $K), $digits);
}

#####################################################################
# Return the HOTP using SHA256, truncated to $digits as per RFC
# $K is the secret
# $C is an 8 byte counter
# $digits is the number of digits required in the HOTP
sub hotp_sha256
{
    my ($K, $C, $digits) = @_;

    return Radius::HOTP::truncate(Digest::SHA::hmac_sha256($C, $K), $digits);
}

#####################################################################
# Return the HOTP using SHA512, truncated to $digits as per RFC
# $K is the secret
# $C is an 8 byte counter
# $digits is the number of digits required in the HOTP
sub hotp_sha512
{
    my ($K, $C, $digits) = @_;

    return Radius::HOTP::truncate(Digest::SHA::hmac_sha512($C, $K), $digits);
}

# Some convenience functions
# This is HOTP-SHA1-4 as per draft-mraihi-mutual-oath-hotp-variants-08.txt
sub hotp_sha1_4
{
    return &hotp_sha1($_[0], $_[1], 4);
}
# This is HOTP-SHA1-6 as per draft-mraihi-mutual-oath-hotp-variants-08.txt
sub hotp_sha1_6
{
    return &hotp_sha1($_[0], $_[1], 6);
}
# This is HOTP-SHA1-8 as per draft-mraihi-mutual-oath-hotp-variants-08.txt
sub hotp_sha1_8
{
    return &hotp_sha1($_[0], $_[1], 8);
}

#####################################################################
# Perform Dynamic Truncation
# $hmac is the output from hmac_sha1, hmac_sha256 or hmac_sha512
# $digits is the number of digits required in the truncation
sub truncate
{
    my ($hmac, $digits) = @_;

    # Offset is the low order 4 bits of hmac[19]
    my @hmac = unpack('C*', $hmac);
    my $len = length($hmac);
    my $offset = $hmac[$len-1] & 0xf;
    my @P = @hmac[$offset .. $offset+3];
    my $p = unpack('N', pack('C4', @P)) & 0x7fffffff;
    $p = $p % (10 ** $digits);
    my $num_leading_zeroes = $digits - length($p);
    $p = '0' x $num_leading_zeroes . $p if $num_leading_zeroes;
    return $p;
}
1;
