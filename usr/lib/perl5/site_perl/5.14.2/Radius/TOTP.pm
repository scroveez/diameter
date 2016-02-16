# TOTP.pm
# 
# functions to support TOTP (RFC 6238)
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2009 Open System Consultants
# $Id: TOTP.pm,v 1.3 2014/11/13 20:31:27 hvn Exp $

package Radius::TOTP;
use Radius::HOTP;
use strict;
use warnings;

# Compute a timestep from the current time and a step delay
sub totp_timestep
{
    my ($time, $stepdelay) = @_;

    return int(($time - $Radius::TOTP::T0) / $Radius::TOTP::X) - $stepdelay;
}

# Compute the SHA for this timestep
sub totp_compute_sha1
{
    my ($K, $T, $digits) = @_;

    return Radius::HOTP::hotp_sha1($K, pack('NN', 0, $T), $digits);
}

sub totp_compute_sha256
{
    my ($K, $T, $digits) = @_;

    return Radius::HOTP::hotp_sha256($K, pack('NN', 0, $T), $digits);
}

sub totp_compute_sha512
{
    my ($K, $T, $digits) = @_;

    return Radius::HOTP::hotp_sha512($K, pack('NN', 0, $T), $digits);
}

1;
