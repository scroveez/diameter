# PBKDF.pm
#
# Implementation of Password Based Key Derivation functions
# based on RFC 2898
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2006 Open System Consultants
# $Id: PBKDF.pm,v 1.2 2007/09/25 11:31:13 mikem Exp $

package Radius::PBKDF;
use Digest::HMAC_SHA1;
use strict;

# RCS version number of this module
$Radius::PBKDF::VERSION = '$Revision: 1.2 $';


#####################################################################
# Password Based Key Derivation Function
# PBKDF2 function from RFC 2898
# PRF is HMAC-SHA-1
sub pbkdf2_hmac_sha1
{
    my ($P, $S, $c, $dkLen) = @_;

    my $dk; 
    my $hLen = 20; # for HMAC-SHA-1
    my $l = int($dkLen / $hLen) + 1; # blocks rounded up
    my $r = $dkLen - (($l - 1) * $hLen); # octets in the last block
    my ($i, $j, $U, $T);
    for ($i = 1; $i <= $l; $i++)
    {
	$T = $U = Digest::HMAC_SHA1::hmac_sha1($S . pack('N', $i), $P); # U_1
	
	for ($j = 1; $j < $c; $j++)
	{
	    $U = Digest::HMAC_SHA1::hmac_sha1($U, $P); # U_n
	    $T ^= $U;
	}
	$dk .= $T;
    }
    return substr($dk, 0, $dkLen);
}

1;
