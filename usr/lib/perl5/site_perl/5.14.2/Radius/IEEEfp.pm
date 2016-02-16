# IEEEfp.pm
#
# Routines for packing and unpacking IEEE 754 compliant floating point
# numbers. Single and double precision are supported. Numbers are unpacked
# to native perl floats. Numbers are packed to 4 or 8 octets. The sign bit is
# in the first octet, the least significant bits of the mantissa are in 
# the last octet.
#
# Its a shame that perl5 does not support IEEE format with pack() and unpack(). 
# I cant see any other
# way to do this except the long way.
#
# Part of the Radius project.
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2004 Open System Consultants
# $Id: IEEEfp.pm,v 1.2 2007/09/25 11:31:13 mikem Exp $

package Radius::IEEEfp;
use strict;

# RCS version number of this module
$Radius::IEEEfp::VERSION = '$Revision: 1.2 $';

# Single precision special numbers
$Radius::IEEEfps::inf_s   = pack('H8', '7f800000');
$Radius::IEEEfps::minf_s  = pack('H8', 'ff800000');
$Radius::IEEEfps::zero_s  = pack('H8', '00000000');
$Radius::IEEEfps::mzero_s = pack('H8', '80000000');
$Radius::IEEEfps::nan_s   = pack('H8', 'ffffffff');

# Double precision special numbers
$Radius::IEEEfps::inf_d   = pack('H16', '7ff0000000000000');
$Radius::IEEEfps::minf_d  = pack('H16', 'fff0000000000000');
$Radius::IEEEfps::zero_d  = pack('H16', '0000000000000000');
$Radius::IEEEfps::mzero_d = pack('H16', '8000000000000000');
$Radius::IEEEfps::nan_d   = pack('H16', 'ffffffffffffffff');

# String represenations of special numbers
$Radius::IEEEfps::inf = 'inf';
$Radius::IEEEfps::minf = '-inf';
$Radius::IEEEfps::zero = '0';
$Radius::IEEEfps::mzero = '-0';
$Radius::IEEEfps::nan = 'NaN';
$Radius::IEEEfps::denorm = 'denormalised not supported';

#####################################################################
# Unpack an IEEE single (4 octets) to a native perl float
# Input is packed IEEE single
# May return '-inf', 'inf', '-0', '0' or 'NaN' as appropriate
sub unpack_s
{
    my ($p) = @_;

    # binary sign, exponent, mantissa as ASCII digits in binary form
    my ($s, $e, $m) = unpack('a a8 a23', unpack('B32', $p));

    $e = unpack('C', pack('B8', $e)); # Turn 8 binary digits into an 8 bit integer
    return $s ? $Radius::IEEEfps::mzero : $Radius::IEEEfps::zero if $e == 0 && $m == 0;
    return $Radius::IEEEfps::denorm if $e == 0;
    return $s ? $Radius::IEEEfps::minf : $Radius::IEEEfps::inf if $e == 255 && $m == 0;
    return $Radius::IEEEfps::nan if $e == 255;

    my $t = 1; # The resulting number,starting with an implicit 1.
    my $i = 0.5;
    # $m starts as 23 character ASCII string, with 0 or 1 in each place
    foreach (split('', $m))
    {
	$t += $i if $_;
	$i /= 2;
    }
    $t = -$t if $s;
    $e -= 127; # Unbias the exponent
    $t *= 2 ** $e; # Apply the exponent.
   
    return $t;
}

#####################################################################
# Pack a native perl float to an IEEE single
# input is a native perl float/double
sub pack_s
{
    my ($f) = @_;

    return $Radius::IEEEfps::minf_s if $f eq '-inf';
    return $Radius::IEEEfps::inf_s if $f eq 'inf';
    return $Radius::IEEEfps::zero_s if $f eq '0';
    return $Radius::IEEEfps::mzero_s if $f eq '-0';
    return $Radius::IEEEfps::nan_s if $f eq 'NaN';

    my $e = 0; # Exponent
    my $s = 0; # sign of mantissa
    $s++, $f = -$f if $f < 0; # Figure out the sign and make $f positive

    # Normalise and figure out the exponent.
    if ($f >= 1.0)
    {
	while ($f > 2 && $e <= 127)
	{
	    $e++;
	    $f /= 2;
	};
    }
    else
    {
	while ($f < 1 && $e >= -127)
	{
	    $e--;
	    $f *= 2;
	};
    }

    # Check for infinities and zeroes
    return $s ? $Radius::IEEEfps::minf_s : $Radius::IEEEfps::inf_s
	if $e > 127; # Too big
    return $s ? $Radius::IEEEfps::mzero_s : $Radius::IEEEfps::zero_s
	if $e < -127; # Too small

    # Now we have e, and 1 <= f < 2
    # Get f as the mantissa
    $f -= 1; # Remove the implicit 1.
    my $m = ''; # String of 0 and 1 characters. Initialisation stops perl 5.6.1 complaining
    my $i = 0.5;
    while ($f > 0 && length($m) < 23 )
    {
	if ($f >= $i)
	{
	    $m .= '1';
	    $f -= $i;
	}
	else
	{
	    $m .= '0';
	}
	$i /= 2;
    }
    $e += 127; # Bias the exponent. Its a perl integer
    return pack('B32', $s . unpack('B8', pack('C', $e)) . $m);
}
#####################################################################
# Unpack an IEEE double (8 octets) to a native perl float
# Input is packed IEEE double
# May return '-inf', 'inf', '-0', '0' or 'NaN' as appropriate
sub unpack_d
{
    my ($p) = @_;

    # binary sign, exponent, mantissa as ASCII digits in binary form
    my ($s, $e, $m) = unpack('a a11 a52', unpack('B64', $p));

    $e = unpack('n', pack('B16', '00000' . $e)); # Turn 11 binary digits into an 11 bit integer
    return $s ? $Radius::IEEEfps::mzero : $Radius::IEEEfps::zero if $e == 0 && $m == 0;
    return $Radius::IEEEfps::denorm if $e == 0;
    return $s ? $Radius::IEEEfps::minf : $Radius::IEEEfps::inf if $e == 2047 && $m == 0;
    return $Radius::IEEEfps::nan if $e == 2047;

    my $t = 1; # The resulting number,starting with an implicit 1.
    my $i = 0.5;
    # $m starts as 23 character ASCII string, with 0 or 1 in each place
    foreach (split('', $m))
    {
	$t += $i if $_;
	$i /= 2;
    }
    $t = -$t if $s;
    $e -= 1023; # Unbias the exponent
    $t *= 2 ** $e; # Apply the exponent.
   
    return $t;
}

#####################################################################
# Pack a native perl float to an IEEE single
# input is a native perl float/double
sub pack_d
{
    my ($f) = @_;

    return $Radius::IEEEfps::minf_d if $f eq '-inf';
    return $Radius::IEEEfps::inf_d if $f eq 'inf';
    return $Radius::IEEEfps::zero_d if $f eq '0';
    return $Radius::IEEEfps::mzero_d if $f eq '-0';
    return $Radius::IEEEfps::nan_d if $f eq 'NaN';

    my $e = 0; # Exponent
    my $s = 0; # sign of mantissa
    $s++, $f = -$f if $f < 0; # Figure out the sign and make $f positive

    # Normalise and figure out the exponent.
    if ($f >= 1.0)
    {
	while ($f > 2 && $e <= 1023)
	{
	    $e++;
	    $f /= 2;
	};
    }
    else
    {
	while ($f < 1 && $e >= -1023)
	{
	    $e--;
	    $f *= 2;
	};
    }

    # Check for infinities and zeroes
    return $s ? $Radius::IEEEfps::minf_d : $Radius::IEEEfps::inf_d
	if $e > 1023; # Too big
    return $s ? $Radius::IEEEfps::mzero_d : $Radius::IEEEfps::zero_d
	if $e < -1023; # Too small

    # Now we have e, and 1 <= f < 2
    # Get f as the mantissa
    $f -= 1; # Remove the implicit 1.
    my $m = ''; # String of 0 and 1 characters. Initialisation stops perl 5.6.1 complaining
    my $i = 0.5;
    while ($f > 0 && length($m) < 52 )
    {
	if ($f >= $i)
	{
	    $m .= '1';
	    $f -= $i;
	}
	else
	{
	    $m .= '0';
	}
	$i /= 2;
    }
    $e += 1023; # Bias the exponent. Its a perl integer
    # Want the last 11 bits of $e
    return pack('B64', $s . substr(unpack('B16', pack('n', $e)), 5) . $m);
}


1;
