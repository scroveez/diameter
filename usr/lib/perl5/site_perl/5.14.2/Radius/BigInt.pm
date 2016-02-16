# BigInt.pm
#
# Routines for packing and unpacking 64 bit signed and unsigned, even in a 32 bit
# perl environment.
# Calculations are done with arrays of integers, base 100000;
#
# Part of the Radiameter project.
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2004 Open System Consultants
# $Id: BigInt.pm,v 1.2 2007/09/25 11:31:13 mikem Exp $

package Radius::BigInt;
use strict;

# RCS version number of this module
$Radius::BigInt::VERSION = '$Revision: 1.2 $';

#####################################################################
# Input is refs to 2 arrays. Each array is base 100000 in reverse order
# Out is array of product, in reverse order
sub add
{
    my ($x, $y) = @_;

    my $i;
    my $carry = 0;
    my $j = 0;
    for $i (@$y)
    {
	$x->[$j] += $i + $carry;
	$carry = $x->[$j] >= 100000 ? 1 : 0;
	$x->[$j] -= 100000 if $carry;
	$j++;
    }
    while ($carry)
    {
	$x->[$j] += $carry;
	$carry = $x->[$j] >= 100000 ? 1 : 0;
	$x->[$j] -= 100000 if $carry;
	$j++;
    }
    return @$x;
}

#####################################################################
# Compute x - y unsigned
# Input is refs to 2 arrays. Each array is base 100000 in reverse order
# Out is array of product, in reverse order
# Requires that $x >= $y
sub sub
{
    my ($x, $y) = @_;

    my $i;
    my $carry = 0;
    my $j = 0;
    for $i (@$x)
    {
	last unless defined $y->[$j] || $carry;
	$y->[$j] = 0 unless defined $y->[$j];
	$i -= $y->[$j] + $carry;
	$carry = $i < 0;
	$i += 100000 if $carry;
	$j++;
    }

    return strip_zeros(@$x);
}

#####################################################################
# Input is refs to 2 arrays. Each array is base 100000 in revere order
# Out is array of product, in reverse order
sub mul
{
    my ($x, $y) = @_;

    my ($carry, $i, $xi, $yi, @prod, @ret, $t);
    for $xi (@$x)
    {
	$carry = $i = 0;
	for $yi (@$y)
	{ 
	    $prod[$i] = 0 unless defined $prod[$i];
	    $t = $xi * $yi + $prod[$i] + $carry;
	    $carry = int($t / 100000);
	    $prod[$i++] = $t - ($carry * 100000);
	}
	$prod[$i] += $carry if $carry; # If prevents trailing (leading) zeroes
	push(@ret, shift @prod);
    }
    push(@ret, @prod); # Left over from the last iteration
    return strip_zeros(@ret);
}

#####################################################################
# Compute $x % $y
# Input is refs to 2 arrays. Each array is base 100000 in revere order
# Out is (ref-to-quotient, ref-to-remainder)
# CAUTION: The only supported case is where $y has one element
sub div
{
    my ($x, $y) = @_;

    die "Division with more than one element is not supported" if @$y != 1;
    my $j = @$x; 
    my $r = 0; 
    my $y1 = $y->[0]; 
    die "Division by 0" if $y1 == 0;
    my ($b, @quot);
    while ($j-- > 0)
    {
	$b = $r * 100000 + $x->[$j];
	$quot[$j] = int($b/$y1);
	$r = $b % $y1;
    }
    pop @quot if @quot > 1 && $quot[-1] == 0;	# remove a leading zero 
    return(\@quot, [$r]);
}

#####################################################################
# Takes an array in reverse order, base 100000.
# Returns a decimal integer string
sub str
{
    my (@x) = @_;

    my ($x, $ret);
    @x = reverse @x;
    $ret = shift(@x); # First digit, no leading zeroes
    for $x (@x)
    {
	$ret .= substr('000000' . $x, -5);
    }
    return $ret;
}

#####################################################################
# Takes a decimal integer string and returns an array in reverse order, base 100000.
# Guaranteed never to have a most significant zero
sub from_str
{
    my ($s) = @_;

    my $l = length($s);
    return int $s if $l < 6;
    my @ret = unpack('a' . ($l % 5) . 'a5' x ($l / 5), $s);
    shift @ret if $ret[0] eq ''; # Strip any leading 0

    return reverse @ret;
}

#####################################################################
# Pack an unsigned reversed base 100000 into a 8 octet binary in network order
# Numbers that exceed 8 octets will silently overflow
sub pack64
{
    my (@s) = @_;

    my @ret;
    my ($quot, $rem) = div(\@s, [65536]);
    unshift(@ret, $rem->[0]);
    ($quot, $rem) = div($quot, [65536]);
    unshift(@ret, $rem->[0]);
    ($quot, $rem) = div($quot, [65536]);
    unshift(@ret, $rem->[0]);
    ($quot, $rem) = div($quot, [65536]);
    unshift(@ret, $rem->[0]);

    return pack('nnnn', @ret);
}

#####################################################################
# Pack an unsigned decimal integer string into a 8 octet binary in network order
# Numbers that exceed 8 octets will silently overflow
sub pack64u
{
    my ($s) = @_;

    return pack64(from_str($s));
}

#####################################################################
# Pack an signed decimal integer string into a 8 octet binary in network order
# Numbers that exceed 8 octets will silently overflow
sub pack64s
{
    my ($s) = @_;

    my @s;
    if ($s =~ /^-(\d+)/)
    {
	@s = from_str($1);
	@s = &sub([from_str('18446744073709551616')], \@s);
    }
    else
    {
	@s = from_str($s);
    }
    return pack64(@s);
}

#####################################################################
# Unpack a binary in network order to an unsigned decimal integer string
# Return an array of base 100000 in reverse order
sub unpack64
{
    my @mul = (1);
    my @ret = (0);
    my $n;
    for $n (reverse @_)
    {
	@ret = add(\@ret, [mul([$n], \@mul)]) if $n;
	@mul = mul([65536], \@mul);  # mult by 65536, same as << 16
    }

    return @ret;
}

#####################################################################
# Unpack an 8 octet binary in network order to an unsigned decimal integer string
sub unpack64u
{
    return str(&unpack64(unpack('nnnn', $_[0])));
}

#####################################################################
# Return $x <=> $y
# $x and $y are refs to arrays
sub cmp
{
    my ($x, $y) = @_;

    my $lxy = (scalar @$x - scalar @$y)
	|| (length(int($x->[-1])) - length(int($y->[-1])));
    return -1 if $lxy < 0;
    return 1 if $lxy > 0;	

    my $a; 
    my $j = scalar @$x;
    while (--$j >= 0)
    {
	last if ($a = $x->[$j] - $y->[$j]);
    }
    return $a <=> 0;
}

#####################################################################
# Unpack an 8 octet binary in network order to an unsigned decimal integer string
sub unpack64s
{
    my (@s) = &unpack64(unpack('nnnn', $_[0]));

    if (&cmp(\@s, [75807, 68547, 37203, 9223]) == 1) # decimal 9223372036854775807 = 2**63 - 1
    {
	# Top bit set, its really a negative
	@s = &sub([from_str('18446744073709551616')], \@s);
	return '-' . str(@s);
    }
    else
    {
	return str(@s);
    }
}

#####################################################################
# Strip all the most significant zeros (from the end of the array)
sub strip_zeros
{
    my (@n) = @_;

    return @n if @n == 1;
    my $cnt = scalar @n;
    my $i = (scalar @n) - 1;
    while ($i > 0)
    {
	last if $n[$i]; # non-zero
	splice(@n, -1);
	$i--;
    }
    return @n;
}
1;
