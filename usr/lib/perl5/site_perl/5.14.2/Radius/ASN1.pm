# ASN1.pm
#
# Simple ASN1 decoder
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2011 Open System Consultants
# $Id: ASN1.pm,v 1.1 2011/02/06 05:55:29 mikem Exp $

package Radius::ASN1;

sub decode
{
    my ($s) = @_;
    my $result = [];

    my ($taglength, $tag) = decode_tag($s);
    my ($lengthlength, $contentslength) = decode_length(substr($s, $taglength));

    if ($tag == 0x30)
    {
	# Sequence
	push(@$result, decode_sequence(substr($s, $taglength+$lengthlength, $contentslength)));
    }
    return $result;
}

sub decode_sequence
{
    my ($s) = @_;

    return unless length $s;

    my $result = [];
    my $index = 0;
    while (length $s)
    {
	my ($taglength, $tag) = decode_tag($s);
	my ($lengthlength, $contentslength) = decode_length(substr($s, $taglength));
	return if $taglength + $lengthlength + $contentslength > length $s;
	if ($tag == 0x02)
	{
	    # Integer
	    push(@$result, decode_integer(substr($s, $taglength + $lengthlength, $contentslength)));
	}
	elsif ($tag == 0x04)
	{
	    # string
	    push(@$result, substr($s, $taglength + $lengthlength, $contentslength));
	}
	# Remove these bytes
	substr($s, 0, $taglength + $lengthlength + $contentslength) = '';
    }
    return $result;
}

# 0      1    2       3     4     5     6
# $optn, $op, $stash, $var, $buf, $pos, $len
sub decode_integer 
{
    return unless length $_[0];

    my $result = 0;
    map { $result = ($result << 8) + ord($_) } split(//, $_[0]);
    return $result;
}

sub decode_length 
{
    return unless length $_[0];
    
    my $len = ord substr($_[0],0,1);
    
    if ($len & 0x80) 
    {
	$len &= 0x7f or return (1,-1);
	
	return if $len >= length $_[0];
	
	return (1+$len, unpack("N", "\0" x (4 - $len) . substr($_[0],1,$len)));
    }
    return (1, $len);
}

sub decode_tag 
{
    return unless length $_[0];
    
    my $tag = ord $_[0];
    my $n = 1;
    
    if (($tag & 0x1f) == 0x1f) 
    {
	my $b;
	do 
	{
	    return if $n >= length $_[0];
	    $b = ord substr($_[0],$n,1);
	    $tag |= $b << (8 * $n++);
	} while($b & 0x80);
    }
    ($n, $tag);
}

1;
