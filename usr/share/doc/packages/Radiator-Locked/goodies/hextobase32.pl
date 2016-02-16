#!/usr/bin/perl
# hextobase32.pl
# Convert hex string to Base32

use strict;
use warnings;
use MIME::Base32 qw(RFC);

die "usage: $0 hexstring\n" unless defined $ARGV[0];

my $hex = $ARGV[0];
my $base32 = MIME::Base32::encode(pack("H*", $hex));

$base32 =~ s/(.{4})/$1 /g;  # Add spaces
$base32 =~ s/ $//;          # Remove trailing space

print $base32 . "\n";