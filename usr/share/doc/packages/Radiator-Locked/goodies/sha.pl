#!/usr/bin/perl
#
# sha.pl
# Simple script to generate the {SHA} version of a password.
#

use strict;
use warnings;
use Digest::SHA;
use MIME::Base64;

my ($alg, $pw);

# Default to SHA-1
$alg = 1 if $#ARGV == 0;
$pw = $ARGV[0];

if ($#ARGV == 2)
{
    $alg = $ARGV[1] if $ARGV[0] eq '-l';
    $pw = $ARGV[2];
}
die "usage: $0 [-l 1|256|384|512] password\n"
    unless defined $alg and $alg =~ /^(1|256|384|512)$/;


my $ctx = Digest::SHA->new($alg);
$ctx->add($pw);

my $result = encode_base64($ctx->digest, '');
my $len = ($alg == 1) ? '' : $alg;
print "{SHA$len}$result\n";
