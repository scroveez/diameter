#!/usr/bin/perl
#
# ssha.pl
# Simple script to generate the {SSHA} version of a password.
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

# Initialize the random number system
# From Programming perl p 223
srand(time() ^ ($$ + ($$ << 15)));
my $salt = &random_string(4);

my $ctx = Digest::SHA->new($alg);
$ctx->add($pw);


$ctx->add($salt);
my $result = encode_base64($ctx->digest . $salt, '');
my $len = ($alg == 1) ? '' : $alg;
print "{SSHA$len}$result\n";

#####################################################################
# Generate a random binary string $l octets long
sub random_string
{
    my ($l) = @_;

    my $ret;
    for (1 .. $l)
    {
	$ret .= chr(rand(256));
    }
    return $ret;
}

