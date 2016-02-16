use Radius::MSCHAP;
use strict;
die "usage: $0 password" unless defined $ARGV[0];

my $result = uc unpack('H*', Radius::MSCHAP::NtPasswordHash(Radius::MSCHAP::ASCIItoUnicode($ARGV[0])));
print "{nthash}$result\n";
