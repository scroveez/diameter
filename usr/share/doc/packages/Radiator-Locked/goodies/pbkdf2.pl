use Radius::PBKDF;
use Radius::Util;
use MIME::Base64;

use strict;
use warnings;

my $opt_help;
my $opt_verbose;
my $opt_password;
my $opt_iterations = 9000;
my $opt_dk_len = 20;
my $opt_salt_len = 8;
my $opt_salt;

use Getopt::Long;
GetOptions(
     'help|h'            => \$opt_help,
     'verbose|v',        => \$opt_verbose,
     'password|p=s',     => \$opt_password,
     'iterations|i=i',   => \$opt_iterations,
     'dk_len|d=i'        => \$opt_dk_len,
     'salt_len|s=i'      => \$opt_salt_len,
     'salt|S=s'          => \$opt_salt,
    )
    or die("Error in command line arguments\n");

usage() if $opt_help;

# Use user supplied or generated salt.
my $salt;
if (defined $opt_salt)
{
    $salt = $opt_salt
}
else
{
    $salt = Radius::Util::random_string($opt_salt_len);
}

# Two ways to give the password.
$opt_password = $ARGV[0] unless $opt_password;
usage() unless $opt_password;

my $hash = Radius::PBKDF::pbkdf2_hmac_sha1($opt_password, $salt, $opt_iterations, $opt_dk_len);

if ($opt_verbose)
{
    print "Salt in hex: ", unpack('H*', $salt), "\n";
    print "Derived key in hex: ", unpack('H*', $hash), "\n";
}


print '{PBKDF2}HMACSHA1:',
    $opt_iterations, ':',
    MIME::Base64::encode_base64($salt, ''), ':',
    MIME::Base64::encode_base64($hash, ''), "\n";


sub usage
{
    print "usage: $0 [options] [password]
    -h, --help              Print this usage and exit
    -v, --verbose           Verbose output
    -p, --password=STRING   Password (key) to derive. Overrides the optional command line value.
    -i, --iterations=N      Iteration count. Defaults to 9000
    -d, --dk_len=N          Derived key length in octets. Must match server value. Defaults to 20.
    -s, --salt_len=N        Salt length in bytes. Defaults to 8
    -S, --salt=SALT         Use this string as salt
    \n";
    exit;
}

