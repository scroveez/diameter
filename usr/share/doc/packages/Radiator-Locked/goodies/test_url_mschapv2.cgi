#!/usr/bin/perl

use strict;
use lib '/usr/local/projects/Radiator/Radius';
use Radius::MSCHAP;

print "Content-type: text/html\n\n";

use CGI;
my $cgi= new CGI;
my $username = $cgi->param('u');
my $challenge = pack('H*', $cgi->param('MSCHAP-Challenge'));
my $attr = pack('H*', $cgi->param('MSCHAP2-Response'));

my $correct_username = 'm';
my $correct_password = 'p';
#my $correct_username = 'mikem';
#my $correct_password = 'fred';
my $nthash = Radius::MSCHAP::NtPasswordHash(Radius::MSCHAP::ASCIItoUnicode($correct_password));

my ($ident, $flags, $peerchallenge, $reserved, $response) = unpack('C C a16 a8 a24', $attr);

# Strip off any DOMAIN, else the mschapv2 auth response will fail
$username =~ s/^(.*)\\//;

if ($username ne $correct_username)
{
    print "wrong user\n";
}
elsif (Radius::MSCHAP::ChallengeResponse
	(Radius::MSCHAP::ChallengeHash($peerchallenge, $challenge, $username), $nthash) ne $response)
{
    print "wrong pass\n";
}
else
{
    my $usersessionkey = Radius::MSCHAP::NtPasswordHash($nthash);
    my $authenticator_response = &Radius::MSCHAP::GenerateAuthenticatorResponseHash
	($usersessionkey, $response, $peerchallenge, $challenge, $username);
    my $success = unpack('H*', pack('C a42', $ident, $authenticator_response));
    print "MS-CHAP2-Success=$success\n";
    print "all ok!!!!!\n";
}

