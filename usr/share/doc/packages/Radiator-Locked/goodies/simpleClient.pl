#!/usr/bin/perl
#
# simpleClient.pl
# Example code showing how to use SimpleClient.pm
#

use Radius::SimpleClient;
use Radius::RDict;

my $dictionary = './dictionary';
my $radius_server = 'localhost:1645';
my $secret = 'mysecret';
my $username = 'mikem';
my $password = 'fred';


# Set the tracing level in SimpleClient. 4 is debug
&Radius::SimpleClient::trace_level(4);

my $dict = Radius::RDict->new($dictionary) 
    || die "Could not open Radius dictionary $dictionary";

my $radius_client = Radius::SimpleClient->new
    (Dest => $radius_server,
     Secret => $secret) 
    || die 'Could not create Radius::SimpleClient';

my $p = Radius::SimpleClient::request
    ($dict, 
     'Code'            => 'Access-Request',
     'User-Name'       => $username,
     'User-Password'   => $password);

# This sends the reque and waits for a reply. If a reply is received it is returned
my $r = $radius_client->sendAndWait($p);

die 'no reply' unless $r;
if ($r->code() eq 'Access-Accept')
{
    print "success\n";
    exit;
}
else
{
    print "fail\n";
    exit 1;
}
