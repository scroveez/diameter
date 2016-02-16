#!/usr/bin/perl
#
# freeswitch-fidelio.pl
# mod_perl program for freeswitch
# Install this in /usr/local/freeswitch/scripts/freeswitch-fidelio.pl
#
# See goodies/freeswitch-fidelio.txt for explanatory documentation.
#
# Using Radiator RADIUS server and the AuthBy FIDELIO module connected 
# to a Micros-Fidelio Opera hotel property management system, 
# confirms that there is someone checked into the
# the room represented by the calling phone, and only if so is the 
# call allowed to proceed.
#
# Requires Radiator RADIUS to be installed on this host, although only the
# client side modules (eg Radius::SimpleClient) 
# are used: you dont have to actually run Radiator 
# on this host.
# See http://www.open.com.au/radiator
#
# To enable mod_perl in Freeswitch, see the instructions in 
# http://wiki.freeswitch.org/wiki/Mod_perl
# Then add something like this to the relevant <extension> clause
# in your /usr/local/freeswitch/conf/dialplan/default.xml
#
# <action application="perl" data="/usr/local/freeswitch/scripts/freeswitch-fidelio.pl"/>
#
# This script could also be used with mod_radius_cdr to post call 
# accounting to Fidelio, 
# causing VOIP calls to be charged to the users hotel bill
#
# Tested with Radiator 4.8 on Ubuntu 10.10 with Freeswitch 1.0.7
# Author: Mike McCauley mikem@open.com.au
# 

use strict;
use Radius::SimpleClient;
use Radius::RDict;

our $session;

# Change these to suit your Radiator environment and host
my $dictionary = '/etc/radius/dictionary';
my $radius_server = '203.63.154.29:1645';
my $secret = 'mysecret';

# Get information about the pending call
my $destination_number = $session->getVariable('destination_number');
# This is expected to be the room number. That means that each phone
# must SIP register with Freeswitch with a username of the room the phone is in.
# If that is not the case you can map $username to the correct roomnumber 
# using any perl algorithm you like.
my $username = $session->getVariable('caller_id_number');

my $dict = Radius::RDict->new($dictionary) 
    || die "Could not open Radius dictionary $dictionary";

my $radius_client = Radius::SimpleClient->new
    (Dest => $radius_server,
     Secret => $secret) 
    || die 'Could not create Radius::SimpleClient';

# Check for presence only: Radiator AuthBy FIDELIO is configured with
# NoCheckPassword
# User-Name is expected to be the room number. 
# If there is no one checked into that
# room according to Fidelio, the Access-Request will be rejected, and the 
# call will not go ahead.
my $p = Radius::SimpleClient::request
    ($dict, 
     'Code'            => 'Access-Request',
     'User-Name'       => $username,
     'Freeswitch-Dst'  => $destination_number);
my $r = $radius_client->sendAndWait($p);

if (!$r)
{
    freeswitch::consoleLog("INFO", "No reply from RADIUS server $radius_server. Hanging up\n");
    # Prevent the call
    $session->hangup();
}
elsif ($r->code() ne 'Access-Accept')
{
    freeswitch::consoleLog("INFO", "$username rejected by RADIUS server $radius_server. Not checked in? Hanging up\n");
    # Prevent the call
    # Could play a recorded message first, eg:
    # $session->streamFile('/usr/local/freeswitch/sounds/en/us/callie/ivr/16000/ivr-phone_not_make_external_calls.wav');
    $session->hangup();
}
else
{
    freeswitch::consoleLog("INFO", "$username accepted by RADIUS server $radius_server\n");
}

1;
