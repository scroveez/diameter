#!/usr/bin/perl
#
# duosim.cgi
#
# Duo Security API simulator CGI script for Apache and other CGI
# capable web servers. Implements (partially) the Duo Security Auth
# API https://www.duosecurity.com/docs/authapi for the purposes of
# testing the AuthBy DUO module.
#
# Install in the appropriate place in your web servers directory tree,
# such as /srv/www/cgi-bin/ with execute permissions.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2013 Open System Consultants
# $Id: duosim.cgi,v 1.1 2013/07/29 20:58:08 hvn Exp $

use CGI;
use strict;
use warnings;

#my @x = %ENV;
#print STDERR "ITS @x\n";

my $q = CGI->new;

# The part of the URL after duosim.cgi, eg /check or /auth
my $path_info = $ENV{'PATH_INFO'};
my $time = time();

# All types other than ping, we should check the Authorization first
# But its impossible to get the Authorization header in a CGI script :-(
# May be able to use ModRewrite in .htaccess to get it into the CGI
#RewriteEngine on
#RewriteBase /
#RewriteCond %{HTTP:Authorization}  ^(.*)
#RewriteRule ^(.*)$ $1 [e=HTTP_AUTHORIZATION:%1]
# but I tried this and it didnt work

if ($path_info eq '/ping')
{
    print $q->header('application/json');
    print qq|{"response": {"time": $time}, "stat": "OK"}|;
}
elsif ($path_info eq '/check')
{
    print $q->header('application/json');
    print qq|{"response": {"time": $time}, "stat": "OK"}|;
}
elsif ($path_info eq '/preauth')
{
    my $username = $q->param('username');

    if ($username eq 'mikem') # Valid username
    {
	print $q->header('application/json');
	print qq|{"response": {"devices": [{"capabilities": ["push", "sms", "phone"], "device": "Z12AB34CD56EF78GH90Z", "display_name": "Mikems phone (+XX XXX XXX XXX)", "name": "Mikems phone", "number": "+XX XXX XXX XXX", "sms_nextcode": "1", "type": "phone"}], "result": "auth", "status_msg": "Account is active"}, "stat": "OK"}|;
    }
    else # invalid username, enroll
    {
	print $q->header('application/json');
	print qq|{"response": {"enroll_portal_url": "https://api-aabbcczz.duosecurity.com.invalid/portal?1122334455667788", "result": "enroll", "status_msg": "Enroll an authentication device to proceed"}, "stat": "OK"}|;
    }
}
elsif ($path_info eq '/auth')
{
    my $username = $q->param('username');
    my $passcode = $q->param('passcode');
    my $factor   = $q->param('factor');
    $factor = 'push' if $factor eq 'auto'; # Default to push

    if ($factor eq 'passcode')
    {
	if ($username eq 'mikem' && $passcode eq '12345') # Good passcode
	{
	    print $q->header('application/json');
	    print qq|{"response": {"result": "allow", "status": "allow", "status_msg": "Success. Logging you in..."}, "stat": "OK"}|;
	}
	elsif ($username eq 'mikem' && $passcode eq '12346') # Fake a replay
	{
	    print $q->header('application/json');
	    print qq|{"response": {"result": "deny", "status": "fraud", "status_msg": "This passcode has already been used. Please generate a new passcode and try again."}, "stat": "OK"}|;
	}
	elsif ($username eq 'mikem') # Bad passcode
	{
	    print $q->header('application/json');
	    print qq|{"response": {"result": "deny", "status": "deny", "status_msg": "Invalid passcode, please try again."}, "stat": "OK"}|;
	}
	else # Bad username
	{
	    print $q->header('application/json');
	    print qq|{"response": {"result": "deny", "status": "deny", "status_msg": "Invalid passcode, please try again."}, "stat": "OK"}|;
	}
    }
    elsif ($factor eq 'sms') # Ask for new SMS codes
    {
	print $q->header('application/json');
	print qq|{"response": {"result": "deny", "status": "sent", "status_msg": "New SMS passcodes sent."}, "stat": "OK"}|;
    }
    elsif ($factor eq 'push')
    {
	if ($username eq 'mikem') # Force an accept
	{
	    sleep(10); # push can be very slow, up to 60 secs
	    print $q->header('application/json');
	    print qq|{"response": {"result": "allow", "status": "allow", "status_msg": "Success. Logging you in..."}, "stat": "OK"}|;
	}
	elsif ($username eq 'mikemdeny') # Force a deny
	{
	    sleep(10); # push can be very slow, up to 60 secs
	    print $q->header('application/json');
	    print qq|{"result": "deny", "status": "deny", "status_msg": "Login request denied."}, "stat": "OK"}|;
	}
	else # Push with bad username
	{
	    print $q->header('application/json', 400);
	    print qq|{"code": 40002, "message": "Invalid request parameters", "message_detail": "username", "stat": "FAIL"}|;
	}
    }
}
else
{
    print $q->header('application/json', 404);
    print qq|{"code": 40401, "message": "Resource not found", "stat": "FAIL"}|;
}

exit;
