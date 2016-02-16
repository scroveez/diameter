# Internode.pm
#
# Interface to the Internode NodeText Gateway, a commercial SMS gateway
# available from Internode in Australia.
#
# The NodeText Gateway is a high reliability, high performance SMS Gateway
# for Australian SMS numbers. Works with GSM, CDMA. Works with Telstra, Optus 
# and Vodafone networks. Billing of SMS delivery charges can be to the sender, 
# or the receiver. The Internode NodeText Gateway can also apply a range of special
# features, such as name to SMS number translation etc. Multiple recipients,
# message splitting etc are supported.
# They also offer an email-to-SMS gateway.
#
# The NodeText Gateway requires a username and password to authenticate the sender,
# you have to get these from Internode when you sign up for the service.
#
# Interface as per 'NodeText Gateway User Guide', 22/05/2006
# Internode SMS gateway access for Australian SMS numbers is available
# from http://www.internode.on.net
# and
# http://www.internode.on.net/products/sms.htm
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2006 Open System Consultants
# $Id: Internode.pm,v 1.2 2006/09/26 22:18:04 mikem Exp $

use strict;
use HTTP::Request;
use LWP::UserAgent;
use LWP::Debug;
package Radius::AuthGeneric;


#####################################################################
# Send a message to an SMS number using the Internode SMS gateway
# Returns undef if all went well and the SMS was queued fopr delivery
# at Internode, else returns an error message.
sub sms_internode
{
    my ($self, %args) = @_;

    # Get configuration from caller args, with some useful defaults
    my $debug   = $args{debug}   || '-';     # - disables, + enables
    my $gateway = $args{gateway} || 'https://txt.on.net/cgi-bin/sms_tcp.cgi';
    my $test    = $args{test}    || 'false'; # 1 or true prevents sending the SMS
    my $timeout = $args{timeout} || 10;
    my $user    = $args{user};    # Get this from Internode
    my $pass    = $args{pass};    # first 8 chars are significant
    my $dest    = $args{dest};    # must start 614, Australia mobile
    my $msg     = $args{msg};     # The message to send
    
    # Construct a GET
    my $method = 'GET';
    my $uri = "$gateway?user=$user&pass=$pass&dest=$dest&msg=$msg&test=$test";
    # Optional keys
    $uri .= "src=$args{src}"           if defined $args{src};   # intl mobile no
    $uri .= "split=$args{split}"       if defined $args{split}; # hard or soft
    $uri .= "timezone=$args{timezone}" if defined $args{timezone};

    $self->log($main::LOG_DEBUG, "Internode SMS requesting $uri");
    &LWP::Debug::level($debug);

    my $ua = LWP::UserAgent->new(timeout => $timeout); 
    my $request = HTTP::Request->new($method, $uri);
    my $response = $ua->request($request);

    my $ret;
    if ($response)
    {
	my $code = $response->code();
	my $message = $response->message();

	if ($code == 200)
	{
	    my $content = $response->content();
	    $self->log($main::LOG_DEBUG, "Internode SMS response content: $content");
	    my ($code, $description) = $content =~ /^Status: (\d+)\s+(.*)/;
	    $ret = $content unless $code == 0;
	}
	else
	{
	    my $status = $response->status_line();
	    $ret = "Internode SMS bad request: $status";
	    $self->log($main::LOG_ERR, $ret);
	}
    }
    else
    {
	$ret = 'Internode SMS no response';
	$self->log($main::LOG_ERR, $ret);
    }
    return $ret;
}

1;
