#!/usr/bin/perl
#
# Install this in your web servers cgi-bin area:
# for Apache, typically /var/www/cgi-bin
# for IIS, typically ?????
# It should be runnable as http://host.name/cgi-bin/soapradius.cgi
# if it apears at a different URL, you wil need to change the Endpoint paramtere in your 
# AuthBy SOAP to suit.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001 Open System Consultants
# $Id: soapradius.cgi,v 1.1 2003/09/08 00:33:56 mikem Exp $

# You may need to change this lib to tell Perl where to find the Radiator SOAPRequest.pm module
use lib '/usr/local/projects/Radiator';
use SOAP::Transport::HTTP;

# All requests are handled by Radius::SOAPRequest::radius()
# The SOAP args will be automatically unpacked and passed to  Radius::SOAPRequest::radius()
SOAP::Transport::HTTP::CGI->dispatch_to('Radius::SOAPRequest')->handle;
