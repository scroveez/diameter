# SOAPRequest.pm
#
# This SOAP request handler receibes SOAP encoded requests, such as those sent
# by Radiator AuthBy SOAP. The received SOAP requests are converted into Radius
# requests and sent to a Radiau server for processing. 
# The Radius reply received is sent back to the requester by SOAP.
#
# This system allows you to send Radius requests via SOAP over HTTP or HTTPS. 
# This can give you improved security and/or improved reliability 
# for Radius requests.
#
# See soaprequest.cgi for example of how to use this
# module to handle SOAP requests.
#
# You will probably need to adjust the Configurable PAramteres section
# to suit your site.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2003 Open System Consultants
# $Id: SOAPRequest.pm,v 1.2 2007/09/25 11:31:13 mikem Exp $

package Radius::SOAPRequest;
use Radius::SimpleClient;
use Radius::RDict;
use strict;

# RCS version number of this module
$Radius::SOAPRequest::VERSION = '$Revision: 1.2 $';

#####################################################################
# Configurable parameters
# Adjust these to suit your site.

# This is the name of the Radius dictionary that wil be used to convert
# Radius attribute names and values into binary values for encoding the Radisu request
my $dictionary = '/usr/local/projects/Radiator/dictionary';

# This Radius host to send requests to
# The shared secret the Radius uses for decoding this requst must be the 
# shared secret of the originating Radius client
my $radius_server = 'localhost:1647';

# End of Configurable parameters
#####################################################################


#####################################################################
# This function wil be called for each incoming SOAP request,
# and will be passed the arguments from the SOAP request
sub radius
{
    my ($class, $code, $identifier, $authenticator, @attrs) = @_;

    my $dict = Radius::RDict->new($dictionary) 
	|| die "Could not open Radius dictionary $dictionary";

    my $radius_client = Radius::SimpleClient->new
	(Dest => $radius_server,
	 EncodePassword => 0)
	|| die 'Could not create Radius::SimpleClient';
    
    my $p =  Radius::Radius->new($dict) || die 'Could not create new Radius request';
    $p->set_code($code);
    $p->set_identifier($identifier);
    $p->set_authenticator($authenticator);
    my @radattrs;
    while (@attrs)
    {
	$p->add_attr($attrs[0][0], $attrs[0][1]);
	shift @attrs;
    }

    # This sends the request and waits for a reply. If a reply is received it is returned
    # It will implement retries and timeouts
    my $r = $radius_client->sendAndWait($p);

    my @replyattrs;
    push(@replyattrs, SOAP::Data->name('code', $r->code));
    push(@replyattrs, SOAP::Data->name('identifier', $r->identifier));
    push(@replyattrs, SOAP::Data->name('authenticator', $r->authenticator));
    # Iterate over all the Radius attributes in the reply
    my $i = 0;
    my ($name, $value);
    while (($name, $value) = $r->get_attr_val_n($i++))
    {
	push(@replyattrs, SOAP::Data->name('attribute' => [$name, $value]));
    }

    return (@replyattrs);
}

1;
