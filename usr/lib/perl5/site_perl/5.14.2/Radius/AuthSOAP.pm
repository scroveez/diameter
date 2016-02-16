# AuthSOAP.pm
#
# Object for handling Authentication via the Radiator SOAP interface
# over HTTP or HTTPS.
# Sends a SOAP request to a remote SOAP server.
#
# Caution: the overheads of creating and processing SOAP requests
# mean you will never get carrier class performance from AuthBy SOAP
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001 Open System Consultants
# $Id: AuthSOAP.pm,v 1.4 2007/12/18 21:23:50 mikem Exp $

package Radius::AuthSOAP;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use SOAP::Lite;
use strict;

%Radius::AuthSOAP::ConfigKeywords = 
('Endpoint'        => 
 ['stringarray', 'With this parameter, you can specify any number of SOAP proxy points. AuthBy SOAP will try to contact each one in turn until the SOAP call succeeds in getting a reply. Defaults to http://localhost/cgi-bin/soapradius.cgi.', 0],

 'URI'             => 
 ['string', 'This parameter specifies the SOAP URI that AuthBy SOAP will try to run. This is not a URL. It is used by the server to deduce the right SOAP module to load. You should not need to change this. Defaults to http://www.open.com.au/Radius/SOAPRequest.', 1],

 'SOAPTrace'       => 
 ['string', 'This enables some or all of the SOAP::Lite internal tracing. ', 1],

 'Timeout'         => 
 ['integer', 'With this optional parameter, you can control how long to wait for the SOAP reply from the SOAP server. Time is in seconds. Defaults to 3 seconds.', 1],

 );

# RCS version number of this module
$Radius::AuthSOAP::VERSION = '$Revision: 1.4 $';

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();

    $self->{Endpoint} = [ 'http://localhost/cgi-bin/soapradius.cgi' ]
	unless defined $self->{Endpoint};
    SOAP::Trace->import($self->{SOAPTrace}) if defined $self->{SOAPTrace};
}

#####################################################################
# Do per-instance default initialization
# This is called by Configurable during Configurable::new before
# the config file is parsed. Its a good place initialize instance 
# variables
# that might get overridden when the config file is parsed.
# Do per-instance default initialization. This is called after
# construction is complete
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    
    $self->{URI} = 'http://open.com.au/Radius/SOAPRequest';
    $self->{Timeout} = 3; # Max time that we will wait in seconds
}

#####################################################################
# Handle a request
# This function is called for each packet. $p points to a Radius::
# packet
sub handle_request
{
    my ($self, $p, $dummy, $extra_checks) = @_;


    return ($main::IGNORE, "Ignored due to IgnoreAuthentication")
	if $self->{IgnoadreAuthentication} 
           && $p->code eq 'Access-Request';
    return ($main::IGNORE, "Ignored due to IgnoreAccounting")
	if $self->{IgnoreAccounting} 
           && $p->code eq 'Accounting-Request';

    # Maybe we will fork?
    return ($main::IGNORE, 'Forked')
	if $self->{Fork} && !$self->handlerFork();

    # OK, now we build the SOAP data for this request
    my @args;
    push(@args, SOAP::Data->name('code' => $p->code));
    push(@args, SOAP::Data->name('identifier' => $p->identifier));
    push(@args, SOAP::Data->name('authenticator' => $p->authenticator));
    # Iterate over all the Radius attributes in the request
    my $i = 0;
    my ($name, $value);
    while (($name, $value) = $p->get_attr_val_n($i++))
    {
	push(@args, SOAP::Data->name('attribute' => [$name, $value]));
    }

    my $endpoint;
    foreach $endpoint (@{$self->{Endpoint}})
    {
	$self->log($main::LOG_DEBUG, "Proxying by SOAP to Endpoint $endpoint");
	
	my $som;
	# This will call Radius::SOAPRequest::radius in the SOAP server at $endpoint
	# CAUTION: blocks until a reply is received
	# REVISIT: Timeout
	eval { $som =  SOAP::Lite
		    ->uri($self->{URI})
		    ->proxy($endpoint, timeout => $self->{Timeout})
		    ->radius(@args); 
	    };

	if ($@)
	{
	    $self->log($main::LOG_WARNING, "SOAP::Lite died: $@");
	}
	elsif ($som)
	{
	    if ($som->fault)
	    {
		my $faultstring = $som->faultstring;
		$self->log($main::LOG_WARNING, "SOAP Fault from $endpoint: $faultstring");
	    }
	    else
	    {
		# Unpack the reply data from SOAP and build the Radius reply
		my $code = $som->valueof('//code');
		$p->{rp}->code($code);
		$p->{rp}->identifier($som->valueof('//identifier'));
		$p->{rp}->authenticator($som->valueof('//authenticator'));
		my @attrs = $som->valueof('//attribute');
		while (@attrs)
		{
		    $p->{rp}->add_attr($attrs[0][0], $attrs[0][1]);
		    shift @attrs;
		}
		return ($main::ACCEPT)
		    if ($code eq 'Access-Accept'
			|| $code eq 'Accounting-Response');
		return ($main::CHALLENGE, 'Challenged by SOAP proxy')
		    if ($code eq 'Access-Challenge');
		return ($main::REJECT, 'Rejected by SOAP proxy');
	    }
	}
	else
	{
	    $self->log($main::LOG_WARNING, "SOAP Error from $endpoint");
	}
    }
    return ($main::REJECT, 'Could not deliver request by SOAP to any Endpoint');
}

1;
