# AuthRSAMOBILE.pm
#
# Object for handling Authentication via RSA Mobile
# RSA Mobile supports a number of authentication methods, including 
# - username and password
# - an access code sent by SMS to your mobile phone
# - RSA Secureid Token Cards
# and all of these can be configured with AuthBy RSAMOBILE
#
# This code supports conventional Radius Access-Accept/Access-Challenge
# conversations, as well as EAP-Generic Token Card and
# EAP-PEAP-Generic Token Card.
#
# Requires SOAP::Lite and all its prerequesites
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2003 Open System Consultants
# $Id: AuthRSAMOBILE.pm,v 1.15 2012/05/22 22:03:41 mikem Exp $

package Radius::AuthRSAMOBILE;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Radius::Context;
use SOAP::Lite;
use HTTP::Cookies;
use strict;

%Radius::AuthRSAMOBILE::ConfigKeywords = 
('Endpoint'        => 
 ['string', 'This optional parameter specifies how to create the endpoint of the SOAP connection to the RSA Mobile server. Special characters are permitted. %0 is replaced by the value of the Protocol parameter (see Section 5.54.2 on page 174) and %1 is replaced by the value of the Host parameter (see Section 5.54.2 on page 174). The default is %0://%1/axis/services/AuthenticationAPI. 
You should not normally need to change this.', 1],

 'Protocol'        => 
 ['string', 'This optional parameter specifies the protocol that will be used to contact the RSA Mobile server. It is used as %0 in the Endpoint parameter. The default is "http". You should not normally need to change this.', 1],

 'Host'            => 
 ['string', 'This parameter specifies the address and port number of the RSA Mobile server. It is used as %1 in the Endpoint parameter. The default is "localhost:7001". You will usually have to change this to the address and port number of your RSA Mobile server. 7001 is the usual port number for RSA Mobile.', 1],

 'URI'             => 
 ['string', 'This optional parameter specifies the SOAP URI that will be accessed in the RSA Mobile server. The default is "http://rsa.com/csf/clientservice/authenticationapi/AuthenticationAPI". You should not normally need to change this. Note that this is not the address of a web resource and it is not accessed by Radiator during authentication.', 1],

 'Policy'          => 
 ['string', 'This optional parameter specifies the authentication policy that is to be requested. The RSA Mobile server can be configured to permit password or RSA SecurID authentication as well as RSA Mobile authentication.', 1],

 'Resource'        => 
 ['string', 'This optional parameter specifies an alternate resource for the RSA Mobile server to use to authenticate each user. The default is an empty string. See your RSA Mobile administrator for information about what resources are available. You should not normally need to set this parameter.', 1],

 'Lang'            => 
 ['string', 'This optional parameter permits an alternate language to be specified for the RSA Mobile server to use for the password prompts to be sent to the user. The default is empty string. See your RSA Mobile administrator for information about what Lang options are available. You should not normally need to set this parameter.', 1],

 'Country'         => 
 ['string', 'This optional parameter permits an alternate language to be specified for the RSA Mobile server to use for the password prompts to be sent to the user. The default is empty string. See your RSA Mobile administrator for information about what Lang options are available. You should not normally need to set this parameter.', 1],

 'SessionUsername' => 
 ['string', 'This parameter specifies a username that will be used to contact the RSA Mobile HTTP server. The default is "authapiuser", which is the same as the default that is installed on the RSA Mobile HTTP server. You will almost certainly have to set this to suit the configuration of your RSA Mobile server. See your RSA Mobile administrator for information about what the RSA Mobile Server HTTP access password and username is.', 0],

 'SessionPassword' => 
 ['string', 'This parameter specifies the password that will be used to contact the RSA Mobile HTTP server. The default is "changeit", which is the same as the default that is installed on the RSA Mobile HTTP server. You will almost certainly have to set this to suit the configuration of your RSA Mobile server. See your RSA Mobile administrator for information about what the RSA Mobile Server HTTP access password and username is.', 0],

 'SessionRealm'    => 
 ['string', 'This optional parameter specifies the HTTP Realm that the SessionUsername and SessionPassword will be used for. The default is "weblogic", which matches the RSA Mobile Server SOAP implementation. You should not normally need to set this parameter.', 1],

 'Timeout'         => 
 ['integer', 'This optional parameter specifies the timeout in seconds that will be used during authentication requests sent by Radiator to the RSA Mobile server. The default is 20 seconds.', 1],

 'SOAPTrace'       => 
 ['string', 'This optional parameter enables low level protocol tracing in the SOAP::Lite module. Setting it to \'debug\' will cause details of each incoming and outgoing SOAP request to be printed on STDOUT.', 1],

 );

# RCS version number of this module
$Radius::AuthRSAMOBILE::VERSION = '$Revision: 1.15 $';

# Defines different types of RSA parameters
my $ParameterTypeTEXT_STRING             = 0;
my $ParameterTypeTEXT_NUMERIC            = 1;
my $ParameterTypeHIDDEN                  = 2;
my $ParameterTypeSUBMIT                  = 3;
my $ParameterTypeSUBMIT_NO_VERIFY        = 4;
my $ParameterTypeTEXT_LABEL              = 5;
my $ParameterTypeTEXT_PASSWORD           = 6;
my $ParameterTypeTEXT_DATE               = 7;
my $ParameterTypeTEXT_READ_ONLY          = 8;
my $ParameterTypeON_LOAD_ALERT           = 9;
my $ParameterTypeSUBMIT_TIMEOUT          = 10;
my $ParameterTypeTEXT_FORMAT             = 11;
my $ParameterTypeTEXT_OPTION             = 12;
my $ParameterTypeTEXT_NO_LABEL_SMALL     = 13;
my $ParameterTypeTEXT_BLUE_LABEL         = 14;
my $ParameterTypeTEXT_FORMAT_SMALL       = 15;

# Status codes in the authStatus field within AuthenticationAPIResponse.
my $AuthStatusRESOURCE_NOT_PROTECTED     = -1;
my $AuthStatusMETHOD_SATISFIED           = 0;
my $AuthStatusPOLICY_SATISFIED           = 1;
my $AuthStatusMETHOD_FAILED              = 2;
my $AuthStatusPOLICY_FAILED              = 3;
my $AuthStatusMETHOD_CONTINUE            = 4;
my $AuthStatusPOLICY_UNRESOLVED          = 5;
my $AuthStatusMETHOD_NOT_ALLOWED         = 6;
my $AuthStatusNEXUS_LICENSE_CHECK_FAILED = 7;

my $rsamobile_context_id = 0;

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
    $self->{Protocol} = 'http';
    $self->{Host} = 'localhost:7001';
    $self->{Endpoint} = '%0://%1/axis/services/AuthenticationAPI';
    $self->{URI} = 'http://rsa.com/csf/clientservice/authenticationapi/AuthenticationAPI';
    $self->{Policy} = '*System Policy: RSA Mobile Only';
    $self->{SessionRealm} = 'weblogic';
    $self->{SessionUsername} = 'authapiuser';
    $self->{SessionPassword} = 'changeit';
    $self->{Timeout} = 20;
}

#####################################################################
# This is a bogus findUser that basically does nothing but does not
# fail
sub findUser
{
    return Radius::User->new();
}

#####################################################################
# We subclass this to do nothing: there are no check items
# except the password, and only if its not an EAP
sub checkUserAttributes
{
    my ($self, $user, $p) = @_;
    
    # Short circuit authentication in EAP requests ?
    return ($main::ACCEPT) 
      if $p->getAttrByNum($Radius::Radius::EAP_MESSAGE);

    return $self->check_plain_password($p->getUserName(), $p->decodedPassword(), undef, $p);
}

#####################################################################
# $submitted_pw is the password being authenticated
# $pw is the correct password if known
# $user is the user name to be authenticated
sub check_plain_password
{
    my ($self, $user, $submitted_pw, $pw, $p, $encrypted) = @_;

    return ($main::ACCEPT) if $self->{NoCheckPassword};

    # This receives the state from any previous
    # cycle of authentication
    my $state = $p->getAttrByNum($Radius::Radius::STATE);
    my ($result, $message, $id, $context);
    if ($state =~ /^RSAMOBILE=(\d+)$/)
    {
	# Follow on with m ore data from an existing conversation
	$context = Radius::Context::find("rsamobile:$1");
	if ($context)
	{
	    $id = $1;
	    $context->{identity} = $user;
	    ($result, $message) =  $self->continue($context, $submitted_pw);
	}
	else
	{
	    # Failure
	    $self->end($context);
	    return ($main::REJECT, "RSA Mobile failure: stale context");
	}
    }
    else
    {
	# New authentication conversation
	$id = $rsamobile_context_id++;
	$context = Radius::Context::get("rsamobile:$id");
	$context->{identity} = $user;
	$context->{pin} = $submitted_pw if $submitted_pw ne '';
	($result, $message) =  $self->start($context);
    }
    if ($result == 2)
    {
	# Prompt for data
	$p->{rp}->addAttrByNum($Radius::Radius::STATE, "RSAMOBILE=$id");
	$p->{rp}->addAttrByNum($Radius::Radius::REPLY_MESSAGE, $message);
	return ($main::CHALLENGE, 'RSA Mobile data request');
    }
    elsif ($result == 1)
    {
	# Success
	$self->end($context);
	return ($main::ACCEPT);
    }
    else
    {
	# Failure
	$self->end($context);
	return ($main::REJECT, "RSA Mobile failure: $message");
    }
}

#####################################################################
# This is called by the EAP_6 GTC code
# Return (2, challenge) for a challenge
#        (1, message) for success
#        (0, message) for failure
sub gtc_start
{
    my ($self, $context, $user) = @_;

    return $self->start($context);
}

#####################################################################
# This is called by the EAP_6 GTC code
# Return (2, challenge) for a challenge
#        (1, message) for success
#        (0, message) for failure
sub gtc_continue
{
    my ($self, $context, $user, $data, $p) = @_;

    return $self->continue($context, $data);
}

#####################################################################
# This is called by the EAP_6 GTC code
# Return (2, challenge) for a challenge
#        (1, message) for success
#        (0, message) for failure
sub gtc_end
{
    my ($self, $context, $user) = @_;

    return $self->end($context);
}

#####################################################################
# $contrext->{rsamobile_som} contains a (possibly partly) processed
# SOAP response. Find the next prompt to process, or perhaps 
# return a success
sub continue
{
    my ($self, $context, $data) = @_;

    $self->log($main::LOG_DEBUG, "RSA Mobile continue $data");
    my $apiresponse = $context->{rsamobile_som}->result;
    return (0, 'No SOAP API response') unless $apiresponse;

    $context->{rsamobile_authContext} = $apiresponse->{authContext};
    my $authStatus = $apiresponse->{authStatus};

    if ($authStatus == $AuthStatusMETHOD_CONTINUE)
    {
	my $p;
	# Maybe add some new data to the outgoing parameters
	if (defined $data)
	{
	    $p = $apiresponse->{requiredParameters}[$context->{rsamobile_index}++];
	    $self->add_parameter($context, $p->{id}, $data);
	}

	# We are part way through collecting prompt replies for this SOAP response

	while ($p = $apiresponse->{requiredParameters}[$context->{rsamobile_index}])
	{
	    my $type = $p->{type};
	    if ($type == $ParameterTypeTEXT_STRING
		|| $type == $ParameterTypeTEXT_NUMERIC
		|| $type == $ParameterTypeTEXT_PASSWORD)
	    {
		# Prompt the user for this required parameter
		# REVISIT: if the prompt if for username or password maybe can satisfy immediately
		my $id = $p->{id};
		my $prompt = $p->{prompt};
		if (($id eq 'AUTH_USERID_PROMPT'
		     || $id eq '1200'
		     || $prompt eq 'User ID:')
		    && defined $context->{identity})
		{
		    $self->add_parameter($context, $p->{id}, $context->{identity});
		}
		elsif (($id eq 'AUTH_PIN_PROMPT'
			|| $id eq '1201'
			|| $prompt eq 'Password:'
			|| $prompt eq 'PIN:')
		       && defined $context->{pin})
		{
		    $self->add_parameter($context, $p->{id}, $context->{pin});
		    # Never use the PIN again: if its wrong, RSA will just keep asking for it
		    delete $context->{pin};
		}
		else
		{
		    # Have to ask the user for it

		    # If this is the Tokencode prompt, we may also have
		    # some additional information for the user about what 
		    # SMS message to use
		    if ($id eq 'AUTH_TOKENCODE_PROMPT')
		    {
			my $nextp = $apiresponse->{requiredParameters}[$context->{rsamobile_index} + 1];
			if ($nextp && $nextp->{id} eq 'TOKEN_MESSAGE_SUBJECT')
			{
			    $prompt = $prompt . ' ' . $nextp->{prompt} . $nextp->{defaultValue} . ':';
			}
		    }

		    # Maybe there is some extra info from RSA Mobile?
		    my $info = $apiresponse->{info};
		    $prompt = "$info\r\n$prompt" if length $info;
		    return (2, 'CHALLENGE=' . $prompt);
		}
	    }
	    elsif ($type == $ParameterTypeHIDDEN)
	    {
		$self->add_parameter($context, $p->{id}, $p->{defaultValue});
	    }
	    # else ignore this one
	    $context->{rsamobile_index}++;
	}
	
	# If we get to here, all the required paramters resulting from the last 
	# request have been gathered. Now its time to submit them to RSA Mobile
	my ($result, $message) = $self->call_soap($context, 'continueAuth', 'ns2');
	return ($result, $message) unless $result;
	# Yes, this is recursive
	return $self->continue($context);
    }
    elsif ($authStatus == $AuthStatusPOLICY_SATISFIED)
    {
	return (1); # All done
    }
    elsif ($authStatus == $AuthStatusRESOURCE_NOT_PROTECTED)
    {
	# Something wrong
	return (0, "$self->{Resource} - Resource is not protected:  $apiresponse->{info}");
    }
    else
    {
	# Something wrong
	return (0, "Authentication failed: $authStatus: $apiresponse->{info}");
    }
}


#####################################################################
# Initiate a new SOAP conversation
sub start
{
    my ($self, $context) = @_;

    my $endpoint = &Radius::Util::format_special
	($self->{Endpoint}, undef, undef,
	 $self->{Protocol}, $self->{Host});

    $self->log($main::LOG_DEBUG, "RSA Mobile start $endpoint");

    SOAP::Trace->import($self->{SOAPTrace}) if defined $self->{SOAPTrace};
    $context->{rsamobile_search} = SOAP::Lite
	->readable(1)
	->xmlschema('http://www.w3.org/2001/XMLSchema')
	->on_action( sub { return '""';} ) # So SOAPAction is correct
	->proxy($endpoint, 
		timeout => $self->{Timeout},
		cookie_jar => HTTP::Cookies->new(ignore_discard => 1),
		credentials => [$self->{Host}, $self->{SessionRealm}, 
				$self->{SessionUsername}, $self->{SessionPassword}])
	->uri($self->{Uri});

    return (0, 'SOAP initialisation failed') unless $context->{rsamobile_search};

    my ($result, $message) = $self->call_soap($context, 'startAuth', 'ns1');
    return ($result, $message) unless $result;

    $context->{rsamobile_authContext} = undef;
    return $self->continue($context);
}

#####################################################################
sub end
{
    my ($self, $context) = @_;

    $self->log($main::LOG_DEBUG, "RSA Mobile end");
    return $self->call_soap($context, 'endAuth', 'ns1');
}

#####################################################################
# Format and call the RAS Mobile SOAP rpc
sub call_soap
{
    my ($self, $context, $call_type, $namespace) = @_;

    $self->log($main::LOG_DEBUG, "Calling SOAP $call_type, $namespace");
    my $method = SOAP::Data->name($call_type)
	->prefix($namespace)
	->uri($self->{URI});

    my $params = SOAP::Data
	->name('request' =>	\SOAP::Data->value
	       (
		SOAP::Data->name('authContext' => $context->{rsamobile_authContext})->type('xsd:string'),
		SOAP::Data->name('lang'        => $self->{Lang})->type('xsd:string'),
		SOAP::Data->name('country'     => $self->{Country})->type('xsd:string'),
		SOAP::Data->name('policy'      => $self->{Policy})->type('xsd:string'),
		SOAP::Data->name('resource'    => $self->{Resource})->type('xsd:string'),
		SOAP::Data->name('parameters'  => \@{$context->{rsamobile_parameters}}),
		));

    my $som;
    # Can get a die inside the call if there is a timeout
    eval {$som = $context->{rsamobile_search}->call($method, $params);};

    return (0, "SOAP call failed: $@") unless $som;
    
    if ($som->fault)
    {
	my $faultcode = $som->faultcode;
	my $faultstring = $som->faultstring;
	return (0, "SOAP Fault $faultcode: $faultstring");
    }

    $context->{rsamobile_som} = $som;
    $context->{rsamobile_index} = 0; # Where we are up to in processing required params
    @{$context->{rsamobile_parameters}} = (); # New list of parameters to send
    return (1);
}

#####################################################################
# Add the id and value of a required parameter to the list of parmateres that 
# will be sent in the next soap_call
sub add_parameter
{
    my ($self, $context, $id, $value) = @_;

    push (@{$context->{rsamobile_parameters}}, 
	  SOAP::Data->name
	  ('item' => \SOAP::Data->value
	   (
	    SOAP::Data->name('id' => $id)->type('xsd:string'),
	    SOAP::Data->name('value' => $value)->type('xsd:string'),
	    ))->type('ns2:APIParameter'));
}

1;
