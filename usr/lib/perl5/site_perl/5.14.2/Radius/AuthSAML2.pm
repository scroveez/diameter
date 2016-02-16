# AuthSAML2.pm
#
# Object for handling Authentication via a SAML2/Moonshot SOAP
# over HTTP or HTTPS.
# Sends a SAML2 request to a remote SAML2 server.
#
# Caution: the overheads of creating and processing SAML2 requests
# mean you will never get carrier class performance from AuthBy SAML2
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001 Open System Consultants
# $Id: AuthSAML2.pm,v 1.1 2011/12/06 07:08:38 mikem Exp $

package Radius::AuthSAML2;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Net::SAML2;
use File::Slurp;
use strict;

%Radius::AuthSAML2::ConfigKeywords = 
('IdPMetadata'        => 
 ['string', 'File name of the metadata file containing the information about the IdP or AAA system to contact. You must get this from the IdP or AAA operator', 0],

'ECPServerAccessPassword'        => 
 ['string', 'Password used to authenticate access to the ECP Web server', 0],

'SPEntityID'        => 
 ['string', 'Identity that identifies this instance of Radiator to the IdP or AAA. You must previously have sent the metadata for this instance of Radiator, acting as an SP to the IdP or AAA operator, and SPEntityID must match the EntityDescriptor entityID in that metadata.', 0],

'SPKeyFile'        => 
 ['string', 'File name of the file containing the PEM format private key which will be used to sign requests when SignRequest is enabled. This must be a PEM format private key, unencrypted.', 0],

'SPCertificateFile'        => 
 ['string', 'File name of the file containing the PEM format certificate which will be used to sign requests when SignRequest is enabled. It must be the certificate that matches SPKeyFile.', 0],

'IdPCACertificateFile'        => 
 ['string', 'File name of the file containing the CA Certificate of the certificate in the IdPMetadata. Used to verify the IdP Certificate is valid', 0],

'UseECP'        => 
 ['flag', 'Indicates whether ECP should be used to request the SAML Assertion from the IdP', 0],

'SignRequest'        => 
 ['flag', 'Indicates whether Requests sent to the IdP should be signed using the SP certificate from SPCertificateFile', 0],

'VerifyResponse'        => 
 ['flag', 'Indicates whether responses from teh IdP should have the Signature verified against the IdP certificate in IdPMetadata', 0],

 );

# RCS version number of this module
$Radius::AuthSAML2::VERSION = '$Revision: 1.1 $';

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();

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
    
    $self->{IdPMetadata} = '/usr/local/etc/moonshot/metadata.xml';
    $self->{SignRequest} = 1;
    $self->{VerifyResponse} = 1;
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

    $self->create_ua();
    $self->read_idp_metadata();

    if ($self->{UseECP})
    {
	# Create and send an ECP AuthnRequest
	my $x = XML::Generator->new(':pretty');
	my $saml  = ['ns2' => 'urn:oasis:names:tc:SAML:2.0:assertion'];
	my $samlp = ['ns1' => 'urn:oasis:names:tc:SAML:2.0:protocol'];
	my $soap = ['ns0' => 'http://schemas.xmlsoap.org/soap/envelope/'];
	
	my $id = unpack 'H*', Crypt::OpenSSL::Random::random_pseudo_bytes(16);
	my $dt = DateTime->now( time_zone => 'UTC' );
	# xml() produces a ref, so we do this append to force it into a string
	# else POST escapes the content
	my $soap_req = '' . $x->xml(
	    $x->Envelope(
		$soap,
		$x->Body(
		    $soap,
		    $x->AuthnRequest(
			$samlp,
			{ AssertionConsumerServiceURL => $self->{SPEntityID} . 'ECP',
			  Destination => $self->{destination_sso_ecp_url},
			  ID => $id,
			  IssueInstant => $dt,
			  ProtocolBinding => 'urn:oasis:names:tc:SAML:2.0:bindings:PAOS',
			  Version => '2.0' 
			},
			$x->Issuer(
			    $saml,
			    { Format => 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
			    },
			    $self->{SPEntityID},
			),
			$x->NameIDPolicy(
			    $samlp,
			    { Format => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent' 
			    },
			)
		    )
		)
	    ));

	# Maybe sign the request
	# Caution: this is not know to be correct: the test server
	# did not accept signed requets from any client we tested with
	if ($self->{SignRequest})
	{
	    my $sig = Net::SAML2::XML::Sig->new({ 
		x509 => 1,
		key  => $self->{SPKeyFile},
		cert => $self->{SPCertificateFile}
						});
	    $soap_req = $sig->sign($soap_req);
	}
	
	$self->log($main::LOG_EXTRA_DEBUG, "Sending SOAP request to $self->{destination_sso_ecp_url}: $soap_req");
	
	# Tell our UserAgent subclass the credentials to use
	$self->{ua}->set_credentials($p->getUserName(), $self->{ECPServerAccessPassword});
	my $response = $self->{ua}->post($self->{destination_sso_ecp_url}, 
					 'x-moonshot-username' => $p->getUserName(), 
					 Content => $soap_req);
	if (!$response)
	{
	    $self->log($main::LOG_ERR, "No response from $self->{destination_sso_ecp_url}");
	    return ($main::IGNORE, 'No response from SAML2 IdP');
	}
	my $content = $response->content();
	if (!$content)
	{
	    $self->log($main::LOG_ERR, "No content in response from $self->{destination_sso_ecp_url}");
	    return ($main::IGNORE, 'No content in response from SAML2 IdP');
	}
	
	$self->log($main::LOG_EXTRA_DEBUG, "Received SOAP response from $self->{destination_sso_ecp_url}: $content");
	# Got something back, lets look at it:
	my $parser = XML::XPath->new(xml => $content);
	if (!$parser)
	{
	    $self->log($main::LOG_ERR, 'Unable to create XML Parser');
	    return ($main::REJECT, 'Software error');
	}
	$parser->set_namespace('soap-env', 'http://schemas.xmlsoap.org/soap/envelope/');
	$parser->set_namespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
	$parser->set_namespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
	$parser->set_namespace('status', 'urn:oasis:names:tc:SAML:2.0:status');

	my $in_response_to_id = $parser->findvalue('//soap-env:Envelope/soap-env:Body/samlp:Response/attribute::InResponseTo');
	if ($in_response_to_id ne $id)
	{
	    $self->log($main::LOG_ERR, "Incorrect ID in response: expected $id, got $in_response_to_id");
	    return ($main::REJECT, 'Incorrect ID in response');
	}

	my $issuer = $parser->findvalue('//soap-env:Envelope/soap-env:Body/samlp:Response/saml:Issuer');
	if ($issuer ne $self->{idp_entity_id})
	{
	    $self->log($main::LOG_ERR, "Incorrect Issuer in response: expected $self->{idp_entity_id}, got $issuer");
	    return ($main::REJECT, 'Incorrect SAML2 Issuer in response');
	}

	my $status = $parser->findvalue('//soap-env:Envelope/soap-env:Body/samlp:Response/samlp:Status/samlp:StatusCode/attribute::Value');
	if ($status !~ /Success/)
	{
	    $self->log($main::LOG_ERR, "Incorrect Status in response: $status");
	    return ($main::REJECT, 'Incorrect SAML2 Status in response');
	}
	
	if ($self->{VerifyResponse})
	{
	    my $sig = Net::SAML2::XML::Sig->new({ 
		x509 => 1,
		cert_text => $self->{idp_cert},
						});
	    if (!$sig->verify($content))
	    {
		$self->log($main::LOG_ERR, 'Could note verify Signature in response');
		return ($main::REJECT, 'Could not verify Signature in response');
	    }
	}

	my $assertion = $parser->findnodes_as_string('//soap-env:Envelope/soap-env:Body/samlp:Response/saml:Assertion');
	if (!$assertion)
	{
	    $self->log($main::LOG_ERR, "No Assertion in reply from $self->{destination_sso_ecp_url}");
	    return ($main::REJECT, 'No Assertion in reply from IdP');
	}
	
	# Encode the assertion in the reply
	my $saml_aaa_assertion = q|<?xml version=\'1.0\' encoding=\'UTF-8\'?>| . $assertion;

	$p->{rp}->add_attr('SAML-AAA-Assertion', $saml_aaa_assertion);
    }

    return ($main::ACCEPT);

}

#####################################################################
# Create the user agent if there is not one already
sub create_ua
{
    my ($self) = @_;

    return 1 if $self->{ua};
    $self->{ua} = Radius::AuthSAML2::UserAgent->new;
    return 1 if $self->{ua};
    $self->log($main::LOG_ERR, "Could not create UserAgent for sending requests");
    return; # Fail
}

#####################################################################
# Create the IdP metadata if there is not one already
sub read_idp_metadata
{
    my ($self) = @_;

    return 1 if $self->{idp};

    $self->log($main::LOG_DEBUG, "Reading IdP metadata from $self->{IdPMetadata}");
    my $metadata = read_file($self->{IdPMetadata});
    if (!length($metadata))
    {
	$self->log($main::LOG_ERR, "Could not read metadata from $self->{IdPMetadata}");
	return;
    }

    $self->{idp} = Net::SAML2::IdP->new_from_xml( xml => $metadata, cacert => $self->{IdPCACertificateFile});
    if (!$self->{idp})
    {
	$self->log($main::LOG_ERR, "Could not create IdP from $self->{IdPMetadata} and $self->{IdPCACertificateFile}");
	return;
    }
    $self->{idp_cert} = $self->{idp}->cert('signing');
    $self->{idp_cert} = $self->{idp}->cert('') unless defined $self->{idp_cert}; # any use
    if (!$self->{idp_cert})
    {
	$self->log($main::LOG_ERR, "Could not find a signing certificate in $self->{IdPMetadata}");
	return;
    }
    $self->{destination_sso_ecp_url} = $self->{idp}->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:SOAP');
    $self->{idp_entity_id} = $self->{idp}->{entityid};

    return 1;
}

#####################################################################
#####################################################################
#####################################################################
# This subclass exists to override get_basic_credentials so we can supply web server 
# access username and password without knowning the Realm name of the server
package Radius::AuthSAML2::UserAgent;
use base ('LWP::UserAgent');

#####################################################################
sub set_credentials
{
    my ($self, $username, $password) = @_;

    $self->{username} = $username;
    $self->{password} = $password;
}

#####################################################################
# Override get_basic_credentials so we can supply our preconfigured username and password
sub get_basic_credentials
{
    my ($self, $realm, $uri, $isproxy) = @_;

    print "get_basic_credentials $self, $realm, $uri, $isproxy\n";
    return ($self->{username}, $self->{password});
}

1;
