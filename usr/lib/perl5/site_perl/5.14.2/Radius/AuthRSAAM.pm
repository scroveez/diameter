# AuthRSAAM.pm
#
# Object for handling Authentication via RSA Authentication Manager 7.1 and later.
# RSA AM supports a number of authentication methods, including 
# - RSA Secureid Token Car
# - Static Passwords
# - On Demand tokencode (by SMS or email)
# - A series of user-configured security questions
# and all of these can be configured with AuthBy RSAAM
#
# This code supports conventional Radius Access-Accept/Access-Challenge
# conversations, as well as EAP-Generic Token Card and
# EAP-PEAP-Generic Token Card.
#
# Requires SOAP::Lite and all its prerequisites for SSL, 
# including Crypt::SSLeay or IO::Socket::SSL+Net::SSLeay
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2003 Open System Consultants
# $Id: AuthRSAAM.pm,v 1.15 2014/03/17 15:48:09 hvn Exp $

package Radius::AuthRSAAM;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Radius::Context;
#use IO::Socket::SSL qw(debug3); # For verbose debugging
use SOAP::Lite;
use HTTP::Cookies;
use MIME::Base64;
use strict;

%Radius::AuthRSAAM::ConfigKeywords = 
('Endpoint'        => 
 ['string', 'This optional parameter specifies how to create the endpoint of the SOAP connection to the RSA AM server. Special characters are permitted. %0 is replaced by the value of the Protocol parameter (see Section 5.54.2 on page 174) and %1 is replaced by the value of the Host parameter (see Section 5.54.2 on page 174). The default is %0://%1/ims-ws/services/CommandServer. 
You should not normally need to change this.', 1],

 'Protocol'        => 
 ['string', 'This optional parameter specifies the protocol that will be used to contact the RSA AM server. It is used as %0 in the Endpoint parameter. The default is "https". You should not normally need to change this.', 1],

 'Host'            => 
 ['string', 'This parameter specifies the address and port number of the RSA AM server. It is used as %1 in the Endpoint parameter. The default is "localhost:7002". You will have to change this to the hostname/address and port number of your RSA AM server, since by default AM does not listen on localhost. 7002 is the usual port number for RSA AM.', 0],

 'URI'             => 
 ['string', 'This optional parameter specifies the SOAP URI that will be accessed in the RSA AM server. The default is "http://webservice.rsa.com/". You should not normally need to change this. Note that this is not the address of a web resource and it is not accessed by Radiator during authentication.', 1],

 'Policy'          => 
 ['string', 'This optional parameter specifies the authentication policy that is to be used.', 0],

 'SessionUsername' => 
 ['string', 'This parameter specifies a username that will be used to contact the RSA AM HTTPS server. You will certainly have to set this to suit the configuration of your RSA AM server. See your RSA AM administrator for information about how to find out what the Command Client username and password are.', 0],

 'SessionPassword' => 
 ['string', 'This parameter specifies the password that will be used to contact the RSA AM HTTP server. You will certainly have to set this to suit the configuration of your RSA AM server. See your RSA AM administrator for information about how to find out what the Command Client username and password are.', 0],

 'SessionRealm'    => 
 ['string', 'This optional parameter specifies the HTTP Realm that the SessionUsername and SessionPassword will be used for. The default is "myrealm", which matches the RSA AM Server SOAP implementation. You should not normally need to set this parameter. Obsolete and unused', 3],

 'Timeout'         => 
 ['integer', 'This optional parameter specifies the timeout in seconds that will be used during authentication requests sent by Radiator to the RSA AM server. The default is 20 seconds.', 1],

 'SOAPTrace'       => 
 ['string', 'This optional parameter enables low level protocol tracing in the SOAP::Lite module. Setting it to \'debug\' will cause details of each incoming and outgoing SOAP request to be printed on STDOUT.', 1],

 'Message'       => 
 ['stringhash', 'This optional parameter enables customisation of various user messages generated by this module. The key for each message is the RSA AM message, and the value is the string you want the user to see', 1],

 'ChallengePrefix'       => 
 ['string', 'This optional parameter sets the prefix for all Access-Challenge responses. Empty value is allowed. Defaults to "CHALLENGE=".', 2],

 'ChallengeHasPrompt'       => 
 ['flag', 'This optional parameter enables sending RADIUS Prompt attribute with Access-Challenge responses. Prompt value is based on the RSA AM responses. Defaults to off.', 1],

 'SSLVerify' =>
 ['string',
  'May be used to control how the RSA AM HTTPS server\'s certificate will be verified. May be one of "none", "optional" or "require".',
  1],

 'SSLCAPath' =>
 ['string', 'When verifying the RSA AM HTTPS server\'s certificate, set this to the pathname of the directory containing CA certificates. These certificates must all be in PEM format. The directory in must contain certificates named using the hash value of the certificates\' subject names.',
  1],

 'SSLCAFile' =>
 ['string',
  'When verifying the RSA AM HTTPS server\'s certificate, set this to the filename containing the certificate of the CA who signed the server\'s certificate. The certificate must be in PEM format.',
  1],

 'SSLVerifyCNName' =>
 ['string',
  'When verifying the RSA AM HTTPS server\'s certificate, the name which is used in verification of server\'s name.',
  1],

 'SSLVerifyCNScheme' =>
 ['string',
  'When verifying the RSA AM HTTPS server\'s certificate, the scheme used to automatically verify the name of the server as documented by Perl module IO::Socket::SSL. If set, value "http" is recommended.',
  1],

 'SSLCertificateVerifyHook' =>
 ['hook',
  'This optional parameter specifies a perl function that will be called after the request username or identity has been matched with the certificate CN. It is passed the certificate, and various other details, and returns 1 or 0 for valid or unvalid.',
  2],

 'SSL_CertificateFile'      => 
 ['string', 
  'Specifies the name of a client certificate file which will be use to authenticate SSL connection to the AM server. The certificate will be sent to the AM server SSL authentication. The certificate file must be in PEM. The certificate file can also contain the client\'s TLS private key if the SSL_PrivateKeyFile parameter specifies the same file. Not required if AM does not require client certificate authentication', 
  1],

 'SSL_PrivateKeyFile'       => 
 ['string', 
  'Specifies the the name of the file containing the SSL client\'s private key. It is sometimes in the same file as the client certificate (SSL_CertificateFile). The private key must not be encrypted and must not require a passphrase.', 
  1],

# Not working yet:
# 'SSL_PrivateKeyPassword'   => 
# ['string', 
#  'This optional parameter specifies the password that is to be used to decrypt the SSL_PrivateKeyFile. Special characters are permitted.', 
#  1],


 );

# RCS version number of this module
$Radius::AuthRSAAM::VERSION = '$Revision: 1.15 $';

my $rsaam_context_id = 0;

# Converts AM promptKeys and message codes
# into user readable prompt strings, used
# where there is no other info about what the user has to enter
my %promptStrings =
(
 'AUTHENTICATIONSERVICE_PRINCIPALID' => 'Username',
 'PASSWORD_CREDENTIAL'               => 'Password',
 'ACEPROXY_PASSCODE'                 => 'Passcode',
 'ACEPROXY_NEWPIN'                   => 'Enter new PIN',
 'ACEPROXY_VERIFY'                   => 'Verify new PIN',
 'ACEPROXY_SYSPIN'                   => 'Enter new System generated PIN: ',
 'NEXT_TOKENCODE'                    => 'Next Tokencode',
 'PASSWORD_NEW_PASSWORD'             => 'New Password',
 'PASSWORD_CONFIRM_NEW_PASSWORD'     => 'Confirm New Password',
 'PIN'                               => 'Pin',
 'Tokencode'                         => 'Tokencode',
 'AUTHN_PASSWORD_CANNOT_REUSE'       => 'Cant reuse that password',
 'AUTHN_PWD_CHANGE_FAILED_CONFIRM_NEW' => 'Password change failed',
 'AUTHN_PASSWORD_INVALID_LENGTH'     => 'Password change failed. Invalid length',
 'AUTHN_PASSWORD_CHAR_REQS',         => 'Password change failed. Does not meet requirements',
 'UPDATED_PIN',                      => 'Enter new PIN',
 'UPDATED_PIN_CONFIRM',              => 'Verify new PIN',
 'POLICY_VIOLATION_PIN_CANNOT_REUSE' => 'Policy Violation: PIN cannot be reused',
 'POLICY_VIOLATION_PIN_INVALID_LENGTH' => 'Policy Violation: Invalid PIN length',
 'POLICY_VIOLATION_PIN_NUMERIC_PROHIBITED', => 'Policy Violation: Numeric PIN prohibited',
 'POLICY_VIOLATION_PIN_ALPHA_PROHIBITED', => 'Policy Violation: Alphabetic PIN prohibited',
 'System Generated Pin'              => 'Enter new System Generated Pin: ',
 'SECURITY_QUESTION_1'               => '',
 'SECURITY_QUESTION_2'               => '',
 'SECURITY_QUESTION_3'               => '',
 'SECURITY_QUESTION_4'               => '',
 'SECURITY_QUESTION_5'               => '',
 'SECURITY_QUESTION_6'               => '',
 'SECURITY_QUESTION_7'               => '',
 'SECURITY_QUESTION_8'               => '',
 'SECURITY_QUESTION_9'               => '',
 'SECURITY_QUESTION_10'              => '',
 'SECURITY_QUESTION_11'              => '',
 'SECURITY_QUESTION_12'              => '',
 'SECURITY_QUESTION_13'              => '',
 'SECURITY_QUESTION_14'              => '',
 'SECURITY_QUESTION_15'              => '',
 'SECURITY_QUESTION_16'              => '',
 'SECURITY_QUESTION_17'              => '',
 'SECURITY_QUESTION_18'              => '',
 );

# Some types allow you to send the pin or password in the initial AM request
# Maps authentication types to the name of the initial password parameter
# that can be passed in the first request for early authentication
my %password_param_name = 
(
 'SecurID_Native' => 'ACEPROXY_PASSCODE',
 'OnDemand'       => 'PIN',
 'LDAP_Password'  => 'PASSWORD_CREDENTIAL',
 'RSA_Password'   => 'PASSWORD_CREDENTIAL',
 );

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
    $self->{Protocol} = 'https';
    $self->{Host} = 'localhost:7002';
    $self->{Endpoint} = '%0://%1/ims-ws/services/CommandServer';
    $self->{URI} = 'http://webservice.rsa.com/';
    $self->{Policy} = 'RSA_Password';
    $self->{SessionRealm} = 'myrealm'; # Was changed to 'weblogic' at SP3. AuthRSAAM now does not need this
    $self->{Timeout} = 20;
    %{$self->{Message}} = %promptStrings;
    $self->{ChallengePrefix} = 'CHALLENGE=';
    $self->{can_check_certs} = 0; # Set later to 1 if we have LWP 6.0 or better and IO::Socket::SSL
}

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    # Without recent enough LWP we can not do check certs
    eval {
	require LWP;
	require IO::Socket::SSL;
    };
    my $msg = "AuthBy RSAAM needs LWP 6.0 or later and IO::Socket::SSL when SSL server certificate check options are defined.";
    $msg .= " $@" if $@;

    $self->{can_check_certs} = 1 if !$@ && $LWP::VERSION >= 6;

    if (defined $self->{SSLVerify} ||
        defined $self->{SSLCAPath} ||
        defined $self->{SSLCAFile} ||
	defined $self->{SSLVerifyCNName} ||
	defined $self->{SSLVerifyCNScheme} ||
	defined $self->{SSLCertificateVerifyHook})
    {
	$self->log($main::LOG_ERR, $msg) unless $self->{can_check_certs};
    }

    if (   (!defined $self->{SSLVerifyCNName} &&  defined $self->{SSLVerifyCNScheme})
        || ( defined $self->{SSLVerifyCNName} && !defined $self->{SSLVerifyCNScheme}))
    {
        $self->log($main::LOG_WARNING, "AuthBy RSAAM You should define both SSLVerifyCNName and SSLVerifyCNScheme or neither.");
    }

    $self->SUPER::check_config();
    return;
}

#####################################################################
# This will be called after the instance is created and after
# parameters have been changed during online reconfiguration.
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate;

    return;
}


#####################################################################
# Collect the certificate verify options from the current configuration.
sub get_ssl_opts
{
    my ($self) = @_;

    my %ssl_verify = ( 'none' => 0, 'optional' => 1, 'require' => 3 );
    my %ssl_opts;

    # Set some options to keep LWP::UserAgent from setting them
    # from environment variables
    $ssl_opts{SSL_ca_file} =  $ssl_opts{SSL_ca_path} = undef;
    $ssl_opts{verify_hostname} = 1;

    $ssl_opts{SSL_ca_file} = Radius::Util::format_special($self->{SSLCAFile})
        if defined $self->{SSLCAFile};
    $ssl_opts{SSL_ca_path} = Radius::Util::format_special($self->{SSLCAPath})
        if defined $self->{SSLCAPath};

    $ssl_opts{SSL_verify_mode} = $ssl_verify{ lc($self->{SSLVerify}) }
        if defined $self->{SSLVerify};
    $ssl_opts{verify_hostname} = 0 if $self->{SSLVerify} eq 'none';

    $ssl_opts{SSL_verify_callback} = sub {Radius::AuthRSAAM::verifyCallback($self, @_);}
        if defined $self->{SSLCertificateVerifyHook};

    $ssl_opts{SSL_verifycn_name} = $self->{SSLVerifyCNName}
        if defined $self->{SSLVerifyCNName};
    $ssl_opts{SSL_verifycn_scheme} = $self->{SSLVerifyCNScheme}
        if defined $self->{SSLVerifyCNScheme};

    # SSL client certificate settings.
    $ssl_opts{SSL_cert_file} = Radius::Util::format_special($self->{SSL_CertificateFile})
        if defined $self->{SSL_CertificateFile};
    $ssl_opts{SSL_key_file} = Radius::Util::format_special($self->{SSL_PrivateKeyFile})
        if defined $self->{SSL_PrivateKeyFile};

    return %ssl_opts;
}

#####################################################################
# Called when a SSL certificate presented by the RSA AM HTTPS server
# is to be validated. It will be called for each element in the chain.
# Return value of 1 means valid and 0 means invalid.
sub verifyCallback
{
    my ($self, $certOK, $store, $certname, $error, $peerCertificate) = @_;

    my ($isok) = $self->runHook('SSLCertificateVerifyHook', undef, $certOK, $store, $certname, $error, $peerCertificate);
    unless ($isok)
    {
        $self->log($main::LOG_INFO, "SSLCertificateVerifyHook returned false");
    }
    return $isok ? 1 : 0;
}

#####################################################################
# Radiator 4.12.1 and earlier used environment variables to configure
# client certificates. Keep these for backwards compatibility for
# systems that do not have LWP 6.0 or later but use Crypt-SSLeay
# instead.
sub set_ssl_environment
{
    my ($self) = @_;

    $ENV{HTTPS_CERT_FILE} = &Radius::Util::format_special
	($self->{SSL_CertificateFile})
	if defined $self->{SSL_CertificateFile};
    $ENV{HTTPS_KEY_FILE} = &Radius::Util::format_special
	($self->{SSL_PrivateKeyFile})
	if defined $self->{SSL_PrivateKeyFile};
    $ENV{HTTPS_CERT_PASS} = &Radius::Util::format_special
	($self->{SSL_PrivateKeyPassword})
	if defined $self->{SSL_PrivateKeyPassword};

    return;
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
    my ($self, $user, $p, $user_name) = @_;
    
    # Short circuit authentication in EAP requests ?
    return ($main::ACCEPT) 
      if $p->getAttrByNum($Radius::Radius::EAP_MESSAGE);

    return $self->check_plain_password($user_name, $p->decodedPassword(), undef, $p);
}

#####################################################################
# $submitted_pw is the password being authenticated
# $pw is the correct password if known
# $user is the user name to be authenticated
sub check_plain_password
{
    my ($self, $user_name, $submitted_pw, $pw, $p, $encrypted) = @_;

    return ($main::ACCEPT) if $self->{NoCheckPassword};

    # This receives the state from any previous
    # cycle of authentication
    my $state = $p->getAttrByNum($Radius::Radius::STATE);
    my ($result, $message, $id, $context);
    if ($state =~ /^RSAAM=(\d+)$/)
    {
	# Follow on with more data from an existing conversation
	$context = Radius::Context::find("rsaam:$1");
	if ($context)
	{
	    $id = $1;
	}
	else
	{
	    # Failure
	    $self->end($context);
	    return ($main::REJECT, "RSA AM failure: stale context");
	}
    }
    else
    {
	# New authentication conversation
	$id = $rsaam_context_id++;
	$context = Radius::Context::get("rsaam:$id", $self->{EAPContextTimeout});
    }

    if (defined $context->{rsaam_authenticator})
    {
	if ($context->{rsaam_authenticator} == $self)
	{
	    # Already using this authenticator, keep using it
	    $context->{identity} = $user_name;
	    ($result, $message) =  $self->continue($context, $p, $user_name, $submitted_pw);
	}
	else
	{
	    # Someone else in the middle of this conversation, fall through
	    return ($main::IGNORE, "RSA AM wrong authenticator");
	}
    }
    else
    {
	# First time here, do a start
	$context->{rsaam_authenticator} = $self;
	$context->{identity} = $user_name;
	$context->{initial_pw} = $submitted_pw if $submitted_pw ne '';
	($result, $message) =  $self->start($context, $user_name, $p);
    }

    if ($result == 2)
    {
	# Prompt for data
	$p->{rp}->addAttrByNum($Radius::Radius::STATE, "RSAAM=$id");
	$p->{rp}->addAttrByNum($Radius::Radius::REPLY_MESSAGE, $message);
	return ($main::CHALLENGE, 'RSA AM data request');
    }
    elsif ($result == 1)
    {
	# Success
	$self->end($context);
	return ($main::ACCEPT);
    }
    else
    {
	# 0 = Failure
	$self->end($context);
	$context->{rsaam_authenticator} = undef;
	if ($self->{rsaam_session})
	{
	    # Auth failed for some good reason
	    return ($main::REJECT, "RSA AM failure: $message");
	}
	else
	{
	    # Session connection failure, try to fail over/fall through
	    return ($main::IGNORE, "RSA AM session failure");
	}
    }
}


#####################################################################
# Cant do mschap
sub check_mschap
{
    return 0;
}
sub check_mschapv2
{
    return 0;
}

#####################################################################
# This is called by the EAP_6 GTC code
# Return (2, challenge) for a challenge
#        (1, message) for success
#        (0, message) for failure
sub gtc_start
{
    my ($self, $context, $user_name, $p) = @_;

    return $self->start($context, $user_name, $p);
}

#####################################################################
# This is called by the EAP_6 GTC code
# Return (2, challenge) for a challenge
#        (1, message) for success
#        (0, message) for failure
sub gtc_continue
{
    my ($self, $context, $user_name, $data, $p) = @_;

    return $self->continue($context, $p, $user_name, $data);
}

#####################################################################
# This is called by the EAP_6 GTC code
# Return (2, challenge) for a challenge
#        (1, message) for success
#        (0, message) for failure
sub gtc_end
{
    my ($self, $context, $user_name) = @_;

    return $self->end($context, $user_name);
}

#####################################################################
# $contrext->{rsaam_som} contains a (possibly partly) processed
# SOAP response. Find the next prompt to process, or perhaps 
# return a success
sub continue
{
    my ($self, $context, $p, $user_name, $data) = @_;

    $self->log($main::LOG_DEBUG, "RSA AM continue $data");
    my $apiresponse = $context->{rsaam_som}->result;
    return (0, 'No SOAP API response') unless $apiresponse;

    my $authenticationState = $apiresponse->{authenticationState};

    if ($authenticationState eq 'in_progress')
    {
	my $param;
	# Maybe add some new data to the outgoing parameters
	if (defined $data)
	{
	    $param = $apiresponse->{parameters}[$context->{rsaam_index}++];
	    $self->add_parameter($context, $param->{promptKey}, $data);
	}

	# We are part way through collecting prompt replies for this SOAP response

	while ($param = $apiresponse->{parameters}[$context->{rsaam_index}])
	{
	    my $type = $param->{type};
	    my $promptKey = $param->{promptKey};

	    if ($self->ignore_prompt($promptKey))
	    {
	      # The user should not be bothered with this parameter
	       $context->{rsaam_index}++;
	    }
	    elsif ($promptKey eq $password_param_name{$self->{Policy}}
		&& defined $context->{initial_pw})
	    {
		# print asked for initial password again
		$self->add_parameter($context, $param->{promptKey}, $context->{initial_pw});
		# Never use the PIN again: if its wrong, RSA will just keep asking for it
		delete $context->{pin};
		$context->{rsaam_index}++;
	    }
	    else
	    {
		my $prompt = $self->{Message}{$promptKey};
		$prompt = $promptKey unless defined $prompt;
		$prompt .= $param->{value}; # Maybe a prompt string
		if (defined $apiresponse->{message}{key})
		{

		    my $message = $self->{Message}{$apiresponse->{message}{key}};
		    $message = $apiresponse->{message}{key} unless defined $message;
		    $prompt = "$message\r\n$prompt";
		}
		$self->add_prompt_attribute($p, $param); # Maybe add RADIUS Prompt attribute in reply
		return (2, $self->{ChallengePrefix} . $prompt . ':'); # Ask for the next one
	    }
	}
	
	# If we get to here, all the required paramters resulting from the last 
	# request have been gathered. Now its time to submit them to RSA AM
	my ($result, $message) = $self->call_LoginCommand($context, $p);
	return ($result, $message) unless $result;

	# Process the resaults
	# Yes, this is recursive
	return $self->continue($context, $p, $user_name);
    }
    elsif ($authenticationState eq 'authenticated')
    {
	return (1); # All done
    }
    elsif ($authenticationState eq 'failed')
    {
	# Something wrong
	my $message = $apiresponse->{message}->{key};
	return (0, "Authentication failed: $message");
    }
    else
    {
	# Something wrong
	return (0, "Unknown Authentication State: $authenticationState");
    }
}


#####################################################################
# Initiate a new SOAP conversation
sub start
{
    my ($self, $context, $user_name, $p) = @_;

    if (!$self->{rsaam_session})
    {
	my $endpoint = &Radius::Util::format_special
	    ($self->{Endpoint}, undef, undef,
	     $self->{Protocol}, $self->{Host});

	$self->log($main::LOG_DEBUG, "RSA AM start $endpoint");

	SOAP::Trace->import($self->{SOAPTrace}) if defined $self->{SOAPTrace};
	$self->{rsaam_session} = SOAP::Lite
	    ->readable(1)
	    ->xmlschema('http://www.w3.org/2001/XMLSchema')
	    ->on_action( sub { return '""';} ) # So SOAPAction is correct
	    ->proxy($endpoint, 
		    timeout => $self->{Timeout},
		    cookie_jar => HTTP::Cookies->new(ignore_discard => 1),
# obsolete: use forced basic auth, see below
# so now SessionRealm is obsolete and unused
#		    credentials => [$self->{Host}, $self->{SessionRealm}, 
#				    $self->{SessionUsername}, $self->{SessionPassword}]
	    )
	    ->uri($self->{Uri});

	return (0, 'SOAP initialisation failed') unless $self->{rsaam_session};
	# Force basic auth, requires SOAP::Lite 0.65 and MIME::Base64
	$self->{rsaam_session}->transport->http_request->header
	    (
	     'Authorization' => 
	     'Basic ' . MIME::Base64::encode("$self->{SessionUsername}:$self->{SessionPassword}", '')
	    );

	# With LWP 6.0 we can do advanced cert checks without %ENV
	if ($self->{can_check_certs})
	{
	    $self->{rsaam_session}->transport->ssl_opts($self->get_ssl_opts());
	}
	else
	{
	    $self->set_ssl_environment(); # Old Crypt-SSLeay method
	}
    }

    # Initialise the state that has to be saved between AM requests
    # State for all these items will be copied from reply to the next request
    $context->{rsaam_state}->{authenticationState} = undef;
    $context->{rsaam_state}->{authenticationStep}  = undef;
    $context->{rsaam_state}->{identitySourceGuid}  = undef;
    $context->{rsaam_state}->{principalGuid}       = undef;
    $context->{rsaam_state}->{sessionId}           = undef;

    # Always send the username in the first request
    $self->add_parameter($context, 
			 'AUTHENTICATIONSERVICE_PRINCIPALID', 
			 $user_name);
    # Maybe send password as initial data too:
    if (defined $context->{initial_pw})
    {
	my $parameter = $password_param_name{$self->{Policy}};
	$self->add_parameter($context, $parameter, $context->{initial_pw})
	    if defined $parameter;
    }

    my ($result, $message) = $self->call_LoginCommand($context, $p);
    return ($result, $message) unless $result;

    return $self->continue($context, $p, $user_name);
}

#####################################################################
sub end
{
    my ($self, $context) = @_;

    return 1;
}

#####################################################################
# Format and call the RAS Am SOAP rpc
sub call_LoginCommand
{
    my ($self, $context, $p) = @_;

    $self->log($main::LOG_DEBUG, "Calling SOAP LoginCommand");
    my $method = SOAP::Data->name('executeCommand')
	->prefix('ns1')
	->uri($self->{URI});

    my @state;
    foreach (keys %{$context->{rsaam_state}})
    {
	push (@state, SOAP::Data->name($_ => $context->{rsaam_state}->{$_})->type('xsd:string'));
    }
    my @optionals_params;
    # If the NAS-IP-Address is available, use that to set the netAddress parameter
    # in the RSA SOAP request. This will make it appear in the Client IP field 
    # of the RSA request, and can be used to select user groups etc.
    my $nas_id = $p->getNasId();
    if ($nas_id =~ /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/)
    {
	my $hex_address = unpack('H*', pack('CCCC', $1, $2, $3, $4));
	push(@optionals_params, SOAP::Data->name('netAddress' => $hex_address)->type('ns3:Inet4Address')->prefix('ns2')->uri('http://net.java'));
    }

    my @query = 
	(
	 SOAP::Data->name('in0' => undef)->type('xsd:string'),
	 SOAP::Data->type('ns2:LoginCommand')
	 ->name('in1' => \SOAP::Data->value
		(
		 SOAP::Data->name('authenticationMethodId' => $self->{Policy})->type('xsd:string'),
		 @state,
	     @optionals_params,
		 SOAP::Data->name
		 ('parameters' => 
		  \SOAP::Data->name
		  ('parameters' => 
		   @{$context->{rsaam_parameters}}
		     )->type('ns6:FieldParameterDTO')->prefix('ns6')->uri('http://data.authn.rsa.com'),
		   )->type('ns7:AbstractParameterDTO[1]')->prefix('ns7')->uri('http://data.authn.rsa.com'),
		  )
		 )->prefix('ns2')->uri('http://authn.rsa.com')
	 );
    
    my $som;
    # Can get a die inside the call if there is a timeout
    eval {$som = $self->{rsaam_session}->call($method, @query);};

    if (!$som)
    {
	$self->{rsaam_session} = undef;
	$self->log($main::LOG_WARNING, "SOAP call failed: $@");
	return (0, "SOAP call failed: $@");
    }
    
    if ($som->fault)
    {
	my $faultcode = $som->faultcode;
	my $faultstring = $som->faultstring;
	$self->log($main::LOG_WARNING, "SOAP Fault $faultcode: $faultstring");
	return (0, "SOAP Fault $faultcode: $faultstring");
    }

    $context->{rsaam_som} = $som;
    $context->{rsaam_index} = 0; # Where we are up to in processing required params
    # REVISIT: save state for next time round
    my $apiresponse = $som->result;
    if ($apiresponse->{authenticationState} eq 'in_progress')
    {
	foreach (keys %{$context->{rsaam_state}})
	{
	    $context->{rsaam_state}->{$_} = $apiresponse->{$_};
	}
    }

    @{$context->{rsaam_parameters}} = (); # New list of parameters to send

    $self->log($main::LOG_DEBUG, "LoginCommand result $apiresponse->{authenticationState}, $apiresponse->{authenticationStep}");

    return (1);
}

#####################################################################
# Add the id and value of a required parameter to the list of parmateres that 
# will be sent in the next soap_call
sub add_parameter
{
    my ($self, $context, $key, $value) = @_;

    push (@{$context->{rsaam_parameters}}, 
	  \SOAP::Data->value
	  (
	   SOAP::Data->name('promptKey' => $key)->type('xsd:string'),
	   SOAP::Data->name('value' => $value)->type('xsd:string'),
	   ));
}

#####################################################################
# We may not want to prompt user for every parameter RSA AM sends.
# Return true if this promptKey should be skipped.
sub ignore_prompt
{
    my ($self, $key) = @_;

    # These are used by 8.0 OnDemand mode.
    return 1 if (grep {lc $key eq lc $_} (qw(TokencodeDestinationType TokencodeDestination TokencodeResendRequested)));

    return 0; # Do not ignore this prompt
}

#####################################################################
# RADIUS Prompt attribute can be returned with Access-Challenge to
# instruct the NAS whether it should echo the user's response or not.
sub add_prompt_attribute
{
    my ($self, $p, $param) = @_;

    return unless $self->{ChallengeHasPrompt};

    my $promptvalue;
    $promptvalue = ($param->{masked} && lc $param->{masked} eq 'true') ? 'No-Echo' : 'Echo';
    $p->{rp}->add_attr('Prompt', $promptvalue);

    return;
}

# Handle deserializing of types not defined in the standard schema
# Inet4Address
sub SOAP::Deserializer::typecast 
{
   my ($self, $value, $name, $attrs, $children, $type) = @_; 
   my $retval = undef; 
   if ( "{http://net.java}Inet4Address" == $type ) 
   { 
       $retval = $value; 
   } 
   return $retval; 
}
    
1;
