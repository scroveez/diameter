# AuthDUO.pm
#
# Object for handling Authentication with Duo Security auth API https://www.duosecurity.com/docs/authapi
#
# The Duo auth API does not provide any genuine non-blocking API calls, so we
# are forced to use HTTP::Async and to poll periodically for responses from the remote server.
#
# This module can form the second part of a 2-factor security (after a previous static password check)
# or a single-factor security system.
#
# Depending on the tokens and phones enrolled for a user, the User-Password may be one of:
# An SMS passcode like A061245, B262627, C634177
# A Yubikey passcode, like vvcjnihvlfbvdruiuhrgidrkfleguhblbijndhjjjhku
# An Oath compiant token passocde, like 123456
# A Duo Mobile passcode, generated on demand by the app, like 075764
# the word push, which will cause a Duo push request to the users phone. The user can use Duo Push
#                if they've installed Duo Mobile and added your account to it
# the word phone, which will cause Duo to make a robot voice callback to the users phone
# the word sms, which means to SMS more passcodes to the users device. The authentication will be denied,
#                but the user can then log in again with one of the newly delivered passcodes
# the word auto, which means use the out-of-band factor (push or phone) recommended by Duo as
#                the best for the user's devices, depending on which devices the user has enrolled.
# an empty password, which means to use 'auto'. This is good for adding 2nd factor to existing
#                user populations using static passwords
# If the user has more than one device enrolled, then push, phone, sms and auto can be followed
# by the number of the device to use, such as 'push2' or 'sms3'.
#
# This module can be tested against the duosim.cgi web server script, which can handle the following
# username/passwords:
# mikem/12345 accept
# mikem/12346 reject due to replay
# mikem/<any> reject
# <any>/<any> reject
# <any>/sms   reject
# mikem/push  accept after API delay of 10 seconds
# mikemdeny/push reject after API delay of 10 seconds
# <any>/push  reject
# mikem/      (defaults to push) accept after API delay of 10 seconds
#
# Requires the following additional perl modules:
# Net::HTTPS::NB
# HTTP::Async 0.19 or later
# JSON
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2013 Open System Consultants
# $Id: AuthDUO.pm,v 1.3 2013/09/02 20:39:24 hvn Exp $

package Radius::AuthDUO;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Radius::Context;
use HTTP::Async 0.19;
#use IO::Socket::SSL qw(debug3); # For verbose debugging
use HTTP::Date;
use HTTP::Request;
use JSON;
use Digest::HMAC_SHA1;
use MIME::Base64;
use strict;
use warnings;

%Radius::AuthDUO::ConfigKeywords =
(
'PollTimerInterval' =>
 ['integer', 'Number of seconds between checking for replies from the Duo auth API server. Defaults to 1 second.', 3],

 'Hostname' =>
 ['string', 'Required. Specifies the Duo API hostname of the Auth API server. You must get this from Duo Security when you create the Auth API integration for your organisation. Typically the form is api-aaaaaaaa.duosecurity.com.', 0],

 'EndpointPrefix' =>
 ['string', 'The prefix for the Auth API. Defaults to /auth/v2. You should not need to change this.', 3],

 'Protocol' =>
 ['string', 'The protocol to use to connect to the Auth API server. Defaults to https. You should not need to change this.', 3],

 'SecretKey' =>
 ['string', 'Required. Specifies the Secret Key for the Auth API integration for your organisation. You must get this from Duo Security when you create the Auth API integration for your orginisation. Typically the form is 40 alpha-numeric digits.', 0],

 'IntegrationKey' =>
 ['string', 'Required. Specifies the Integration Key for the Auth API integration for your organisation. You must get this from Duo Security when you create the Auth API integration for your orginisation. Typically the form is 20 alpha-numeric digits.', 0],

 'Slots' =>
 ['integer', 'Specifies the maximum number of simultaneous requests outstanding to the Auth API server, and the maximum number of HTTP connections to the server. If more than this number of requests are waiting, then subsequent requests will be queued and sent after a reply a received from an outstanding request. Defaults to 20.', 3],

 'Timeout' =>
 ['integer', 'Specifies the maximum number of seconds to wait for the start of a reply from the Auth API server. The Auth API server can take up to 60 seconds to reply. Default is 100 seconds. You should not need to change this.', 3],

 'MaxRequestTime' =>
 ['integer', 'Specifies the maximum number of seconds to wait for a complete reply from the Auth API server. The Auth API server can take up to 60 seconds to reply. Default is 120 seconds. You should not need to change this.', 3],

 'ProxyHost' =>
 ['string', 'Specifies the name of a HTTP proxy to use to contact the Auth API server.', 3],

 'ProxyPort' =>
 ['integer', 'Specifies the port on the ProxyHost to use to contact the Auth API server.', 3],

 'Address' =>
 ['string', 'Specifies how to assemble the users address that will be recorded by the Auth API, and which is shown in the Duo Security logs.', 1],

 'DefaultFactor' =>
 ['string', 'If the user does not specify a valid password or factor, this will be the factor requests from Duo. May be one of "push", "sms", "phone", "auto". Defaults to "auto"', 1],

 'SSLVerify' =>
 ['string',
  'May be used to control how the Duo server\'s certificate will be verified. May be one of "none", "optional" or "require".',
  1],

 'SSLCAPath' =>
 ['string', 'When verifying the Duo server\'s certificate, set this to the pathname of the directory containing CA certificates. These certificates must all be in PEM format. The directory in must contain certificates named using the hash value of the certificates\' subject names.',
  1],

 'SSLCAFile' =>
 ['string',
  'When verifying the Duo server\'s certificate, set this to the filename containing the certificate of the CA who signed the server\'s certificate. The certificate must all be in PEM format.',
  1],

 'SSLVerifyCNName' =>
 ['string',
  'When verifying the Duo server\'s certificate, the name which is used in verification of server\'s name.',
  1],

 'SSLVerifyCNScheme' =>
 ['string',
  'When verifying the Duo server\'s certificate, the scheme used to automatically verify the name of the server as documented by Perl module IO::Socket::SSL. If set, value "http" is recommended.',
  1],

 'SSLCertificateVerifyHook' =>
 ['hook',
  'This optional parameter specifies a perl function that will be called after the request username or identity has been matched with the certificate CN. It is passed the certificate, and various other details, and returns 1 or 0 for valid or unvalid.',
  2],
 );

# RCS version number of this module
$Radius::AuthDUO::VERSION = '$Revision: 1.3 $';

#####################################################################
# Do per-instance default initialization.
# This is called by Configurable during Configurable::new before the
# config file is parsed. Its a good place initialize instance
# variables that might get overridden when the config file is parsed.
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{PollTimerInterval} = 1;
    $self->{EndpointPrefix} = '/auth/v2';
    $self->{Protocol} = 'https';
    $self->{Slots} = 20; # the default
    $self->{Timeout} = 100;
    $self->{MaxRequestTime} = 120; # the default
    $self->{ProxyHost} = ''; # the default
    $self->{ProxyPort} = ''; # the default
    $self->{Address} = '%{Calling-Station-Id}';
    $self->{DefaultFactor} = 'auto';

    return;
}

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    if (!defined $self->{Hostname})
    {
	$self->log($main::LOG_WARNING, "No Hostname defined for AuthBy DUO in '$main::config_file'");
    }
    if (!defined $self->{SecretKey})
    {
	$self->log($main::LOG_WARNING, "No SecretKey defined for AuthBy DUO in '$main::config_file'");
    }
    if (!defined $self->{IntegrationKey})
    {
	$self->log($main::LOG_WARNING, "No IntegrationKey defined for AuthBy DUO in '$main::config_file'");
    }

    if (   (!defined $self->{SSLVerifyCNName} &&  defined $self->{SSLVerifyCNScheme})
	|| ( defined $self->{SSLVerifyCNName} && !defined $self->{SSLVerifyCNScheme}))
    {
	$self->log($main::LOG_WARNING, "AuthBy DUO You should define both SSLVerifyCNName and SSLVerifyCNScheme or neither.");
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

    # Get the SSL options hash
    my %ssl_opts = $self->get_ssl_opts();

    # Create Async interface
    $self->{async} = HTTP::Async->new(
	slots      => $self->{Slots},
	timeout    => $self->{Timeout},
	proxy_host => $self->{ProxyHost},
	proxy_port => $self->{ProxyPort},
	);
    $self->{async}->ssl_options(\%ssl_opts) if %ssl_opts;
    $self->{json} = JSON->new->allow_nonref;

    # Hash to map ids from HTTP::Async to the original request
    %{$self->{id_to_request}} = ();

    # Set up 1 second polling timer.
    $self->setPollTimer();

    return;
}

#####################################################################
# Collect the certificate verify options from the current configuration.
sub get_ssl_opts
{
    my ($self) = @_;

    my %ssl_verify = ( 'none' => 0, 'optional' => 1, 'require' => 3 );
    my %ssl_opts;

    $ssl_opts{SSL_ca_file} = Radius::Util::format_special($self->{SSLCAFile})
	if defined $self->{SSLCAFile};
    $ssl_opts{SSL_ca_path} = Radius::Util::format_special($self->{SSLCAPath})
	if defined $self->{SSLCAPath};
    $ssl_opts{SSL_verify_mode} = $ssl_verify{ lc($self->{SSLVerify}) }
	if defined $self->{SSLVerify};

    $ssl_opts{SSL_verify_callback} = sub {Radius::AuthDUO::verifyCallback($self, @_);}
	if defined $self->{SSLCertificateVerifyHook};

    $ssl_opts{SSL_verifycn_name} = $self->{SSLVerifyCNName}
	if defined $self->{SSLVerifyCNName};
    $ssl_opts{SSL_verifycn_scheme} = $self->{SSLVerifyCNScheme}
	if defined $self->{SSLVerifyCNScheme};

    return %ssl_opts;
}

#####################################################################
# Called when a SSL certificate presented by the Duo server is to be validated
# It will be called for each element in the chain.
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
sub setPollTimer
{
    my ($self) = @_;

    Radius::Select::remove_timeout($self->{poll_timer})
	if $self->{poll_timer};
    $self->{poll_timer} = Radius::Select::add_timeout
	(time + $self->{PollTimerInterval}, \&pollTimerElapsed, $self);

    return;
}

#####################################################################
sub checkForResponses
{
    my ($self) = @_;

    $self->{async}->poke();
    while (my ($response, $id) = $self->{async}->next_response)
    {
	$self->log($main::LOG_EXTRA_DEBUG, $response->as_string());

	# Recover the original RADIUS request from the HTTP::Async id
	my $p = $self->{id_to_request}{$id};
	if (!defined $p)
	{
	    $self->log($main::LOG_WARNING, "AuthBy DUO received a response with an unknown id $id. Ignored");
	    return;
	}
	delete $self->{id_to_request}{$id};

	my $content = $response->content();
	$self->log($main::LOG_DEBUG, "AuthBy DUO received response $id: " . $content);

	# Decide how to reply to the original RADIUS client
	if ($response->is_success)
	{
	    # HTTP 200
	    # Decode the JSON response if there is one. Note: decode can croak.
	    my ($json_reply);
	    eval { $json_reply = $self->{json}->decode($content); };
	    unless ($json_reply)
	    {
		$self->log($main::LOG_WARNING, "AuthBy DUO failed to decode JSON reply. Ignored");
		return;
	    }

	    my $status_msg = $json_reply->{response}{status_msg};
	    my $api_result = $json_reply->{response}{result};
	    my $result;
	    if ($api_result eq 'deny')
	    {
		$result = $main::REJECT;
	    }
	    elsif ($api_result eq 'allow')
	    {
		$result = $main::ACCEPT;
	    }
	    else
	    {
		$self->log($main::LOG_WARNING, "AuthBy DUO received response $id with unexpected result $api_result. Ignored");
		return;
	    }
	    # Synthesize a reply to the original request and send it
	    # back to the original requester. It already has the
	    # identifier and authenticator set.
	    $p->{rp}->add_attr('Reply-Message', $status_msg);
	    $p->{Handler}->handlerResult($p, $result, $status_msg);
	}
	else
	{
	    # API failure, consider this the same as a database failure and IGNORE
	    my $status_line = $response->status_line;
	    $self->log($main::LOG_INFO, "AuthBy DUO received bad response: $status_line");
	    $p->{Handler}->handlerResult($p, $main::IGNORE, $status_line);
	}
    }

    return;
}

#####################################################################
sub pollTimerElapsed
{
    my ($handle, $self) = @_;

    $self->checkForResponses();
    $self->setPollTimer();

    return;
}

#####################################################################
# Handle a request
sub handle_request
{
    my ($self, $p, $dummy, $extra_checks) = @_;

    $self->log($main::LOG_DEBUG, "Handling with Radius::AuthDUO", $p);

    # Now we might fork before processing the request
    # Should only do this for "slow" authentication methods
    return ($main::IGNORE, 'forked')
	if $self->{Fork} && !$self->handlerFork();

    return ($main::IGNORE, "Ignored due to IgnoreAuthentication")
	if $self->{IgnoreAuthentication}
           && $p->code eq 'Access-Request';
    return ($main::IGNORE, "Ignored due to IgnoreAccounting")
	if $self->{IgnoreAccounting}
           && $p->code eq 'Accounting-Request';

    if ($p->code eq 'Access-Request')
    {
	my $password = $p->decodedPassword();
	my $lcpassword = lc $password;

	my %params;
	$params{ipaddr} = Radius::Util::format_special($self->{Address}, $p);
	$params{username} = $p->getUserName();

	if ($lcpassword eq '')
	{
	    # Empty password, default to 'auto' factor and let Duo decide which to use
	    $params{factor} = $self->{DefaultFactor};
	    $params{device} = 'auto' unless $params{device};
	}
	elsif ($lcpassword =~ /^(sms|phone|push|auto)(\d*)$/)
	{
	    # non-passcode factor
	    $params{factor} = $1;
	    $params{device} = $2;
	    $params{device} = 'auto' unless $params{device};
	}
	else
	{
	    # passcode
	    $params{factor} = 'passcode';
	    $params{passcode} = $password;
	}
	my $id = $self->call('POST', 'auth', %params);
	return ($main::IGNORE, "AuthBy DUO call failed") unless defined $id;

	$self->{id_to_request}{$id} = $p;
	$p->{proxied}++; # Let the caller know the reply will come later

	# Some time later (up to a minute for phone and push) HTTP::Async will produce a response
	# which will be found by checkForRepsonse when we poll sometime in the next PollTimerInterval
	# seconds. In the meantime, no reply:
	return ($main::IGNORE, 'Waiting for response from Duo API server');
    }
    elsif ($p->code eq 'Accounting-Request')
    {
	return ($main::ACCEPT);
    }
    else
    {
	return ($main::REJECT, "Unknown request code: " . $p->code)
    }

}

sub call
{
    my ($self, $method, $endpoint, %params) = @_;

    # Caution: you get a complete HTTPS handshake, query and socket close for every request

    # Format up the Authorization string, and generate the Authorization hash
    my $hostlc = lc $self->{Hostname};
    my $methoduc = uc $method;
    my $date = HTTP::Date::time2str(time);

    # Make a sorted array of "param=value", with value escaped
    my @paramarray = map { "$_=" . URI::Escape::uri_escape_utf8($params{$_}) } sort keys %params;

    # Make a string of "param1=value&param2=value"
    my $paramstring = join('&', @paramarray);

    # Generate the authorization string and the resulting password hash
    my $auth_string = "$date\n$methoduc\n$hostlc\n$self->{EndpointPrefix}/$endpoint\n$paramstring";
    my $pw = Digest::HMAC_SHA1::hmac_sha1_hex($auth_string, $self->{SecretKey});

    # Now generate the Authorization header
    my $useridpw = "$self->{IntegrationKey}:$pw";
    my $authorization = 'Basic ' . MIME::Base64::encode_base64($useridpw, ''); # No EOL

    my $request;
    if ($method eq 'GET')
    {
	# GET
	# The request params are in the url
	$request = HTTP::Request->new('GET', "$self->{Protocol}://$self->{Hostname}$self->{EndpointPrefix}/$endpoint?$paramstring");
	$request->header('Date' => $date);
	$request->header('Authorization' => $authorization);
	$request->header('Host' => $self->{Hostname});
	$self->log($main::LOG_EXTRA_DEBUG, $request->as_string())
    }
    else
    {
	# POST
	# The requst params are in the Content
	# Generate Content-Type: application/x-www-form-urlencoded
	# with the request parameters
	$request = HTTP::Request->new('POST', "$self->{Protocol}://$self->{Hostname}$self->{EndpointPrefix}/$endpoint");
	$request->header('Date' => $date);
	$request->header('Authorization' => $authorization);
	$request->header('Host' => $self->{Hostname});
	$request->header('Content-Type' => 'application/x-www-form-urlencoded');
	$request->content($paramstring);
	$self->log($main::LOG_EXTRA_DEBUG, $request->as_string());
    }

    my $id;
    eval {$id = $self->{async}->add($request)};
    if (defined $id)
    {
	$self->log($main::LOG_DEBUG, "Auth DUO added request $id");
    }
    else
    {
	$self->log($main::LOG_ERR, "Auth DUO failed to add request: $@");
    }
    return $id;
}

1;
