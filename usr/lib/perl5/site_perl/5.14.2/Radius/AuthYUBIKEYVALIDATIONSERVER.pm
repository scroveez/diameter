# AuthYUBIKEYVALIDATIONSERVER.pm
#
# Object for handling Authentication of Yubikey tokens (yubico.com)
# with Yubikey Validation Server. Allows validating credentials
# against YubiHSM.
#
# Author: Sami Keski-Kasari (samikk@open.com.au)
# Copyright (C) 2001-2014 Open System Consultants
# $Id: AuthYUBIKEYVALIDATIONSERVER.pm,v 1.1 2014/03/25 21:57:47 hvn Exp $

package Radius::AuthYUBIKEYVALIDATIONSERVER;
@ISA = qw(Radius::AuthYUBIKEYBASE);
use Radius::AuthYUBIKEYBASE;
#use IO::Socket::SSL qw(debug3); # For verbose debugging
use LWP::UserAgent;

use strict;
use warnings;

%Radius::AuthYUBIKEYVALIDATIONSERVER::ConfigKeywords =
(
'ValidationServerURL' =>
 ['string', 'The URL for Yubikey Validation server. Defaults to http://127.0.0.1:8003/yhsm/validate?', 0],

'Timeout' =>
 ['integer', 'Specifies a timeout interval in seconds that Radiator will wait for when talking to the Yubikey Validation server. Defaults to 3 seconds', 1],

'SSLVerify' =>
 ['string', 'May be used to control how the Yubikey Validation Server\'s certificate will be verified. May be one of "none" or "require".',
  1],

 'SSLCAPath' =>
 ['string', 'When verifying the XML Yubikey Validation Server\'s certificate, set this to the pathname of the directory containing CA certificates. These certificates must all be in PEM format. The directory in must contain certificates named using the hash value of the certificates\' subject names.',
  1],

 'SSLCAFile' =>
 ['string', 'When verifying the Yubikey Validation Server\'s certificate, set this to the filename containing the certificate of the CA who signed the server\'s certificate. The certificate must all be in PEM format.',
  1],
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
    $self->{ValidationServerURL} = 'http://127.0.0.1:8003/yhsm/validate?';
    $self->{Timeout} = 3; # In seconds

    return;
}

#####################################################################
sub activate
{
    my ($self) = @_;

    # Get the SSL options hash
    my %ssl_opts = $self->get_ssl_opts();

    $self->SUPER::activate();
    $self->{ua} = LWP::UserAgent->new (
	ssl_opts => {%ssl_opts},
	);
    $self->{ua}->timeout($self->{Timeout});

    return;
}

#####################################################################
sub checkYubikey
{
    my ($self, $user, $submitted_pw, $p) = @_;

    # Yubico own tokencode is 32 bytes long. TokenId is 0-16 bytes
    # long
    my $method= "OTP";
    my $query= "otp=$submitted_pw";

    # OATH-ID (TokenId) is 12 bytes long.
    # OATH-HOTP codes can be 6 ot 8 bytes.
    # Currently Yubikey Validation Server doesn't support 8 byte OATH-HOTP
    if (length $submitted_pw <= 20)
    {
	$method="OATH-HOTP";
	$query= "hotp=$submitted_pw";
    }

    my $uri = "$self->{ValidationServerURL}".$query;
    my $response = $self->{ua}->get($uri);

    unless ($response->is_success)
    {
	my $status = $response->status_line;
	$self->log($main::LOG_WARNING, "Call to Validation Server failed with HTTP status $status");
	return ($main::REJECT, "Call to Validation Server failed with HTTP status $status");
    }

    # HTTP 200
    my $decoded_response = $response->decoded_content;
    chomp $decoded_response;
    if ($decoded_response =~ /^OK /)
    {
	$self->log($main::LOG_DEBUG, "YubiKey $method validation result: $decoded_response");
	return ($main::ACCEPT);
    }
    else
    {
	return ($main::REJECT, "$method: $decoded_response");
    }
}

#####################################################################
# Collect the certificate verify options from the current
# configuration.
sub get_ssl_opts
{
    my ($self) = @_;

    my %ssl_verify = ( 'none' => 0, 'require' => 1 );
    my %ssl_opts;

    $ssl_opts{SSL_ca_file} = Radius::Util::format_special($self->{SSLCAFile})
        if defined $self->{SSLCAFile};
    $ssl_opts{SSL_ca_path} = Radius::Util::format_special($self->{SSLCAPath})
        if defined $self->{SSLCAPath};
    $ssl_opts{verify_hostname} = $ssl_verify{ lc($self->{SSLVerify}) }
        if defined $self->{SSLVerify};

    return %ssl_opts;
}

1;
