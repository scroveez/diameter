# TLS.pm
#
# Radiator module for supporting some TLS operations, including some
# that should
# really be available in openssl
#
# Requires Net_SSLeay.pm-1.16 or later
# Requires openssl 0.9.8 or later
# See example in goodies/eap_ttls.cfg
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2002 Open System Consultants
# $Id: TLS.pm,v 1.73 2014/11/06 18:08:56 hvn Exp $
package Radius::TLS;
use Net::SSLeay qw(ERROR_WANT_READ ERROR_WANT_WRITE);
use strict;

# RCS version number of this module
$Radius::TLS::VERSION = '$Revision: 1.73 $';

# Whether or not the TLS library has been initialised
$Radius::TLS::initialised = 0;

# From RFC 2716:
$Radius::TLS::FLAG_LENGTH_INCLUDED = 0x80;
$Radius::TLS::FLAG_MORE_FRAGMENTS  = 0x40;
$Radius::TLS::FLAG_START           = 0x20;

$Radius::TLS::EXT_TYPE_SESSION_TICKET  = 35; # TLS Hello Extension type


# This is the closure to be called when a client certificate is to be verified
# There is only one, due to limitations in SSLeay, so it must be set and cleared
# during each call to openssl that might result in a ceritifacte verification 
# ie before calling accept().
# It is required to return 0 if there is no error in validating the certificate
# else an error code from the set X509_V_ERR* in openssl/include/x509_vfy.h
$Radius::TLS::verifyFn = undef;

# Certificate Verify codes from verify(1) and x509_txt.c
# Remove them when Net::SSLeay::X509_verify_cert_error_string becomes available
%Radius::TLS::verify_results = 
(
 0   => 'ok',
 2   => 'unable to get issuer certificate',
 3   => 'unable to get certificate CRL',
 4   => 'unable to decrypt certificate\'s signature',
 5   => 'unable to decrypt CRL\'s signature',
 6   => 'unable to decode issuer public key',
 7   => 'certificate signature failure',
 8   => 'CRL signature failure',
 9   => 'certificate is not yet valid',
 10   => 'certificate has expired',
 11   => 'CRL is not yet valid',
 12   => 'CRL has expired',
 13   => 'format error in certificate\'s notBefore field',
 14   => 'format error in certificate\'s notAfter field',
 15   => 'format error in CRL\'s lastUpdate field',
 16   => 'format error in CRL\'s nextUpdate field',
 17   => 'out of memory',
 18   => 'self signed certificate',
 19   => 'self signed certificate in certificate chain',
 20   => 'unable to get local issuer certificate',
 21   => 'unable to verify the first certificate',
 22   => 'certificate chain too long',
 23   => 'certificate revoked',
 24   => 'invalid CA certificate',
 25   => 'path length constraint exceeded',
 26   => 'unsupported certificate purpose',
 27   => 'certificate not trusted',
 28   => 'certificate rejected',
 29   => 'subject issuer mismatch',
 30   => 'authority and subject key identifier mismatch',
 31   => 'authority and issuer serial number mismatch',
 32   => 'key usage does not include certificate signing',
 33   => 'unable to get CRL issuer certificate',
 34   => 'unhandled critical extension',
 35   => 'key usage does not include CRL signing',
 36   => 'unhandled critical CRL extension',
 37   => 'invalid non-CA certificate (has CA markings)',
 38   => 'proxy path length constraint exceeded',
 39   => 'key usage does not include digital signature',
 40   => 'proxy cerificates not allowed, please set the appropriate flag',
 41   => 'invalid or inconsistent certificate extension',
 42   => 'invalid or inconsistent certificate policy extension',
 43   => 'no explicit policy',
 44   => 'different CRL scope',
 45   => 'unsupported extension feature',
 46   => 'RFC 3779 resource not subset of parent\'s resources',
 47   => 'permitted subtree violation',
 48   => 'excluded subtree violation',
 49   => 'name constraints minimum and maximum not supported',
 50   => 'application verification failure',
 51   => 'unsupported name constraint type',
 52   => 'unsupported or invalid name constraint syntax',
 53   => 'unsupported or invalid name syntax',
 54   => 'CRL path validation error',
 );


#####################################################################
# Generate $req_len bytes of key material from the constant string $s using the
# masterkey and client and server random strings as described in 
# draft-ietf-pppext-eap-ttls-01.txt and See rfc2716
# This should really be implemented inside openssl
sub PRF
{
    my ($context, $s, $req_len) = @_;

    # Use Net::SSLeay::export_keying_material if present (OpenSSL 1.0.1 and later, NetSSLeay 1.52+latest patches and later)
    if (exists &Net::SSLeay::export_keying_material)
    {
	return &Net::SSLeay::export_keying_material($context->{ssl}, $req_len, $s, undef);
    }
    else
    {
	my $client_random = &Net::SSLeay::get_client_random($context->{ssl});
	my $server_random = &Net::SSLeay::get_server_random($context->{ssl});
	my $session = &Net::SSLeay::get_session($context->{ssl});
	my $master_key = &Net::SSLeay::SESSION_get_master_key($session) if $session;

	return &tls1_PRF($master_key, $s, $client_random . $server_random, $req_len);
    }
}

#####################################################################
# TLS PRF function as per RFC 2246
sub tls1_PRF
{
    my ($secret, $label, $seed, $req_len) = @_;

    # Split the secret into 2. If its odd length, overlap by 1
    my $slen = length($secret);
    my $len = int($slen / 2);
    my $s2 = substr($secret, $len);
    $len += ($slen & 1); # add for odd, make longer
    my $s1 = substr($secret, 0, $len);

    my $md5 = &tls_p_md5($s1, $label . $seed, $req_len);
    my $sha = &tls_p_sha1($s2, $label . $seed, $req_len);
    return $md5 ^ $sha;
}

#####################################################################
# P_hash for MD5 as per RFC 2246
sub tls_p_md5
{
    my ($secret, $seed, $req_len) = @_;

    use Digest::HMAC_MD5;
    my ($result, $temp);
    my $ai = $seed;
    my $i = 0;
    while ($i < $req_len)
    {
	$ai = Digest::HMAC_MD5::hmac_md5($ai, $secret);
	$result .= Digest::HMAC_MD5::hmac_md5($ai . $seed, $secret);
	$i += 16;
    }
    return substr($result, 0, $req_len);
}


#####################################################################
# P_hash for SHA-1 as per RFC 2246
sub tls_p_sha1
{
    my ($secret, $seed, $req_len) = @_;

    use Digest::HMAC_SHA1;
    my ($result, $temp);
    my $ai = $seed;
    my $i = 0;
    while ($i < $req_len)
    {
	$ai = Digest::HMAC_SHA1::hmac_sha1($ai, $secret);
	$result .= Digest::HMAC_SHA1::hmac_sha1($ai . $seed, $secret);
	$i += 20;
    }
    return substr($result, 0, $req_len);
}

#####################################################################
# Initialise openssl exactly once
sub tlsInit
{
    if (!$Radius::TLS::initialised)
    {
	&Net::SSLeay::randomize();
	&Net::SSLeay::load_error_strings();
	&Net::SSLeay::ERR_load_crypto_strings();
	&Net::SSLeay::SSLeay_add_ssl_algorithms();
	# Initialize SHA256 digest if available, required for WiMAX
	&Net::SSLeay::EVP_add_digest(&Net::SSLeay::EVP_sha256())
	    if exists &Net::SSLeay::EVP_sha256;
	# Enable hardware acceleration if available
	# These are not available before Net::SSLeay 1.33:
	eval { &Net::SSLeay::ENGINE_load_builtin_engines();
	       &Net::SSLeay::ENGINE_register_all_complete();
	       # This should be configurable?
	       my $e = &Net::SSLeay::ENGINE_by_id('pkcs11');
	       &Net::SSLeay::ENGINE_set_default($e, 0xFFFF)
		   if $e;
	   };
	$Radius::TLS::initialised++;
    }
}

#####################################################################
# Initialise TLS
# Initialise a per AuthBy TLS context
# Initialise a per-client context (passed in as $context);
# $parent is the current AuthBy
# $p is the current request (if any)
sub contextInit
{
    my ($context, $parent, $p) = @_;

    &tlsInit();

    $context->{ssl_verify_mode} = &Net::SSLeay::VERIFY_CLIENT_ONCE;
    if (!$parent->{ssl_ctx})
    {
	# First one for this AuthBy. Initialise the SSL
	# context and configuration
	# We create an SSL context once for each AuthBY
	# since each one may have different configuration paramters
	# We enable the SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS, otherwise the
	# empty fragement sent by the server at the beginning of the applicaiotn data
	# confuses Windows Vista Beta 2. Consider using SSL_OP_ALL to enable
	# all workarounds
	my $options = &Net::SSLeay::OP_NO_SSLv2
	    | &Net::SSLeay::OP_NO_SSLv3
	    | &Net::SSLeay::OP_SINGLE_DH_USE 
	    | 0x800 # SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
	    | 0x4000; # SSL_OP_NO_TICKET
	# Maybe set SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
	$options |= 0x10000 unless $parent->{EAPTLS_SessionResumption};
	# Maybe set SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
	# Requires OpenSSL 0.9.8m and later. Only needed with OpenSSL 0.9.8m and unpatched clients
	$options |= 0x40000 if $parent->{EAPTLS_AllowUnsafeLegacyRenegotiation};

	my $certtype = &Radius::Util::format_special($parent->{EAPTLS_CertificateType}, $p) eq 'PEM' 
	    ? &Net::SSLeay::FILETYPE_PEM : &Net::SSLeay::FILETYPE_ASN1;

	$parent->{ssl_ctx} = &Net::SSLeay::CTX_new(); 
	if (!$parent->{ssl_ctx})
	{
	    $parent->log($main::LOG_ERR, 'TLS could not CTX_new');
	    return;
	}

	&Net::SSLeay::CTX_set_options($parent->{ssl_ctx}, $options);
	# Ensure openssl is using our timeout
	&Net::SSLeay::CTX_set_timeout
	    ($parent->{ssl_ctx}, 
	     &Radius::Util::format_special($parent->{EAPTLS_SessionResumptionLimit}, $p))
	    if $parent->{EAPTLS_SessionResumption};

	if (&Net::SSLeay::CTX_load_verify_locations
	    ($parent->{ssl_ctx}, 
	     &Radius::Util::format_special($parent->{EAPTLS_CAFile}, $p), 
	     &Radius::Util::format_special($parent->{EAPTLS_CAPath}, $p))
	    != 1)
	{
	    my $errs = &Net::SSLeay::print_errs();
	    $parent->log($main::LOG_ERR, "TLS could not load_verify_locations " . &Radius::Util::format_special($parent->{EAPTLS_CAFile}, $p) . ", " . &Radius::Util::format_special($parent->{EAPTLS_CAPath}, $p) . ": $errs");
	    $parent->{ssl_ctx} = undef;
	    return;
	}
	
	if (&Net::SSLeay::CTX_set_default_verify_paths($parent->{ssl_ctx}) != 1)
	{
	    my $errs = &Net::SSLeay::print_errs();
	    $parent->log($main::LOG_ERR, "TLS could not set_default_verify_paths: $errs");
	    $parent->{ssl_ctx} = undef;
	    return;
	}
	
	&Net::SSLeay::CTX_set_client_CA_list
	    ($parent->{ssl_ctx}, 
	     &Net::SSLeay::load_client_CA_file(&Radius::Util::format_special($parent->{EAPTLS_CAFile}, $p)));
	
	# There is only one callback, but since the callback will
	# only be called once during the subsequent CTX_use_PrivateKey_file
	# we dont care if it is overwritten later
	# prevent references to $parent	
	my $pw = &Radius::Util::format_special($parent->{EAPTLS_PrivateKeyPassword}, $p);
	&Net::SSLeay::CTX_set_default_passwd_cb($parent->{ssl_ctx}, sub {return $pw;});
	if (defined $parent->{EAPTLS_CertificateFile}
	    && &Net::SSLeay::CTX_use_certificate_file
	    ($parent->{ssl_ctx}, &Radius::Util::format_special($parent->{EAPTLS_CertificateFile}, $p), 
	     $certtype) != 1)
	{
	    my $errs = &Net::SSLeay::print_errs();
	    $parent->log($main::LOG_ERR, "TLS could not use_certificate_file " . &Radius::Util::format_special($parent->{EAPTLS_CertificateFile}, $p) . ", $certtype: $errs");
	    $parent->{ssl_ctx} = undef;
	    return;
	}

	# Versions of openssl up to 0.9.8e and perhaps later get a bogus 
	# 'file not found' error from 
	# CTX_use_certificate_chain_file unless we clear the error stack first.
	&Net::SSLeay::ERR_clear_error();

	if (defined $parent->{EAPTLS_CertificateChainFile}
	    && &Net::SSLeay::CTX_use_certificate_chain_file
	    ($parent->{ssl_ctx}, &Radius::Util::format_special($parent->{EAPTLS_CertificateChainFile}, $p)) != 1)
	{
	    my $errs = &Net::SSLeay::print_errs();
	    $parent->log($main::LOG_ERR, "TLS could not use_certificate_chain_file " . &Radius::Util::format_special($parent->{EAPTLS_CertificateChainFile}, $p) . ": $errs");
	    $parent->{ssl_ctx} = undef;
	    return;
	}

	if (defined $parent->{EAPTLS_PrivateKeyFile}
	    && &Net::SSLeay::CTX_use_PrivateKey_file
	    ($parent->{ssl_ctx}, &Radius::Util::format_special($parent->{EAPTLS_PrivateKeyFile}, $p), 
	     $certtype) != 1)
	{
	    my $errs = &Net::SSLeay::print_errs();
	    $parent->log($main::LOG_ERR, "TLS could not use_PrivateKey_file " . &Radius::Util::format_special($parent->{EAPTLS_PrivateKeyFile}, $p) . ", $certtype: $errs");
	    $parent->{ssl_ctx} = undef;
	    return;
	}
	# Remove the callback to prevent thread problems that can cause crashes at exit.
	&Net::SSLeay::CTX_set_default_passwd_cb($parent->{ssl_ctx}, undef);

	if (defined $parent->{EAPTLS_RandomFile}
	    && !&Net::SSLeay::RAND_load_file(&Radius::Util::format_special($parent->{EAPTLS_RandomFile}, $p), 
					     1024*1024))
	{
	    my $errs = &Net::SSLeay::print_errs();
	    $parent->log($main::LOG_ERR, "TLS Could not load randomness: $errs");
	    $parent->{ssl_ctx} = undef;
	    return;
	}

        # Generate ephemeral RSA key, required for clients that need to do 
        # export RSA but our local key is more than 512 bits
	my $rsa = &Net::SSLeay::RSA_generate_key(512, 0x10001); # RSA_F4
	if (&Net::SSLeay::CTX_set_tmp_rsa($parent->{ssl_ctx}, $rsa) < 0)
	{
	    $parent->log($main::LOG_ERR, 'TLS Could not set ephemeral RSA key');
	    $parent->{ssl_ctx} = undef;
	    return;
	}
	&Net::SSLeay::RSA_free($rsa);

	# Maybe load the DH group file
	if (defined $parent->{EAPTLS_DHFile})
	{
	    my $bio = &Net::SSLeay::BIO_new_file(&Radius::Util::format_special($parent->{EAPTLS_DHFile}, $p), 'r');
	    my $dh = &Net::SSLeay::PEM_read_bio_DHparams($bio);
	    if (&Net::SSLeay::CTX_set_tmp_dh($parent->{ssl_ctx}, $dh) < 0)
	    {
		$parent->log($main::LOG_ERR, 'TLS Could not set ephemeral DH key');
		$parent->{ssl_ctx} = undef;
		return;
	    }
	    &Net::SSLeay::BIO_free($bio);
	    &Net::SSLeay::DH_free($dh);

	}

        if (defined $parent->{EAPTLS_ECDH_Curve})
        {
            if (defined &Net::SSLeay::CTX_set_tmp_ecdh)
            {
              	my $curve_config = $parent->{EAPTLS_ECDH_Curve};
                my $curve = Net::SSLeay::OBJ_txt2nid($curve_config);
                unless ($curve)
                {
		    $parent->log($main::LOG_ERR, "TLS Could not find NID for curve name '$curve_config'");
		    $parent->{ssl_ctx} = undef;
		    return;
                }
                my $ecdh = Net::SSLeay::EC_KEY_new_by_curve_name($curve);
                unless ($ecdh)
                {
		    $parent->log($main::LOG_ERR, "TLS Could not cannot create curve for NID '$curve'");
		    $parent->{ssl_ctx} = undef;
		    return;
                }
                if (Net::SSLeay::CTX_set_tmp_ecdh($parent->{ssl_ctx}, $ecdh) < 0)
                {
		    $parent->log($main::LOG_ERR, 'TLS Could not set ephemeral EC key');
		    $parent->{ssl_ctx} = undef;
		    return;
                }

                Net::SSLeay::CTX_set_options($parent->{ssl_ctx}, Net::SSLeay::OP_SINGLE_ECDH_USE());
                Net::SSLeay::EC_KEY_free($ecdh);
	    }
	    else
	    {
		$parent->log($main::LOG_WARNING, 'TLS Could not use Ephemeral ECDH: too old Net::SSLEAY and/or OpenSSL');
		$parent->{ssl_ctx} = undef;
		return;
	    }
        }

	# Maybe check a certificate revocation file (CRL)
	# Caution: if this flag is turned on, we must be able to find a CRL
	# file in EAPTLS_CAPath. CRL files are conventionally named with the hash
	# of the subject name and a suffix that depends on the serial number.
	# eg ab1331b2.r0, ab1331b2.r1 etc.
	# You can find out the hash of the issuer name in a CRL with
	#  openssl crl -in crl.pem -hash -noout
	# If a CRL file cant be found for a given client certificate, the client
	# authentication will fail with a n error:
	#   SSL3_GET_CLIENT_CERTIFICATE:no certificate returned
	if ($parent->{EAPTLS_CRLCheck})
	{
	    # Sigh, some versions of Net::SSLeay dont have this necessary function
	    eval {&Net::SSLeay::X509_STORE_set_flags
		    (&Net::SSLeay::CTX_get_cert_store($parent->{ssl_ctx}), 
		     &Net::SSLeay::X509_V_FLAG_CRL_CHECK);};
	    if ($@)
	    {
		$parent->log($main::LOG_WARNING, "EAPTLS_CRLCheck cannot be enabled since the installed version of Net::SSLeay does not support X509_STORE_set_flags. Upgrade Net::SSLeay to 1.30 and OpenSSL to 0.9.8 or later: $@");
	    }
	}

	# Maybe set policy OIDs that are required to be in the certificate path
	# Caution, this requires a number of functions that were added to Net-SSLeay SVN in 1.36, and 
	# 1.37 and later
	if (defined $parent->{EAPTLS_PolicyOID})
	{
	    my $pm;
	    eval {$pm = &Net::SSLeay::X509_VERIFY_PARAM_new()};
	    if ($@ || !$pm)
	    {
		$parent->log($main::LOG_ERR, "EAPTLS_PolicyOID cannot be enabled since the installed version of Net::SSLeay does not support X509_VERIFY_PARAM_new. Upgrade Net::SSLeay to 1.37 or later");
	    }
	    else
	    {
		# Required Net-SSLeay functions must be present
		my $oid;
		foreach $oid (@{$parent->{EAPTLS_PolicyOID}})
		{
		    my $pobject = &Net::SSLeay::OBJ_txt2obj($oid, 0);
		    &Net::SSLeay::X509_VERIFY_PARAM_add0_policy($pm, $pobject);
		}
		&Net::SSLeay::X509_VERIFY_PARAM_set_flags($pm, &Net::SSLeay::X509_V_FLAG_POLICY_CHECK() | &Net::SSLeay::X509_V_FLAG_EXPLICIT_POLICY());
		my $store = &Net::SSLeay::CTX_get_cert_store($parent->{ssl_ctx});
		&Net::SSLeay::X509_STORE_set1_param($store, $pm);
	    }
	}

	# Make sure that TLS session resumption cannot occur after 
	# EAPContextTimeout or EAPTLS_SessionResumptionLimit has expired. 
	# If TLS tries to resume a session but the context is gone, we get lost
	my $tls_session_timeout = $parent->{EAPContextTimeout};
	$tls_session_timeout = &Radius::Util::format_special($parent->{EAPTLS_SessionResumptionLimit}, $p)
	    if &Radius::Util::format_special($parent->{EAPTLS_SessionResumptionLimit}, $p) < $tls_session_timeout;
	&Net::SSLeay::CTX_set_timeout($parent->{ssl_ctx}, $tls_session_timeout);

	&Radius::TLS::reloadCrls($parent, $p);
    }

    # OK, now we make the per-client context
    $context->{first_frag} = 1; # output
    $context->{handshake_finished} = undef;
    $context->{success} = undef;
    $context->{parent} = $parent;

    # REVISIT: disabled for testing. We now use CTX_Session_set_timeout to 
    # limit session resumption times for us
    if (0 && $context->{ssl} 
	&& &Radius::Util::format_special($parent->{EAPTLS_SessionResumption}, $p)
	&& ($context->{first_session_time} + &Radius::Util::format_special($parent->{EAPTLS_SessionResumptionLimit}, $p) > time))
    {
	# Permit renegotiation of an existing session, provided the client has the right
	# session key and context ID
	$parent->log($main::LOG_DEBUG, "Resuming session for $context\n");

	# See http://www.linuxjournal.com/article.php?sid=5487 for details about this:
	# Needs Net::SSLeay::set_state, Not available in Net_SSLEAY yet
	# This sets a unique binary context identifier to identify renegotiated sessions
#	&Net::SSLeay::renegotiate($context->{ssl});
#	&Net::SSLeay::do_handshake($context->{ssl});
#	&Net::SSLeay::set_state($context->{ssl}, &Net::SSLeay::ST_ACCEPT);
#	&Net::SSLeay::do_handshake($context->{ssl});

	# Create 2 memory BIOs to do the IO with SSL
	# Its possible for old junk to be left in the BIOs after a botched
	# resumption attempt
	$context->{rbio} = &Net::SSLeay::BIO_new(&Net::SSLeay::BIO_s_mem());
	$context->{wbio} = &Net::SSLeay::BIO_new(&Net::SSLeay::BIO_s_mem());
	&Net::SSLeay::set_bio($context->{ssl}, $context->{rbio}, $context->{wbio});

	# But just this usually works OK:
	&Net::SSLeay::set_accept_state($context->{ssl});
	&Net::SSLeay::clear($context->{ssl});
	&Net::SSLeay::do_handshake($context->{ssl});
    }
    else
    {
	&contextSessionInit($context, $parent);
    }

    # Maybe reload a CRL
    &Radius::TLS::reloadCrls($parent, $p);

    return $context;
}

#####################################################################
# Load for the first time all the CRL files configured.
# Subsequently, if the CRL files timestamp has changed, releoad it.
# Reloading will replace the previous version
sub reloadCrls
{
    my ($self, $p) = @_;

    # Maybe load some additional CRL files. If defined, openssl will look in these
    # before looking for file named with the issuer name hash
    if (defined $self->{EAPTLS_CRLFile})
    {
	my $fileglob;
	my $cert_store = &Net::SSLeay::CTX_get_cert_store($self->{ssl_ctx});
	foreach $fileglob (@{$self->{EAPTLS_CRLFile}})
	{
	    $fileglob = &Radius::Util::format_special($fileglob, $p);
	    my $file;
	    foreach $file (glob $fileglob)
	    {
		# See if it is the first load, or if it has changed since the last time
		my $new_time = (stat($file))[9];
		$self->log($main::LOG_ERR, "TLS Could not stat '$file': $!"), next unless $new_time;
		next if $new_time == $self->{LastModTime}{$file};
		$self->{LastModTime}{$file} = $new_time;
		
		$self->log($main::LOG_DEBUG, "(Re)loading CRL file '$file'");
		my $bio = &Net::SSLeay::BIO_new_file($file, 'r');
		my $crl = &Net::SSLeay::PEM_read_bio_X509_CRL($bio);
		if ($crl)
		{
		    # Replaces any previous CRL from the same issuer
		    if (!&Net::SSLeay::X509_STORE_add_crl($cert_store, $crl))
		    {
			$self->log($main::LOG_ERR, "Failed to add CRL file '$file': " . &Net::SSLeay::ERR_error_string(&Net::SSLeay::ERR_get_error()));
		    }
		}
		else
		{
		    $self->log($main::LOG_ERR, "TLS Could not load CRL file '$file'");
		}
		&Net::SSLeay::BIO_free($bio);
	    }
	}
    }
}

#####################################################################
# This is called for each certificate in the certificate chain. If it returns 0
# then further checking will be stopped.
# We call a local verification routin, which could be a closure etc.
sub verifyCallback
{
    my ($ok, $x509_store_ctx) = @_;

    # Bail out if a previous callback failed already
    return 0 unless $ok;

    my $err = 0;    # 0 means no verify error

    # Call a protocol specific verify routine as a closure, if present
    $err = &$Radius::TLS::verifyFn($x509_store_ctx) if $Radius::TLS::verifyFn;

    # Tell the caller what the problem was. This is available as Net::SSLeay::get_verify_result()
    &Net::SSLeay::X509_STORE_CTX_set_error($x509_store_ctx, $err) if $err;

    # Return 1 if no error from local callback
    return $err == 0;
}

#####################################################################
# Clean a new clean session context 
sub contextSessionInit
{
    my ($context, $parent) = @_;

    &Net::SSLeay::free($context->{ssl}) if $context->{ssl};
    $context->{ssl} = &Net::SSLeay::new($parent->{ssl_ctx});
    if (!$context->{ssl})
    {
	$parent->log($main::LOG_ERR, 'TLS could not create SSL: Net::SSLeay::new failed: ' . &Net::SSLeay::print_errs() . ",". $!);
	return;
    }

    $context->{tls_no_resumption} = undef; # resumption may be permitted again

    # Create 2 memory BIOs to do the IO with SSL
    $context->{rbio} = &Net::SSLeay::BIO_new(&Net::SSLeay::BIO_s_mem());
    $context->{wbio} = &Net::SSLeay::BIO_new(&Net::SSLeay::BIO_s_mem());
    &Net::SSLeay::set_bio($context->{ssl}, $context->{rbio}, $context->{wbio});
    
    # Arrange for our SSL per-client context to be destroyed when the EAP
    # per-client context is destroyed. $_[0] is the context being destroyed
    # Make sure any TLS session associated with this context is also destroyed, otherwise, 
    # TLS may try to resurrect the sess, but we wont be able to deal with it properly
    $context->destroy_callback
	(sub {if ($_[0]->{ssl})
	      {#my $sess = &Net::SSLeay::get_session($_[0]->{ssl});
	       #&Net::SSLeay::CTX_remove_session($parent->{ssl_ctx}, $sess) if $sess; 
	       &Net::SSLeay::free($_[0]->{ssl});
	       $_[0]->{ssl} = undef;
	      }});
    
    # This sets a unique binary context identifier to identify renegotiated sessions
    # Actually, it doesnt set the session ID at all: the session_id_context is only
    # use during imporint and exporting of session cache data, but the openssl session code
    # complains if it has not been set
    my $contextid = "$context->{ssl}"; # stringify the address of the SSL context
    &Net::SSLeay::set_session_id_context($context->{ssl}, $contextid, length($contextid));
    
    # This remembers how long this session has been around for session resumption
    # time limit purposes
    $context->{first_session_time} = time;
}

#####################################################################
# Remove a session entirely so it can never be reused or resumed
sub contextSessionClear
{
    my ($context) = @_;

    &Net::SSLeay::CTX_remove_session($context->{parent}->{ssl_ctx}, $context->{ssl});
    &Net::SSLeay::free($context->{ssl});
    $context->{ssl} = undef;
}

#####################################################################
# Tell SSL this session is allowed to be reused, even if the SSL struct is freed
# Sets the shutdown flag, otherwise the session will never be reused
sub contextSessionAllowReuse
{
    my ($context) = @_;

    &Net::SSLeay::shutdown($context->{ssl}) 
	if &Radius::Util::format_special($context->{parent}->{EAPTLS_SessionResumption});
}

sub verify_error_string
{
    my ($result) = @_;

    # Use this when it becomes available in Net_SSLeay:
    my $ret;
    # if Net::SSLeay::X509_verify_cert_error_string is available, use it
    eval {$ret = &Net::SSLeay::X509_verify_cert_error_string($result);};
    if (@!)
    {
	$ret = $Radius::TLS::verify_results{$result};
	$ret = "error number $result" unless defined $ret;
    }
    return $ret;
}

#####################################################################
# Net_SSLeay has only one callback handle. Sigh. Some other users of 
# Net_SSLeay may be operating within our code too, so to prevent collisions with their
# use of the verify callback, we have to explicitly set it every time we need it 
sub set_verify
{
    my ($parent, $context, $cb) = @_;

    $Radius::TLS::verifyFn = $cb;
    # Call a callback to verify the client certificate chain
    # SSLeay only supports on one calback, which we are forced to share
    # Reset it here in case someone else has been using it
    &Net::SSLeay::set_verify($context->{ssl}, $context->{ssl_verify_mode}, \&verifyCallback);
}

# Reset and remove the verify callback. This has the effect of removing the previously set
# verify callback. You must do this in the same thread as set_verify else Net::SSLeay may have 
# thread safety problems in a threaded environment
sub reset_verify
{
    my ($parent, $context) = @_;

    &Net::SSLeay::set_verify($context->{ssl}, $context->{ssl_verify_mode}, undef);
}

1;

