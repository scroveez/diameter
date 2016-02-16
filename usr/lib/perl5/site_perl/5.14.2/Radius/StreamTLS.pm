# StreamTLS.pm
#
# Radius module for supporting some TLS operations on stream connections
# including some that should really be available in openssl.
# Processes TLS and SSL streams
#
# Requires Net_SSLeay.pm-1.26 or later
# Requires openssl 0.9.8 or later
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2002-2005 Open System Consultants
# $Id: StreamTLS.pm,v 1.58 2014/09/25 18:27:06 hvn Exp $
package Radius::StreamTLS;
use Radius::Util;
use Radius::TLS;
use strict;

# RCS version number of this module
$Radius::StreamTLS::VERSION = '$Revision: 1.58 $';

# Whether or not the TLS library has been initialised
$Radius::StreamTLS::initialised = undef;

# This is the closure to be called when a client certificate is to be verified
# There is only one, due to limitations in SSLeay, so it must be set and cleared
# during each call to openssl that might result in a ceritifacte verification 
# ie before calling accept().
# It is required to return 0 if there is no error in validating the certificate
# else an error code from the set X509_V_ERR* in openssl/include/x509_vfy.h
$Radius::StreamTLS::verifyFn = undef;

# This flag indicates whetehr the (one and only) password callback funciton has been set
$Radius::StreamTLS::password_callback_set = undef;


#####################################################################
sub init
{
    my ($self) = @_;

    &Radius::TLS::tlsInit();
    $Radius::StreamTLS::initialised++;

    $self->{TLS_Options} = $self->{UseSSL} ? 
	  (&Net::SSLeay::OP_NO_SSLv2
	   | &Net::SSLeay::OP_NO_TLSv1)
	: (&Net::SSLeay::OP_NO_SSLv2
	   | &Net::SSLeay::OP_NO_SSLv3
	   | &Net::SSLeay::OP_SINGLE_DH_USE
	   | 0x4000) # SSL_OP_NO_TICKET
	unless defined $self->{TLS_Options};

    $self->{TLS_VerifyMode} = &Net::SSLeay::VERIFY_PEER 
	| &Net::SSLeay::VERIFY_CLIENT_ONCE 
	unless defined $self->{TLS_VerifyMode};
    $self->{TLS_VerifyMode} |= &Net::SSLeay::VERIFY_FAIL_IF_NO_PEER_CERT 
	if $self->{TLS_RequireClientCert};

    my $certtype = defined $self->{TLS_CertificateType} && $self->{TLS_CertificateType} eq 'PEM' 
	? &Net::SSLeay::FILETYPE_PEM : &Net::SSLeay::FILETYPE_ASN1;

    $self->{ssl_ctx_streamtls} = $self->{UseSSL} 
        ? &Net::SSLeay::CTX_v23_new() 
	: &Net::SSLeay::CTX_tlsv1_new(); 

    if (!$self->{ssl_ctx_streamtls})
    {
	$self->log($main::LOG_ERR, 'StreamTLS could not CTX_tlsv1_new');
	return;
    }

    &Net::SSLeay::CTX_set_options($self->{ssl_ctx_streamtls}, $self->{TLS_Options});
    if (&Net::SSLeay::CTX_load_verify_locations
	($self->{ssl_ctx_streamtls}, &Radius::Util::format_special($self->{TLS_CAFile}), 
	 &Radius::Util::format_special($self->{TLS_CAPath}))
	!= 1)
    {
	$self->log($main::LOG_ERR, "StreamTLS could not load_verify_locations " . &Radius::Util::format_special($self->{TLS_CAFile}) . ", " . &Radius::Util::format_special($self->{TLS_CAPath}) . ": " . &Net::SSLeay::print_errs());
	$self->{ssl_ctx_streamtls} = undef;
	return;
    }
    
    if (&Net::SSLeay::CTX_set_default_verify_paths($self->{ssl_ctx_streamtls}) != 1)
    {
	my $errs = &Net::SSLeay::print_errs();
	$self->log($main::LOG_ERR, "StreamTLS could not set_default_verify_paths: $errs");
	$self->{ssl_ctx_streamtls} = undef;
	return;
    }
    
    &Net::SSLeay::CTX_set_client_CA_list
	($self->{ssl_ctx_streamtls}, 
	 &Net::SSLeay::load_client_CA_file(&Radius::Util::format_special($self->{TLS_CAFile})));
    
    # There is only one callback, but since the callback will
    # only be called once during the subsequent CTX_use_PrivateKey_file
    # we dont care if it is overwritten later. Also, versions of Net_SSLeay up to
    # at least 1.25 are not threadsafe if CTX_set_default_passwd_cb is called more
    # than once in different threads. Make sure the clear the callback after use
    # to prevent these problems.
    my $pw = &Radius::Util::format_special($self->{TLS_PrivateKeyPassword});
    &Net::SSLeay::CTX_set_default_passwd_cb($self->{ssl_ctx_streamtls}, sub {return $pw;});

    if (defined $self->{TLS_CertificateFile} 
	&& &Net::SSLeay::CTX_use_certificate_file
	($self->{ssl_ctx_streamtls}, &Radius::Util::format_special($self->{TLS_CertificateFile}),
	 $certtype) != 1)
    {
	$self->log($main::LOG_ERR, "StreamTLS could not use_certificate_file $self->{TLS_CertificateFile}, $certtype: " . &Net::SSLeay::print_errs());
	$self->{ssl_ctx_streamtls} = undef;
	return;
    }
    
    # Versions of openssl up to 0.9.8e and perhaps later get a bogus 
    # 'file not found' error from 
    # CTX_use_certificate_chain_file unless we clear the error stack first.
    &Net::SSLeay::ERR_clear_error();

    if (defined $self->{TLS_CertificateChainFile} 
	&& &Net::SSLeay::CTX_use_certificate_chain_file
	($self->{ssl_ctx_streamtls}, &Radius::Util::format_special($self->{TLS_CertificateChainFile})) != 1)
    {
	$self->log($main::LOG_ERR, "StreamTLS could not use_certificate_chain_file $self->{TLS_CertificateFile}: " . &Net::SSLeay::print_errs());
	$self->{ssl_ctx_streamtls} = undef;
	return;
    }
    
    if (defined $self->{TLS_PrivateKeyFile}
	&& &Net::SSLeay::CTX_use_PrivateKey_file
	($self->{ssl_ctx_streamtls}, &Radius::Util::format_special($self->{TLS_PrivateKeyFile}), 
	 $certtype) != 1)
    {
	$self->log($main::LOG_ERR, "StreamTLS could not use_PrivateKey_file $self->{TLS_PrivateKeyFile}, $certtype: " . &Net::SSLeay::print_errs());
	$self->{ssl_ctx_streamtls} = undef;
	return;
    }
    # Remove the callback to prevent thread problems that can cause crashes at exit.
    &Net::SSLeay::CTX_set_default_passwd_cb($self->{ssl_ctx_streamtls}, undef);

    if (defined $self->{TLS_RandomFile}
	&& !&Net::SSLeay::RAND_load_file(&Radius::Util::format_special($self->{TLS_RandomFile}), 
					 1024*1024))
    {
	$self->log($main::LOG_ERR, 'StreamTLS Could not load randomness: ' . &Net::SSLeay::print_errs());
	$self->{ssl_ctx_streamtls} = undef;
	return;
    }
    
    # Generate ephemeral RSA key, required for clients that need to do 
    # export RSA but our local key is more than 512 bits
    my $rsa = &Net::SSLeay::RSA_generate_key(512, 0x10001); # RSA_F4
    if (&Net::SSLeay::CTX_set_tmp_rsa($self->{ssl_ctx_streamtls}, $rsa) < 0)
    {
	$self->log($main::LOG_ERR, 'StreamTLS Could not set ephemeral RSA key');
	$self->{ssl_ctx_streamtls} = undef;
	return;
    }
    &Net::SSLeay::RSA_free($rsa);
    
    # Maybe load the DH group file
    if (defined $self->{TLS_DHFile})
    {
	my $bio = &Net::SSLeay::BIO_new_file(&Radius::Util::format_special($self->{TLS_DHFile}), 'r');
	my $dh = &Net::SSLeay::PEM_read_bio_DHparams($bio);
	if (&Net::SSLeay::CTX_set_tmp_dh($self->{ssl_ctx_streamtls}, $dh) < 0)
	{
	    $self->log($main::LOG_ERR, 'StreamTLS Could not set ephemeral DH key');
	    $self->{ssl_ctx_streamtls} = undef;
	    return;
	}
	&Net::SSLeay::BIO_free($bio);
	&Net::SSLeay::DH_free($dh);
    }

    if (defined $self->{TLS_ECDH_Curve})
    {
	if (defined &Net::SSLeay::CTX_set_tmp_ecdh)
    	{
	    my $curve_config = $self->{TLS_ECDH_Curve};
	    my $curve = Net::SSLeay::OBJ_txt2nid($curve_config);
	    unless ($curve)
	    {
		$self->log($main::LOG_ERR, "StreamTLS Could not find NID for curve name '$curve_config'");
		$self->{ssl_ctx_streamtls} = undef;
		return;
	    }
	    my $ecdh = Net::SSLeay::EC_KEY_new_by_curve_name($curve);
	    unless ($ecdh)
	    {
		$self->log($main::LOG_ERR, "StreamTLS Could not cannot create curve for NID '$curve'");
		$self->{ssl_ctx_streamtls} = undef;
		return;
	    }
	    if (Net::SSLeay::CTX_set_tmp_ecdh($self->{ssl_ctx_streamtls}, $ecdh) < 0)
	    {
		$self->log($main::LOG_ERR, 'StreamTLS Could not set ephemeral EC key');
		$self->{ssl_ctx_streamtls} = undef;
		return;
	    }

	    Net::SSLeay::CTX_set_options($self->{ssl_ctx_streamtls}, Net::SSLeay::OP_SINGLE_ECDH_USE());
	    Net::SSLeay::EC_KEY_free($ecdh);
        }
	else
	{
            $self->log($main::LOG_WARNING, 'StreamTLS Could not use Ephemeral ECDH: too old Net::SSLEAY and/or OpenSSL');
	    $self->{ssl_ctx_streamtls} = undef;
	    return;
        }
    }

    # Maybe check a certificate revocation file (CRL)
    # Caution: if this flag is turned on, we must be able to find a CRL
    # file in TLS_CAPath. CRL files are conventionally named with the hash
    # of the subject name and a suffix that depends on the serial number.
    # eg ab1331b2.r0, ab1331b2.r1 etc.
    # You can find out the hash of the issuer name in a CRL with
    #  openssl crl -in crl.pem -hash -noout
    # If a CRL file cant be found for a given client certificate, the client
    # authentication will fail with a n error:
    #   SSL3_GET_CLIENT_CERTIFICATE:no certificate returned
    if ($self->{TLS_CRLCheck})
    {
	# Sigh, some versions of Net::SSLeay dont have this necessary function
	eval {&Net::SSLeay::X509_STORE_set_flags
		  (&Net::SSLeay::CTX_get_cert_store($self->{ssl_ctx_streamtls}), 
		   &Net::SSLeay::X509_V_FLAG_CRL_CHECK);};
	if ($@)
	{
	    $self->log($main::LOG_ERR, "StreamTLS TLS_CRLCheck cannot be enabled since the installed version of Net::SSLeay does not support X509_STORE_set_flags. Upgrade Net::SSLeay to 1.30 or later");
	}
    }
    &Radius::StreamTLS::reloadCrls($self);

    # Maybe set policy OIDs that are required to be in the certificate path
    # Caution, this requires a number of functions that were added to Net-SSLeay SVN in 1.36, and 
    # 1.37 and later
    if (defined $self->{TLS_PolicyOID})
    {
	my $pm;
	eval {$pm = &Net::SSLeay::X509_VERIFY_PARAM_new()};
	if ($@ || !$pm)
	{
	    $self->log($main::LOG_ERR, "StreamTLS TLS_PolicyOID cannot be enabled since the installed version of Net::SSLeay does not support X509_VERIFY_PARAM_new. Upgrade Net::SSLeay to 1.37 or later");
	}
	else
	{
	    # Required Net-SSLeay functions must be present
	    my $oid;
	    foreach $oid (@{$self->{TLS_PolicyOID}})
	    {
		my $pobject = &Net::SSLeay::OBJ_txt2obj($oid, 0);
		&Net::SSLeay::X509_VERIFY_PARAM_add0_policy($pm, $pobject);
	    }
	    &Net::SSLeay::X509_VERIFY_PARAM_set_flags($pm, &Net::SSLeay::X509_V_FLAG_POLICY_CHECK() | &Net::SSLeay::X509_V_FLAG_EXPLICIT_POLICY());
	    my $store = &Net::SSLeay::CTX_get_cert_store($self->{ssl_ctx_streamtls});
	    &Net::SSLeay::X509_STORE_set1_param($store, $pm);
	}
    }
}

#####################################################################
# Load for the first time all the CRL files configured.
# Subsequently, if the CRL files timestamp has changed, releoad it.
# Reloading will replace the previous version
sub reloadCrls
{
    my ($self) = @_;

    # Maybe load some additional CRL files. If defined, openssl will look in these
    # before looking for file named with the issuer name hash
    if (defined $self->{TLS_CRLFile})
    {
	my $fileglob;
	my $cert_store = &Net::SSLeay::CTX_get_cert_store($self->{ssl_ctx_streamtls});
	foreach $fileglob (@{$self->{TLS_CRLFile}})
	{
	    $fileglob = &Radius::Util::format_special($fileglob);
	    my $file;
	    foreach $file (glob $fileglob)
	    {
		# See if it is the first load, or if it has changed since the last time
		my $new_time = (stat($file))[9];
		$self->log($main::LOG_ERR, "StreamTLS Could not stat '$file': $!"), next unless $new_time;
		
		next if $new_time == $self->{LastModTime}{$file};
		$self->{LastModTime}{$file} = $new_time;
		
		$self->log($main::LOG_DEBUG, "(Re)loading CRL file '$file'");
		my $bio = &Net::SSLeay::BIO_new_file($file, 'r');
		my $crl = &Net::SSLeay::PEM_read_bio_X509_CRL($bio);
		if ($crl)
		{
		    # Replaces any previous CRL from the same issuer
		    &Net::SSLeay::X509_STORE_add_crl($cert_store, $crl);
		}
		else
		{
		    $self->log($main::LOG_ERR, "StreamTLS Could not load CRL file '$file'");
		}
		&Net::SSLeay::BIO_free($bio);
	    }
	}
    }
}

#####################################################################
sub serverInit
{
    my ($self, $object, $peername) = @_;

    # OK, now we make the per-connection context when running as a TLS server
    if ($object->{ssl_streamtls} 
	&& $self->{TLS_SessionResumption} 
	&& ($object->{first_session_time} + $self->{TLS_SessionResumptionLimit} > time))
    {
	# Permit renegotiation of an existing session, provided the client has the right
	# session key and context ID
	$self->log($main::LOG_DEBUG, "Resuming session for connection to $peername");

	# Create 2 memory BIOs to do the IO with SSL
	# Its possible for old junk to be left in the BIOs after a botched
	# resumption attempt
	$object->{rbio} = &Net::SSLeay::BIO_new(&Net::SSLeay::BIO_s_mem());
	$object->{wbio} = &Net::SSLeay::BIO_new(&Net::SSLeay::BIO_s_mem());
	&Net::SSLeay::set_bio($object->{ssl_streamtls}, $object->{rbio}, $object->{wbio});

	# But just this usually works OK:
	&Net::SSLeay::set_accept_state($object->{ssl_streamtls});
	&Net::SSLeay::clear($object->{ssl_streamtls});
	&Net::SSLeay::do_handshake($object->{ssl_streamtls});
	return 1;
    }
    else
    {
	return &sessionInit($self, $object, $peername);
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
    $err = &$Radius::StreamTLS::verifyFn($x509_store_ctx) if $Radius::StreamTLS::verifyFn;

    # Tell the caller what the problem was. This is available as Net::SSLeay::get_verify_result()
    &Net::SSLeay::X509_STORE_CTX_set_error($x509_store_ctx, $err) if $err;

    # Return 1 if no error from local callback
    return $err == 0;
}

#####################################################################
# Compare this host name or IP address against a certificate name or wildcard
sub matchHostName
{
    my ($hostname, $pattern) = @_;

    if ($pattern =~ /^\*(.*)$/)
    {
	# Wildcard starting with '*.'. Make a regexp
	# eg '*.open.com.au' -> 'open\.com\.au$'
	my $regexp = quotemeta($1) . '$';
	return 1 if $hostname =~ /$regexp/;
    }
    else
    {
	return 1 if lc($hostname) eq lc($pattern); # Exact match, case insens
    }
    return; # No match
}

#####################################################################
# This is called from within verifyCallback, having been set in receive()
# This is called to verify each certificate in the client certificate chain, 
# starting with the root. Return 0 if no error,
# else one X509_V_ERR_* from openssl/include/x509_vfy.h
# Returning 50 (X509_V_ERR_APPLICATION_VERIFICATION) triggers 
# TLS error 0x80090326 in Windows XP SP1 TLS client
sub verifyFn
{
    my ($object, $x509_store_ctx) = @_;

    my $depth = Net::SSLeay::X509_STORE_CTX_get_error_depth($x509_store_ctx);
    if ($depth == 0)
    {
	# This is the peer certificate we need to check
	my $cert = Net::SSLeay::X509_STORE_CTX_get_current_cert($x509_store_ctx);
	my $subject_name = &Net::SSLeay::X509_get_subject_name($cert);
	my $subject = &Net::SSLeay::X509_NAME_oneline($subject_name);
	my $hostname = $object->{Host};

	# Sigh: need to canonicalise IPV6 IP addresses for compressed zeroes etc
	# else may not match an altname IPV6 IP address
	$object->log($main::LOG_DEBUG, "verifyFn start, hostname $hostname");
	if ($hostname =~ /ipv6:(.*:.*)/i || $hostname =~ /(^[0-9a-fA-F:]+:[0-9a-fA-F:]+$)/i)
	{
	    $hostname = $1;
	    # IPV6 raw IP address, canonicalise
	    $hostname = Radius::Util::inet_ntop(Radius::Util::inet_pton($hostname));
	    $object->log($main::LOG_DEBUG, "verifyFn hostname after canonicalise $hostname");
        }
	elsif ($hostname =~ /^ipv6:(.*)/)
	{
	    $hostname = $1;
	}
	$object->log($main::LOG_DEBUG, "Verifying certificate with Subject '$subject' presented by peer $object->{Host}");

	# If CertificateFingerprint is defined, the finger[rint of the certificate must match one of 
	# the fingerprints in the TLS_Fingerprint array
	# Requires X509_get_fingerprint which is not present in all versions of SSLeay
	if (defined $object->{TLS_CertificateFingerprint} 
	    && exists &Net::SSLeay::X509_get_fingerprint)
	{
	    my $found;

	    # At least one must match
	    foreach (@{$object->{TLS_CertificateFingerprint}})
	    {
		my ($fingerprint, $requiredfingerprint);

		if (/^sha-1:(.*)/)
		{
		    $requiredfingerprint = $1;
		    $fingerprint = &Net::SSLeay::X509_get_fingerprint($cert, 'sha1');
		}
		elsif (/^sha-256:(.*)/)
		{
		    $requiredfingerprint = $1;
		    $fingerprint = &Net::SSLeay::X509_get_fingerprint($cert, 'sha256');
		}
		elsif (/^md5:(.*)/)
		{
		    $requiredfingerprint = $1;
		    $fingerprint = &Net::SSLeay::X509_get_fingerprint($cert, 'md5');
		}
		else
		{
		    $object->log($main::LOG_ERR, "Invalid format in TLS_CertificateFingerprint: $_");
		    last;
		}
		$object->log($main::LOG_DEBUG, "Checking if TLS_CertificateFingerprint $_ matches $fingerprint");
		$found = $fingerprint eq $requiredfingerprint; # Found a match
		last if $found;
	    }
	    if (!$found)
	    {
		$object->log($main::LOG_WARNING, "No match for any TLS_CertificateFingerprint");
		return 50;
	    }
	}

	# try to get subjectAltName extensions with type DNS
	# Support for X509_get_subjectAltNames was added in 1.30
	my $have_subject_alt_name_dns; # Have found a subjectAltName of type DNS
	my $have_subject_alt_name_srv; # Have found a subjectAltName of type SRV
	my $subject_alt_name_srv_matches; # Found a subjectAltName of type SRV that matches TLS_SRVName
	if (exists &Net::SSLeay::X509_get_subjectAltNames)
	{
	    # X509_get_subjectAltNames returns array of (type, string)
	    # type == 2 is dnsname. Type 7 is IPADD, type 6 is URI.
	    # For other types see openssl/x509v3.h GEN_*

	    # If TLS_SubjectAltNameURI is defined it must match at least one
	    # SubjectAltName:URI
	    if (defined $object->{TLS_SubjectAltNameURI})
	    {
		my $found = 0;
		my @altnames = &Net::SSLeay::X509_get_subjectAltNames($cert);
		while (@altnames)
		{
		    my ($type, $name) = splice(@altnames, 0, 2);
		    $name = Radius::Util::inet_ntop($name) if $type == 7;
		    $object->log($main::LOG_DEBUG, "Checking for subjectAltName:URI in type $type, value $name");
		    if ($type == 6
			&& $name =~ /$object->{TLS_SubjectAltNameURI}/)
		    {
			$object->log($main::LOG_DEBUG, "Matched TLS_SubjectAltNameURI $object->{TLS_SubjectAltNameURI} with $name");
			$found++;
			last;
		    }
		}
		if (!$found)
		{
		    $object->log($main::LOG_ERR, "Verification of TLS_SubjectAltNameURI $object->{TLS_SubjectAltNameURI} in certificate presented by $object->{Host} failed");
		    return 50; # Application error
		}
	    }

	    my @altnames = &Net::SSLeay::X509_get_subjectAltNames($cert);
	    while (@altnames)
	    {
		my ($type, $name) = splice(@altnames, 0, 2);
		if ($type == 7)
		{
		    $name = Radius::Util::inet_ntop($name);
		}
		$object->log($main::LOG_DEBUG, "Checking subjectAltName type $type, value $name against $hostname");
		$have_subject_alt_name_dns++ if $type == 2;

		# On client side can use Type 2 DNS name or type 7 IPADD
		if (!$object->{tls_is_server} && ($type == 2 || $type == 7) 
		    && &matchHostName($hostname, $name))
		{
		    $object->log($main::LOG_DEBUG, "Certificate DNS subjectAltName $name matches server Host name $object->{Host}");
		    return 0;
		}
		# On client side, subjectAltName:SRV extensions need to be checked against
		# possible DNS SRV name in order to confirm the certificate is associated
		# with the right SRV and server
		elsif (   defined $object->{TLS_SRVName} 
		       && !$object->{tls_is_server} 
		       && $type == 0 
		       && $name =~ /_(.+?)\.(.+)/)
		{
		    my ($service, $srvname) = ($1, $2);
		    $object->log($main::LOG_DEBUG, "Checking certificate SubjectAltName::SRV against TLS_SRVName '$object->{TLS_SRVName}'");
		    $have_subject_alt_name_srv++;

		    # Decompose TLS_SRVName, which should be in the format
		    # _service._transport.name
		    # eg:
		    # _radsec._tcp.example.com
		    if ($object->{TLS_SRVName} =~ /_(.+?)\._(.+?)\.(.+)/)
		    {
			$subject_alt_name_srv_matches++ if $1 eq $service && $3 eq $srvname;
		    }

		}
		# On server side can use type 7 IPADD
		elsif ($object->{tls_is_server} && $type == 7 && $hostname eq $name)
		{
		    $object->log($main::LOG_DEBUG, "Certificate IPAddress subjectAltName $name matches client address $object->{Host}");
		    return 0;
		}
		# Handled URI above
	    }
	}

	# If there was no subjectAltName type DNS seen,
	# check if the host name matches a CN, honouring wildcards
	# On the clinet side, Host is the configured Host name.
	# On the server side, Host is the IP address of the client.
	# Subject name could be in the form: /DC=com/DC=mtghouse/CN=Users/CN=vinny
	# Extract all the CNs and see if at least one of them matches
	# Array of names following each CN=
	# CN may be an exact hostname xyz.pqr.com or wildcard *.pqr.com
	if (!$have_subject_alt_name_dns)
	{
	    my @cn = map {/CN=([^\/]+)/ ? $1 : ()} split(/\//, $subject);
	    my $cn;
	    foreach $cn (@cn)
	    {
		if (&matchHostName($hostname, $cn))
		{
		    $object->log($main::LOG_DEBUG, "Certificate CN $cn matches $object->{Host}");
		    return 0;
		}
	    }
	}

	# If a subjectAltName type SRV was seen, but none of them matched the defined TLS_SrvName
	# then the verify fails
	if ($have_subject_alt_name_srv && !$subject_alt_name_srv_matches)
	{
	    $object->log($main::LOG_WARNING, "No SubjectAltName:SRV certificate extension matches TLS_SRVName '$object->{TLS_SRVName}'");
	    return 50;
	}

	# OK if we match a configured pattern in TLS_ExpectedPeerName
	if (   defined $object->{TLS_ExpectedPeerName}
	    && $subject =~ /$object->{TLS_ExpectedPeerName}/)
	{
	    $object->log($main::LOG_DEBUG, "Certificate Subject matches TLS_ExpectedPeerName");
	    return 0;
	}

	# Nothing worked
	$object->log($main::LOG_ERR, "Verification of certificate presented by $object->{Host} failed");
	return 50; # Application error
    }

    return 0;
}


#####################################################################
# Create a new clean session context 
sub sessionInit
{
    my ($self, $object, $peername) = @_;

    $self->log($main::LOG_DEBUG, "StreamTLS sessionInit for $peername");
    &Net::SSLeay::free($object->{ssl_streamtls}) if $object->{ssl_streamtls};
    $object->{handshake_finished} = undef;
    $object->{ssl_streamtls} = &Net::SSLeay::new($self->{ssl_ctx_streamtls});

    if (!$object->{ssl_streamtls})
    {
	$object->log($main::LOG_ERR, 'StreamTLS could not create SSL: Net::SSLeay::new failed: ' . &Net::SSLeay::print_errs() . ",". $!);
	return;
    }

    # There is only one callback, but since the callback will
    # only be called once during the subsequent CTX_use_PrivateKey_file
    # we dont care if it is overwritten later. Also, versions of Net_SSLeay up to
    # at least 1.25 are not threadsafe if CTX_set_default_passwd_cb is called more
    # than once in different threads. Make sure the clear the callback after use
    # to prevent these problems.
    my $pw = $object->{TLS_PrivateKeyPassword}; # prevent references to $object
    &Net::SSLeay::CTX_set_default_passwd_cb($self->{ssl_ctx_streamtls}, sub {return $pw;});

    # Certificate files names can depend on the identity of the other end
    my $certtype = defined $object->{TLS_CertificateType} && $object->{TLS_CertificateType} eq 'PEM' 
	? &Net::SSLeay::FILETYPE_PEM : &Net::SSLeay::FILETYPE_ASN1;


    if (defined $object->{TLS_CertificateFile} 
	&& &Net::SSLeay::use_certificate_file
	($object->{ssl_streamtls}, &Radius::Util::format_special($object->{TLS_CertificateFile}),
	 $certtype) != 1)
    {
	$self->log($main::LOG_ERR, "StreamTLS could not use_certificate_file $object->{TLS_CertificateFile}, $certtype: " . &Net::SSLeay::print_errs());
	$object->sessionClear();
	return;
    }

    # There is no SSL_use_certificate_chain_file

    if (defined $object->{TLS_PrivateKeyFile}
	&& &Net::SSLeay::use_PrivateKey_file
	($object->{ssl_streamtls}, &Radius::Util::format_special($object->{TLS_PrivateKeyFile}, undef, undef, $peername), 
	 $certtype) != 1)
    {
	$self->log($main::LOG_ERR, "StreamTLS could not use_PrivateKey_file $object->{TLS_PrivateKeyFile}, $certtype: " . &Net::SSLeay::print_errs());
	$object->sessionClear();
	return;
    }
    # Remove the callback to prevent thread problems that can cause crashes at exit.
    &Net::SSLeay::CTX_set_default_passwd_cb($self->{ssl_ctx_streamtls}, undef);

    # Maybe reload CRLS that have changed
    &Radius::StreamTLS::reloadCrls($self);

    $object->{tls_no_resumption} = undef; # resumption may be permitted again

    # Create 2 memory BIOs to do the IO with SSL
    $object->{rbio} = &Net::SSLeay::BIO_new(&Net::SSLeay::BIO_s_mem());
    $object->{wbio} = &Net::SSLeay::BIO_new(&Net::SSLeay::BIO_s_mem());
    &Net::SSLeay::set_bio($object->{ssl_streamtls}, $object->{rbio}, $object->{wbio});
    
    # This sets a unique binary context identifier to identify renegotiated sessions
    my $objectid = "$object->{ssl_streamtls}"; # stringify the address of the SSL context
    &Net::SSLeay::set_session_id_context($object->{ssl_streamtls}, $objectid, length($objectid));

    # Need this in set_verify
    $object->{TLS_VerifyMode} = $self->{TLS_VerifyMode};

    # This remembers how long this session has been around for session resumption
    # time limit purposes
    $object->{first_session_time} = time;
    return 1;
}

#####################################################################
# Remove a session entirely so it can never be reused or resumed
sub sessionClear
{
    my ($self) = @_;

    &Net::SSLeay::free($self->{ssl_streamtls}) if $self->{ssl_streamtls};
    $self->{ssl_streamtls} = undef;
}

#####################################################################
# This can initialise any object as a TLS server
# $self can be any type of object that can manage IO
sub start_server
{
    my ($self, $object, $peername) = @_;

    return unless $Radius::TLS::initialised;
    return unless &serverInit($self, $object, $peername);
    $object->{tls_enabled}++;
    $object->{tls_is_server}++;
    &receive($object); # Provoke output of any data to the peer
    $object->log($main::LOG_DEBUG, "StreamTLS Server Started for $object->{Host}:$object->{Port}");
    return 1;
}

#####################################################################
# This can initialise any object as a TLS client
# $self can be any type of object that can manage IO
sub start_client
{
    my ($self, $object, $peername) = @_;

    return unless $Radius::TLS::initialised;
    return unless &sessionInit($self, $object, $peername);
    $object->{tls_enabled}++;
    &receive($object); # Provoke output of any data to the peer
    $object->log($main::LOG_DEBUG, "StreamTLS Client Started for $object->{Host}:$object->{Port}");
    return 1;
}

#####################################################################
# Called to handle incoming data
sub receive
{
     my ($object, $data) = @_;

     no warnings "uninitialized";
     $object->log($main::LOG_EXTRA_DEBUG, 'StreamTLS receive: ' . unpack('H*', $data));
     &Net::SSLeay::BIO_write($object->{rbio}, $data);
     return unless $object->{ssl_streamtls};
     if (!$object->{handshake_finished})
     {
	 &Radius::StreamTLS::set_verify($object, sub {&verifyFn($object, @_)});
	 
	 # SSL handshake is not yet complete
	 if ($object->{tls_is_server})
	 {
	     # We are an SSL server
	     my $ret = &Net::SSLeay::accept($object->{ssl_streamtls});
	     my $reason = &Net::SSLeay::get_error($object->{ssl_streamtls}, $ret);
	     my $state = &Net::SSLeay::get_state($object->{ssl_streamtls});
	     &Radius::StreamTLS::reset_verify($object); # prevent SSLeay thread safety problems
	     $object->log($main::LOG_DEBUG, "StreamTLS SSL_accept result: $ret, $reason, $state");
	     if ($ret == 1)
	     {
		 # Success, the SSL accept has completed successfully,
		 # therefore the client has verified credentials.
		 # However, there may be some more data in the output
		 # BIO to send to the client, so we defer the ACCEPT
		 # until it is acked
		 $object->{handshake_finished}++;
	     }
	     elsif ($ret == 0)
	     {
		 # Handshake was not successful
		 $object->log($main::LOG_ERR, "StreamTLS server Handshake unsuccessful: " . &Net::SSLeay::print_errs());
		 $object->stream_disconnected();
		 return;
	     }
	     elsif (   $reason == Net::SSLeay::ERROR_WANT_READ
		    || $reason == Net::SSLeay::ERROR_WANT_WRITE)
	     {
		 # Looking for more read or write data, object will provide it when its available
	     }
	     else
	     {
		 my $errs = &Net::SSLeay::print_errs();
		 my $verify_result = &Net::SSLeay::get_verify_result($object->{ssl_streamtls});
		 if ($verify_result)
		 {
		     my $verify_error_string = &Radius::TLS::verify_error_string($verify_result);
		     $object->log($main::LOG_ERR, "StreamTLS Certificate verification error: $verify_error_string");
		 }
		 else
		 {
		     $object->log($main::LOG_ERR, "StreamTLS server error: $ret, $reason, $state, " . 
			   &Net::SSLeay::print_errs());
		 }
		 # Error
		 $object->stream_disconnected();
		 return;
	     }
	 }
	 else
	 {
	     # We are an SSL client
	     my $ret = &Net::SSLeay::connect($object->{ssl_streamtls});
	     my $reason = &Net::SSLeay::get_error($object->{ssl_streamtls}, $ret);
	     my $state = &Net::SSLeay::get_state($object->{ssl_streamtls});
	     &Radius::StreamTLS::reset_verify($object); # prevent SSLeay thread safety problems
	     $object->log($main::LOG_DEBUG, "StreamTLS SSL_connect result: $ret, $reason, $state");
	     if ($ret == 1)
	     {
		 # Success, the SSL accept has completed successfully,
		 # therefore the client has verified credentials.
		 # However, there may be some more data in the output
		 # BIO to send to the client, so we defer the ACCEPT
		 # until it is acked
		 $object->{handshake_finished}++;
	     }
	     elsif ($ret == 0)
	     {
		 # Handshake was not successful
		 $object->log($main::LOG_ERR, "StreamTLS client Handshake unsuccessful: " 
			      . &Net::SSLeay::print_errs());
		 $object->stream_disconnected();
		 return;
	     }
	     elsif (   $reason == Net::SSLeay::ERROR_WANT_READ
		    || $reason == Net::SSLeay::ERROR_WANT_WRITE)
	     {
		 # Looking for more read or write data, object will provide it when its available
	     }
	     else
	     {
		 # Error
		 $object->log($main::LOG_ERR, "StreamTLS client error: $ret, $reason, $state, " 
			      . &Net::SSLeay::print_errs());
		 $object->stream_disconnected();
		 return;
	     }
	 }
	 $object->write();
     }

     # See if we have some translated data for the application
     if ($object->{handshake_finished})
     {
	 my $ret;
	 # Maybe multiple chunks waiting?
	 while (($data = &Net::SSLeay::read($object->{ssl_streamtls})) ne '')
	 {
	     if (!defined $data)
	     {
		 # Error
		 $object->log($main::LOG_ERR, 'StreamTLS read failed: '
			      . &Net::SSLeay::print_errs());
		 $object->stream_disconnected();
		 return;
	     }
	     $ret .= $data;
	 }
	 return $ret;
     }
     return;
}

#####################################################################
# Called to get any data that must be sent to the other peer
# Also insert any plaintext data for possible encryption
sub get_pending
{
    my ($self, $data) = @_;

    no warnings "uninitialized";
    if ($self->{ssl_streamtls} && $self->{handshake_finished})
    {
	# Recover application data that was waiting for TLS
	$data .= $self->{wait_for_tls_data};
	$self->{wait_for_tls_data} = '';

	my $ret = &Net::SSLeay::write($self->{ssl_streamtls}, $data);
	if ($ret < 0)
	{
	    my $reason = &Net::SSLeay::get_error($self->{ssl_streamtls}, $ret);
	    $self->log($main::LOG_DEBUG, "SSLeay::write returned $ret, $reason");
	    
	    $self->log($main::LOG_ERR, "SSLeay::write failed: $ret, $reason, " . &Net::SSLeay::print_errs())
		if $reason != Net::SSLeay::ERROR_WANT_READ 
		   && $reason != Net::SSLeay::ERROR_WANT_WRITE;
	}
    }
    else
    {
	# Hold this application data until TLS is up.
	$self->{wait_for_tls_data} .= $data;
    }

    if ($self->{ssl_streamtls})
    {
	$data = &Net::SSLeay::BIO_read($self->{wbio}, $self->{MaxBufferSize});
	$self->log($main::LOG_EXTRA_DEBUG, 'StreamTLS send: ' . unpack('H*', $data));
	return $data;
    }
    return;
}

#####################################################################
# Net_SSLeay has only one callback handle. Sigh. Some other users of 
# Net_SSLeay may be operating within our code too, so to prevent collisions with their
# use of the verify callback, we have to explicitly set it every time we need it 
sub set_verify
{
    my ($object, $cb) = @_;

    $Radius::StreamTLS::verifyFn = $cb;
    # Call a callback to verify the client certificate chain
    # SSLeay only supports on one calback, which we are forced to share
    # Reset it here in case someone else has been using it
    &Net::SSLeay::set_verify($object->{ssl_streamtls}, $object->{TLS_VerifyMode}, \&verifyCallback);
}

# Reset and remove the verify callback. This has the effect of removing the previously set
# verify callback. You must do this in the same thread as set_verify else Net::SSLeay may have 
# thread safety problems in a threaded environment.
sub reset_verify
{
    my ($object) = @_;

    &Net::SSLeay::set_verify($object->{ssl_streamtls}, $object->{TLS_VerifyMode}, undef);

}

1;

