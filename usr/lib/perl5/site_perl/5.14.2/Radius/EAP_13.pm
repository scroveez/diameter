# EAP_13.pm
#
# Radiator module for  handling Authentication via EAP type 13 (TLS)
# which uses certificates for the server to authenticate the client
# and possibly vice-versa.
#
# See RFCs 2869 2284 1994 2246 2716
#
# Requires Net_SSLeay.pm-1.20 or later
# Requires openssl 0.9.7 or later
# See example in goodies/eap_tls.cfg
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2002 Open System Consultants
# $Id: EAP_13.pm,v 1.49 2013/12/20 20:37:18 hvn Exp $

package Radius::EAP_13;
use Radius::TLS;
use strict;

# RCS version number of this module
$Radius::EAP_13::VERSION = '$Revision: 1.49 $';


#####################################################################
# Called by EAP.pm when the caller wants to know the EAP type name this class supports
sub type_name
{
    my ($classname) = @_;

    return 'TLS';
}

#####################################################################
# request
# Called by EAP.pm when a request is received for this protocol type
sub request
{
    my ($classname, $self, $context, $p, $data) = @_;

    return $self->eap_error('Unexpected EAP request');
}

#####################################################################
# Called by EAP.pm when an EAP Response/Identity is received
sub response_identity
{
    my ($classname, $self, $context, $p) = @_;

    # Initialise our EAP context for use with TLS
    return ($main::REJECT, 'EAP TLS Could not initialise context') 
	unless &Radius::TLS::contextInit($context, $self, $p);

    # Forget the user structure for a previous auth
    $context->{tls_authenticated_user} = undef;

    # Require a valid client certificate
    $context->{ssl_verify_mode} |= (&Net::SSLeay::VERIFY_PEER | &Net::SSLeay::VERIFY_FAIL_IF_NO_PEER_CERT);

    # Ready to go: acknowledge with a TLS Start
    my $message = pack('C', $Radius::TLS::FLAG_START);
    $self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_TLS, $message);
    return ($main::CHALLENGE, 'EAP TLS Challenge');
}

#####################################################################
# Called by EAP.pm when an EAP Response (other than Identity)
# is received. Handles defragmenting packets. All the fragments
# are concatenated into $context->{data}, which will end up 
# a number of messages, each precended by a 4 byte length
sub response
{
    my ($classname, $self, $context, $p, $type, $typedata) = @_;

    return $self->eap_error('TLS not initialised')
	unless $context->{ssl};

    # Decode the typedata to get the TLS flags, 
    # the TLS message length (if present) and TLS data (in TLS record format)
    my ($flags) = unpack('C', $typedata);
    my ($tlsdata, $length);
    if ($flags & $Radius::TLS::FLAG_LENGTH_INCLUDED)
    {
	($flags, $length, $tlsdata) = unpack('C N a*', $typedata);
    }
    else
    {
	($flags, $tlsdata) = unpack('C a*', $typedata);
    }

    # Just finished with this request?
    my $handshake_just_finished; 

    # If we actually received anything
    if (length($tlsdata))
    {
	# TLS data is appended to SSL engine read BIO for processing:
	&Net::SSLeay::BIO_write($context->{rbio}, $tlsdata);
	
	if (!($flags & $Radius::TLS::FLAG_MORE_FRAGMENTS))
	{
	    # We have discovered that the user database _must_ be checked during
	    # certificate validation instead of after the TLS handshake is complete
	    # else Windows XP SP1 PEAP-TLS behaves strangely.
	    &Radius::TLS::set_verify($self, $context, sub {&verifyCallback($self, $context, $p, @_)});
	    
	    # We must have all of this message set,
	    # so continue with the accept. It will go as far as it can
	    # and maybe prompt us for more data
	    my $ret = &Net::SSLeay::accept($context->{ssl});
	    my $reason = &Net::SSLeay::get_error($context->{ssl}, $ret);
	    # Remove the callback to prevent thread problems that can cause crashes at exit.
	    &Radius::TLS::reset_verify($self, $context);
	    
	    if ($ret == 1)
	    {
		# Success, the SSL accept has completed successfully,
		# therefore the client has verified credentials.
		# However, there may be some more data in the output
		# BIO to send to the client, so we defer the ACCEPT
		# until it is acked
		$handshake_just_finished++;
		$context->{handshake_finished}++;
	    }
	    elsif ($ret == 0)
	    {
		# Handshake was not successful
		my $errs = &Net::SSLeay::print_errs();
		return ($main::REJECT, "EAP TLS Handshake unsuccessful: $errs");
	    }
	    elsif ($reason == Net::SSLeay::ERROR_WANT_READ)
	    {
		# Looking for more data, just ack this
	    }
	    elsif ($reason == Net::SSLeay::ERROR_WANT_WRITE)
	    {
		# Looking for more data, just ack this
	    }
	    else
	    {
		# Error
		my $errs = &Net::SSLeay::print_errs();
		my $state = &Net::SSLeay::get_state($context->{ssl});
		my $verify_result = &Net::SSLeay::get_verify_result($context->{ssl});
		if ($verify_result)
		{
		    # Certificate verification failed, keep going
		    # so we tell the client what the problem was
		    my $verify_error_string = &Radius::TLS::verify_error_string($verify_result);
		    $self->log($main::LOG_INFO, "EAP TLS certificate verification failed: $verify_error_string, $errs", $p);
		    
		}
		else
		{
		    # Serious TLS error, bail out
		    $self->log($main::LOG_ERR, "EAP TLS error: $ret, $reason, $state, $verify_result, $errs", $p);
		    &Radius::TLS::contextSessionClear($context);
		    $self->eap_failure($p->{rp}, $context);
		    return ($main::REJECT, "EAP TLS error");
		}
	    }
	}
    }

    # If there are any bytes to send to the peer, get them and
    # package them, else just acknowledge this packet
    my $message;
    my $pending = &Net::SSLeay::BIO_pending($context->{wbio});
    if ($pending)
    {
	# In case we run e.g., inside PEAP, we must check outer frag size too.
	my $framedmtu = $p->get_attr('Framed-MTU'); 
	my $innerfragsize = $p->{outerRequest}->{EAPOuterFragSize} - 40
	    if defined $p->{outerRequest} && defined $p->{outerRequest}->{EAPOuterFragSize};
	my $maxfrag = $self->{EAPTLS_MaxFragmentSize};
	$maxfrag = $framedmtu if defined $framedmtu && $framedmtu < $maxfrag;	
	$maxfrag = $innerfragsize if defined $innerfragsize && $innerfragsize < $maxfrag;

	my $towrite = &Net::SSLeay::BIO_read($context->{wbio}, $maxfrag);
	my $flags;
	my $more_pending = &Net::SSLeay::BIO_pending($context->{wbio});
	$flags |= $Radius::TLS::FLAG_MORE_FRAGMENTS
	    if $more_pending;
	if ($context->{first_frag})
	{
	    $flags |= $Radius::TLS::FLAG_LENGTH_INCLUDED;
	    
	    $message = pack('C N a*', $flags, $pending, $towrite);
	}
	else
	{
	    $message = pack('C a*', $flags, $towrite);
	}

	# This tells us if the next fragment will be the first
	# of a new message set:
	$context->{first_frag} = $more_pending ? 0 : 1;
    }
    elsif ($handshake_just_finished || ($context->{handshake_finished} && (length($tlsdata) == 0)))
    {
	# The handshake has successfully completed recently, so the client
	# certificate is correctly signed by a root with a short enough
	# certificate chain, and verifyCallback was happy with each one,
	# or maybe we are doing a session resumption
	my $peer = &Net::SSLeay::get_peer_certificate($context->{ssl});
	if (!$peer)
	{
	    &Radius::TLS::contextSessionClear($context);
	    $self->eap_failure($p->{rp}, $context);
	    return ($main::REJECT, 'EAP TLS No peer certificate');
	}
	&Net::SSLeay::X509_free($peer); # get_peer_certificate increments the count

	my $authuser = $context->{tls_authenticated_user};
	$context->{tls_authenticated_user} = undef;
	if (!$authuser && !$self->{EAPTLS_NoCheckId})
	{
	    # This is a session resumption, not a new session
	    # Make sure the user we authenticated in the initial session 
	    # is still in our user database
	    my ($user, $result, $reason) = $self->get_user($context->{tls_authenticated_cn}, $p);
	    if (!$user || $result != $main::ACCEPT)
	    {
		&Radius::TLS::contextSessionClear($context);
		$self->eap_failure($p->{rp}, $context);
		return ($main::REJECT, "EAP TLS session resumed by user $context->{tls_authenticated_cn} is not authenticated: $reason");
	    }
	    $authuser = $user;
	}

	# Send the EAP success
	$p->{rp}->{inner_identity} = $context->{tls_authenticated_cn};
	$self->eap_success($p->{rp}, $context);
	&Radius::TLS::contextSessionAllowReuse($context);
	$self->authoriseUser($authuser, $p) unless $self->{EAPTLS_NoCheckId};
	$self->adjustReply($p);
	$self->setTLSMppeKeys($context, $p, 'client EAP encryption');
	return ($main::ACCEPT); # Success, all done
    }
    elsif (length($tlsdata))
    {
	# Reply with an ACK
	$message = pack('C', 0); # ACK
    }
    else
    {
	# An ack, probably acknowledge an alert, now fail
	&Radius::TLS::contextSessionClear($context);
	$self->eap_failure($p->{rp}, $context);
	return ($main::REJECT, 'TLS Alert acknowledged');
    }
    $self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_TLS, $message);
    return ($main::CHALLENGE, 'EAP TLS Challenge');

}

#####################################################################
# This is called to verify each clertificate in the client certificate chain, 
# starting with the root. Return 0 if no error,
# else one X509_V_ERR_* from openssl/include/x509_vfy.h
# Returning 50 (X509_V_ERR_APPLICATION_VERIFICATION) triggers 
# TLS error 0x80090326 in Windows XP SP1 TLS client
sub verifyCallback
{
    my ($self, $context, $p, $x509_store_ctx) = @_;

    my $depth = Net::SSLeay::X509_STORE_CTX_get_error_depth($x509_store_ctx);
    if ($depth == 0)
    {
	# This is the peer certificate we need to check
	my $cert = Net::SSLeay::X509_STORE_CTX_get_current_cert($x509_store_ctx);
	my $subject_name = &Net::SSLeay::X509_get_subject_name($cert);
	my $subject = &Net::SSLeay::X509_NAME_oneline($subject_name);
	my $matchedcn;
	&main::log($main::LOG_DEBUG, "Certificate Subject Name is $subject", $p);
	if (!$self->{EAPTLS_NoCheckId})
	{

	    my $username = $p->getUserName();
	    # Build a success request packet

	    # Strip off any DOMAIN or host/ , else the username may not match the cert
	    my $username_nodomain =  $username;
	    $username_nodomain =~ s/^(.*)\\//;
	    $username_nodomain =~ s/^host\///;
	    my $identity_nodomain = $context->{identity};
	    $identity_nodomain =~ s/^(.*)\\//;
	    $identity_nodomain =~ s/^host\///;


	    # Subject name could be in the form: /DC=com/DC=mtghouse/CN=Users/CN=vinny
	    # Extract all the CNs and make sure at least one of them matches
	    # Array of names following each CN=
	    my @cn = map {/CN=([^\/]+)/ ? $1 : ()} split(/\//, $subject);
	    my $cn;
	    foreach $cn (@cn)
	    {
		# Maybe rewrite the certificate common name
		my $rule;
		foreach $rule (@{$self->{EAPTLSRewriteCertificateCommonName}})
		{
		    # We use an eval so an error in the pattern wont kill us.
		    eval("\$cn =~ $rule");
		    &main::log($main::LOG_ERR, "Error while rewriting certificate common name $cn: $@", $p) 
			if $@;
		    
		    &main::log($main::LOG_DEBUG, "Rewrote certificate common name to $cn", $p);
		}
		# The subject conversion can leave literal '\x00' where there were NUL chars in 
		# a Unicode CN string. Here we remove them to give the ASCII equivalent. 
		# Some CAs use Unicode iff there is an @ in the CN.
		$cn =~ s/\\x00//g;

		# If there is a hook, run it to see if the CN matches the 
		# username or whatever
		if (defined $self->{EAPTLS_CommonNameHook})
		{
		    ($matchedcn) = $self->runHook('EAPTLS_CommonNameHook', $p, $cn, $username, $context->{identity}, $p);
		    if (defined $matchedcn)
		    {
			&main::log($main::LOG_DEBUG, "Matched certificate CN $cn using EAPTLS_CommonNameHook", $p);
			last;
		    }
		}
		if (   $username eq $cn || $username_nodomain eq $cn 
		    || $context->{identity} eq $cn || $identity_nodomain eq $cn)
		{
		    &main::log($main::LOG_DEBUG, "Matched certificate CN $cn with User-Name $username or identity $context->{identity}", $p);
		    $matchedcn = $cn;
		    last;
		}
	    }

	    if (!defined $matchedcn)
	    {
		# Look for a SubjectAltName that might match
		# X509_get_subjectAltNames returns array of (type, string)
		# type == 0 is OTHERNAME, whcih might be a Windows UPN, as 
		# per http://support.microsoft.com/kb/281245
		# For other types see openssl/x509v3.h GEN_*
		# Caution: Net-SSLEay versions before 1.33 can crash 
		# when there are unusual subject alt names in the cert.
		my @altnames = &Net::SSLeay::X509_get_subjectAltNames($cert);
		while (@altnames)
		{
		    my ($type, $name) = splice(@altnames, 0, 2);
		    
		    $self->log($main::LOG_DEBUG, "Checking subjectAltName type $type, value $name");
		    if ($type == 0)
		    {
			# GEN_OTHERNAME:
			if (   $username eq $name || $username_nodomain eq $name 
			       || $context->{identity} eq $name || $identity_nodomain eq $name)
			{
			    &main::log($main::LOG_DEBUG, "Matched certificate subjectAltName $name with User-Name $username or identity $context->{identity}", $p);
			    $matchedcn = $name;
			    last;
			}
		    }
		}
	    }

	    if (!defined $matchedcn)
	    {
		# Still no match
		$self->log($main::LOG_INFO, "EAP TLS client certificate subject $subject does not match user name $username or identity $context->{identity}", $p);
		return 50; # X509_V_ERR_APPLICATION_VERIFICATION
	    }

	    # Make sure the user we authenticated is in our database too
	    my ($user, $result, $reason) = $self->get_user($matchedcn, $p);
	    if (!$user || $result != $main::ACCEPT)
	    {
		$self->log($main::LOG_INFO, "EAP TLS Could not authenticate user $matchedcn: $reason", $p);
		return 50; # X509_V_ERR_APPLICATION_VERIFICATION
	    }
	    $context->{tls_authenticated_user} = $user;
	    $context->{tls_authenticated_cn} = $matchedcn;
	    
	}

	if (defined $self->{EAPTLS_CertificateVerifyHook})
	{
	    ($matchedcn) = $self->runHook('EAPTLS_CertificateVerifyHook', $p, $matchedcn, $x509_store_ctx, $cert, $subject_name, $subject, $p);
	    if (!defined $matchedcn)
	    {
		$self->log($main::LOG_INFO, "EAPTLS_CertificateVerifyHook returned undefined", $p);
		return 50; # X509_V_ERR_APPLICATION_VERIFICATION
	    }
	}
    }
    return 0;
}

1;
