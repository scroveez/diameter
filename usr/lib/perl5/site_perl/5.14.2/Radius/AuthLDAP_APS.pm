# AuthLDAP_APS.pm
#
# Object for handling Authentication via LDAP then via Apple Password Server (if appropriate).
# If this module is configured correctly, the 'correct password' passed to these 
# functions will be the user's authAuthority attribute from the Mac OS-X Directory Server. 
# If it is this format:
# ;ApplePasswordServer;0x45de6abc3dce3ee80000000400000004,1024 35 156132593913068703948785881998128565986086729156521138815551995107230241392569438668769971816362272614251975258090659334261125362335258547283617124617396734939337472013513216627957294252663720755271465197239066894869711871954048503316649280339728422169429922391305083883839650971445948825476785569514372513271 root@yoke.local:203.63.154.59
# then this module will contact the indicated Apple Password server to authenticate 
# the submitted password. PAP and MSCHAPV2 are the only supported mechanisms so far. 
# MacOX-X 10.4 PS does not appear to support CHAP or MSCHAPV1. 
# PS does support DIGEST-MD5, but that is not supported by this module (yet). 
#
# Therefore, this module support Mac OS-X authentication of users configured into 
# Apple Directory Server with an authentication type of Apple Password Server.
#
# Supports PAP, MSCHAPV2, but not CHAP, MSCHAPV1 or DIGEST-MD5
#
# Requires:
# Crypt::OpenSSL::Random;
# Crypt::OpenSSL::RSA;
# Crypt::OpenSSL::Bignum;
# MIME::Base64;
# Digest::MD5;
# Digest::HMAC_MD5;
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthLDAP_APS.pm,v 1.8 2008/09/17 21:30:33 mikem Exp $

package Radius::AuthLDAP_APS;
@ISA = qw(Radius::AuthLDAP2);
use Radius::AuthLDAP2;
use Radius::ApplePasswordServer;
use strict;

%Radius::AuthLDAP_APS::ConfigKeywords = 
('PasswordServerAddress'            => 
 ['string', 
  'If this parameter is set, it forces Radiator to use the specified address as the address of the Apple Password server, instead of deducing it from the user\'s password details. Addresses may be one of the forms: 203.63.154.59, dns/yoke.open.com.au, ipv4/203.63.154.59 or ipv6/2001:720:1500:1::a100. This can be useful with replicated password servers.', 
  2],
 );

# RCS version number of this module
$Radius::AuthLDAP_APS::VERSION = '$Revision: 1.8 $';


#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();

    $self->{APS} = Radius::ApplePasswordServer->new();
    $self->{APS}->activate();
}


#####################################################################
# Overrideable function that checks a plaintext password response
# $p is the current request
# $username is the users (rewritten) name
# $submitted_pw is the PAP password received from the user
# $pw is the correct password if known
sub check_plaintext
{
    my ($self, $p, $username, $submitted_pw, $pw) = @_;

    # split into userid,server_public_certificate,PS_address
    # Caution, the spec says it might be preceded by a version number
    if ($pw =~ /ApplePasswordServer;(0x[0-9a-fA-F]+),(\d+ \d+ \d+ \S+):(\S+)/)
    {
	my ($userid, $certificate, $psaddress) = ($1, $2, $3);
	$psaddress = $self->{PasswordServerAddress} 	
	     if defined  $self->{PasswordServerAddress};
	my $ps = $self->{APS}->connect($psaddress, $certificate);
	if (!$ps)
	{
	    $self->log($main::LOG_ERR, "Could not connect to Apple Password server at $psaddress");
	    return;
	}
	return $ps->auth_plaintext($userid, $submitted_pw);
    }
    else
    {
	return $self->SUPER::check_plain_password($p, $username, $submitted_pw, $pw);
    }
}

#####################################################################
# Overrideable function that checks a MSCHAP password response
# $p is the current request
# $username is the users (rewritten) name
# $pw is the 'plaintext password' from the LDAP server, it could be the ApplePasswordServer
# string
# $sessionkeydest is a ref to a string where the session key for MPPE will be returned
# $context may be present some persistent storage for handles etc
sub check_mschapv2_plaintext
{
    my ($self, $p, $username, $pw, $challenge, $peerchallenge, $response, 
	$mppekeys_dest, $authenticator_responsedest, $lanmansessionkeydest, $context) = @_;

    # Strip off any DOMAIN, else the mschapv2 auth response will fail
    $username =~ s/^(.*)\\//;

    # split into userid,server_public_certificate,PS_address
    # Caution, the spec says it might be preceded by a version number
    if ($pw =~ /ApplePasswordServer;(0x[0-9a-fA-F]+),(\d+ \d+ \d+ \S+):(\S+)/)
    {
	my ($userid, $certificate, $psaddress) = ($1, $2, $3);
	$psaddress = $self->{PasswordServerAddress} 	
	     if defined  $self->{PasswordServerAddress};
	my $ps = $self->{APS}->connect($psaddress, $certificate);
	if (!$ps)
	{
	    $self->log($main::LOG_ERR, "Could not connect to Apple Password server at $psaddress");
	    return;
	}
	return $ps->auth_mschapv2($userid, $challenge, $peerchallenge, $response, $username,
				  $mppekeys_dest, $authenticator_responsedest);
    }
    else
    {
	return $self->SUPER::check_mschapv2_plaintext
	    ($p, $username, $pw, $challenge, $peerchallenge, $response, 
	     $mppekeys_dest, $authenticator_responsedest, $lanmansessionkeydest, $context);
    }
}

#####################################################################
# Not working yet
sub check_digest_md5
{
    my ($self, $p, $username, $realm, $nonce, $cnonce, $nc, $qop, 
	$method, $uri, $eb_hash, $response, $pw) = @_;

    # split into userid,server_public_certificate,PS_address
    # Caution, the spec says it might be preceded by a version number
    if ($pw =~ /ApplePasswordServer;(0x[0-9a-fA-F]+),(\d+ \d+ \d+ \S+):(\S+)/)
    {
	my ($userid, $certificate, $psaddress) = ($1, $2, $3);
	$psaddress = $self->{PasswordServerAddress} 	
	     if defined  $self->{PasswordServerAddress};
	my $ps = $self->{APS}->connect($psaddress, $certificate);
	if (!$ps)
	{
	    $self->log($main::LOG_ERR, "Could not connect to Apple Password server at $psaddress");
	    return;
	}

	return $ps->auth_digest_md5($userid, $realm, $nonce, $cnonce, $nc, $qop, $method, $uri, $response);
    }
    else
    {
	return $self->SUPER::check_digest_md5
	    ($p, $username, $realm, $nonce, $cnonce, $nc, $qop, 
	     $method, $uri, $eb_hash, $response, $pw);
    }
}
1;




