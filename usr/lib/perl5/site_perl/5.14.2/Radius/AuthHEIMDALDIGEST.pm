# AuthHEIMDALDIGEST.pm
#
# Object for handling Authentication with a Heimdal Kerberos KDC
# This module uses the program kdigest shipped with Heimdal to do digest
# authentication without the radius server ever seeing the password.
#
# This file will be 'require'd only one time when the first Realm 
# with an AuthType of HEIMDALDIGEST is found in the config file
#
# Author: Klas Lindfors (klas.lindfors@it.su.se)
# Modified and modernized, fixed some bugs, integrated into Radiator 4.10 by Mike McCauley 2012
# Copyright (C) Open System Consultants Pty Ltd.
# assigned to OSC by Stockholm University 2012-11-02
# $Id: AuthHEIMDALDIGEST.pm,v 1.3 2013/08/13 20:58:45 hvn Exp $

package Radius::AuthHEIMDALDIGEST;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use strict;

$Radius::AuthHEIMDALDIGEST::VERSION = '$Revision: 1.3 $';

%Radius::AuthHEIMDALDIGEST::ConfigKeywords =
(
 'KdigestPath'              => 
 ['string', 
  'The path to the executable Heimdal kdigest program. This program will be run externally by AuthBy HEIMDALDIGEST to authenticate each password. Defaults to /usr/libexec/kdigest',
  1],

 'KdigestSuffix'              => 
 ['string', 
  'String that will be added to the end of each username before authenticating with kdigest. Defaults to empty string. See also default_realm in krb5.conf, which will be used if username does not contain a Kerberos realm.',
  1],

 'KdigestRealm'              => 
 ['string', 
  'String specifying the Kerberos realm that will be used to authenticate each user. Used to specify --kerberos-realm= to kdigest. Defaults to undefined',
  1],
);

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    $self->log($main::LOG_ERROR, "KdigestPath binary $self->{KdigestPath} is not executable") 
	unless -e $self->{KdigestPath};

    $self->SUPER::check_config();
    return;
}

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;

    $self->{KdigestPath} = '/usr/libexec/kdigest';
}

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate;
}

#####################################################################
# Find the named user, return a User object if found for this
# authentication type else undef.
# If there is a database access error (as opposed to the user
# was not found, return (undef, 1)
sub findUser
{
    my ($self, $name, $p) = @_;
    
    $self->log($main::LOG_DEBUG, "AuthBy HEIMDALDIGEST findUser", $p);
    my $user = Radius::User->new($name);
    # A password that can never succeed: protect against unsupported auth types.
    $user->get_check->add_attr('User-Password', '{nthash}xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx');
    return($user);
}

#####################################################################
sub checkUserAttributes
{
    my ($self, $user, $p) = @_;

    my $userName = $p->getUserName();
    
    # Short circuit authentication in EAP requests ?
    return ($main::ACCEPT) if $p->getAttrByNum($Radius::Radius::EAP_MESSAGE);
    return ($main::ACCEPT) if $self->check_password($p, $p->decodedPassword(), $userName);
    return ($main::REJECT, 'AuthBy HEIMDALDIGEST Cant handle this type of request');
}

#####################################################################
# Check a plaintext PAP password
# Generate kdigest challenge and do the MD5 challenge test
# $pw is the submitted password
sub check_password
{
    my ($self, $p, $pw, $username, $encrypted) = @_;

    my $id = 1;
    my $context = { this_id => $id}; # Fake context for kdigest_digest
    my $challenge = $self->kdigest_challenge($context, "CHAP");
    my $response = Digest::MD5::md5(chr($id) . $pw . $challenge);
    return $self->kdigest_digest($username, $context, $response, undef, 'CHAP');
}

#####################################################################
# Check an MD5 repsonse digest
sub check_md5
{
    my ($self, $context, $p, $username, $pw, $chapid, $challenge, $response) = @_;

    return $self->kdigest_digest($username, $context, $response, undef, 'CHAP');
}

#####################################################################
# Check an mschap response digest
sub check_mschapv2
{
    my ($self, $p, $username, $nthash, $challenge, $peerchallenge, $response,
	$mppekeys_dest, $authenticator_responsedest, $lanmansessionkeydest, $context) = @_;
    
    my $status = $self->kdigest_digest($username, $context, $response, $peerchallenge, 'MS-CHAP-V2');
    $$authenticator_responsedest = "S=" . $context->{rsp};
    
    # Maybe generate MPPE keys.
    # session_key from kdigest is in fact the MSCHAP master key
    $$mppekeys_dest = Radius::MSCHAP::mppeGetKeyFromMasterKey($context->{session_key}, 16) 
	if defined $mppekeys_dest;
    
    return ($status);
}

#####################################################################
# Check a digest against using Heimdal kdigest
sub kdigest_digest
{
    my ($self, $username, $context, $client_response, $client_challenge, $type) = @_;

    my $status;
    my $realm;
    my $client_nonce;
    $username .= $self->{KdigestSuffix} 
        if defined $self->{KdigestSuffix};
    $realm = '--kerberos-realm="' . $self->{KdigestRealm} . '"' 
	if defined $self->{KdigestRealm};
    $client_nonce = '--client-nonce="' . $self->kdigest_unpackstring($client_challenge) . '"' 
	if defined $client_challenge;

    my $command = $self->{KdigestPath} . " digest-server-request --type=$type --username=\"$username\" --opaque=\"" . $context->{kdigest_opaque} . "\" --server-identifier=\"" . sprintf('%.2X', $context->{this_id}) . "\" --server-nonce=\"" . $self->kdigest_unpackstring($context->{challenge}) . "\" --client-response=\"" . $self->kdigest_unpackstring($client_response) . "\" $client_nonce $realm |";
    $self->log($main::LOG_DEBUG, "AuthHEIMDALDIGEST digest command: $command");

    open(FH, $command);
    while(<FH>)
    {
	chomp;
	my $output = $_;
	$self->log($main::LOG_DEBUG, "AuthHEIMDALDIGEST digest command output: $output");
	
	m/([\w\-]+)\=([\w\-]+)/;
	next if $1 eq 'tickets';
	$status = $2 and next if $1 eq 'status';
	$context->{rsp} = $2 and next if $1 eq 'rsp';
	$context->{session_key} = $self->kdigest_packstring($2) and next if $1 eq 'session-key';
	$self->log($main::LOG_ERROR, "Unexpected output from kdigest: $output.");
    }
    close(FH);
    if ($status eq "ok")
    {
	return $status;
    }
    else
    {
	return;
    }
}

#####################################################################
# Use Heimdal to generate an MD5 challenge
sub md5_challenge
{
    my ($self, $context, $p) = @_;
    $context->{md5_challenge} = $self->kdigest_challenge($context, 'CHAP');
}

#####################################################################
# Use Heimdal to generate an MSCHAP challenge
sub mschapv2_challenge
{
    my ($self, $context, $p) = @_;
    $context->{mschapv2_challenge} = $self->kdigest_challenge($context, 'MS-CHAP-V2');
}

#####################################################################
# Generate a challenge for the user with Heimdal kdigest
sub kdigest_challenge
{
    my ($self, $context, $type) = @_;
    my $realm;
    $realm = "--kerberos-realm=\"" . $self->{KdigestRealm} . "\"" if defined $self->{KdigestRealm};

    my $command = $self->{KdigestPath} . " digest-server-init --type=$type $realm |";
    $self->log($main::LOG_DEBUG, "AuthHEIMDALDIGEST challenge command: $command");
    open(FH, $command);
    while(<FH>)
    {
	chomp;
	my $output = $_;
	$self->log($main::LOG_DEBUG, "AuthHEIMDALDIGEST challenge command output: $output");

	m/([\w\-]+)\=([\w\-]+)/;
	next if $2 eq "$type";
	
	$context->{challenge} = $self->kdigest_packstring($2) and next if $1 eq 'server-nonce';
	$context->{kdigest_identifier} = $2 and next if $1 eq 'identifier';
	$context->{kdigest_opaque} = $2 and next if $1 eq 'opaque';
	$self->log($main::LOG_ERROR, "Unexpected output from kdigest: $output.");
    }
    close(FH);
    return($context->{challenge});
}

#####################################################################
sub kdigest_packstring
{
    my ($self, $string) = @_;

    return pack('H*', $string);
}

#####################################################################
sub kdigest_unpackstring
{
    my ($self, $string) = @_;

    return uc(unpack('H*', $string));
}

1;

