# AuthYUBIKEYGENERIC.pm
#
# Object for handling Authentication of Yubikey tokens (yubico.com)
# from any type of database
#
# Requires Auth-Yubikey_Decrypter-0.05 or later, and Crypt::Rijndael
# See http://www.yubico.com/files/YubiKey_Manual_2009-12-03.pdf
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001-2010 Open System Consultants
# $Id: AuthYUBIKEYGENERIC.pm,v 1.5 2014/03/25 21:57:47 hvn Exp $

package Radius::AuthYUBIKEYGENERIC;
@ISA = qw(Radius::AuthYUBIKEYBASE);
use Radius::AuthYUBIKEYBASE;
use Auth::Yubikey_Decrypter;
use MIME::Base64;
use strict;

%Radius::AuthYUBIKEYGENERIC::ConfigKeywords = 
( 'Require2Factor'           => 
 ['flag', 'Forces all authentications to require 2 factor authentication', 0],

  'CheckSecretId'           => 
 ['flag', 'If CheckSecretId is set, then check that the secretId fetched from the database matches the secretId encoded in the submitted Yubikey OTP. This increases the security of the Yubikey OTP and is recommended best practice.', 0],

 );

# RCS version number of this module
$Radius::AuthYUBIKEYGENERIC::VERSION = '$Revision: 1.5 $';

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    $self->SUPER::check_config();
    return;
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
}

#####################################################################
# $submitted_pw is the response being authenticated
# $user is the user name to be authenticated
# return (result, reason)
sub checkYubikey
{
    my ($self, $user, $submitted_pw, $p) = @_;

    # yubikey codes consist of 12 bytes of tokenid, followed by 32 bytes of one-time-password
    # The user might prefix a static password if 2 Factor authenticaiotn is in use
    # unpack the password into password, tokenid, otp
    # for example (no static password):
    #   ccccccccefeiujbfhkhfurbitjcvuvnedivhbeighuvf
    # static password:
    #   fred:ccccccccefeiujbfhkhfurbitjcvuvnedivhbeighuvf
    # static password (for Yubikeys with default token lengths:
    #   fredccccccccefeiujbfhkhfurbitjcvuvnedivhbeighuvf
    # Caution: it is possible to reprogram a Yubikey with a different length token ID. Such
    # tokens will not work with the following code:
    my ($password, $tokenid, $otp) = $submitted_pw =~ /^(.*):([cbdefghijklnrtuv]{12})([cbdefghijklnrtuv]+)$/;
    ($password, $tokenid, $otp) = $submitted_pw =~ /^(.*)([cbdefghijklnrtuv]{12})([cbdefghijklnrtuv]{32})$/
	unless defined $password;

    return ($main::REJECT, "Bad Yubikey password format")
	unless (defined $tokenid && defined $otp);
	
    my ($secret, $active, $secretId, $counter, $session_use, $dummy, $staticpassword) = 
	$self->getYubikeyData($user, $tokenid, $p);
    return ($main::REJECT, "Yubikey secret not found in database")
	unless defined $secret;

    return ($main::REJECT, "Yubikey is not active")
	if defined $active && not $active;
    if (length $password || $self->{Require2Factor})
    {
	$staticpassword = $self->translate_password($staticpassword);
	return ($main::REJECT, "Bad static password")
	    unless $self->check_plain_password($user, $password, $staticpassword);
    }

    my $secret_hex;
    if ($secret =~ /^[0-9a-fA-F]{32}$/)
    {
	# Secret is in hex
	$secret_hex = $secret;
    }
    else
    {
	# Secret is Base64
	my $secret_bin = MIME::Base64::decode_base64($secret);
	$secret_hex = unpack('H*', $secret_bin);
    }

    my ($publicID, $secretid_hex, $counter_dec, $timestamp_dec, $session_use_dec, $random_dec, $crc_dec, $crc_ok);
    eval
    {
	# yubikey_decrypt can die
	($publicID, $secretid_hex, $counter_dec, $timestamp_dec, $session_use_dec, $random_dec, 
	 $crc_dec, $crc_ok) = Auth::Yubikey_Decrypter::yubikey_decrypt($tokenid . $otp, $secret_hex);
    };
#    print "Decrypted OTP to $publicID, $secretid_hex, $counter_dec, $timestamp_dec, $session_use_dec, $random_dec, $crc_dec, $crc_ok\n";
    return ($main::REJECT, "yubikey_decrypt failed: $@")
	if $@ ne '';

    return ($main::REJECT, "Bad Yubikey password")
	unless $crc_ok;

    return ($main::REJECT, "Bad Yubikey Secret-Id")
	if $self->{CheckSecretId} && $secretid_hex ne $secretId;

    $counter_dec &= 0x7fff; # Mask off the external keyboard trigger bit

    # Maybe check the counter and timestamp for a reply attack
    # If the counter has gone backwards, or if it is the same and the timestamps are also the same, then
    # its a replay of an earlier auth.
    return ($main::REJECT, "Replay attack detected")
	if (defined $counter 
	    && (($counter > $counter_dec) 
		|| (($counter == $counter_dec) && ($session_use >= $session_use_dec))));

    return ($main::IGNORE, "Database update failed")
	unless $self->updateYubikeyData($user, $tokenid, $counter_dec, $session_use_dec, $p);
	
    # Update the database with the new counter and timestamps
    return ($main::ACCEPT);
}


1;
