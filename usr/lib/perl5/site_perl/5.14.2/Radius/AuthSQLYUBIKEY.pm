# AuthSQLYUBIKEY.pm
#
# Object for handling Authentication of Yubikey tokens (yubico.com)
# from an SQL database
#
# Requires Auth-Yubikey_Decrypter-0.05 or later, and Crypt::Rijndael
# See http://www.yubico.com/files/YubiKey_Manual_2009-12-03.pdf
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001-2010 Open System Consultants
# $Id: AuthSQLYUBIKEY.pm,v 1.16 2013/08/13 20:58:45 hvn Exp $

package Radius::AuthSQLYUBIKEY;
@ISA = qw(Radius::AuthYUBIKEYGENERIC Radius::SqlDb);
use Radius::AuthYUBIKEYGENERIC;
use Radius::SqlDb;
use Auth::Yubikey_Decrypter;
use MIME::Base64;
use strict;

%Radius::AuthSQLYUBIKEY::ConfigKeywords = 
('AuthSelect'            => 
 ['string', 'SQL query that will be used to fetch Yubikey data from the database. Special characters are permitted, and %0 is replaced with the quoted user name. %1 is replaced with the token ID. The default works with the (obsolete) sample yubikey database created by db_schema.sql from the YubiKey Validation Server.', 0],
 'UpdateQuery'           => 
 ['string', 'SQL query that will be used to store Yubikey token data back to the database after successful authentication.', 0],
 );

# RCS version number of this module
$Radius::AuthSQLYUBIKEY::VERSION = '$Revision: 1.16 $';

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    $self->Radius::AuthYUBIKEYGENERIC::check_config();
    $self->Radius::SqlDb::check_config();
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
    $self->Radius::SqlDb::initialize();
    $self->{AuthSelect}        = 'select secret, active, userId, counter, low, high, NULL from yubikeys where userId=%0';
    $self->{UpdateQuery}       = 'update yubikeys set accessed=current_timestamp(), counter=%0, low=%1, high=%2 where userId=%3';
}


#####################################################################
# Get data for a yubikey from the database
# Required to return ($secret, $active, $secretId, $counter, $session_use, $dummy, $staticpassword)
sub getYubikeyData
{
    my ($self, $username, $tokenid, $p) = @_;

    # Convert the token id to b64, the format used in the database
    my $tokenid_bin = Auth::Yubikey_Decrypter::yubikey_modhex_decode($tokenid);
    my $tokenid_b64 = MIME::Base64::encode_base64($tokenid_bin, '');
    my $tokenid_hex = unpack('H*', $tokenid_bin);

    # Get data for this user or token from the database
    my $qname = $self->quote($username);
    my $qtokenid_b64 = $self->quote($tokenid_b64);
    my $qtokenid_hex = $self->quote($tokenid_hex);
    my $qtokenid_modhex = $self->quote($tokenid);
    my $q = &Radius::Util::format_special($self->{AuthSelect}, $p, $self, $qname, $qtokenid_b64, $qtokenid_hex, $qtokenid_modhex);
    my $sth = $self->prepareAndExecute($q);
    return unless $sth;

    # CAUTION: what was low is now really the session_use counter, which is incremented
    # each time the button is pressed and reset to 0 when the counter is inserted
    # it is a more reliable detector of replay attacks than the timestamp
    my ($secret, $active, $secretId, $counter, $session_use, $dummy, $staticpassword) 
	= $self->getOneRow($sth);
    $self->log($main::LOG_DEBUG, "AuthSQLYUBIKEY read: $secret, $active, $secretId, $counter, $session_use, $dummy, $staticpassword", $p);	
    return unless defined $secret;

    return ($secret, $active, $secretId, $counter, $session_use, $dummy, $staticpassword)
}

#####################################################################
# Update data for a yubikey from the database
sub updateYubikeyData
{
    my ($self, $username, $tokenid, $counter_dec, $session_use_dec, $p) = @_;

    # Convert the token id to various formats for user in teh database
    my $tokenid_bin = Auth::Yubikey_Decrypter::yubikey_modhex_decode($tokenid);
    my $tokenid_b64 = MIME::Base64::encode_base64($tokenid_bin, '');
    my $tokenid_hex = unpack('H*', $tokenid_bin);

    # Get data for this user or token from the database
    my $qname = $self->quote($username);
    my $qtokenid_b64 = $self->quote($tokenid_b64);
    my $qtokenid_hex = $self->quote($tokenid_hex);
    my $qtokenid_modhex = $self->quote($tokenid);

    my $q = &Radius::Util::format_special($self->{UpdateQuery}, $p, $self, $counter_dec, $session_use_dec, 0, $qname, $qtokenid_b64, time(), $qtokenid_hex, $qtokenid_modhex);
    return $self->do($q);

}

1;

