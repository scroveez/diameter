# AuthKRB5.pm
#
# Object for handling Authentication via Kerberos 5
#
# This file will be 'require'd only one time when the first Kerberos
# Realm with an AuthType of KRB5 is found in the config file
#
# This package only verifies the users password, and doesn't
# try to maintain credentials in any way.  
# Accounting packets are ignored.
#
# Author: Steven Harper (s.harper@utah.edu)
# Based on AuthPAM.pm and AuthTEST.pm 
#  by Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001 Open System Consultants
#
# 2004/04/23 -  Fixes by Jeff Wolfe (wolfe@ems.psu.edu) to enable
#               the module to call to multiple K5 realms. 
#
# $Id: AuthKRB5.pm,v 1.13 2013/04/26 08:42:13 hvn Exp $

package Radius::AuthKRB5;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Authen::Krb5;   
use Sys::Hostname;
use strict;

%Radius::AuthKRB5::ConfigKeywords = 
 ('KrbRealm'   => 
  ['string', 'This optional parameter is the name of the Kerberos realm that all Kerberos users are assumed to be in. Defaults to the default Kerberos realm defined by your Kerberos administrator.', 1],

  'KrbServerRealm'   => 
  ['string', 'This optional parameter is the name of the Kerberos realm that the Kerberos server is assumed to be in. Defaults to the KrbRealm value.', 1],

  'KrbKeyTab'  => 
  ['string', 'This optional parameter provides the path to a Kerberos keytab file. When this option is present, a service ticket will be obtained as part of each Kerberos authentication attempt to guard against Key Distribution Center spoofing.', 1],

  'KrbService' => 
  ['string', 'This optional parameter overrides the default value of "radius" for the service name used when locating a key to obtain a service ticket as part of Kerberos Key Distribution Center spoof detection. This parameter has no effect unless the KrbKeyTab parameter is defined. ', 1],

  'KrbServer'  => 
  ['string', 'This optional parameter overrides the default value of the fully qualified domain name of the server running radiator when locating a key to obtain a service ticket as part of Kerberos Key Distribution Center spoof detection. This parameter has no effect unless the KrbKeyTab parameter is defined. ', 0],

);

# RCS version number of this module
$Radius::AuthKRB5::VERSION = '$Revision: 1.13 $';

#####################################################################
# Do per-instance default initialization
# This is called by Configurable during Configurable::new before
# the config file is parsed. Its a good place initialize instance 
# variables
# that might get overridden when the config file is parsed.
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    if (! $Radius::AuthKRB5::InitStatus++)
    {
	&Authen::Krb5::init_context();
#	&Authen::Krb5::init_ets(); # Not present in krb5-1.4.* and not needed?
    }
    $self->{KrbRealm} = Authen::Krb5::get_default_realm();
    $self->{KrbService} = "radius";
    $self->{KrbServer} = lc gethostbyaddr(gethostbyname(hostname()),2);
    $self->{NoDefault} = 1;
}

#####################################################################
# We subclass this to do nothing: there are no check items
# except the password, and only if its not an EAP
sub checkUserAttributes
{
    my ($self, $user, $p) = @_;
    
    # Short circuit authentication in EAP requests ?
    return ($main::ACCEPT) 
      if $p->getAttrByNum($Radius::Radius::EAP_MESSAGE);

    return $self->check_plain_password($p->getUserName(), $p->decodedPassword(), undef, $p);
}

#####################################################################
# $submitted_pw is the password being authenticated
# $pw is the correct password if known
# $user is the user name to be authenticated
sub check_plain_password
{
    my ($self, $user_name, $submitted_pw, $pw, $p, $encrypted) = @_;

    return ($main::ACCEPT) if $self->{NoCheckPassword};

    #Strips "@BLAHBLAH.COM"
    $user_name =~ s/@[^@]*$//;
    my $password = $p->decodedPassword();

    my ($result, $reason);

    $self->log($main::LOG_DEBUG, "Building Kerberos principal: $user_name\@$self->{KrbRealm}", $p);

    # If the full principal isn't specified, k5 will try to use the default_realm from k5.conf
    # which will cause an unhelpful realm name/principal name mismatch error.
    my $kprinc = Authen::Krb5::parse_name("$user_name\@$self->{KrbRealm}");
    unless ($kprinc) 
    {
	$result = $main::REJECT;
	$reason = 'parse_name failed: ' . Authen::Krb5::error($kprinc);
	return ($result, $reason);
    }

    # rather than use sname_to_principal, use a simple parse_name call for the server princ.
    # it's much cleaner. Tested against DCE, MIT K5 and Win AD.
    my $kservprinc = Authen::Krb5::parse_name("krbtgt/$self->{KrbRealm}\@$self->{KrbRealm}");
    unless ($kservprinc) 
    {
	$result = $main::REJECT;
	$reason = 'parse_name failed: ' . Authen::Krb5::error($kservprinc);
	return ($result, $reason);
    }

    #use cc_resolve(TYPE:RESIDUAL) here instead..    
    # Create a credentials cache object from the cache ID:
    my $kcc = Authen::Krb5::cc_resolve("MEMORY:RADIUS");
    unless ($kcc) 
    {
	$result = $main::REJECT;
	$reason = 'cc_default failed: ' . Authen::Krb5::error($kcc);
	$kcc->destroy;
	return ($result, $reason);
    }

    # Initialize the credential cache.
    $kcc->initialize($kprinc);

    # Check principle and passphrase by requesting ticket granting ticket.
    my $kerror = Authen::Krb5::get_in_tkt_with_password($kprinc, $kservprinc, $password, $kcc);
    unless ($kerror) 
    {
	$result = $main::REJECT;
	$reason = 'Kinit failed: ' . Authen::Krb5::error($kerror);
	$kcc->destroy;
	return ($result, $reason);
    }        
    
    $self->log($main::LOG_DEBUG, "Valid TGT obtained for principal: " . $kprinc->data() . "@" . $kprinc->realm(), $p);
    
    # if a keytab is provided, obtain a service ticket to detect a spoofed KDC.
    if (defined($self->{KrbKeyTab})) 
    {
	$self->log($main::LOG_DEBUG, "Obtaining service ticket using KrbKeyTab: " . $self->{KrbKeyTab} . " service: " . $self->{KrbService} . " server: " . $self->{KrbServer} . " realm: " . $self->{KrbServerRealm}, $p);
	
	# Set KrbServerRealm to KrbRealm if not defined
	unless (defined $self->{KrbServerRealm}) 
	{
	    $self->{KrbServerRealm} = $self->{KrbRealm};
	}

	# Create a new service principal object from the service, hostname and realm.
	my $sprinc = Authen::Krb5::parse_name("$self->{KrbService}/$self->{KrbServer}\@$self->{KrbServerRealm}");
	unless ($sprinc) 
	{
	    $result = $main::REJECT;
	    $reason = 'parse_name failed: ' . Authen::Krb5::error($sprinc);
	    $kcc->destroy;
	    return ($result, $reason);	
	}
	
	# Allocate an auth context object.
	my $ac = new Authen::Krb5::AuthContext;
	unless ($ac) 
	{
	    $result = $main::REJECT;
	    $reason = 'AuthContext failed: ' . Authen::Krb5::error($ac);
	    $kcc->destroy;
	    return ($result, $reason);
	}
	
	# Send a service ticket request.
	my $ap_rep = Authen::Krb5::mk_req($ac,0,$self->{KrbService},$self->{KrbServer},0,$kcc);
	unless ($ap_rep) 
	{
	    $result = $main::REJECT;
	    $reason = 'mk_req failed: ' . Authen::Krb5::error($ap_rep);
	    $kcc->destroy;
	    return ($result, $reason);
	}

	# Create a keytab ID from the argument keytab file.
	my $kt = Authen::Krb5::kt_resolve("FILE:" . $self->{KrbKeyTab});
	unless ($kt) 
	{
	    $result = $main::REJECT;
	    $reason = 'kt_resolve failed: ' . Authen::Krb5::error($kt);
	    $kcc->destroy;
	    return ($result, $reason);
	}

	# Allocate a new auth context, effectively freeing the old one.  (This
	# assures that we use the keytab file instead of a non-NULL keyblock
	# contained in the old auth context).
	$ac = new Authen::Krb5::AuthContext;
	
	# Validate the service ticket.
	my $svc_tkt = Authen::Krb5::rd_req($ac,$ap_rep,$sprinc,$kt);
	unless ($svc_tkt) 
	{
	    $result = $main::REJECT;
	    $reason = 'rd_req failed: ' . Authen::Krb5::error($svc_tkt);
	    $kcc->destroy;
	    return ($result, $reason);
	}

	$self->log($main::LOG_DEBUG, "Service ticket is valid", $p);
    }

    # If we got this far, the authentication succeeded:
    $result = $main::ACCEPT;
    
    $kcc->destroy;
    return ($result, $reason);
}

#####################################################################
# This is a bogus findUser that basically does nothing but does not
# fail
sub findUser
{
    my ($self, $name, $p) = @_;

    return Radius::User->new();
}

1;
