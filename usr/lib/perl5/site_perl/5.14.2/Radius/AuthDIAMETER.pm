# AuthDIAMETER.pm
#
# RFC 4005 Diameter Network Access Server Application
#
# Author: Heikki Vatiainen (hvn@open.com.au)
# Copyright (C) 2013 Open System Consultants
# $Id: AuthDIAMETER.pm,v 1.4 2014/11/27 20:57:06 hvn Exp $

package Radius::AuthDIAMETER;
@Radius::AuthDIAMETER::ISA = qw(Radius::AuthGeneric Radius::DiaClient);
use Radius::AuthGeneric;
use Radius::DiaClient;
use Radius::RadiusDiameterGateway;
use strict;
use warnings;

#####################################################################
# This hash describes all the standards types of keywords understood by this
# class. If a keyword is not present in ConfigKeywords for this
# class, or any of its superclasses, Configurable will call sub keyword
# to parse the keyword
# See Configurable.pm for the list of permitted keywordtype
%Radius::AuthDIAMETER::ConfigKeywords =
('Peer'                       =>
 ['string', 'Name or IP address of the Diameter peer. IPV4 and IPV6 addresses are supported', 0],

 'AuthApplicationIds'             => 
 ['string', 'This optional parameter allows you to define the Auth Application Ids announced in CER. Defaults to DIAMETER BASE, NASREQ and Diameter-EAP', 1],

 'AcctApplicationIds'             => 
 ['string', 'This optional parameter allows you to define the Acct Application Ids announced in CER. Defaults to BASE_ACCOUNTING', 1],

 'SupportedVendorIds'             => 
 ['string', 'This optional parameter allows you to define the Supported Vendor Ids announced in CER. There is no default and no Supported-Vendor-Id is announced by default. Keyword "DictVendors" is an alias group for all vendors in the default dictionary and the dictionary file configured with DiameterDictionaryFile.', 1],

 'PostDiaToRadiusConversionHook'             =>
 ['hook', 'This optional parameter allows you to define a Perl function that will be called during packet processing. PostDiaToRadiusConversionHook is called after an incoming Diameter request has been converted to its equivalent RADIUS request, allowing you to alter or ad to attritbute conversions etc. It is passed references to the incoming Diameter reqest and the converted RADIUS request.', 2],

 'PostRadiusToDiaConversionHook'             =>
 ['hook', 'This optional parameter allows you to define a Perl function that will be called during packet processing. PostDiaToRadiusConversionHook is called after an RADIUS reply has been converted to its equivalent Diameter reply, prior to being sent back to the Diameter client. It is passed references to the RADIUS reply and the converted Diameter reply.', 2],

 # Local* options will move to appropriate class in the future
 'LocalAddress'                       =>
 ['string', 'This optional parameter specifies the address to bind to the Diameter client source port. Defaults to 0.0.0.0', 2],

 'LocalPort'                       =>
 ['string', 'If LocalAddress is specified, this optional parameter specifies the symbolic service name or port number of the source port. Defaults to 0, which means to allocate a port number automatically.', 2],

);

# RCS version number of this module
$Radius::AuthDIAMETER::VERSION = '$Revision: 1.4 $';

$Radius::AuthDIAMETER::dictionary = Radius::DiaDict->new
    (Filename => Radius::Util::format_special($main::config->{DiameterDictionaryFile}));
$Radius::AuthDIAMETER::dictionary->activate();


#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->Radius::AuthGeneric::initialize();
    $self->Radius::DiaClient::initialize();

    $self->{Dictionary} = $Radius::AuthDIAMETER::dictionary;
    $self->{OriginHost}  = $main::hostname;
    $self->{OriginRealm} = 'testoriginrealm';
    $self->{SupportedVendorIds} = undef;
    $self->{AuthApplicationIds} = "$Radius::DiaMsg::APPID_BASE, $Radius::DiaMsg::APPID_NASREQ, $Radius::DiaMsg::APPID_DIAMETER_EAP";
    $self->{AcctApplicationIds} = "$Radius::DiaMsg::APPID_BASE_ACCOUNTING";

    return;
}

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->{Host} = $self->{Peer}; # We will use Peer for Diameter

    $self->Radius::AuthGeneric::activate();
    $self->Radius::DiaClient::activate();

    return;
}

#####################################################################
sub handle_request
{
    my ($self, $p, $dummy, $extra_checks) = @_;

    $self->log($main::LOG_DEBUG, "Handling with Radius::AuthDIAMETER", $p);

    if ($self->{DiaPeer}->state() ne 'I-Open')
    {
	# Dont queue up requests: not useful
	$self->log($main::LOG_WARNING, "AuthDIAMETER Diameter peer not connected. Ignoring");
	return $main::IGNORE;
    }

    my $m = Radius::RadiusDiameterGateway::handle_request($self, $p);
    $self->send_request($m, $p); # $p is user_data, get this back later

    return $main::IGNORE;
}

#####################################################################
# Called automatically when a reply to a Diameter request is received
sub handleReply
{
    my ($self, $peer, $msg, $sp, $user_data) = @_;

    return Radius::RadiusDiameterGateway::handle_reply($self, $msg, $sp, $user_data);
}

1;
