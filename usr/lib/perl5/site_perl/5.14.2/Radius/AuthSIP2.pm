# AuthSIP2.pm
#
# Object for handling authentication via 3M Standard Interchange Protocol 2
# as used in 3Ms Automated Circulation Systems (ACS) for book libraries
#
# This code supports conventional Radius PAP
# as well as EAP-Generic Token Card and
# EAP-PEAP-Generic Token Card.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2012 Open System Consultants
# $Id: AuthSIP2.pm,v 1.4 2014/08/01 21:56:02 hvn Exp $

package Radius::AuthSIP2;
@ISA = qw(Radius::AuthGeneric Radius::SIP2);
use Radius::AuthGeneric;
use Radius::SIP2;
use strict;


# RCS version number of this module
$Radius::AuthSIP2::VERSION = '$Revision: 1.4 $';


#####################################################################
sub activate
{
    my ($self) = @_;

    # In case this is a HUP:
    $self->acs_disconnect();

    $self->Radius::AuthGeneric::activate;
    $self->Radius::SIP2::activate;

}

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->Radius::AuthGeneric::initialize;
    $self->Radius::SIP2::initialize;
}

#####################################################################
# This is a bogus findUser that basically does nothing but does not
# fail
sub findUser
{
    return Radius::User->new();
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

    if (defined $p->getAttrByNum($Radius::Radius::CHAP_PASSWORD)
	|| defined $p->get_attr('CHAP-Challenge')
	|| defined $p->get_attr('MS-CHAP-Response')
	|| defined $p->get_attr('MS-CHAP-Challenge')
	|| defined $p->get_attr('MS-CHAP2-Response'))
    {
	return ($main::REJECT, "Authentication type not supported. Only PAP and EAP-GTC is supported by AuthBy SIP2");
    }

    return $self->acs_check_password($p->getUserName(), $p->decodedPassword(), $p);
}

sub get_plaintext_password
{
    return 1;
}
