# AuthSASLAUTHD.pm
#
# Object for handling Authentication via SASLAUTHD.
#
# Requires opie-2.4 or better from http://www.inner.net/opie 
# and Authen-SASLAUTHD-1.00 or better from CPAN
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001-2004 Open System Consultants
# $Id: AuthSASLAUTHD.pm,v 1.5 2007/12/18 21:23:50 mikem Exp $

package Radius::AuthSASLAUTHD;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Socket;
use strict;

%Radius::AuthSASLAUTHD::ConfigKeywords = 
(
 'SocketPath'               => 
 ['string', 'This optional parameter specifies the name of the UNIX domain socket to use to connect to the saslauthd server. Defaults to /var/lib/sasl2/mux.', 1],

 'Service'                  => 
 ['string', 'This optional parameter specifies the service name that will be passed to saslauthd in each authentication request. The service name is used by some types of saslauthd authentication methods, for example if saslauthd is using PAM, then this specifies the PAM service name to use. Defaults to "login".', 1],

 );

# RCS version number of this module
$Radius::AuthSASLAUTHD::VERSION = '$Revision: 1.5 $';

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
    $self->{NoDefault}  = 1;
    $self->{SocketPath} = '/var/lib/sasl2/mux';
    $self->{Service}    = 'login'; # Used when saslauthd is using PAM: specifies the PAM service
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

    return $self->check_plain_password($p->getUserName(), $p->decodedPassword(), undef, $p);
}

#####################################################################
# $submitted_pw is the password being authenticated
# $pw is the correct password if known
# $user is the user name to be authenticated
sub check_plain_password
{
    my ($self, $username, $submitted_pw, $pw, $p, $encrypted) = @_;

    return ($main::ACCEPT) if $self->{NoCheckPassword};

    my ($user, $realm) = split(/@/, $username);
    my $error = $self->saslauthd_verify_password($user, $submitted_pw, $self->{Service}, $realm);
    return ($main::REJECT, "SASLAUTHD authentication failed: $error")
	    if defined $error;
    return ($main::ACCEPT); # OK
}

#####################################################################
# Caution: this is synchronous, and can be slow, eg with PAM and an incorrect password
sub  saslauthd_verify_password
{
    my ($self, $userid, $password, $service, $realm) = @_;

    # Connect to the saslauthd server
    my $s;
    return "socket creation failed $!"
	unless socket($s, Socket::PF_UNIX, Socket::SOCK_STREAM, 0);
    return "connect failed $!"
	unless connect($s, Socket::sockaddr_un($self->{SocketPath})) ;

    # Send the request to the server
    my $request = pack('n/a* n/a* n/a* n/a*', $userid, $password, $service, $realm);
    my $written = syswrite($s, $request);
    return "syswrite failed: $!"
	unless $written == length($request);

    # Read the response from the server
    my $buffer;
    my $read = sysread($s, $buffer, 2);
    return "sysread of response length failed: $!"
	unless $read == 2;
    my $count = unpack('n', $buffer);
    $read = sysread($s, $buffer, $count);
    return "sysread of response failed: $!"
	unless $read == $count;

    # Decode the response
    if ($buffer =~ /^OK/)
    {
	return;
    }
    elsif ($buffer =~ /^NO ?(.*)/)
    {
	return $1;
    }
    else
    {
	return "saslauthd returned unknown response: $buffer";
    }
}

1;
