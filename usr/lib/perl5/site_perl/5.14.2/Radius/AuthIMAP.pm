# AuthIMAP.pm
#
# Object for handling Authentication via IMAP(S).
# Handles PAP and TTLS-PAP
#
# Copyright (C) 2004 Open System Consultants
# Author: Karl Gaissmaier (karl.gaissmaier@kiz.uni-ulm.de)
#
# $Log: AuthIMAP.pm,v $
# Revision 1.11  2009/02/11 21:39:45  mikem
# patches_4.3.1
#
# Revision 1.10  2007/12/18 21:23:50  mikem
# *** empty log message ***
#
# Revision 1.9  2007/09/25 11:31:13  mikem
# *** empty log message ***
#
# Revision 1.8  2006/02/21 08:20:59  mikem
# patches_3.14
#
# Revision 1.7  2004/11/16 21:43:53  mikem
# patches_3.11
#
# Revision 1.7  2004/11/16 12:57:26  gaissmai
# we can't use $imap->connect() therefore we must read the greeting
#
# Revision 1.6  2004/11/14 23:00:07  mikem
# patches_3.11
#
# Revision 1.6  2004/11/14 21:13:14  gaissmai
#
# - set Timeout in Mail::IMAPClient object not only for the socket
# - bug in Mail::IMAPClient::new, therefore set the Socket after
#   creation with the setter method, no select handle is created
#   when the Socket is set with new()
#

package Radius::AuthIMAP;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Mail::IMAPClient;
use strict;

#####################################################################
# This hash describes all the standard types of keywords understood by this
# class. If a keyword is not present in ConfigKeywords for this
# class, or any of its superclasses, Configurable will call sub keyword
# to parse the keyword
# See Configurable.pm for the list of permitted keywordtype
#
%Radius::AuthIMAP::ConfigKeywords = 
(
 'Host'                   => 
 ['string', 'This parameter specifies the host name of the IMAP server. ', 0],

 'Port'                   => 
 ['string', 'This optional parameter specifies the port number to contact on the IMAP server. Defaults to 143, the standard imap port.', 1],

 'LocalAddr'              => 
 ['string', 'Local host bind address.', 1],

 'Timeout'                => 
 ['integer', 'This optional parameter specifies a timeout in seconds. If the connection to the IMAP server is not complete within this time, the authentication will fail with REJECT. ', 1],

 'Debug'                  => 
 ['integer', 'If this optional parameter is set, Mail::IMAPClient prints details of its transactions to stdout.', 1],

 'UseSSL'                 => 
 ['flag', 'This parameter forces AuthBy IMAP to use an SSL connection to the IMAP server. If you wish to use USeSSL, you must also configure the SSL* parameters described below.', 1],

 'SSLVerify'              => 
 ['string', 'This optional parameter specifies what sort of SSL client verification that AuthBy IMAP will provide to the IMAP server.', 1],

 'SSLCAFile'              => 
 ['string', 'If you want to verify that the IMAP server certificate has been signed by a reputable certificate authority, then you should use this option to locate the file containing the certificate(s) of the reputable certificate authorities if it is not already in the OpenSSL file certs/my-ca.pem. Special characters are permitted.', 1],

 'SSLCAPath'              => 
 ['string', 'If you are unusually friendly with the OpenSSL documentation, you might have set yourself up a directory containing several trusted certificates as separate files as well as an index of the certificates. If you want to use that directory for validation purposes, and that directory is not ca/, then use this option to specify the directory. There is no need to set both SSLCAFile and  SSLCAPath. Special characters are permitted.', 1],

 'SSLCAClientCert'        => 
 ['string', 'This optional parameter specifies the location of the SSL client certificate that AuthBy IMAP will use to verifiy itself with the IMAP server. If SSL client verification is not required, then this option does not need to be specified. Special characters are permitted.', 1],

 'SSLCAClientKey'         => 
 ['string', 'This optional parameter specifies the location of the SSL private key that AuthBy IMAP will use to communicate with the IMAP server. If SSL client verification is not required, then this option does not need to be specified. Special characters are permitted.', 1],

 'SSLCAClientKeyPassword' => 
 ['string', 'If the SSLCAClientKey contains an encrypted private key, then you must specifiy the decryption password with this parameter. If a key is required, you will generally have been given the password by whoever provided the private key and certificate.', 1],

);

# RCS version number of this module
$Radius::AuthIMAP::VERSION = '$Revision: 1.11 $';

# Just a name for useful printing
my $class = 'AuthIMAP';

#####################################################################
# Do per-instance default initialization
sub initialize {
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{Host}    = 'localhost';
    $self->{Timeout} = 10;
}

#####################################################################
# Try to authenticate the named user against an imap server.
# On success return a user object with a 'Password' check-item value
# that always match the password from the request otherwise
# return a 'Password' check-item value that always fails.
# If there is a socket or connect error (as opposed to the user
# was not successful authenticated, return (undef, 1)
#
sub findUser {
    my ( $self, $username, $p ) = @_;

    # problem with the "user database", means here we can't connect to
    # the imap server (socket is closed when $sock goes out of scope)
    my $sock = $self->_get_socket($p)
      or return ( undef, 1 );

    # get the password from auth request
    my $password = $p->decodedPassword();

    # try to authenticate against the imap server
    my $success = $self->_auth_imap( $sock, $username, $password, $p );

    my $user = Radius::User->new($username);

    if ($success) {

        # fill the check-item with the request password
        # so AuthGeneric::check_plain_password always match
        $user->get_check->add_attr( 'Password', $password );
    }
    else {

        # fill the check-item with a fake password
        # so AuthGeneric::check_plain_password always fails
        my $match_never = $password eq 'foo' ? 'bar' : 'foo';
        $user->get_check->add_attr( 'Password', $match_never );
    }

    return $user;
}

#####################################################################
sub _auth_imap {
    my ( $self, $sock, $user, $password, $p ) = @_;

    $self->log( $main::LOG_DEBUG, "$class: create Mail::IMAPClient object",
        $p );

    my %args;
    $args{Timeout} = $self->{Timeout}
      if defined $self->{Debug};
    $args{Debug} = $self->{Debug}
      if defined $self->{Debug};

    my $imap = new Mail::IMAPClient(%args);
    unless ($imap) {
        $self->log( $main::LOG_WARNING,
            "Could not create Mail::IMAPClient object: $!" );
        return undef;
    }

    $imap->User($user);
    $imap->Password($password);

    # bug with select(), don't do this in new()
    $imap->RawSocket($sock);
    $imap->State( Mail::IMAPClient::Connected() );

    # since we provide the socket we must also read the greeting, sigh
    $imap->_read_line();

    $self->log( $main::LOG_DEBUG, "$class: login to imap server", $p );

    my $success = $imap->login();

    if ($success) {
        $self->log( $main::LOG_DEBUG, "$class: imap login for $user successful",
            $p );
        $self->log( $main::LOG_DEBUG, "$class: logout from imap server", $p );
        $imap->logout();
    }
    else {
        $self->log( $main::LOG_DEBUG, "$class: login for $user failed", $p );
    }

    return $success ? 1 : undef;
}

#####################################################################
sub _get_socket {
    my ( $self, $p ) = @_;

    my ( $sock, %args );

    $args{Proto}   = 'tcp';
    $args{Timeout} = $self->{Timeout} if defined $self->{Timeout};

    $args{PeerHost} = &Radius::Util::format_special($self->{Host}, $p)
      if defined $self->{Host};
    $args{PeerPort} = &Radius::Util::format_special($self->{Port}, $p)
      if defined $self->{Port};
    $args{LocalAddr} = &Radius::Util::format_special($self->{LocalAddr}, $p)
      if defined $self->{LocalAddr};

    unless ( $self->{UseSSL} ) {

        $args{PeerPort} ||= 143;    # imap default

        $self->log( $main::LOG_DEBUG, "$class: create IMAP socket", $p );
        unless ( $sock = IO::Socket::INET->new(%args) ) {
            $self->log( $main::LOG_WARNING, "Could not create socket: $!" );
            return undef;
        }
    }
    else {
        require IO::Socket::SSL;

        # Different OpenSSL verify modes.
        my %ssl_verify = ( 'none' => 0, 'optional' => 1, 'require' => 3 );

        $args{PeerPort} ||= 993;    # imaps default

        $args{SSL_verify_mode} = $ssl_verify{ lc( $self->{SSLVerify} ) }
          if defined $self->{SSLVerify};

        $args{SSL_ca_file} = &Radius::Util::format_special($self->{SSLCAFile}, $p)
          if defined $self->{SSLCAFile};
        $args{SSL_ca_path} = &Radius::Util::format_special($self->{SSLCAPath}, $p)
          if defined $self->{SSLCAPath};
        $args{SSL_cert_file} =
	    &Radius::Util::format_special($self->{SSLCAClientCert}, $p)
	    if defined $self->{SSLCAClientCert};
        $args{SSL_key_file} =
	    &Radius::Util::format_special($self->{SSLCAClientKey}, $p)
	    if defined $self->{SSLCAClientKey};
        $args{SSL_passwd_cb} = sub { return $self->{SSLCAClientKeyPassword} }
          if defined $self->{SSLCAClientKeyPassword};

        $self->log( $main::LOG_DEBUG, "$class: create IMAPS socket", $p );

        unless ( $sock = IO::Socket::SSL->new(%args) ) {
            $self->log( $main::LOG_WARNING, "Could not create SSL socket: $!" );
            return undef;
        }
    }

    return $sock;
}

1;
