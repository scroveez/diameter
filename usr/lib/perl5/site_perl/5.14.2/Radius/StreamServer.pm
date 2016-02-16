# StreamServer.pm
#
# Object for a stream oriented server, with or without TLS/SSL encryption.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2007 Open System Consultants 
# $Id: StreamServer.pm,v 1.9 2014/08/05 09:25:02 hvn Exp $

package Radius::StreamServer;
@ISA = qw(Radius::Configurable);
use Radius::Configurable;
use Radius::TLSConfig;
use Fcntl;
use Errno;
use Socket;
use strict;

%Radius::StreamServer::ConfigKeywords = 
('Port'                        => 
 ['string', 
  'Port number to listen for connections. Service names or integer port numbers are permitted.', 
  0],
 'BindAddress'                 => 
 ['string', 
  'Host IP address to listen on for connections. IPV4 or IPV6 addresses are permitted', 
  1],
 'Protocol'                 => 
 ['string', 
  'Specifies the communications protocol with which to accept connections. May be \'tcp\' or \'sctp\'. Defaults to \'tcp\'',
  2],
 'Clients'                     => 
 ['splitstringarray', 
  'List of IP addresses of permitted clients. If not defined, all clients are permitted, subject to authentication', 
  0],
 'MaxBufferSize'               => 
 ['integer', 
  'Maximum input buffer size', 
  2],
 'UseSSL'                      => 
 ['flag', 
  'Only permit SSL encrypted connections', 
  1],
 'UseTLS'                      => 
 ['flag', 
  'Only permit TLS encrypted connections', 
  1],

 @Radius::TLSConfig::serverkeywords,

 );

# RCS version number of this module
$Radius::StreamServer::VERSION = '$Revision: 1.9 $';

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();

    # Remove any old state
    $self->delete_sockets();

    # Set up the TCP listener
    my $port = Radius::Util::get_port($self->{Port});
    my $protocol = getprotobyname($self->{Protocol});
    if (!defined $protocol)
    {
	$self->log($main::LOG_ERR,  "StreamServer: Unknown Protocol type $self->{Protocol}");
	return;
    }
    foreach (split(/\s*,\s*/, &Radius::Util::format_special($self->{BindAddress})))
    {
	&main::log($main::LOG_DEBUG, "Creating StreamServer $self->{Protocol} port $_:$port");
    
	my $s = do { local *FH };
	my $bind_address = &Radius::Util::format_special($_);
	my ($paddr, $pfamily) = &Radius::Util::pack_sockaddr_pton($port, $bind_address);

	socket($s, $pfamily, Socket::SOCK_STREAM, $protocol)
	    || &main::log($main::LOG_ERR,  "Could not create StreamServer socket: $!");
	$main::forkclosesfdexceptions{fileno($s)}++;
	binmode($s); # Make safe in UTF environments
	setsockopt($s, Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1);

	# Set the socket nonblocking.
	if ($^O ne 'MSWin32')
	{
	    # Windows does not support fcntl.
	    fcntl($s, F_SETFL, fcntl($s, F_GETFL, 0) | O_NONBLOCK)
		|| $self->log($main::LOG_ERR, "StreamServer could not fcntl NONBLOCK listen socket");
	}
	elsif ($^O eq 'MSWin32' && $] >= 5.008)
	{
	    # Uses ioctl FIONBIO for setting socket to nonblock. Works with Perl 5.8 and later.
	    # http://www.nntp.perl.org/group/perl.perl5.porters/2008/10/msg140537.html
	    # 0x80000000  IOC_IN
	    # 0x00040000  sizeof(u_long)<<16
	    # 0x00006600  'f'<<8
	    # 0x0000007e  126
	    # ==========
	    # 0x8004667e

	    my $nonblock=pack("I", 1);
	    $self->log($main::LOG_ERR, "StreamServer could not ioctl NONBLOCK listen socket on Windows")
		if (!ioctl ($s, 0x8004667e, \$nonblock));
	}
	else
	{
	    # Windows with old Perl.
	    $self->log($main::LOG_DEBUG, "StreamServer could not ioctl NONBLOCK listen socket on Windows with Perl version lower than 5.8"); 
	}

	bind($s, $paddr)
	    || &main::log($main::LOG_ERR,  "Could not bind StreamServer socket: $!");
	listen($s, Socket::SOMAXCONN)
	    || &main::log($main::LOG_ERR,  "Could not listen on StreamServer socket: $!");
	&Radius::Select::add_file(fileno($s), 1, undef, undef, 
				  \&handle_listen_socket_read, $s, $self);
	push(@{$self->{sockets}}, $s);
    }
    
    # Enable SSL if required
    if ($self->{UseSSL} || $self->{UseTLS})
    {
	if (!eval("require Radius::StreamTLS"))
	{
	    $self->log($main::LOG_ERR, "UseSSL/UseTLS specified, but could not load required modules: $@");
	}
	else
	{
	    Radius::StreamTLS::init($self);
	}
    }
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

    $self->{MaxBufferSize} = 10000000;
    $self->{BindAddress} = $main::config->{BindAddress} || '0.0.0.0';
    $self->{Protocol} = 'tcp';
    $self->{TLS_ExpectedPeerName} = '.+'; # Accept any
}

#####################################################################
sub delete_sockets
{
    my ($self) = @_;

    foreach (@{$self->{sockets}})
    {
	&Radius::Select::remove_file(fileno($_), 1, 1, 1);
	close($_);
    }
    delete $self->{sockets};
}

#####################################################################
# Remove various circular references that would prevent automatic destruction
# of ServerRADSEC and RadSecConnection objects
sub destroy
{
    my ($self) = @_;

    # Remove any old state
    $self->delete_sockets();

    if ($self->{ssl_ctx_streamtls})
    {
	&Net::SSLeay::CTX_free($self->{ssl_ctx_streamtls});
	$self->{ssl_ctx_streamtls} = undef;
	$Radius::StreamTLS::verifyFn = undef;
    }
}

#####################################################################
# This is called by Select::select whenever our listen socket
# becomes readable, which means someone is trying to connect to us
# We accept the new connection
sub handle_listen_socket_read
{
    my ($fileno, $listensocket, $self) = @_;

    # This could have been done with FileHandle, but this is much
    # more lightweight. It makes a reference to a TYPEGLOB
    # and Perl can use a typeglob ref as an IO handle
    my $newsocket = do { local *FH };
    
    if (!accept($newsocket, $listensocket))
    {
	&main::log($main::LOG_ERR,  "Could not accept on StreamServer listen socket: $!")
	    unless $!{EWOULDBLOCK} || $!{EAGAIN}; # another process in the farm got it?
	return;
    }
    $self->handle_new_connection($newsocket);
}

#####################################################################
# On FreeBSD, need to close the old socket on HUP, else get 
# 'Could not bind ServerHTTP socket: Address already in use'
sub DESTROY
{
    my ($self) = @_;

    # Remove any old state
    $self->delete_sockets();
}

#####################################################################
#####################################################################
#####################################################################
# Helper class. One instance fo each active connection
package Radius::StreamServer::Connection;
use base ('Radius::Stream');

#####################################################################
sub new
{
    my ($class, $parent, $socket, @args) = @_;

    my $self = $class->SUPER::new(@args);

    $self->{parent} = $parent;
    $self->{socket} = $socket;

    if ($socket)
    {
	$self->{peer} = getpeername($self->{socket})
	    || $parent->log($main::LOG_ERR,  "Could not get peer name on StreamServer socket: $!");
	($self->{Port}, $self->{Peeraddr}) = Radius::Util::unpack_sockaddr_in($self->{peer});
	$self->{Host} = Radius::Util::inet_ntop($self->{Peeraddr});
    }

    if (defined $parent->{Clients})
    {
	# Make sure this is a valid Client
	if (!grep($self->{Host} eq $_, @{$parent->{Clients}}))
	{
	    $parent->log($main::LOG_WARNING,  "Attempt to connect to StreamServer from invalid Client: $self->{Host}. Rejected");
	    return;
	}
    }
    $self->stream_server_connected($parent);

    $parent->log($main::LOG_DEBUG, "New StreamServer Connection created for $self->{Host}:$self->{Port}");

    return $self;
}


1;

