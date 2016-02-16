# Stream.pm
#
# Low level routines for sending and receiving data
# over a TCP stream, possibly with TLS encryption.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2005 Open System Consultants
# $Id: Stream.pm,v 1.49 2014/08/05 09:25:02 hvn Exp $

package Radius::Stream;
use Socket qw(SO_KEEPALIVE SO_ERROR SOL_SOCKET);
use Radius::Util;
use Fcntl;
use Errno;
use strict;

# RCS version number of this module
$Radius::Stream::VERSION = '$Revision: 1.49 $';

#####################################################################
# Constructs a new object
sub new
{
    my ($class, %args) = @_;

    my $self = {%args};
    bless $self, $class;  
    $self->set_defaults();

    return $self;
}

#####################################################################
# new may not have been called in multiple inheritance situations
sub set_defaults
{
    my ($self) = @_;

    $self->{ReconnectTimeout} = 5 unless defined $self->{ReconnectTimeout}; 
    $self->{Protocol} = 'tcp' unless defined $self->{Protocol};
    $self->{Host} = 'localhost' unless defined $self->{Host};
    $self->{MaxBufferSize} = 10000000 unless defined $self->{MaxBufferSize};
    $self->{DisconnectErrorLevel} = $main::LOG_ERR
	unless defined $self->{DisconnectErrorLevel};
    $self->{do_ssl_tls} = $self->{UseTLS} || $self->{UseSSL};
    $self->{inbuffer} = undef;
    $self->{outbuffer} = undef;
    $self->{sctp_peer_counter} = 0;
}

#####################################################################
# Attempt to connect to the target Stream server
# Return 1 if successful, and set $self->{socket}
sub stream_connect
{
    my ($self) = @_;

    # new may not have been called in multiple inheritance situations
    $self->set_defaults();

    &Radius::Select::remove_timeout($self->{reconnectTimeoutHandle})
	if $self->{reconnectTimeoutHandle};
    my $timeout = Radius::Util::format_special($self->{ReconnectTimeout});
    $self->{reconnectTimeoutHandle} = &Radius::Select::add_timeout(time + $timeout, \&reconnect_timeout, $self);
    return $self->stream_reconnect();
}

#####################################################################
# get the host that should be connected to next
sub get_next_host
{
    my ($self) = @_;

    # Caller may already have an IP address worked out
    return $self->{HostAddress} if defined $self->{HostAddress};

    my $host = $self->{Host};

    # With SCTP we cycle through SCTPPeer array if it exists
    # overriding any Host. Next time here we get the next peer.
    if (    $self->{Protocol} eq 'sctp'
	&& $self->{SCTPPeer})
    {
	$host = $self->{SCTPPeer}[$self->{sctp_peer_counter}];
	my $sctp_peer_count = @{$self->{SCTPPeer}};
	$self->{sctp_peer_counter} = ($self->{sctp_peer_counter} + 1) % $sctp_peer_count;
    }

    return Radius::Util::format_special($host);
}

#####################################################################
# reconnect has a name clash with SqlDb::reconnect
sub stream_reconnect
{
    my ($self) = @_;

    my $port = Radius::Util::get_port($self->{Port});
    if (!$port)
    {
	$self->log($main::LOG_ERR, "Stream: Unknown port: $self->{Port}");
	return;
    }

    my $host = $self->get_next_host();
    my ($paddr, $pfamily) = &Radius::Util::pack_sockaddr_pton($port, $host);

    if (!defined $paddr)
    {
	# still nothing!
	$self->log($main::LOG_WARNING, "Could not resolve Host '$host'");
	return;
    }

    my $protocol = getprotobyname($self->{Protocol});
    if (!defined $protocol)
    {
	$self->log($main::LOG_ERR,  "Stream: Unknown Protocol type: $self->{Protocol}");
	return;
    }
    # Make sure any preexisting socket is closed first
    $self->stream_close_socket();
    if (socket($self->{socket}, $pfamily, &Socket::SOCK_STREAM(), $protocol))
    {
	$self->log($main::LOG_DEBUG, "Stream attempting $self->{Protocol} connection to $host:$port");

	# Maybe bind to a specific local socket
	if (defined $self->{LocalAddress})
	{
	    my $localport = $self->{LocalPort} || 0;
	    
	    my ($thisaddr, $thispfamily) = &Radius::Util::pack_sockaddr_pton
		(&Radius::Util::get_port($localport), 
		 $self->{LocalAddress});
	    bind($self->{socket}, $thisaddr) 
		|| $self->log($main::LOG_ERR,  "Stream: Could not bind local port to $self->{LocalAddress}:$localport: $!");;
	}

	# Need to keep fileno, since if syswrite fails, you cant get fileno
	# from the socket any more and therefore cant remove the 
	# socket from Select
	$self->{socket_fileno} = fileno($self->{socket});

	# Connect can block unless non-blocking is set

	# If ConnectOnDemand is set then we wait until the connection succeeds or fails
	# this behaviour removed because it can cause long term blocking
	$self->set_nonblocking();
	if (connect($self->{socket}, $paddr))
	{
	    # Got an immediate connection, dont need to wait for
	    # connection with select()
	    $self->stream_client_connected();
	    return 1;
	}
	#Windows returns WSAEWOULDBLOCK instead of EINPROGRESS
	elsif ($!{EINPROGRESS} || ($^O eq 'MSWin32' && $! == 10035))
	{
	    # connect is in progress with a non-blocking socket, so some time later the socket
	    # will become writeable, at wchic time we can see whether the connection was successful
	    # or not.
	    $self->log($main::LOG_DEBUG, "Stream connection in progress to $host:$port");

	    # When the connection is up, it will become writeable, handle the
	    # new connection in handle_socket_write
	    &Radius::Select::add_file($self->{socket_fileno}, undef, 1, 1, 
				      \&handle_socket_connected, $self);
	    return;
	}
    }
    else
    {
	$self->log($main::LOG_WARNING, "Stream Could not create socket for connection to $host:$port $!");
	# Connection failure, try again later
	$self->{socket} = undef;
	return;
    }
}

#####################################################################
# Make the socket non-blocking.
sub set_nonblocking
{
    my ($self) = @_;

    # Windows does not support fcntl.
    if ($^O ne 'MSWin32')
    {
	fcntl($self->{socket}, F_SETFL, fcntl($self->{socket}, F_GETFL, 0) | O_NONBLOCK)
	    || $self->log($main::LOG_ERR, "Stream could not fcntl NONBLOCK socket for connection to $self->{Host}:$self->{Port}");
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
	$self->log($main::LOG_ERR, "Stream could not ioctl NONBLOCK socket on Windows for connection to $self->{Host}:$self->{Port}")
	    if (!ioctl ($self->{socket}, 0x8004667e, \$nonblock)); 
    }
    else
    {
	# Windows with old Perl.
	$self->log($main::LOG_DEBUG, "Stream could not ioctl NONBLOCK socket on Windows with Perl version lower than 5.8");
    }
}

#####################################################################
# This is called by Select::select whenever our socket
# becomes readable. 
sub handle_socket_read
{
    my ($fileno, $self) = @_;

    no warnings "uninitialized";
    # Append the next lot of bytes to the buffer
    my $buf;
    if (sysread($self->{socket}, $buf, 16384))
    {
	# Maybe decrypt it
	$buf = &Radius::StreamTLS::receive($self, $buf) if $self->{tls_enabled};
	$self->{inbuffer} .= $buf;

	$self->read_data();
    }
    elsif (!$!{EWOULDBLOCK} && !$!{EAGAIN})
    {
	# Strange, nothing there, must be a disconnection error
	$self->log($self->{DisconnectErrorLevel}, "Stream sysread for $self->{Host}:$self->{Port} failed: $!. Peer probably disconnected.");
	$self->stream_disconnected();
    }
}

#####################################################################
# This is called by Select::select when our forwarding socket
# becomes connected
sub handle_socket_connected
{
    my ($fileno, $self) = @_;

    # Dont need this callback any more
    &Radius::Select::remove_file($fileno, undef, 1, undef);

    my $sockerror = unpack('l', getsockopt($self->{socket}, SOL_SOCKET, SO_ERROR));
    if (defined $sockerror && $sockerror == 0)
    {
	$self->stream_client_connected();
    }
    else
    {
	$! = $sockerror;
	$self->stream_error("Stream connection to $self->{Host}:$self->{Port} failed: $!");
    }
}

#####################################################################
# This is called by Select::select whenever our forwarding socket
# becomes writeable.
sub handle_socket_write
{
    my ($fileno, $self) = @_;

    $self->write_pending();
    # Dont need this callback any more if all the pending bytes
    # have been written
    &Radius::Select::remove_file($fileno, undef, 1, undef)
	if !length $self->{outbuffer};
}

#####################################################################
# This is called by Select::select whenever our forwarding socket
# gets an exception
sub handle_socket_except
{
    my ($fileno, $self) = @_;

    $self->stream_error("Stream Socket exception $!");
}

#####################################################################
sub write
{
    my ($self, $s) = @_;
    no warnings "uninitialized";

    $s = &Radius::StreamTLS::get_pending($self, $s) 
	if $self->{do_ssl_tls} && $Radius::StreamTLS::initialised;
    $self->{outbuffer} .= $s;

    # Is this really necessary?
    if (length $self->{outbuffer} > $self->{MaxBufferSize})
    {
	$self->stream_error("Stream MaxBufferSize exceeded, disconnecting");
    }
    else
    {
	$self->write_pending();
    }
}

#####################################################################
sub write_pending
{
    my ($self) = @_;

    # If the socket would block, a callback is set up to write the
    # remaining octetes when the socket becomes writeable
    no warnings "uninitialized";

    return unless $self->isconnected();
    my $written = syswrite($self->{socket}, $self->{outbuffer}, length $self->{outbuffer});
    if (!defined $written && !$!{EWOULDBLOCK})
    {
	$self->stream_error("Stream write error, disconnecting: $!");
    }
    else
    {
	# Remove the bytes that have been written already
	substr($self->{outbuffer}, 0, $written, '');

	# Anything left? it was a partial write, need to
	# get control when the socket is writeable again
	&Radius::Select::add_file
	    ($self->{socket_fileno}, undef, 1, undef, 
	     \&handle_socket_write, $self)
	    if length $self->{outbuffer};
    }
}

#####################################################################
# Return  true if the socket is currently connected
sub isconnected
{
    my ($self) = @_;

    return $self->{connected};
}

#####################################################################
# Called when a client connection has been successfully established
sub stream_connected
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "Stream connected to $self->{Host}:$self->{Port}");
    $self->{connected}++;

    return unless $self->{socket};
    $self->{PeerName} = getpeername($self->{socket});
    $self->{socket_fileno} = fileno($self->{socket});
    binmode($self->{socket}); # Make safe in UTF environments

    &Radius::Select::add_file
	($self->{socket_fileno}, 1, undef, undef, 
	 \&handle_socket_read, $self);
    &Radius::Select::add_file
	($self->{socket_fileno}, undef, undef, 1, 
	 \&handle_socket_except, $self);
    $self->set_nonblocking();

    # KEEPALIVE timouts in Linux can be very long and may not therefore be very useful
    # but we will enable them anyway for good luck
    setsockopt($self->{socket}, SOL_SOCKET, SO_KEEPALIVE,  pack("l", 1)) 
	|| $self->log($main::LOG_ERR, "Stream could not setsockopt SO_KEEPALIVE socket for connection to $self->{Host}:$self->{Port}: $!");

    # Maybe disable TCP Nagle algorithm for better performance with small packets
    # Not available on all platforms
    if ($self->{DisableNagle} && defined &Socket::IPPROTO_TCP() && defined &Socket::TCP_NODELAY())
    {
	setsockopt($self->{socket}, Socket::IPPROTO_TCP(), Socket::TCP_NODELAY(),  pack("l", 1)) 
	    || $self->log($main::LOG_ERR, "Stream could not disable Nagle algorithm for connection to $self->{Host}:$self->{Port}: $!");
    }

    return 1;
}

#####################################################################
sub stream_client_connected
{
    my ($self) = @_;

    $self->stream_connected();
    &Radius::StreamTLS::start_client($self, $self, $self->{Host}) 
	if $self->{do_ssl_tls} && $Radius::StreamTLS::initialised;
    $self->write_pending();
}

#####################################################################
sub stream_server_connected
{
    my ($self, $object) = @_;

    $self->stream_connected();
    &Radius::StreamTLS::start_server($object, $self, $self->{Host}) 
	if $self->{do_ssl_tls} && $Radius::StreamTLS::initialised;
}

#####################################################################
# Close the socket adn delete any references to it
sub stream_close_socket
{
    my ($self) = @_;

    # Deleting any references to this Stream will
    # cause it to be destroyed
    if ($self->{socket})
    {
	&Radius::Select::remove_file($self->{socket_fileno}, 1, 1, 1);
	close($self->{socket});
	$self->{socket} = undef;
    }
}

#####################################################################
# Handle the disconnection of the other end.
# All pending input and out is flushed, and the socket is closed and vaped.
sub stream_disconnected
{
    my ($self) = @_;

    $self->stream_close_socket();
    # Dump any pending data: cant deliver it now
    $self->{inbuffer} = '';
    $self->{outbuffer} = '';
    $self->{wait_for_tls_data} = '';
    $self->{connected} = undef;
    # Clean up TLS session
    &Radius::StreamTLS::sessionClear($self) if $self->{tls_enabled};;
    $self->log($main::LOG_DEBUG, "Stream disconnected from $self->{Host}:$self->{Port}");
}

#####################################################################
# Clients will try to connect()
# at ReconnectTimeout intervals until reconnected.
sub reconnect_timeout
{
    my ($handle, $self) = @_;

    # This will also restart the connect timer
    $self->stream_reconnect() unless $self->isconnected() || ($self->{ConnectOnDemand} && length($self->{outbuffer}) == 0 && length($self->{wait_for_tls_data}) == 0);
    $self->{reconnectTimeoutHandle} = &Radius::Select::add_timeout(time + $self->{ReconnectTimeout}, \&reconnect_timeout, $self);
}

#####################################################################
# A serious stream error has occurred, log it and disconnect
sub stream_error
{
    my ($self, $msg) = @_;

    # This order so that loggers can remove themselved before we
    # try to log a message
    $self->stream_disconnected();
    $self->log($main::LOG_ERR, $msg);
}

#####################################################################
# Set some attributes
sub set
{
    my ($self, @args) = @_;

    my $key;
    while (@args)
    {
	$key = shift(@args);
	$self->{$key} = shift(@args);
    }
}

1;

