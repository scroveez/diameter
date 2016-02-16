# ServerRADIUS.pm
#
# Object for receiving RADIUS requests and satisfying them
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2007 Open System Consultants
# $Id: ServerRADIUS.pm,v 1.11 2014/04/11 09:19:57 hvn Exp $

package Radius::ServerRADIUS;
@ISA = qw(Radius::Configurable);
use Radius::Configurable;
use Radius::Select;
use Socket;
use Fcntl;
use strict;

#####################################################################
%Radius::ServerRADIUS::ConfigKeywords = 
(
 'AuthPort'           => 
 ['string', 'Comma separated list of port names or numbers used to listen for RADIUS Authentication requests', 1],

 'AcctPort'           => 
 ['string', 'Comma separated list of port names or numbers used used to listen for RADIUS Accounting requests', 1],

 'BindAddress'        => 
 ['string', 'Host IP address to listen on for RADIUS requests. IPV4 or IPV6 addresses are permitted', 1],

'BindV6Only'   =>
 ['flag',
  'When set, does setsockopt() to turn IPV6_V6ONLY on or off for IPv6 wildcard sockets. See RFC 3493 for details. This option is not set by default and thus no setsockopt() is called and system default is used. Using this option requires support from Perl socket modules.',
  1],

 'SocketQueueLength'  => 
 ['integer', 'The maximum length of the RADIUS socket queue in octets. Longer queues mean that more RADIUS requests can be waiting to be processed', 1],

 'DisableMTUDiscovery'      => 
 ['flag',
  'Disables MTU discovery on platforms that support that behaviour (currently Linux only). This can be used to prevent discarding of certain large RADIUS packet fragments on supporting operating systems.',
  2],

 'AddToRequest'         => 
 ['string', 'This optional parameter adds any number of RADIUS attributes to the RADIUS requests handled by ServerRADIUS. It can be used to distinguish incoming RADIUS requests from TACACS+ requests.', 1],


 );

# RCS version number of this module
$Radius::ServerRADIUS::VERSION = '$Revision: 1.11 $';

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();
    $self->close_sockets();
    $self->create_ports();
}

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;

    $self->{AuthPort} = 1645;
    $self->{AcctPort} = 1646;
    $self->{BindAddress} = $main::config->{BindAddress} || '0.0.0.0';
    $self->{BindV6Only} = $main::config->{BindV6Only};
    $self->{SocketQueueLength} = $main::config->{SocketQueueLength};
}

#####################################################################
sub destroy
{
    my ($self) = @_;

    $self->close_sockets();
}

#####################################################################
sub close_sockets
{
    my ($self) = @_;

    # Perhaps we don't want to close listen sockets on reload
    return if $main::config->{KeepSocketsOnReload};

    # This is a hash of all the radius sockets we are listening on
    # Close any that are currently opened, else can get errors on BSD*
    my $bind_address;
    foreach $bind_address (keys %{$self->{sockets}})
    {
	foreach (keys %{$self->{sockets}{$bind_address}})
	{
	    my $s = $self->{sockets}{$bind_address}{$_};
	    &Radius::Select::remove_file(fileno($s), 1);
	    close($s);
	}
    }
    %{$self->{sockets}} = ();
}

#####################################################################
sub create_ports
{
    my ($self) = @_;

    # Make Radius listening ports
    my $proto = getprotobyname('udp');

    # For each address in the BindAddress list, make the required auth and acct ports
    foreach (split(/\s*,\s*/, &Radius::Util::format_special($self->{BindAddress})))
    {
	my $bind_address = &Radius::Util::format_special($_);
	# Make authentication listeners
	foreach (split(/\s*,\s*/, $self->{AuthPort}))
	{
	    $self->make_radius_port($_, $proto, $bind_address, 'authentication');
	}
	
	# Make accounting listeners. These are bsically the same as authentication listeners
	foreach (split(/\s*,\s*/, $self->{AcctPort}))
	{
	    $self->make_radius_port($_, $proto, $bind_address, 'accounting');
	}
    }
}


#####################################################################
# Construct a Radius UDP port listing on the given portname
# If the port number is the same as $main::stdin_port, then we listen
# to STDIN instead of a new socket
sub make_radius_port
{
    my ($self, $portname, $proto, $bind_address, $descr) = @_;
    my $s;

    my $port = Radius::Util::get_port($portname);
    return unless $port;

    # Do we already have a socket?
    unless (defined $self->{sockets}{$bind_address}{$port})
    {
	# No, we are here first time or KeepSocketsOnReload is not set
	$s = $self->setup_socket($port, $proto, $bind_address, $descr);
    }
    else
    {
	# Yes, KeepSocketsOnReload is keeping the sockets alive
	$s = $self->{sockets}{$bind_address}{$port};
	$self->log($main::LOG_DEBUG, "Keeping old $descr port $bind_address:$port");
    }

    # Arrange for callback when readable
    &Radius::Select::add_file(fileno($s), 1, undef, undef, \&main::handle_radius_socket_read, $s, $self);

    # On some hosts, select sometimes incorrectly says that there
    # is a request waiting, even when there isnt. 
    # Set the socket non-blocking to prevent waiting forever
    if ($^O ne 'MSWin32')
    {
	# Win95 does not support fcntl or non-blocking sockets yet.
	fcntl($s, F_SETFL, fcntl($s, F_GETFL, 0) | O_NONBLOCK)
	    || $self->log($main::LOG_WARNING, "Could not fcntl $descr socket: $!");
    }
}

#####################################################################
# Make and setup a new listen socket, possibly from STDIN
sub setup_socket
{
    my ($self, $port, $proto, $bind_address, $descr) = @_;

    $self->log($main::LOG_DEBUG, "Creating $descr port $bind_address:$port");

    my $s = $self->{sockets}{$bind_address}{$port} = do { local *RADIUS_SOCKET };
    if (defined $main::stdin_port &&  $main::stdin_port == $port)
    {
	# We are under inetd and stdin is the auth port socket
	$s = $self->{sockets}{$bind_address}{$port} = \*STDIN;
    }
    else
    {
	# Open a port listening for radius requests
	my ($paddr, $pfamily) = &Radius::Util::pack_sockaddr_pton($port, $bind_address);
	socket($s, $pfamily, Socket::SOCK_DGRAM, $proto)
	    || $self->log($main::LOG_ERR, "Could not create $descr socket: $!");
	binmode($s); # Make safe in UTF environments

	# Control if socket bound to IPv6 wildcard address should receive both IPv6 and IPv4.
	# Need to make sure Perls with no IPV6_V6ONLY or PF_INET6 safely ignore this.
	if (   defined $self->{BindV6Only}
	    && $pfamily ne Socket::PF_INET) # Not using eq Socket::PF_INET6 since it may not be defined.
	{
	    no strict 'subs';
	    # Note: bind_address may start with 'ipv6:' prefix.
	    my $is_wildcard = (Radius::Util::inet_pton($bind_address) eq Radius::Util::inet_pton("ipv6:::")) ? 1 : 0;
	    if ($is_wildcard)
	    {
		my $on = $self->{BindV6Only} ? 1 : 0;
		setsockopt($s, Socket::IPPROTO_IPV6, Socket::IPV6_V6ONLY, $on)
		    || $self->log($main::LOG_ERR, "Could not setsockopt(IPV6_V6ONLY, $on): $!");
	    }
	}

#	setsockopt($s, Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1);
	bind($s, $paddr)
	    || $self->log($main::LOG_ERR, "Could not bind $descr socket: $!");

	if ($^O ne 'MSWin32' && $self->{SocketQueueLength})
	{
	    my $actual;
	    # Note: your OS may also need to be configured to allow
	    # you to choose long socket queue lengths.
	    setsockopt($s, Socket::SOL_SOCKET, 
		       Socket::SO_RCVBUF, $self->{SocketQueueLength})
		|| $self->log($main::LOG_WARNING, "Could not set socket read queue length for $descr to $self->{SocketQueueLength}: $!");
	    $actual = unpack('l', getsockopt($s, Socket::SOL_SOCKET, Socket::SO_RCVBUF));
	    # Check for match (FreeBSD) or allow match of double requested value (Linux)
	    if ($actual != $self->{SocketQueueLength} && ($actual / 2) != $self->{SocketQueueLength})
	    {
		$self->log($main::LOG_WARNING, "socket read queue length set to $actual instead of $self->{SocketQueueLength}");
	    }
	}
	# Maybe disable MTU discovery and enable Dont Frag. Only available on Linux
	if ($^O eq 'linux' && $self->{DisableMTUDiscovery})
	{
	    # Constants from /usr/include/bits/in.h
	    setsockopt($s, 
		       0, # IPPROTO_IP
		       10, # IP_MTU_DISCOVER 
		       0 ) # IP_PMTUDISC_DONT
		|| $self->log($main::LOG_WARNING, "Could not disable MTU discovery for $descr: $!");
	}
    }

    return $s;
}

1;

