#!/usr/bin/perl
#
# fideliosim.pl
#
# Simulates a Micros Fidelio Hotel Property Management System (PMS)
# with serial interface.
# For testing AuthBy FIDELIO
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: fideliosim.pl,v 1.22 2013/03/13 02:45:07 mikem Exp $

# Make sure we get the local libs for preference
BEGIN
{
    unshift(@INC, '.');
}

use Getopt::Long;
use Radius::Fidelio;
use Radius::Log;
use Socket;
use strict;

my $next_guest_number = 12349;
my %clients;
my $next_transaction_number = 1;

# A fake user database, indexed by room number, then by guest number, 
# so we can support multiple guests per room
my %guests =
(
 '001' => { '12345' => { 'RN' => '001',
			 'G#' => '12345',
			 'GN' => 'Mr Test User',
			 'GL' => 'EA',
	    },
 },
 '002' => { '12346' => { 'RN' => '002',
			 'G#' => '12346',
			 'GN' => 'Mr Test User 2',
			 'GL' => 'EA',
	    },
 },
 '003' => { '12347' => { 'RN' => '003',
			 'G#' => '12347',
			 'GN' => 'Mr Test User 3',
			 'GL' => 'EA',
	    },'12348' => { 'RN' => '003',
			 'G#' => '12348',
			 'GN' => 'Mr Test User 4',
			   'GL' => 'EA',
	    },
 },

 );

$main::link_alive_timeout = 10; # Seconds

package Radius::Fidelio::Server;
our @ISA = qw(Radius::Fidelio);

sub new
{
    my ($class, @args) = @_;

    my $self = $class->SUPER::new(undef, undef, @args);
    &Radius::Select::add_timeout(time + $main::link_alive_timeout,
				 \&handle_link_alive_timeout, $self);

    return $self;
}

# Send a link alive request
sub handle_link_alive_timeout
{
    my ($handle, $self) = @_;

    $self->send_link_alive()
	if $self->isconnected();

    # New timer:
    &Radius::Select::add_timeout(time + $main::link_alive_timeout,
				 \&handle_link_alive_timeout, $self);

}

# Override Radius::Fidelio::handle_message so we can get control for each message received
# $record is a pointer to a hash containing decoded data in the incoming message
sub handle_message
{
    my ($self, $type, $record) = @_;

    if ($type eq 'LS')
    {
	# Link Start, send a link start reply
	$self->send_link_start();
    }
    elsif ($type eq 'LA')
    {
	# Link alive, send one in reply
	$self->send_link_alive();
    }
    elsif ($type eq 'DR')
    {
	# Database resync request
	$self->send_resync_start();

	foreach (keys %guests)
	{
	    my $rn = $_;
	    foreach (keys %{$guests{$rn}})
	    {
		$self->send_message('GI', %{$guests{$rn}{$_}}, 'SF' => '');
	    }
	}
	$self->send_resync_end();
    }
    elsif ($type eq 'PS')
    {
	print "Received PS: $record->{RN} $record->{'P#'} '$record->{CT}' $record->{TA}\n";
	# Posting, reply with a PA
	if ($record->{RN} !~ /^\d+$/)
	{
	    $self->send_message("PA|ASNG|P#$record->{'P#'}|CTInvalid Room Number");
	}
	else
	{
	    $self->send_message("PA|ASOK|RN$record->{'RN'}|P#$record->{'P#'}|CTPosting successful. Interface transaction number/s - $next_transaction_number");
	    $next_transaction_number++;
	}
    }
}
*Radius::Fidelio::handle_message = *Radius::Fidelio::Server::handle_message;

sub stream_disconnected
{
    my ($self) = @_;

    $self->SUPER::stream_disconnected();
    # Remove this client from the clients list
    delete $clients{$self};
}

######################################################################################
package main;

my @options = 
    (
     'h:s',        # Print usage
     't:s',        # Transport protocol (serial, tcp)
     'p:s',        # Port
     'trace:i',    # Trace
     );

&GetOptions(@options) || &usage;
&usage if $main::opt_h;

$main::config = Radius::Configurable->new();
$main::config->{LogStdout} = 1;
$main::config->{Trace} = $main::opt_trace;

my $opt_protocol = $main::opt_t || 'tcp';
my $opt_port = $main::opt_p || ($opt_protocol eq 'serial' ? '/dev/ttyUSB1:9600:8:n:1:rts' : 5010);
my $opt_host = $main::opt_h || 'localhost';
my $opt_bindaddress = '0.0.0.0';

if ($opt_protocol eq 'serial')
{
    my $f = Radius::Fidelio->new(undef, 'Fidelio', 
				 Protocol => $opt_protocol,
				 Host => $opt_host,
				 Port => $opt_port,
				 UseChecksums => 1,
				 );
    die 'Could not create serial Radius::Fidelio' unless $f;
    $f->create_server();
    $f->send_link_start();
}
else
{
    # Create a TCP socket to listen on, register it with select
    # Set up the TCP listener
    my $port = Radius::Util::get_port($opt_port);
    my $protocol = getprotobyname($opt_protocol);
    if (!defined $protocol)
    {
	warn "fideliosim: Unknown Protocol type $opt_protocol";
	return;
    }
    foreach (split(/\s*,\s*/, &Radius::Util::format_special($opt_bindaddress)))
    {
	warn "Creating fideliosim $opt_protocol port $_:$port";
	my $s = do { local *FH };
	my $bind_address = &Radius::Util::format_special($_);
	my ($paddr, $pfamily) = &Radius::Util::pack_sockaddr_pton($port, $bind_address);
	socket($s, $pfamily, Socket::SOCK_STREAM, $protocol)
	    || warn "Could not create Fidelio server socket: $!";
	$main::forkclosesfdexceptions{fileno($s)}++;
	binmode($s); # Make safe in UTF environments
	setsockopt($s, Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1);
	bind($s, $paddr)
	    || warn "Could not bind Fidelio server socket: $!";
	listen($s, Socket::SOMAXCONN)
	    || warn "Could not listen on Fidelio server socket: $!";
	&Radius::Select::add_file
	    (fileno($s), 1, undef, undef, 
	     \&handle_listen_socket_read, $s);
    }
}

# This breaks Windows:
# Create a listener on the stdin for sommands
if ($^O ne 'MSWin32')
{
    &Radius::Select::add_file
	(0, 1, undef, undef, 
	 \&handle_command_read);
}

&Radius::Select::simple_main_loop();

# Send a GI to all connected clients
sub send_all_gi
{
    my ($room, $guest_number) = @_;
    
    foreach (values %clients)
    {
	$_->send_message('GI', %{$guests{$room}{$guest_number}});
    }
}

# Send a GO to all connected clients
sub send_all_go
{
    my ($room, $guest_number) = @_;

    
    foreach (values %clients)
    {
	$_->send_message('GO', 
			 'RN' => $guests{$room}{$guest_number}{'RN'},
			 'G#' => $guests{$room}{$guest_number}{'G#'},
	    );
    }
}

# Called when there is something to read from stdin
sub handle_command_read
{
    my $command = <STDIN>;

    chomp($command);
    if ($command =~ /^ci (\d+) \"(.+)\"/)
    {
	# ci roomnum "guest name" 
	my $room = $1;
	my $guestname = $2;
	$guests{$room}{$next_guest_number} = { 'RN' => $room,
					       'G#' => $next_guest_number,
					       'GN' => $guestname,
					       'GL' => 'EA',
	};
	&send_all_gi($room, $next_guest_number);
	
	print "Added guest number $next_guest_number\n";
	$next_guest_number++;
    }
    elsif ($command =~ /^co (\d+)/)
    {
	# co roomnum
	my $room = $1;
	if (exists $guests{$room})
	{
	    # Remove them all and send a GO
	    foreach (keys %{$guests{$room}})
	    {
		&send_all_go($room, $_);
		delete $guests{$room}{$_};
		print "Checked out guest number $_ from room $room\n";
	    }
	}
	else
	{
	    print "No guest in room $room\n";
	}
    }
    elsif ($command =~ /^l/)
    {
	# l
	foreach (sort keys %guests)
	{
	    my $rn = $_;
	    foreach (sort keys %{$guests{$rn}})
	    {
		print "$rn: $guests{$rn}{$_}->{'G#'} $guests{$rn}{$_}->{'GN'} \n";
	    }
	}
    }
    elsif ($command =~ /^h/)
    {
	# h
	print "Commands:
 Check in new guest:
  ci roomnum \"guest name\"
 Check out guest:
  co roomnum
 List all guests:
  l
 This help:
  h\n";
    }
    elsif ($command eq '')
    {
    }
    else
    {
	print "Unknown command: $command\n";
    }
}

#####################################################################
# This is called by Select::select whenever our listen socket
# becomes readable, which means someone is trying to connect to us
# We accept the new connection
sub handle_listen_socket_read
{
    my ($fileno, $listensocket) = @_;

    # This could have been done with FileHandle, but this is much
    # more lightweight. It makes a reference to a TYPEGLOB
    # and Perl can use a typeglob ref as an IO handle
    my $newsocket = do { local *FH };
    if (!accept($newsocket, $listensocket))
    {
	warn "Could not accept on Fidelio listen socket: $!";
	return;
    }

    my $s = Radius::Fidelio::Server->new
	(
	 socket => $newsocket,
	 Host => $opt_host,
	 Port => $opt_port,
	 Protocol => $opt_protocol,
	 UseChecksums => 0,
	 );
    $s->stream_server_connected();
    $clients{$s} = $s;
}

sub usage
{
    print "usage: $0 [-h] [-trace n]
 [-port devicename[:baud[:databits[:parity[:stopbits[:handshake]]]]]]\n";
}

