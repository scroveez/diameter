# Fidelio.pm
#
# Routines for connecting to a Micros Fidelio Hotel Property Management System (PMS)
# Supports serial ports and TCP-IP sockets
#
# See 
# http://cisco.com/univercd/cc/td/doc/product/aggr/bbsm/bbsm53/sdkif/sdk53_05.htm
# http://zyxel.ru/content/support/knowledgebase/KB-1330/VSG-1200FieldTypeswithMicros-Fidelio.pdf
# http://www.telesis.com.tr/doc/pdf/fidelio1.pdf
# For protocol description
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: Fidelio.pm,v 1.28 2014/08/27 20:54:04 hvn Exp $

package Radius::Fidelio;
@ISA = qw(Radius::Configurable Radius::Stream);
use Radius::Configurable;
use Radius::Stream;
use Radius::Select;
use strict;

my $STX = "\002";
my $ETX = "\003";
my $ENQ = "\005";
my $ACK = "\006";
my $NAK = "\025";

%Radius::Fidelio::ConfigKeywords = 
(
 'Protocol'          => 
 ['string', 'Connection protocol to use to connect to Opera. A Protocol of serial requires Device::SerialPort', 1],

 'Port'              => 
 ['string', 'When Protocol is serial, Port specifies the serial port and port parameters to use to connect to the Opera server. Format is <p><pre><code>devicename[:baud[:bits[:parity[:stopbits[:handshake]]]]]</code></pre><p>When Protocol is tcp, specifies the TCP-IP port name or number of the Opera server', 1],

 'Host'              => 
 ['string', 'When Protocol is tcp, specifies the name or address of the Opera server', 0],

 'Baudrate'          => 
 ['integer', 'When Protocol is serial, specifies the baud rate to use if not explicitly set in the Port parameter', 2],

 'Databits'          => 
 ['integer', 'When Protocol is serial, specifies the number of data bits to use if not explicitly set in the Port parameter', 2],

 'Parity'            => 
 ['string', 'When Protocol is serial, specifies the parityto use if not explicitly set in the Port parameter', 2],

 'Stopbits'          => 
 ['integer', 'When Protocol is serial, specifies the number of stop bits to use if not explicitly set in the Port parameter', 2],

 'Handshake'         => 
 ['string', 'When Protocol is serial, specifies the type of handshake to use if not explicitly set in the Port parameter. Choose none or rts. Do not use xoff: it will cause problems', 2],

 'ReadCharTimeout'   => 
 ['integer', 'When Protocol is serial, specifies the read timeout to use if not explicitly set in the Port parameter. Time is in milliseconds', 2],

 'TransmitTimeout'   => 
 ['integer', 'Specifies the retransmission timeout in seconds', 2],

 'InterfaceFamily'   => 
 ['string', 'Specifies the Opera interface family that this module will use', 1],

 'FieldSeparator'    => 
 ['string', 'Specifies the field separator that will be used in messages sent and received from Opera', 2],

 'MaxBufferSize'     => 
 ['integer', 'Maximum input buffer size', 1],

 'UseChecksums'      => 
 ['flag', 'Controls whether to use checksums in messages to and from Opera', 2],

 'MessageHook'      => 
 ['hook', 'This hook is called whenever a new message is received from Opera. It can be used to adjust the contents of the message before it is passed to the handle_message() function. It is passed a pointer to the current Fidelio subclass, and the received message unpacked into a hash', 2],

 );

# RCS version number of this module
$Radius::Fidelio::VERSION = '$Revision: 1.28 $';

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->Radius::Configurable::activate;
}

#####################################################################
# Do per-instance default initialization
# This is called by Configurable during Configurable::new before
# the config file is parsed. Its a good place initalze 
# instance variables
# that might get overridden when the config file is parsed.
sub initialize
{
    my ($self) = @_;

    $self->Radius::Configurable::initialize;
    $self->{Protocol} = 'tcp';
    $self->{Port} = $self->{Protocol} eq 'serial' ? '/dev/ttyS0' : '5010';
    $self->{Host} = 'localhost';
    $self->{Baudrate} = '9600';
    $self->{Databits} = '8';
    $self->{Parity} = 'n';
    $self->{Stopbits} = '1';
    $self->{Handshake} = 'rts';
    $self->{ReconnectTimeout} = 5; # sec
    $self->{ReadCharTimeout} = 2000; # ms
    $self->{TransmitTimeout} = 2; # sec
    $self->{InterfaceFamily} = 'WW'; # Internet
    $self->{FieldSeparator} = '|';
    $self->{MaxBufferSize} = 100000;
}

#####################################################################
# reconnect has a name clash with SqlDb::reconnect
sub stream_reconnect
{
    my ($self) = @_;

    return $self->open_serial_port() if $self->{Protocol} eq 'serial';
    # TCP:
    my $ret = $self->SUPER::stream_reconnect();
    if ($self->{socket})
    {
	# Autoflush:
	my $oldfh = select($self->{socket});
	$| = 1;
	select($oldfh);
    }
    return $ret;
}

#####################################################################
# disconnect has a name clash with SqlDb::disconnect
sub fidelio_disconnect
{
    my ($self) = @_;

    $self->stream_disconnected();
}

#####################################################################
sub open_serial_port
{
    my ($self) = @_;

    # Connect to serial port
    require Device::SerialPort;
    
    $self->{serialport}->close() if $self->{serialport};

    # We provide a variety of ways to configure the serial port.
    # Easiest is, for example
    #   Port /dev/ttyUSB0:8:n:1:rts
    my ($portname, $baudrate, $databits, $parity, $stopbits, $handshake) 
	= split(/:/, $self->{Port});
    $self->{Baudrate}  = $baudrate  if defined $baudrate;
    $self->{Databits}  = $databits  if defined $databits;
    $self->{Parity}    = $parity    if defined $parity;
    $self->{Stopbits}  = $stopbits  if defined $stopbits;
    $self->{Handshake} = $handshake if defined $handshake;
    
    
    $self->log($main::LOG_DEBUG, "Fidelio is connecting to $portname with $self->{Databits}:$self->{Parity}:$self->{Stopbits}:$self->{Handshake}");
    $self->{serialport} = new Device::SerialPort($portname);
    if (!$self->{serialport})
    {
	$self->log($main::LOG_ERR, "Could not open serial port $portname: $!");
	return;
    }
    $self->{serialport}->baudrate($self->{Baudrate});
    $self->{serialport}->databits($self->{Databits});
    $self->{serialport}->parity($self->{Parity});
    $self->{serialport}->stopbits($self->{Stopbits});
    $self->{serialport}->handshake($self->{Handshake});
    $self->{serialport}->read_char_time($self->{ReadCharTimeout});
    $self->{serialport}->read_const_time(0);
    $self->{serialport}->stty_icanon(0);

    Radius::Select::add_file($self->{serialport}->{FD}, 1, undef, undef, \&handle_serial_read, $self);
    $self->stream_connected();
    return 1;
}

#####################################################################
# Called when a connection has been successfully established
sub stream_connected
{
    my ($self) = @_;

    $self->{last_response} = $NAK;
    $self->{read_state} = 'idle';
    $self->SUPER::stream_connected if $self->{Protocol} ne 'serial';
    $self->send_link_start();
    return if $self->{Protocol} ne 'serial';

    # Serial connection
    $self->{connected}++;
    $self->log($main::LOG_DEBUG, "Fidelio connected to serial port $self->{Port}");
}

#####################################################################
# Called when a connection has been successfully established
sub stream_disconnected
{
    my ($self) = @_;

    $self->SUPER::stream_disconnected();
}

#####################################################################
# Called when we know there is at least one char waiting to be read from 
# the serial port 
sub handle_serial_read
{
    my ($fileno, $self) = @_;

    my ($count, $ch) = $self->{serialport}->read(1);
#    print "handle_serial_read got $count: " . unpack('H*', $ch) . "\n";
    return $self->handle_char($ch) if $count;

    # Read failed: timeout?
    $self->log($main::LOG_ERR, 'Nothing read in handle_serial_read');
    return;
}

#####################################################################
# Returns undefined on timeout or after receipt and handling of a message
# Else returns the character that was read
sub handle_char
{
    my ($self, $ch) = @_;

#    print "handle_char got: " . unpack('H*', $ch) . "\n";
    if ($self->{read_state} eq 'idle')
    {
	if ($ch eq $STX)
	{
	    $self->log($main::LOG_EXTRA_DEBUG, 'Fidelio received STX');
	    $self->{read_state} = 'data';
	    $self->{read_checksum} = 0;
	    $self->{read_buf} = '';
	}
	elsif ($ch eq $ENQ)
	{
	    $self->log($main::LOG_WARNING, 'Fidelio received ENQ');
	    # Other end asks again for our last reponse
	    $self->send_lowlevel($self->{last_response});
	}
	elsif ($ch eq $ACK)
	{
	    $self->log($main::LOG_EXTRA_DEBUG, 'Fidelio received ACK');
	    $self->clear_transmit_timeout();
	    $self->dequeue(1);
	    $self->check_queue();
	}
	elsif ($ch eq $NAK)
	{
	    $self->log($main::LOG_WARNING, 'Fidelio received NAK');
	    $self->clear_transmit_timeout();
	    # retransmit the head of the queue
	    $self->retransmit();
	}
	else
	{
	    $self->log($main::LOG_ERR, 'Fidelio received unexpected character in waitstx');
	    $self->set_transmit_timeout();
	    $self->send_lowlevel($ENQ);
	    
	}
    }
    elsif ($self->{read_state} eq 'data')
    {
	if ($ch eq $ETX)
	{
	    $self->log($main::LOG_EXTRA_DEBUG, 'Fidelio received ETX');
	    if ($self->{UseChecksums})
	    {
		$self->{read_state} = 'checksum';
	    }
	    else
	    {
		# Dont check the checksum
		# Acknowledge
		$self->send_ack($ACK);
		
		# handle the message
		# Caution: can be reentrant
		$self->handle_raw_message($self->{read_buf});
		$self->{read_state} = 'idle';
	    }
	}
	else
	{
	    $self->{read_buf} .= $ch;
	}
	$self->{read_checksum} ^= ord($ch);
    }
    elsif ($self->{read_state} eq 'checksum')
    {
	# Check the checksum
	$self->log($main::LOG_DEBUG, "Fidelio receives: $self->{read_buf}");

	if ($self->{read_checksum} == ord($ch))
	{
	    # Good checksum, Acknowledge
	    $self->send_ack($ACK);
	    
	    # handle the message
	    # Caution: can be reentrant
	    $self->handle_raw_message($self->{read_buf});
	}
	else
	{
	    $self->log($main::LOG_ERR, 'Fidelio received bad checksum');
	    $self->send_ack($NAK);
	}
	$self->{read_state} = 'idle';
    }
    else
    {
	$self->log($main::LOG_DEBUG, "Fidelio received unexpected data: " . unpack('H*', $ch));
    }
}

#####################################################################
# Maybe send an ack or nak if its serial. TCP does not send
# acks/naks unless it gets an ENQ
sub send_ack
{
    my ($self, $response) = @_;

    
    $self->{last_response} = $response;
    $self->send_lowlevel($response) if $self->{Protocol} eq 'serial';
}

#####################################################################
sub send_response
{
    my ($self, $response) = @_;

    
    $self->{last_response} = $response;
    $self->send_lowlevel($response);
}

#####################################################################
sub create_server
{
    my ($self) = @_;

    return $self->open_serial_port()
	if $self->{Protocol} eq 'serial';

    # Make a TCP listener
    
}

#####################################################################
sub handle_raw_message
{
    my ($self, $raw) = @_;

    $self->log($main::LOG_DEBUG, "Fidelio read: $raw");
    my ($type, @fields) = split(quotemeta($self->{FieldSeparator}), $raw);
    my $record = {};

    # Unpack each field
    foreach (@fields)
    {
	$record->{substr($_, 0, 2)} = substr($_, 2);
    }

    $self->runHook('MessageHook', undef, $self, $record);
    $self->handle_message($type, $record);
}

#####################################################################
sub handle_message
{
    my ($self, $message) = @_;

    $self->log($main::LOG_ERR, 'You forgot to override handle_message');
}

#####################################################################
# Format DA and TI fields
# Adds separator at end
sub date_time
{
    my ($self) = @_;
    my @time = localtime(time);

    return sprintf('DA%02d%02d%02d' . $self->{FieldSeparator} . 'TI%02d%02d%02d', 
		   $time[5] % 100,
		   $time[4] + 1,
		   $time[3],
		   $time[2],
		   $time[1],
		   $time[0]) . $self->{FieldSeparator};
}

#####################################################################
sub send_link_start
{
    my ($self) = @_;
    
    my $message = 'LS' . $self->{FieldSeparator} . $self->date_time();
    $self->send_raw($message);
    $self->link_started();
}

#####################################################################
# Callback after link is started or restarted
sub link_started
{
    my ($self) = @_;
}


#####################################################################
sub send_link_end
{
    my ($self) = @_;
    
    my $message = 'LE'  . $self->{FieldSeparator} . $self->date_time();
    $self->send_raw($message);
}

#####################################################################
sub send_link_description
{
    my ($self) = @_;
    
    my $message = 'LD'  . $self->{FieldSeparator} . $self->date_time() . "V#${main::VERSION}" . $self->{FieldSeparator} . "IF$self->{InterfaceFamily}" . $self->{FieldSeparator};
    $self->send_raw($message);
}

#####################################################################
sub send_resync_request
{
    my ($self) = @_;
    
    my $message = 'DR' . $self->{FieldSeparator} . $self->date_time();
    $self->send_raw($message);
}

#####################################################################
sub send_resync_start
{
    my ($self) = @_;
    
    my $message = 'DS' . $self->{FieldSeparator} . $self->date_time();
    $self->send_raw($message);
}

#####################################################################
sub send_resync_end
{
    my ($self) = @_;
    
    my $message = 'DE' . $self->{FieldSeparator}  . $self->date_time();
    $self->send_raw($message);
}

#####################################################################
# These are only queued if we think we are actually connected
sub send_link_alive
{
    my ($self) = @_;
    
    return unless $self->isconnected();
    my $message = 'LA' . $self->{FieldSeparator}  . $self->date_time();
    $self->send_raw($message);
}

#####################################################################
sub send_message
{
    my ($self, $type, %fields) = @_;
    
    my $message = $type . $self->{FieldSeparator};
    foreach (keys %fields)
    {
	# REVISIT: remove any field separator  from the data?
	$message .= $_ . $fields{$_} .  $self->{FieldSeparator} ;
    }
    $message .=  $self->date_time();
    $self->send_raw($message);
}

#####################################################################
sub send_raw
{
    my ($self, $message) = @_;

    $self->log($main::LOG_DEBUG, "Fidelio queues: $message");
    # Compute checksum as XOR over all except the initial STX
    my $m = $message . $ETX;
    $message = $STX . $m;
    if ($self->{UseChecksums})
    {
	my $checksum = 0;
	map {$checksum ^= ord($_)} split(//, $m);
	$message .= chr($checksum);
    }
    if ($self->{Protocol} eq 'serial')
    {
	$self->enqueue($message);
	$self->check_queue();
    }
    else
    {
	# No ack/nak for tcp
	$self->send_lowlevel($message);
	return 1;
    }
}

#####################################################################
# Add a message to the tail of the queue
sub enqueue
{
    my ($self, $message) = @_;

    push(@{$self->{queue}}, $message);
}

#####################################################################
# Remove the message from head of the queue.
# $success is true if the message was received OK by the other end
sub dequeue
{
    my ($self, $success) = @_;

    shift(@{$self->{queue}});
    $self->{waiting_for_response} = 0;
}

#####################################################################
# See if there are any mnore messages to be enqueued
sub check_queue
{
    my ($self) = @_;

#    print "check_queue $self->{waiting_for_response}\n";
    if (@{$self->{queue}} 
	&& !$self->{waiting_for_response})
    {
#	print "check_queue start next message\n";
	$self->{transmit_counter} = 0;
	$self->send(${$self->{queue}}[0]);
    }
}

#####################################################################
sub retransmit
{
    my ($self) = @_;

    if ($self->{retransmit_counter} < 3)
    {
	$self->send(${$self->{queue}}[0]);
    }
    else
    {
	$self->log($main::LOG_ERR, 'Retransmissions count exceeded');
	$self->dequeue(0);
	$self->check_queue();
    }
}

#####################################################################
# Send a message and wait for successful transmission acknowledgement
sub send
{
    my ($self, $message) = @_;

    $self->send_lowlevel($message);
    $self->{transmit_counter}++;
    $self->{waiting_for_response}++;
    # Set timeout
    $self->set_transmit_timeout();
}

#####################################################################
sub clear_transmit_timeout
{
    my ($self) = @_;

    &Radius::Select::remove_timeout($self->{transmitTimeoutHandle})
	if $self->{transmitTimeoutHandle};
    $self->{transmitTimeoutHandle} = undef;
}
#####################################################################
sub set_transmit_timeout
{
    my ($self) = @_;

    $self->clear_transmit_timeout();
    $self->{transmitTimeoutHandle} = &Radius::Select::add_timeout(time + $self->{TransmitTimeout}, \&transmit_timeout, $self);
}

#####################################################################
# Did not get a reply from the other end. Send ENQ
sub transmit_timeout
{
    my ($handle, $self) = @_;

    
    $self->log($main::LOG_WARNING, 'Fidelio transmit timeout');
    if ($self->{transmit_counter} > 3)
    {
	# Link failure
	$self->log($main::LOG_ERR, 'Fidelio no response from peer');
	$self->dequeue();
	$self->fidelio_disconnect();
	return;
    }
    $self->{transmit_counter}++;
    $self->{waiting_for_response}++;
    $self->send_lowlevel($ENQ);
    $self->set_transmit_timeout();
}

#####################################################################
sub send_lowlevel
{
    my ($self, $message) = @_;

    $self->log($main::LOG_EXTRA_DEBUG, "Fidelio sends: " . unpack('H*', $message));
    return $self->{serialport}->write($message) if $self->{Protocol} eq 'serial';
    # TCP:
    return $self->write($message);
}

#####################################################################
# Called when a socket stream has some data to read
sub read_data
{
    my ($self) = @_;

    map {$self->handle_char($_)} split('', $self->{inbuffer});
    $self->{inbuffer} = '';
}

#####################################################################
# Send an LE if we can
sub DESTROY
{
    my ($self) = @_;

    $self->send_link_end();
}

1;
