# SimpleClient.pm
#
# Object that acts as a simple Radius client
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2002 Open System Consultants
# $Id: SimpleClient.pm,v 1.12 2013/07/15 07:15:01 hvn Exp $
package Radius::SimpleClient;
use Radius::Radius;
use Radius::Util;
use Radius::Log;
use strict;

my $trace_level =  $main::LOG_ERR;

# RCS version number of this module
$Radius::SimpleClient::VERSION = '$Revision: 1.12 $';

#####################################################################
# Create a new client, along with a radius socket for sending requests
sub new
{
    my ($class, %args) = @_;

    my $self = {};
    bless $self, $class;

    my $s = $self->{_socket} = do { local *FH };
    socket($s, Socket::PF_INET, Socket::SOCK_DGRAM, scalar getprotobyname('udp'))
	|| die "Could not create Radius socket in SimpleClient: $!";
    binmode($s)
	|| die "Could not binmode Radius socket in SimpleClient: $!"; # Make safe in UTF environments
    $self->{_nextidentifier} = 0;
    $self->{_defaultdest} = $args{Dest} || 'localhost:1645';
    $self->{_defaultsecret} = $args{Secret} || 'mysecret';
    $self->{_defaulttimeout} = 5;
    $self->{_defaulttimeout} = $args{Timeout} if defined $args{Timeout};
    $self->{_defaultretries} = 3;
    $self->{_defaultretries} = $args{Retries} if defined $args{Retries};
    $self->{_encodepassword} = 1;
    $self->{_encodepassword} = $args{EncodePassword} if defined $args{EncodePassword};
    $trace_level = $args{Trace} if defined  $args{Trace};
    return $self;
}

#####################################################################
sub nextIdentifier
{
    my ($self) = @_;

    my $ret = $self->{_nextidentifier};
    $self->{_nextidentifier} = ($self->{_nextidentifier} + 1) % 256;
    return $ret;
}


#####################################################################
# Send the Radius packet to the destination address
# $p is the Radius::Radius packet
# $paddr is the packet addreess to send to
sub sendTo
{
    my ($self, $p, $secret, %args) = @_;

    $p->set_identifier($self->nextIdentifier())
	unless (defined $p->identifier());

    my $dest = $args{Dest} || $self->{_defaultdest};
    my ($address, $port) = split(/:/, $dest);
    $address ||= 'localhost';
    $port ||= 1645;
    my $paddr = Socket::sockaddr_in($port, Socket::inet_aton($address));

    $p->assemble_packet($secret);
    return $p->sendTo($self->{_socket}, $paddr);
}

#####################################################################
# Wait for a reply to the given packet. Return handle
# to a Radius::Radius. If timeout expires first
# return undef
sub wait
{ 
    my ($self, $p, $timeout) = @_;

    my $result;
    # CAUTION: dont expect timeouts to work on Windows
    {
	eval
	{
	    local $SIG{ALRM} = sub {die "timeout"};
	    alarm($timeout);
	    
	    # Get a response
	    my $r = Radius::Radius->newRecvFrom($self->{_socket}, $p->{Dict});
	    # Is it the response to the request we sent?
	    $result = $r if $r && $r->identifier() == $p->identifier();
	};
    
	alarm(0); # Cancel the alarm
    }
    return $result;
}

#####################################################################
# Send the Radius packet to the destination address and wait for
# a response, discarding all non-responses received.
# Request will be sent at least one, and until Retries is exhausted.
# The reply will be decoded
sub sendAndWait
{    
    my ($self, $p, %args) = @_;

    # Maybe encode the user password
    my $secret = $args{Secret} || $self->{_defaultsecret};
    my $attr = $p->get_attr('User-Password');
    $p->set_authenticator(Radius::Util::random_string(16)) unless defined $p->authenticator;
    $p->change_attr('User-Password', $p->encode_password($attr, $secret)) 
	if $self->{_encodepassword} && defined $attr;

    my $start_time = time;

    # Send the request
    my $timeout = $args{Timeout} || $self->{_defaulttimeout};
    my $retries = $args{Retries} || $self->{_defaultretries};

    # Keep going until retries are exhausted
    my $ret;
    do
    {
	# Maybe adjust Acct-Delay-Time
	if ($p->code eq 'Accounting-Request')
	{
	    $p->changeAttrByNum($Radius::Radius::ACCT_DELAY_TIME, time - $start_time);
	    $p->set_identifier($self->nextIdentifier());
	}

	$self->sendTo($p, $secret, %args);
	if ($ret = $self->wait($p, $timeout))
	{
	    $ret->decode_attrs($secret, $p);
	    $ret->recv_debug_dump($self) if ($self->willLog($main::LOG_DEBUG, $ret));
	    return $ret;
	}
    } while ($retries-- > 0);
    $self->log($main::LOG_ERR, "Radius::SimpleClient::sendAndWait failed. No reply");
    return;
}

#####################################################################
# Construct a simple new request, with named attributes as given
# Defaults to an Access-Request
sub request
{
    my ($d, %args) = @_;

    my $p = Radius::Radius->new($d) || die 'Radius::Radius';
    my $code = delete $args{Code} || 'Access-Request';
    my $authenticator = delete $args{Authenticator} 
        || &Radius::Util::random_string(16);
    foreach (keys %args)
    {
	$p->add_attr($_, $args{$_});
    }
    $p->set_code($code);
    $p->set_authenticator($authenticator);
    return $p;
}

#####################################################################
# Create a socket, construct a request, send it and wait for a reply.
# Return the reply, or undef if anything failed
sub createSendWait
{
    my ($class, %args) = @_;

    my $s = $class->new('Secret'  => delete $args{Secret},
			'Dest'    => delete $args{Dest},
			'Timeout' => delete $args{Timeout}) || return;
    my $dictionary = delete $args{Dictionary} || './dictionary';
    my $d = Radius::RDict->new($dictionary) || return;
    my $p = Radius::SimpleClient::request($d, %args);
    return $s->sendAndWait($p);
}

#####################################################################
# Maybe set a new trace level. Return the old trace level
sub trace_level
{
    my ($new) = @_;

    my $old = $trace_level;
    $trace_level = $new if defined $new;

    return $old;
}

#####################################################################
# Provide a basic implementation of a logger
sub log
{    
    my ($self, $priority, $s, $p) = @_;

    my $pname = $Radius::Log::priorityToString[$priority];
    print STDERR "$pname: $s\n"
	if ($priority <= $trace_level);
}

sub willLog
{    
    my ($self, $priority, $p) = @_;

    return ($priority <=  $trace_level);
}


1;
