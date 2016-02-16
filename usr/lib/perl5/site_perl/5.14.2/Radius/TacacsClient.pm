# TacacsClient.pm
#
# Object that acts as a simple TACACS+ client
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2002 Open System Consultants
# $Id: TacacsClient.pm,v 1.6 2014/03/18 21:19:33 hvn Exp $
package Radius::TacacsClient;
use Radius::Tacacsplus;
use Radius::Log;
use IO::Socket::INET;
use strict;

# RCS version number of this module
$Radius::TacacsClient::VERSION = '$Revision: 1.6 $';

#####################################################################
# Create a new client, along with a radius socket for sending requests
sub new
{
    my ($class, %args) = @_;

    my $self = {};
    bless $self, $class;

    $self->resetSequence();
    $self->{Host} = $args{Host} || 'localhost';
    $self->{Port} = $args{Port} || $Radius::Tacacsplus::TAC_PLUS_PORT;
    $self->{Key}  = $args{Key} || 'mysecret';
    $self->{Timeout} = $args{Timeout} || 5;
    $self->{TFlags} = $args{TFlags} || 0;
    $self->{LocalAddr} = $args{LocalAddr}; # Might be undef

    $self->reconnect();
    return $self;
}

#####################################################################
sub reconnect
{
    my ($self) = @_;

    return $self->{_socket} if $self->{_socket} && $self->{_socket}->connected();

    my $class = 'IO::Socket::INET';
    if ($self->{Host} =~ /:/)
    {
	unless (eval {require IO::Socket::INET6} )
	{
	    main::log($main::LOG_ERR, "Could not load IO::Socket::INET6 for IPv6 support: $!");
	    return;
	}
	$class = 'IO::Socket::INET6';
    }

    my %args = (PeerAddr => $self->{Host},
		PeerPort => $self->{Port},
		Proto => 'tcp',
		Type => SOCK_STREAM);
    $args{LocalAddr} = $self->{LocalAddr} if defined $self->{LocalAddr};

    $self->{_socket} = $class->new(%args);
    if (!$self->{_socket})
    {
	&main::log($main::LOG_ERR, "Failed to open TacacsClient socket for $self->{Host}:$self->{Port}: $!");
	return;
    }
    binmode($self->{_socket});
    return $self->{_socket};
}

#####################################################################
sub nextSequence
{
    my ($self) = @_;

    my $ret = $self->{_nextsequence};
    $self->{_nextsequence} = ($self->{_nextsequence} + 1) % 256;
    return $ret;
}

#####################################################################
sub resetSequence
{
    my ($self) = @_;

    $self->{_nextsequence} = 1;
}

#####################################################################
sub authentication
{
    my ($self, %args) = @_;

    return unless $self->reconnect();
    $args{SessionId} = 1 unless defined $args{SessionId};
    $args{Action} = $Radius::Tacacsplus::TAC_PLUS_AUTHEN_LOGIN unless defined $args{Action};
    $args{PrivLevel} = 0 unless defined $args{PrivLevel};
    $args{AuthenType} = $Radius::Tacacsplus::TAC_PLUS_AUTHEN_TYPE_PAP unless defined $args{AuthenType};
    $args{Service} = $Radius::Tacacsplus::TAC_PLUS_AUTHEN_SVC_NONE unless defined $args{Service};

    $self->resetSequence();
    my $r = &Radius::Tacacsplus::pack_authentication_start
	($self->nextSequence(),
	 $self->{TFlags},
	 $args{SessionId},
	 $args{Action},
	 $args{PrivLevel},
	 $args{AuthenType},
	 $args{Service},
	 $args{Username},
	 $args{Userport},
	 $args{RemoteAddress},
	 $self->{Key},
	 $args{Password});
    &main::log($main::LOG_INFO, "sending Authentication request...");
    &main::log($main::LOG_EXTRA_DEBUG, unpack('H*', $r));
    $self->{_socket}->send($r);

  wait_for_reply:
    # Now wait for and unpack a reply
    my ($version, $type, $seq_no, $tflags, $session_id, $body) = 
	&Radius::Tacacsplus::recv_response($self->{_socket}, $self->{Key});
    if (defined $version)
    {
	# Got a reply
	&main::log($main::LOG_WARNING, "Received incorrect response type: $type")
	    unless ($type == $Radius::Tacacsplus::TAC_PLUS_AUTHEN);

	# Check for Authentication reply
	my ($status, $rflags, $server_msg, $data) = 
	    &Radius::Tacacsplus::unpack_authentication_response($body);
	if ((   $status == $Radius::Tacacsplus::TAC_PLUS_AUTHEN_STATUS_GETDATA
	     || $status == $Radius::Tacacsplus::TAC_PLUS_AUTHEN_STATUS_GETPASS
	     || $status == $Radius::Tacacsplus::TAC_PLUS_AUTHEN_STATUS_GETUSER)
	    && $args{Interactive})
	{
	    # Server is asking for more data, get it and send a CONTINUE request
	    # with the requested data in the user_msg field
	    my $response = <STDIN>;
	    chomp $response;
	    $r = &Radius::Tacacsplus::pack_authentication_continue
		($self->nextSequence(),
		 $self->{TFlags},
		 $args{SessionId},
		 $response,    # user_msg
		 0,            # auth flags
		 $self->{Key});
	    &main::log($main::LOG_INFO, "sending Authentication continue...");
	    &main::log(5, unpack('H*', $r));
	    $self->{_socket}->send($r);
	    goto wait_for_reply;
	}
	&main::log($main::LOG_DEBUG, "authentication response: $version, $type, $seq_no, $rflags, $session_id, $status, $tflags, $server_msg, $data");
	$self->disconnect() unless $self->{TFlags} && ($tflags & $Radius::Tacacsplus::TAC_PLUS_SINGLE_CONNECT_FLAG);
	return ($version, $type, $seq_no, $rflags, $session_id, $status, $tflags, $server_msg, $data);
    }
    else
    {
	&main::log($main::LOG_WARNING, "TacacsClient recv_response failed. Peer probably disconnected: $!");
	$self->disconnected();
	return;
    }
}

#####################################################################
sub authorization
{
    my ($self, %args) = @_;

    return unless $self->reconnect();
    $args{SessionId} = 1 unless defined $args{SessionId};
    $args{PrivLevel} = 0 unless defined $args{PrivLevel};
    $args{AuthenType} = $Radius::Tacacsplus::TAC_PLUS_AUTHEN_TYPE_PAP unless defined $args{AuthenType};
    $args{AuthenMethod} = $Radius::Tacacsplus::TAC_PLUS_AUTHEN_METH_TACACSPLUS unless defined $args{AuthenMethod};
    $args{Service} = $Radius::Tacacsplus::TAC_PLUS_AUTHEN_SVC_NONE unless defined $args{Service};

    # Create an authorization request
    $self->resetSequence();
    my $r = &Radius::Tacacsplus::pack_authorization_request
	($self->nextSequence(),
	 $self->{TFlags},
	 $args{SessionId},
	 $args{AuthenMethod},
	 $args{PrivLevel},
	 $args{AuthenType},
	 $args{Service},
	 $args{Username},
	 $args{Userport},
	 $args{RemoteAddress},
	 $self->{Key},
	 @{$args{AuthorArgs}});
    &main::log($main::LOG_INFO, "sending Authorization request...");
    &main::log($main::LOG_EXTRA_DEBUG, unpack('H*', $r));
    $self->{_socket}->send($r);
    
    #  Now wait for and unpack a reply
    my ($version, $type, $seq_no, $tflags, $session_id, $body) = 
	&Radius::Tacacsplus::recv_response($self->{_socket}, $self->{Key});
    if (defined $version)
    {
	&main::log($main::LOG_WARNING, "Received incorrect response type: $type\n")
	    unless ($type == $Radius::Tacacsplus::TAC_PLUS_AUTHOR);
	# Authorization reply
	my ($status, $server_msg, $data, @args) = 
	    &Radius::Tacacsplus::unpack_authorization_response($body);
	&main::log($main::LOG_DEBUG, "authorization response: $version, $type, $seq_no, $tflags, $session_id, $status, $server_msg, $data, @args");
	$self->disconnect() unless $self->{TFlags} && ($tflags & $Radius::Tacacsplus::TAC_PLUS_SINGLE_CONNECT_FLAG);
	return ($version, $type, $seq_no, $tflags, $session_id, $status, $server_msg, $data);
    }
    else
    {
	&main::log($main::LOG_WARNING, "TacacsClient recv_response failed. Peer probably disconnected: $!");
	$self->disconnected();
	return;
    }
}

#####################################################################
sub accounting
{
    my ($self, %args) = @_;

    return unless $self->reconnect();
    $args{AFlags} = 0 unless defined $args{AFlags};
    $args{SessionId} = 1 unless defined $args{SessionId};
    $args{PrivLevel} = 0 unless defined $args{PrivLevel};
    $args{AuthenType} = $Radius::Tacacsplus::TAC_PLUS_AUTHEN_TYPE_PAP unless defined $args{AuthenType};
    $args{AuthenMethod} = $Radius::Tacacsplus::TAC_PLUS_AUTHEN_METH_TACACSPLUS unless defined $args{AuthenMethod};
    $args{Service} = $Radius::Tacacsplus::TAC_PLUS_AUTHEN_SVC_NONE unless defined $args{Service};

    # Create an accounting request
    $self->resetSequence();
    my $r = &Radius::Tacacsplus::pack_accounting_request
	($self->nextSequence(),
	 $self->{TFlags},
	 $args{AFlags},
	 $args{SessionId},
	 $args{AuthenMethod},
	 $args{PrivLevel},
	 $args{AuthenType},
	 $args{Service},
	 $args{Username},
	 $args{Userport},
	 $args{RemoteAddress},
	 $self->{Key},
	 @{$args{AcctArgs}});
    &main::log($main::LOG_INFO, "sending Accounting request...");
    &main::log($main::LOG_EXTRA_DEBUG, unpack('H*', $r));
    $self->{_socket}->send($r);
    
    #  Now wait for and unpack a reply
    my ($version, $type, $seq_no, $tflags, $session_id, $body) = 
	&Radius::Tacacsplus::recv_response($self->{_socket}, $self->{Key});
    if (defined $version)
    {
	&main::log($main::LOG_WARNING, "Received incorrect response type: $type\n")
	    unless ($type == $Radius::Tacacsplus::TAC_PLUS_ACCT);

	# Accounting reply
	my ($status, $server_msg, $data) = 
	    &Radius::Tacacsplus::unpack_accounting_response($body);
	&main::log($main::LOG_DEBUG, "accounting response: $version, $type, $seq_no, $tflags, $session_id, $status, $server_msg, $data");
	$self->disconnect() unless $self->{TFlags} && ($tflags & $Radius::Tacacsplus::TAC_PLUS_SINGLE_CONNECT_FLAG);
	return ($version, $type, $seq_no, $tflags, $session_id, $status, $server_msg, $data);
    }
    else
    {
	&main::log($main::LOG_WARNING, "TacacsClient recv_response failed. Peer probably disconnected: $!");
	$self->disconnected();
	return;
    }
}

#####################################################################
sub disconnected
{
    my ($self) = @_;

    &main::log($main::LOG_DEBUG, "Disconnected from $self->{Host}:$self->{Port}");
    $self->{_socket} = undef;
}

#####################################################################
sub disconnect
{
    my ($self) = @_;

    if ($self->{_socket})
    {
	&main::log($main::LOG_DEBUG, "Disconnect from $self->{Host}:$self->{Port}");
	$self->{_socket}->close();
    }
    $self->{_socket} = undef;
}
