# DiaClient.pm
#
# Object that acts as a simple Diameter client
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2002 Open System Consultants
# $Id: DiaClient.pm,v 1.16 2014/08/20 20:58:18 hvn Exp $
package Radius::DiaClient;
use Radius::TLSConfig;
use Radius::DiaUtil;
use Radius::DiaDict;
use Radius::DiaPeer;
use Radius::Diameter;
use strict;
@Radius::DiaClient::ISA = qw(Radius::Logger Radius::Diameter);

%Radius::DiaClient::ConfigKeywords = 
('Host'                       => 
 ['string', 'Name or IP address of the Diameter peer. IPV4 and IPV6 addresses are supported', 0],

 'SCTPPeer'                       => 
 ['stringarray', 'With this parameter, you can specify any number of names or IP addresses of the Diameter SCTP peers. When defined, SCTPPeer is used instead of Host. IPV4 and IPV6 addresses are supported', 0],

 'Port'                       => 
 ['string', 'The port name or number of the Diameter peer.', 0],

 'MaxBufferSize'              => 
 ['integer', 'Maximum input buffer sie in octets.', 1],

 'ReconnectTimeout'           => 
 ['integer', 'This optional parameter specifies the number of seconds to wait before attempting to reconnected a failed, dropped or disconnected Diameter peer connection.', 1],

 'ConnectOnDemand'            => 
 ['flag', 'This optional parameter tells this peer not to connect to its Diameter peer server as soon as possible, but to wait until a request has been reeceived that must be sent to that server. ', 1],

 'Protocol'                   => 
 ['string', 'This optional parameter specifies which Stream protocol will be used to carry Diameter.', 1],

# 'Dictionary'                 => 
# ['string', '', 1],

 'OriginHost'                 => 
 ['string', '', 1],

 'OriginRealm'                => 
 ['string', '', 1],

 'DestinationHost'                 => 
 ['string', '', 1],

 'DestinationRealm'                => 
 ['string', '', 1],

 'UseTLS'                     => 
 ['flag', 'This optional parameter forces the use of TLS for authentication and encryption of the Diameter connection. Requires Net::SSLeay Perl module from CPAN. When this parameter is enabled, the other TLS_* parameters become available for use. Defaults to disabled.', 1],

 'NoreplyTimeout'             => 
 ['integer', 'If no reply is received to a proxied request within this number of seconds, the NoReplyHook will be called for this request. Defaults to 5 seconds.', 1],

 'NoReplyHook'                => 
 ['hook', 'Perl function that will be called if no reply is received from any Diameter server. ', 2],

 @Radius::TLSConfig::clientkeywords,
 );

# RCS version number of this module
$Radius::DiaClient::VERSION = '$Revision: 1.16 $';

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();

    if ($self->{UseTLS})
    {
	if (!eval("require Radius::StreamTLS"))
	{
	    $self->log($main::LOG_ERR, "DiaClient has UseTLS, but could not load required modules: $@");
	}
	else
	{
	    Radius::StreamTLS::init($self);
	}
    }



    # Resolve the application names in SupportedAuth- and
    # SupportedVendorAuth and -AcctApplicationIds to numeric
    # values. Load any dictionaries the applications need. Then
    # resolve the supported vendors and vendor parts in supported
    # vendor apps.
    Radius::DiaUtil::resolve_application_ids($self);
    Radius::DiaUtil::load_dictionaries($self);
    Radius::DiaUtil::resolve_vendor_ids($self);

    $self->{DiaPeer} = Radius::DiaPeer->new
	(IConn => $self,
	 RecvMessageCallback => sub {$self->client_recv_callback(@_)},
#	 ErrorCallback => \&client_error_callback,
#	 TransportUpCallback => \&client_connection_up,
	 Dictionary => $self->{Dictionary},
	 OriginHost => $self->{OriginHost},
	 OriginRealm => $self->{OriginRealm},
	 Trace => $self->{Trace},
	 UseTLS => $self->{UseTLS},
	 SupportedVendorIds	   => $self->{Ids}{SupportedVendorIds},
	 AuthApplicationIds	   => $self->{Ids}{AuthApplicationIds},
	 AcctApplicationIds	   => $self->{Ids}{AcctApplicationIds},
	 VendorAuthApplicationIds  => $self->{Ids}{VendorAuthApplicationIds},
	 VendorAcctApplicationIds  => $self->{Ids}{VendorAcctApplicationIds},
	 InbandSecurityIds      => [($self->{UseTLS} ?
				     $Radius::DiaAttrList::INBAND_SECURITY_ID_TLS :
				     $Radius::DiaAttrList::INBAND_SECURITY_ID_NO_INBAND_SECURITY  )],
	 );
    $self->{DiaPeer}->activate();
    $self->{DiaPeer}->connect();

    return $self;
}

#####################################################################
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{Port} = 3868; 
    $self->{MaxBufferSize} = 100000;
    $self->{Protocol} = 'tcp';
    $self->{NoreplyTimeout} = 5;
    $self->{SupportedVendorIds} = "$Radius::DiaAttrList::VCODE_BASE";
    $self->{AuthApplicationIds} = "$Radius::DiaMsg::APPID_BASE, $Radius::DiaMsg::APPID_NASREQ";
    $self->{AcctApplicationIds} = "$Radius::DiaMsg::APPID_BASE, $Radius::DiaMsg::APPID_BASE_ACCOUNTING";
    $self->{InbandSecurityIds}  = [$Radius::DiaAttrList::INBAND_SECURITY_ID_TLS];
}

#####################################################################
sub client_recv_callback
{
    my ($self, $peer, $msg) = @_;

    # Support for simple clients with only one pending request and simple main loop
    if (defined $self->{waiting_for_eeid} && ($msg->eeid() == $self->{waiting_for_eeid}))
    {
	# This is the one we were waiting for
	$self->{found_reply} = $msg;
	delete $self->{waiting_for_eeid};
	$Radius::Select::exit_simple_main_loop = 1;
    }
    else
    {
	# Support for asynchronous clients, multiple pending requests
	my $eeid = $msg->eeid();
	my $ref = $self->{pendingRequests}{$eeid}; 
	if (!defined $ref)
	{
	    &main::log($main::LOG_WARNING, "Unknown reply received in DiaClient for request $eeid from $peer->{PeerOriginHost}");
	}
	else
	{
	    &main::log($main::LOG_DEBUG, "Received reply in DiaClient for req $eeid from $peer->{PeerOriginHost}");

	    # Cross it off our pending list
	    delete $self->{pendingRequests}{$eeid};
	    
	    # sp is the packet we forwarded to the remote diameter
	    # user_data was suplied to send_request
	    my ($sp, $user_data) = @$ref;

	    # Cross it of our timeout list
	    &Radius::Select::remove_timeout($sp->{noreplyTimeoutHandle})
		|| $self->log($main::LOG_ERR, "Timeout $sp->{noreplyTimeoutHandle} was not in the timeout list", $msg);

	    $self->handleReply($peer, $msg, $sp, $user_data);
	}
    }
}

#####################################################################
# Called by DiaPeer when a message is recived but not handled by superclass
sub handleReply
{
    my ($self, $peer, $msg, $sp, $user_data) = @_;

}

#####################################################################
# Handle the disconnection of the other end.
sub stream_disconnected
{
    my ($self) = @_;

    $self->SUPER::stream_disconnected();
    $self->{DiaPeer}->event('I-Peer-Disc');
}

#####################################################################
sub stream_client_connected
{
    my ($self) = @_;

    $self->SUPER::stream_client_connected();
    $self->{DiaPeer}->connect();
}

#####################################################################
# Called by DiaPeer when the connection is to be connected
sub connect
{
    my ($self) = @_;

    $self->stream_connect();
    return $self->{socket};
}

#####################################################################
# Called by DiaPeer when the connection is to be closed
sub close
{
    my ($self) = @_;

    return $self->stream_disconnected();
}

#####################################################################
sub hostipaddress
{
    my ($self) = @_;

    my ($port, $addr) = Radius::Util::unpack_sockaddr_in(getsockname($self->{socket}));
    return $addr;
}

#####################################################################
# Called by DiaPeer when an assembled message is to be sent
sub send
{
    my ($self, $msg) = @_;

    $self->write($msg);
}

#####################################################################
# Called when a complete request has been received
# Parse and process it
# Version has been checked
sub recv_diameter
{
    my ($self, $rec) = @_;

    # If we have already got our peer, use it.
    return $self->{DiaPeer}->i_recv_callback($self, $rec);

}

#####################################################################
# A serious stream error has occurred, log it and disconnect
sub stream_error
{
    my ($self, $msg) = @_;

    $self->SUPER::stream_error($msg);
    $self->{DiaPeer}->i_error_callback($self, $msg) if $self->{DiaPeer};
}

#####################################################################
# handle_noreply_timeout
# This is called from within Select::process_timeouts for each packet
# we have forwarded but not received a reply within the timeout period
# All we do is call the per-instance method for the instance that
# set the timeout. The args are the same as were passed to add_timeout
# fp is the packet we forwarded, $p is the original request packet, 
sub handle_noreply_timeout
{
    my ($handle, $self, $msg, $user_data) = @_;

    my $eeid = $msg->eeid();
    $self->log($main::LOG_INFO, "DiaClient: No reply from Diameter server for message $eeid", $msg);
    delete $self->{pendingRequests}{$eeid};
    $self->runHook('NoReplyHook', $msg, \$msg, $user_data);
}

#####################################################################
# Send a request and set up no reply and reply callbacks
# Returns the EEID
sub send_request
{
    my ($self, $msg, $user_data) = @_;

    $self->{DiaPeer}->send_request($msg);

    my $eeid = $msg->eeid();

    $self->{pendingRequests}{$eeid} = [$msg, $user_data];
    # Arrange for no reply timeout
    # We remember the timeout handle so we can remove 
    # it if we get a reply
    # Arrange for noreply retransmission timeout
    # We remember the timeout handle so we can remove 
    # it if we get a reply
    $msg->{noreplyTimeoutHandle} = 
	&Radius::Select::add_timeout
	(time + $self->{NoreplyTimeout},
	 \&handle_noreply_timeout,
	 $self, $msg, $user_data);
    return $eeid;
}

#####################################################################
# Simple client sending interface
sub sendAndWait
{
    my ($self, $msg) = @_;

    $self->send_request($msg);
    # Loop will be terminated when client_recv_callback
    # sees we have received a reply
    $self->{waiting_for_eeid} = $msg->eeid();
    &Radius::Select::simple_main_loop();
    return $self->{found_reply};
}
1;
