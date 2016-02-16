# DiaPeer.pm
#
# Implments the Diameter state machine described in RFC 3588
#
# Normally one of IConn or RConn is set to a Transport object, depending on whether this
# DiaPeer is an Initiator or a Responder.
#
# This object manages 1 or 2 Transport objects. Its possible for 
# a new incoming connection (IConn) to be assigned to a DiaPeer that is already managing an existing
# outgoing connection (RConn), in which case an Election occurs.
# 
# The watchdog timer code does not use StateMachine because DiaPeer already _is_ a 
# StateMachine, and in any case the code comes out neater (based on RFC 2539) with
# inline state switches.
#
# Part of the Radius project.
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2004 Open System Consultants
# $Id: DiaPeer.pm,v 1.13 2014/09/17 19:33:54 hvn Exp $

package Radius::DiaPeer;
use base ('Radius::StateMachine');
use Radius::DiaMsg;
use Radius::Select;
use strict;

# RCS version number of this module
$Radius::DiaPeer::VERSION = '$Revision: 1.13 $';

# Describes the Diameter Peer state machine
# This is a direct translation of the Peer state machine described in RFC3588
# current state        event                next state       transition func names
my %smspec =
(
 'Closed'        => {'Start'          => [ 'Wait-Conn-Ack', ['I_Snd_Conn_Req']],
	             'R-Conn-CER'     => [ 'R-Open',        ['R_Accept', 'Process_CER','R_Snd_CEA']]},
 'Wait-Conn-Ack' => {'I-Rcv-Conn-Ack' => [ 'Wait-I-CEA',    ['I_Snd_CER']],
	             'I-Rcv-Conn-Nack'=> [ 'Closed',        ['Cleanup']],
	             'R-Conn-CER'     => [ 'Wait-Conn-Ack-Elect', ['R_Accept', 'Process_CER']],
	             'Timeout'        => [ 'Closed',        ['Error']]},
 'Wait-I-CEA'    => {'I-Rcv-CEA'      => [ 'I-Open',        ['Process_CEA']],
	             'R-Conn-CER'     => [ 'Wait-Returns',  ['Accept', 'Process_CER', 'Elect']],
	             'I-Peer-Disc'    => [ 'Closed',        ['I_Disc']],
	             'I-Rcv-Non-CEA'  => [ 'Closed',        ['Error']],
	             'Timeout'        => [ 'Closed',        ['Error']]},
 'Wait-Conn-Ack-Elect' => { 'I-Rcv-Conn-Ack'  => [ 'Wait-Returns', ['I_Snd_CER', 'Elect']],
	             'I-Rcv-Conn-Nack'=> [ 'R-Open',        ['R_Snd_CEA']],
	             'R-Peer-Disc'    => [ 'Wait-Conn-Ack', ['R_Disc']],
	             'R-Conn-CER'     => [ 'Wait-Conn-Ack-Elect', ['R_Reject']],
	             'Timeout'        => [ 'Closed',        ['Error']]},
 'Wait-Returns'  => {'Win-Election'   => [ 'R-Open',        ['I_Disc', 'R_Snd_CEA']],
	             'I-Peer-Disc'    => [ 'R-Open',        ['I_Disc', 'R_Snd_CEA']],
	             'I-Rcv-CEA'      => [ 'I-Open',        ['R_Disc']],
	             'R-Peer-Disc'    => [ 'Wait-I-CEA',    ['R_Disc']],
	             'R-Conn-CER'     => [ 'Wait-Returns',  ['R_Reject']],
	             'Timeout'        => [ 'Closed',        ['Error']]},
 'R-Open'        => {'Send-Message'   => [ 'R-Open',        ['R_Snd_Message']],
	             'R-Rcv-Message'  => [ 'R-Open',        ['Process']],
	             'R-Rcv-DWR'      => [ 'R-Open',        ['Process_DWR', 'R_Snd_DWA']],
	             'R-Rcv-DWA'      => [ 'R-Open',        ['Process_DWA']],
	             'R-Conn-CER'     => [ 'R-Open',        ['R_Reject']],
	             'Stop'           => [ 'Closing',       ['R_Snd_DPR']],
	             'R-Rcv-DPR'      => [ 'Closed',        ['R_Snd_DPA', 'R_Disc']],
	             'R-Peer-Disc'    => [ 'Closed',        ['R_Disc']],
	             'R-Rcv-CER'      => [ 'R-Open',        ['R_Snd_CEA']],
	             'R-Rcv-CEA'      => [ 'R-Open',        ['Process_CEA']]},
 'I-Open'        => {'Send-Message'   => [ 'I-Open',        ['I_Snd_Message']],
	             'I-Rcv-Message'  => [ 'I-Open',        ['Process']],
	             'I-Rcv-DWR'      => [ 'I-Open',        ['Process_DWR', 'I_Snd_DWA']],
	             'I-Rcv-DWA'      => [ 'I-Open',        ['Process_DWA']],
	             'R-Conn-CER'     => [ 'I-Open',        ['R_Reject']],
	             'Stop'           => [ 'Closing',       ['I_Snd_DPR']],
	             'I-Rcv-DPR'      => [ 'Closed',        ['I_Snd_DPA', 'I_Disc']],
	             'I-Peer-Disc'    => [ 'Closed',        ['I_Disc']],
	             'I-Rcv-CER'      => [ 'I-Open',        ['I_Snd_CEA']],
	             'I-Rcv-CEA'      => [ 'I-Open',        ['Process_CEA']]},
 'Closing'       => {'I-Rcv-DPA'      => [ 'Closed',        ['I_Disc']],
	             'I-Rcv-DPA'      => [ 'Closed',        ['I_Disc']],
	             'Timeout'        => [ 'Closed',        ['Error']],
	             'I-Peer-Disc'    => [ 'Closed',        ['I_Disc']],
	             'R-Peer-Disc'    => [ 'Closed',        ['R_Disc']]},
    );

#####################################################################
sub new
{
    my ($class, @args) = @_;

    my $self = $class->SUPER::new(Spec => \%smspec, 
				  InitialState => 'Closed', 
				  Twinit => 30,
				  WatchdogState => 'INITIAL',
				  Trace => 0,
				  OriginHost => 'unknown',
				  OriginRealm => 'unknown',
				  PeerOriginHost => 'unknown',
				  PeerOriginRealm => 'unknown',
				  ProductName => 'Radiator',
				  ObjType => 'Radius::DiaPeer',
				  @args,
				  ChangeStateCallback => \&change_state);
    return $self;
}

#####################################################################
sub activate
{
    my ($self) = @_;
    
    $self->SUPER::activate();
    $self->{next_hhid} = 0;
    $self->setRConn($self->{RConn}) if $self->{RConn};
    $self->setIConn($self->{IConn}) if $self->{IConn};
    $self->setWatchdog();
}

#####################################################################
# Record a new incoming Responder connection.
sub setRConn
{
    my ($self, $connection) = @_;

    $self->{RConn} = $connection;
    $connection->set
	(RecvCallback => sub {$self->r_recv_callback(@_)},
	 ErrorCallback => sub {$self->r_error_callback(@_)});
}

#####################################################################
# Record a new Initiator connection.
sub setIConn
{
    my ($self, $connection) = @_;

    $self->{IConn} = $connection;
    $connection->set
	(RecvCallback => sub {$self->i_recv_callback(@_)},
	 ErrorCallback => sub {$self->i_error_callback(@_)});
}

#####################################################################
# Attempt to initiate a new connection to another peer
sub I_Snd_Conn_Req
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} I_Snd_Conn_Req ");
    my $s = $self->{IConn}->connect();
    $self->event($s ? 'I-Rcv-Conn-Ack' : 'I-Rcv-Conn-Nack');
}

#####################################################################
sub I_Accept
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} I_Accept");
}

#####################################################################
sub R_Accept
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} R_Accept");
}

#####################################################################
sub Process_CER
{
    my ($self) = @_;

    my $m = $self->{current_message};
    $self->{PeerOriginHost} = $m->get($Radius::DiaAttrList::ACODE_ORIGIN_HOST);
    $self->{PeerOriginRealm} = $m->get($Radius::DiaAttrList::ACODE_ORIGIN_REALM);
    @{$self->{PeerHostIPAddress}} = $m->get($Radius::DiaAttrList::ACODE_HOST_IP_ADDRESS);
    $self->{PeerVendorId} = $m->get($Radius::DiaAttrList::ACODE_VENDOR_ID);
    $self->{PeerProductName} = $m->get($Radius::DiaAttrList::ACODE_PRODUCT_NAME);
    @{$self->{PeerSupportedVendorId}} = $m->get($Radius::DiaAttrList::ACODE_SUPPORTED_VENDOR_ID);
    $self->{PeerFirmwareRevision} = $m->get($Radius::DiaAttrList::ACODE_FIRMWARE_REVISION);
    $self->log($main::LOG_DEBUG, "Process_CER $self->{OriginHost} got $self->{PeerOriginHost} $self->{PeerOriginRealm}");
}

#####################################################################
sub Process_CEA
{
    my ($self) = @_;

    my $m = $self->{current_message};
    $self->{PeerOriginHost} = $m->get($Radius::DiaAttrList::ACODE_ORIGIN_HOST);
    $self->{PeerOriginRealm} = $m->get($Radius::DiaAttrList::ACODE_ORIGIN_REALM);
    @{$self->{PeerHostIPAddress}} = $m->get($Radius::DiaAttrList::ACODE_HOST_IP_ADDRESS);
    $self->{PeerVendorId} = $m->get($Radius::DiaAttrList::ACODE_VENDOR_ID);
    $self->{PeerProductName} = $m->get($Radius::DiaAttrList::ACODE_PRODUCT_NAME);
    @{$self->{PeerSupportedVendorId}} = $m->get($Radius::DiaAttrList::ACODE_SUPPORTED_VENDOR_ID);
    $self->{PeerFirmwareRevision} = $m->get($Radius::DiaAttrList::ACODE_FIRMWARE_REVISION);
    $self->log($main::LOG_DEBUG, "Process_CEA $self->{OriginHost} got $self->{PeerOriginHost} $self->{PeerOriginRealm}");
}

#####################################################################
sub I_Snd_CER
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} I_Snd_CER");
    $self->Snd_CER($self->{IConn});
}

#####################################################################
sub R_Snd_CER
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} R_Snd_CER");
    $self->Snd_CER($self->{RConn});
}

#####################################################################
sub Snd_CER
{
    my ($self, $conn) = @_;

    my $m = Radius::DiaMsg->new_request
	(Code => $Radius::DiaMsg::CODE_CER,
	 Flags => $Radius::DiaMsg::FLAG_REQUEST,
	 Dictionary => $self->{Dictionary},
	 Hhid => $self->next_hhid());
    $m->add_attr($Radius::DiaAttrList::ACODE_ORIGIN_HOST, 0,
		 $Radius::DiaAttrList::AFLAG_MANDATORY, $self->{OriginHost});
    $m->add_attr($Radius::DiaAttrList::ACODE_ORIGIN_REALM, 0,
		 $Radius::DiaAttrList::AFLAG_MANDATORY, $self->{OriginRealm});
    foreach ($conn->hostipaddress())
    {
	$m->add_attr($Radius::DiaAttrList::ACODE_HOST_IP_ADDRESS, 0,
		     $Radius::DiaAttrList::AFLAG_MANDATORY, $_);
    }
    $m->add_attr($Radius::DiaAttrList::ACODE_PRODUCT_NAME, 0, 
		 0, $self->{ProductName});
    $m->add_attr($Radius::DiaAttrList::ACODE_VENDOR_ID, 0,
		 $Radius::DiaAttrList::AFLAG_MANDATORY, $self->{VendorId} || 9048);

    $m->add_attr($Radius::DiaAttrList::ACODE_FIRMWARE_REVISION, 0, 
		    $Radius::DiaAttrList::AFLAG_NULL, $self->{FirmwareRevision} || 1);
    foreach (@{$self->{SupportedVendorIds}})
    {
	$m->add_attr($Radius::DiaAttrList::ACODE_SUPPORTED_VENDOR_ID, 0, 
		     $Radius::DiaAttrList::AFLAG_MANDATORY, $_);
    }
    foreach (@{$self->{AuthApplicationIds}})
    {
	$m->add_attr($Radius::DiaAttrList::ACODE_AUTH_APPLICATION_ID, 0, 
		     $Radius::DiaAttrList::AFLAG_MANDATORY, $_);
    }
    foreach (@{$self->{AcctApplicationIds}})
    {
	$m->add_attr($Radius::DiaAttrList::ACODE_ACCT_APPLICATION_ID, 0, 
		     $Radius::DiaAttrList::AFLAG_MANDATORY, $_);
    }
    foreach (@{$self->{InbandSecurityIds}})
    {
	$m->add_attr($Radius::DiaAttrList::ACODE_INBAND_SECURITY_ID, 0, 
		     $Radius::DiaAttrList::AFLAG_MANDATORY, $_);
    }
    foreach my $authid (@{$self->{VendorAuthApplicationIds}})
    {
	my $g = Radius::DiaAttrList->new();
	$g->add_attr($Radius::DiaAttrList::ACODE_VENDOR_ID, 0,
		     $Radius::DiaAttrList::AFLAG_MANDATORY,
		     $authid->[0]);
	$g->add_attr($Radius::DiaAttrList::ACODE_AUTH_APPLICATION_ID, 0,
		     $Radius::DiaAttrList::AFLAG_MANDATORY,
		     $authid->[1]);
	$m->add_attr($Radius::DiaAttrList::ACODE_VENDOR_SPECIFIC_APPLICATION_ID, 0, 
		     $Radius::DiaAttrList::AFLAG_MANDATORY,
		     $g);
    }
    foreach my $acctid (@{$self->{VendorAcctApplicationIds}})
    {
	my $g = Radius::DiaAttrList->new();
	$g->add_attr($Radius::DiaAttrList::ACODE_VENDOR_ID, 0,
		     $Radius::DiaAttrList::AFLAG_MANDATORY,
		     $acctid->[0]);
	$g->add_attr($Radius::DiaAttrList::ACODE_ACCT_APPLICATION_ID, 0,
		     $Radius::DiaAttrList::AFLAG_MANDATORY,
		     $acctid->[1]);
	$m->add_attr($Radius::DiaAttrList::ACODE_VENDOR_SPECIFIC_APPLICATION_ID, 0, 
		     $Radius::DiaAttrList::AFLAG_MANDATORY,
		     $g);
    }
    $self->send_msg($m, $conn);
}

#####################################################################
sub I_Snd_CEA
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} I_Snd_CEA");
    $self->Snd_CEA($self->{RConn});
}

#####################################################################
sub R_Snd_CEA
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} R_Snd_CEA");
    $self->Snd_CEA($self->{RConn});
}

#####################################################################
sub Snd_CEA
{
    my ($self, $conn) = @_;

    my $m = $self->{current_message}->new_reply();
    $m->add_attr($Radius::DiaAttrList::ACODE_RESULT_CODE, 0,
		 $Radius::DiaAttrList::AFLAG_MANDATORY, 
		 $Radius::DiaAttrList::RESULT_CODE_DIAMETER_SUCCESS);
    $m->add_attr($Radius::DiaAttrList::ACODE_ORIGIN_HOST, 0,
		 $Radius::DiaAttrList::AFLAG_MANDATORY, $self->{OriginHost});
    $m->add_attr($Radius::DiaAttrList::ACODE_ORIGIN_REALM, 0,
		 $Radius::DiaAttrList::AFLAG_MANDATORY, $self->{OriginRealm});
    foreach ($conn->hostipaddress())
    {
	$m->add_attr($Radius::DiaAttrList::ACODE_HOST_IP_ADDRESS, 0,
		     $Radius::DiaAttrList::AFLAG_MANDATORY, $_);
    }
    $m->add_attr($Radius::DiaAttrList::ACODE_PRODUCT_NAME, 0, 
		 0, $self->{ProductName});
    $m->add_attr($Radius::DiaAttrList::ACODE_VENDOR_ID, 0,
		 $Radius::DiaAttrList::AFLAG_MANDATORY, $self->{VendorId} || 9048);
    $m->add_attr($Radius::DiaAttrList::ACODE_FIRMWARE_REVISION, 0, 
		 $Radius::DiaAttrList::AFLAG_NULL, $self->{FirmwareRevision} || 1);
    foreach (@{$self->{SupportedVendorIds}})
    {
	$m->add_attr($Radius::DiaAttrList::ACODE_SUPPORTED_VENDOR_ID, 0, 
		     $Radius::DiaAttrList::AFLAG_MANDATORY, $_);
    }
    foreach (@{$self->{AuthApplicationIds}})
    {
	$m->add_attr($Radius::DiaAttrList::ACODE_AUTH_APPLICATION_ID, 0, 
		     $Radius::DiaAttrList::AFLAG_MANDATORY, $_);
    }
    foreach (@{$self->{AcctApplicationIds}})
    {
	$m->add_attr($Radius::DiaAttrList::ACODE_ACCT_APPLICATION_ID, 0, 
		     $Radius::DiaAttrList::AFLAG_MANDATORY, $_);
    }
    foreach (@{$self->{InbandSecurityIds}})
    {
	$m->add_attr($Radius::DiaAttrList::ACODE_INBAND_SECURITY_ID, 0, 
		     $Radius::DiaAttrList::AFLAG_MANDATORY, $_);
    }
    foreach my $authid (@{$self->{VendorAuthApplicationIds}})
    {
	my $g = Radius::DiaAttrList->new();
	$g->add_attr($Radius::DiaAttrList::ACODE_VENDOR_ID, 0,
		     $Radius::DiaAttrList::AFLAG_MANDATORY,
		     $authid->[0]);
	$g->add_attr($Radius::DiaAttrList::ACODE_AUTH_APPLICATION_ID, 0,
		     $Radius::DiaAttrList::AFLAG_MANDATORY,
		     $authid->[1]);
	$m->add_attr($Radius::DiaAttrList::ACODE_VENDOR_SPECIFIC_APPLICATION_ID, 0, 
		     $Radius::DiaAttrList::AFLAG_MANDATORY,
		     $g);
    }
    foreach my $acctid (@{$self->{VendorAcctApplicationIds}})
    {
	my $g = Radius::DiaAttrList->new();
	$g->add_attr($Radius::DiaAttrList::ACODE_VENDOR_ID, 0,
		     $Radius::DiaAttrList::AFLAG_MANDATORY,
		     $acctid->[0]);
	$g->add_attr($Radius::DiaAttrList::ACODE_ACCT_APPLICATION_ID, 0,
		     $Radius::DiaAttrList::AFLAG_MANDATORY,
		     $acctid->[1]);
	$m->add_attr($Radius::DiaAttrList::ACODE_VENDOR_SPECIFIC_APPLICATION_ID, 0, 
		     $Radius::DiaAttrList::AFLAG_MANDATORY,
		     $g);
    }

# For Arthur?
#    my $group = new Radius::DiaAttrList;
#    $group->add_attr($Radius::DiaAttrList::ACODE_VENDOR_ID, 0,
#		     $Radius::DiaAttrList::AFLAG_MANDATORY, 0);
#    $group->add_attr($Radius::DiaAttrList::ACODE_AUTH_APPLICATION_ID, 0,
#		     $Radius::DiaAttrList::AFLAG_MANDATORY, 0x01000000);
#    $m->add_attr($Radius::DiaAttrList::ACODE_VENDOR_SPECIFIC_APPLICATION_ID, 0,
#		 $Radius::DiaAttrList::AFLAG_MANDATORY, $group);
    $self->send_msg($m, $conn);
}

#####################################################################
sub Cleanup
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} Cleanup");
    $self->{IConn}->close() if $self->{IConn};
    $self->{RConn}->close() if $self->{RConn};
}

#####################################################################
sub Error
{
    my ($self) = @_;

    $self->log($main::LOG_ERR, "$self->{OriginHost} $self->{PeerOriginHost} DiaPeer Error: $self->{last_error}");
    $self->Cleanup();
}

#####################################################################
sub Elect
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} Elect, comparing with $self->{PeerOriginHost}");
    # Compare the OriginHost we received in the other peers CER with our
    # own OriginHost. 
    $self->event('Win-Election')
	if $self->{OriginHost} > $self->{PeerOriginHost};
}

#####################################################################
sub I_Disc
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} I_Disc");
    $self->{IConn}->close();
}

#####################################################################
sub R_Disc
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} R_Disc");
    $self->{RConn}->close();
}

#####################################################################
sub R_Reject
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} R_Reject");
    $self->{RConn}->close();
}

#####################################################################
sub I_Snd_Message
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} I_Snd_Message");
    # Send the pending messages from the message queue
    $self->send_next_msg($self->{IConn});
}

#####################################################################
sub R_Snd_Message
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} R_Snd_Message");
    # Send the pending messages from the message queue
    $self->send_next_msg($self->{RConn});
}

#####################################################################
sub Process
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} Process");

    # See if we need to make a reply callback
    my $msg = $self->{current_message};
    if (!($msg->flags() & $Radius::DiaMsg::FLAG_REQUEST))
    {
	# Its a reply, see if we are waiting for it
	# Make sure we dont autovivify
	my $hhid = $msg->hhid();
	if (exists $self->{pending}{$hhid})
	{
	    my ($request, $callback) = @{$self->{pending}{$hhid}};
	    delete $self->{pending}{$hhid};
	    &$callback($self, $request, $msg) if $callback;
	}
	else
	{
	    $self->log($main::LOG_ERR, "Received a reply from $self->{PeerOriginHost}, but no matching request. Ignored");
	}
    }
    &{$self->{RecvMessageCallback}}($self, $msg)
	if $self->{RecvMessageCallback};
}

#####################################################################
sub Process_DWR
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} Process_DWR");
}

#####################################################################
sub Snd_DWR
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} Snd_DWR");
    my $m = Radius::DiaMsg->new_request
	(Code => $Radius::DiaMsg::CODE_DWR,
	 Flags => $Radius::DiaMsg::FLAG_REQUEST,
	 Dictionary => $self->{Dictionary},
	 Hhid => $self->next_hhid());
    $m->add_attr($Radius::DiaAttrList::ACODE_ORIGIN_HOST, 0,
		 $Radius::DiaAttrList::AFLAG_MANDATORY, $self->{OriginHost});
    $m->add_attr($Radius::DiaAttrList::ACODE_ORIGIN_REALM, 0,
		 $Radius::DiaAttrList::AFLAG_MANDATORY, $self->{OriginRealm});
    $self->send_msg($m, $self->{RConn} || $self->{IConn});
}

#####################################################################
sub I_Snd_DWA
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} I_Snd_DWA");
    $self->Snd_DWA($self->{IConn});
}

#####################################################################
sub R_Snd_DWA
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} R_Snd_DWA");
    $self->Snd_DWA($self->{RConn});
}

#####################################################################
sub Snd_DWA
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} Snd_DWA");
    my $m = $self->{current_message}->new_reply();
    $m->add_attr($Radius::DiaAttrList::ACODE_ORIGIN_HOST, 0,
		 $Radius::DiaAttrList::AFLAG_MANDATORY, $self->{OriginHost});
    $m->add_attr($Radius::DiaAttrList::ACODE_ORIGIN_REALM, 0,
		 $Radius::DiaAttrList::AFLAG_MANDATORY, $self->{OriginRealm});
    $m->add_attr($Radius::DiaAttrList::ACODE_RESULT_CODE, 0,
		 $Radius::DiaAttrList::AFLAG_MANDATORY, 
		 $Radius::DiaAttrList::RESULT_CODE_DIAMETER_SUCCESS);
    $self->send_msg($m, $self->{RConn} || $self->{IConn});
}

#####################################################################
sub Process_DWA
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} Process_DWA");
    my $m = $self->{current_message};
    $self->{PeerResultCode} = $m->get($Radius::DiaAttrList::ACODE_RESULT_CODE);
    $self->{PeerErrorMessage} = $m->get($Radius::DiaAttrList::ACODE_ERROR_MESSAGE);
}

#####################################################################
sub I_Snd_DPR
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} I_Snd_DPR");
    $self->Snd_DPR($self->{IConn});
}

#####################################################################
sub R_Snd_DPR
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} R_Snd_DPR");
    $self->Snd_DPR($self->{RConn});
}

#####################################################################
sub Snd_DPR
{
    my ($self, $conn) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} Snd_DPR");
    my $m = Radius::DiaMsg->new_request
	(Code => $Radius::DiaMsg::CODE_DPR,
	 Flags => $Radius::DiaMsg::FLAG_REQUEST,
	 Dictionary => $self->{Dictionary},
	 Hhid => $self->next_hhid());
    $m->add_attr($Radius::DiaAttrList::ACODE_ORIGIN_HOST, 0,
		 $Radius::DiaAttrList::AFLAG_MANDATORY, $self->{OriginHost});
    $m->add_attr($Radius::DiaAttrList::ACODE_ORIGIN_REALM, 0,
		 $Radius::DiaAttrList::AFLAG_MANDATORY, $self->{OriginRealm});
    $m->add_attr($Radius::DiaAttrList::ACODE_DISCONNECT_CAUSE, 0,
		 $Radius::DiaAttrList::AFLAG_MANDATORY, $self->{disconnect_cause});
    $self->send_msg($m, $conn);
}

#####################################################################
sub I_Snd_DPA
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} I_Snd_DPA");
    $self->Snd_DPA($self->{IConn});
}

#####################################################################
sub R_Snd_DPA
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} R_Snd_DPA");
    $self->Snd_DPA($self->{RConn});
}

#####################################################################
sub Snd_DPA
{
    my ($self, $conn) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} Snd_DPA");
    # REVISIT: this only happens after receiving a DPR, do 
    # we need to save any data from the DPR?
    my $m = $self->{current_message}->new_reply();
    $m->add_attr($Radius::DiaAttrList::ACODE_ORIGIN_HOST, 0,
		 $Radius::DiaAttrList::AFLAG_MANDATORY, $self->{OriginHost});
    $m->add_attr($Radius::DiaAttrList::ACODE_ORIGIN_REALM, 0,
		 $Radius::DiaAttrList::AFLAG_MANDATORY, $self->{OriginRealm});
    $m->add_attr($Radius::DiaAttrList::ACODE_RESULT_CODE, 0,
		 $Radius::DiaAttrList::AFLAG_MANDATORY, 
		 $Radius::DiaAttrList::RESULT_CODE_DIAMETER_SUCCESS);
    # If there was an error, need to append ERROR_MESSAGE, too
    $self->send_msg($m, $conn);
}

#####################################################################
# Full message received from IConn
sub i_recv_callback
{
    my ($self, $connection, $msg) = @_;

    $self->recv($msg, 'I-');
}

#####################################################################
# Full message received from RConn
sub r_recv_callback
{
    my ($self, $connection, $msg) = @_;

    $self->recv($msg, 'R-');
}

#####################################################################
# Error received from IConn
sub i_error_callback
{
    my ($self, $connection, $msg) = @_;

    $self->event('I-Peer-Disc');
}

#####################################################################
# Error received from RConn
sub r_error_callback
{
    my ($self, $connection, $msg) = @_;

    $self->event('R-Peer-Disc');
}

#####################################################################
sub error
{
    my ($self, $msg) = @_;
    
    $self->{last_error} = $msg;
    $self->Error();
}

#####################################################################
# Called with a complete message received by Transport, as defined by the leading octet count
sub recv
{
    my ($self, $msg, $role) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} DiaPeer::recv");
    my ($verslen) = unpack('N', $msg);
    my $version = $verslen >> 24;
    if ($version == 1)
    {
	my $length = $verslen & 0xffffff;
	if ($length < 20)
	{
	    $self->error("Invalid Diameter messsage length $length received. Disconnecting");
	}
	else
	{
	    $self->recv_v1msg($msg, $role);
	}
    }
    else
    {
	# Unknown version number bail out 
	$self->error("Unknown Diameter version number $version received");
    }
}


#####################################################################
# Called when a complete Diameter version 1 message (according to the 
# message length counts) has been received. Find out what sort
# it is and prod the state machine.
sub recv_v1msg
{
    my ($self, $msg, $role) = @_;

    my $p = Radius::DiaMsg->new
	(Data => $msg,
	 Dictionary => $self->{Dictionary});
    $self->{current_message} = $p;
    return unless $p;

    # These are expensive, only do them if necessary
    if (main::willLog($main::LOG_DEBUG, $p))
    {
	$self->log($main::LOG_EXTRA_DEBUG, "$self->{OriginHost} <- $self->{PeerOriginHost} recv_v1msg raw data: " . unpack('H*', $msg))
	    if main::willLog($main::LOG_EXTRA_DEBUG, $p);
	$self->log($main::LOG_DEBUG, "$self->{OriginHost} <- $self->{PeerOriginHost} recv_v1msg:\n" . $p->format());
    }

    my $code = $p->code();
    my $flags = $p->flags();
    my $isreq = $flags & $Radius::DiaMsg::FLAG_REQUEST; # This is a request

    # First check the watchdog state, and see if we have to throw it away
    if ($self->{WatchdogState} eq 'OKAY')
    {
	$self->setWatchdog();
    }
    elsif ($self->{WatchdogState} eq 'SUSPECT')
    {
	$self->{WatchdogState} = 'OKAY';
	$self->failback();
	$self->setWatchdog();
    }
    elsif ($self->{WatchdogState} eq 'REOPEN')
    {
	if ($code == $Radius::DiaMsg::CODE_DWR && !$isreq) # its a DWA
	{
	    $self->{numDWA}++;
	    if ($self->{numDWA} >= 3)
	    {
		$self->{WatchdogState} = 'OKAY';
		$self->failback();
	    }
	}
    }

    if (($code != $Radius::DiaMsg::CODE_CER || $isreq) && $self->state() eq 'Wait-I-CEA' )
    {
	$self->event("${role}Rcv-Non-CEA");
    }
    elsif ($code == $Radius::DiaMsg::CODE_CER && $isreq)
    {
	$self->event("${role}Rcv-CER");
    }
    elsif ($code == $Radius::DiaMsg::CODE_CER && !$isreq)
    {
	$self->event("${role}Rcv-CEA");
    }
    elsif ($code == $Radius::DiaMsg::CODE_DPR && $isreq)
    {
	$self->event("${role}Rcv-DPR");
    }
    elsif ($code == $Radius::DiaMsg::CODE_DPR && !$isreq)
    {
	$self->event("${role}Rcv-DPA");
    }
    elsif ($code == $Radius::DiaMsg::CODE_DWR && $isreq)
    {
	$self->event("${role}Rcv-DWR");
    }
    elsif ($code == $Radius::DiaMsg::CODE_DWR && !$isreq)
    {
	$self->{WatchdogPending} = 0;
	$self->event("${role}Rcv-DWA");
    }
    else
    {
	$self->event("${role}Rcv-Message");
    }
}

#####################################################################
sub next_hhid
{    
    my ($self) = @_;

    return $self->{next_hhid}++;
}

#####################################################################
sub send_request
{
    my ($self, $msg, $callback) = @_;

    my $hhid = $self->next_hhid();
    $msg->set_hhid($hhid);
    # We maintain pending (unreplied) messages in a hash by hop-to-hop id,
    $self->{pending}{$hhid} = [$msg, $callback];
    # and also a list of unsent message in transmission order
    push(@{$self->{queue}}, $msg);
    $self->send($msg);
}

#####################################################################
sub send_reply
{
    my ($self, $msg) = @_;

    # Add to the list of unsent message in transmission order
    push(@{$self->{queue}}, $msg);
    $self->send($msg);
}

#####################################################################
sub send
{
    my ($self, $msg) = @_;

    $self->event('Send-Message');
}

#####################################################################
# Immediately send the DiaMsg passed in
# The message is packed into wire form and passed the the connection 
# for transmission
sub send_msg
{
    my ($self, $msg, $conn) = @_;

    return unless $conn; # prevent silly crashes during testing
    my $data = $msg->assemble();

    # These are expensive, only do them if necessary
    if (main::willLog($main::LOG_DEBUG))
    {
	$self->log($main::LOG_EXTRA_DEBUG, "$self->{OriginHost} -> $self->{PeerOriginHost} send_msg raw data: " . unpack('H*', $data))
	    if main::willLog($main::LOG_EXTRA_DEBUG);
	$self->log($main::LOG_DEBUG, "$self->{OriginHost} -> $self->{PeerOriginHost} send_msg:\n" . $msg->format());
    }

    $conn->send($data);
}

#####################################################################
# Send the next message in the mesage queue.
sub send_next_msg
{
    my ($self, $conn) = @_;

    # Get the next message to send
    my $msg;
    while ($msg = shift(@{$self->{queue}}))
    {
	$self->send_msg($msg, $conn);
    }
}

#####################################################################
sub change_state
{
    my ($self, $oldstate, $newstate) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} change_state, $oldstate -> $newstate\n");
    
    $self->connectionUp() if $newstate eq 'I-Open' || $newstate eq 'R-Open' ;
    $self->connectionDown() if $newstate eq 'Closed';
}

#####################################################################
# Called when a peer connection changes to Open
sub connectionUp
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} -> $self->{PeerOriginHost} DiaPeer: connectionUp WatchdogState $self->{WatchdogState}");
    if ($self->{WatchdogState} eq 'INITIAL')
    {
	$self->{WatchdogState} = 'OKAY';
	$self->setWatchdog();
    }
    elsif ($self->{WatchdogState} eq 'DOWN')
    {
	$self->{WatchdogState} = 'REOPEN';
	$self->{numDWA} = 0;
	$self->Snd_DWR();
	$self->setWatchdog();
	$self->{WatchdogPending}++;
    }

    if ($self->{UseTLS})
    {
	if (!$Radius::TLS::initialised)
	{
	    $self->error('Cant UseTLS: TLS subsystem has not been properly intialised');
	    return;
	}
#	Radius::StreamTLS::start_server($self->{RConn}, $self->{RConn}, $self->{PeerOriginHost})
#	    if $self->{State} eq 'R-Open';
#	Radius::StreamTLS::start_client($self->{IConn}, $self->{IConn}, $self->{PeerOriginHost})
#	    if $self->{State} eq 'I-Open';
    }

    # Send the next message from the message queue
    $self->send_next_msg($self->{RConn}) if $self->{State} eq 'R-Open';
    $self->send_next_msg($self->{IConn}) if $self->{State} eq 'I-Open';

    &{$self->{TransportUpCallback}}($self)
	if $self->{TransportUpCallback};
}

#####################################################################
# Called when a peer connection changes to Closed
sub connectionDown
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} -> $self->{PeerOriginHost} DiaPeer: connectionDown WatchdogState $self->{WatchdogState}");
    # Manage watchdog state 
    if ($self->{WatchdogState} eq 'OKAY')
    {
	$self->failover();
	$self->setWatchdog();
    }
    elsif ($self->{WatchdogState} eq 'SUSPECT' || $self->{WatchdogState} eq 'REOPEN')
    {
	$self->setWatchdog();
    }
    $self->{WatchdogState} = 'DOWN';

    # Call clients routines
    &{$self->{TransportDownCallback}}($self)
	if $self->{TransportDownCallback};
}

#####################################################################
sub setWatchdog
{
    my ($self) = @_;

    # Calculate random timeout
    $self->{tw} = $self->{Twinit} + 5 + int rand(5);
    &Radius::Select::remove_timeout($self->{watchdog_timer})
	if $self->{watchdog_timer};
    $self->{watchdog_timer} = &Radius::Select::add_timeout
	(time + $self->{tw}, \&watchdogElapsed, $self);
}

#####################################################################
sub watchdogElapsed
{
    my ($handle, $self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} $self->{PeerOriginHost} DiaPeer: watchdogElapsed WatchdogState $self->{WatchdogState}");
    if ($self->{WatchdogState} eq 'OKAY')
    {
	if (!$self->{WatchdogPending})
	{
	    $self->Snd_DWR();
	    $self->setWatchdog();
	    $self->{WatchdogPending}++;
	}
	else
	{
	    $self->{WatchdogState} = 'SUSPECT';
	    $self->failover();
	    $self->setWatchdog();
	}
    }
    elsif ($self->{WatchdogState} eq 'SUSPECT')
    {
	$self->{WatchdogState} = 'DOWN';
	$self->Cleanup();
	$self->setWatchdog();
    }
    # DOWN and INITIAL are treated differently to recover better from
    # unresponsive but open TCP connections.
    elsif ($self->{WatchdogState} eq 'DOWN')
    {
	$self->Error() if $self->{IConn};
	$self->connect() if $self->{IConn};
	$self->setWatchdog();
    }
    elsif ($self->{WatchdogState} eq 'INITIAL')
    {
	$self->Error() if $self->{IConn};
	$self->connect() if $self->{IConn};
	$self->{WatchdogState} = 'INITIAL' if $self->{IConn};
	$self->setWatchdog();
    }
    elsif ($self->{WatchdogState} eq 'REOPEN')
    {
	if (!$self->{WatchdogPending})
	{
	    $self->Snd_DWR();
	    $self->{WatchdogPending}++;
	}
	elsif ($self->{numDWA} < 0)
	{
	    $self->{WatchdogState} = 'DOWN';
	    $self->Cleanup();
	}
	else
	{
	    $self->{numDWA} = -1;
	}
	$self->setWatchdog();
    }
}

#####################################################################
sub failback
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} $self->{PeerOriginHost} failback");
    &{$self->{FailBackCallback}}($self)
	if $self->{FailBackCallback};
}

#####################################################################
sub failover
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "$self->{OriginHost} $self->{PeerOriginHost} failover");
    &{$self->{FailOverCallback}}($self)
	if $self->{FailOverCallback};
}

#####################################################################
sub connect
{
    my ($self) = @_;

    $self->event('Start');
}

#####################################################################
sub stop
{
    my ($self, $disconnect_cause) = @_;
    $self->{disconnect_cause} = $disconnect_cause;
    $self->event('Stop');
}

#####################################################################
# Force cleanup and destruction of this peer object
# The main issue here is removing any reference loops
# After the last ref loop disappears (and any refs held by parents,
# then DESTROY will be called automatically (if present)
sub destroy
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "DiaPeer $self->{OriginHost} $self->{PeerOriginHost} destroy");
    &Radius::Select::remove_timeout($self->{watchdog_timer})
	if $self->{watchdog_timer};

    # Remove this entry from the peers table
    $self->delete();
    return;
}


#####################################################################
# Find a suitable peer to send a message to. Match PeerOriginHost
# and/or PeerOriginRealm
sub find
{
    return Radius::Configurable::find('Radius::DiaPeer', @_);
}

1;
