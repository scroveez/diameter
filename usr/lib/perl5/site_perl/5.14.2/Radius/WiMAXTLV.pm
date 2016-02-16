# WiMAXTLV.pm
#
# Module for packing and unpacking WiMAX TLVs as per
# WiMAX_End-to-End_Network_Systems_Architecture_Stage_2-3_Release_1.1.0, 
#  NWG_R1.1.0-Stage-3.pdf
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2007 Open System Consultants
# $Id: WiMAXTLV.pm,v 1.4 2008/10/14 22:53:14 mikem Exp $

package Radius::WiMAXTLV;
use strict;

# RCS version number of this module
$Radius::WiMAXTLV::VERSION = '$Revision: 1.4 $';

#####################################################################
# Symbolic contants for WiMAX TLVs
# WiMAX-Capability
$Radius::WiMAXTLV::CAPABILITY_RELEASE                             = 1;
$Radius::WiMAXTLV::CAPABILITY_ACCOUNTING_CAPABILITIES             = 2;
$Radius::WiMAXTLV::CAPABILITY_HOTLINING_CAPABILITIES              = 3;
$Radius::WiMAXTLV::CAPABILITY_IDLE_MODE_NOTIFICATION_CAPABILITIES = 4;

# Accounting capabilities
$Radius::WiMAXTLV::CAPABILITY_ACCOUNTING_IP_SESSION               = 0x01;
$Radius::WiMAXTLV::CAPABILITY_ACCOUNTING_FLOW                     = 0x02;

# Hotlining capability flags:
$Radius::WiMAXTLV::CAPABILITY_HOTLINE_PROFILE                     = 0x01;
$Radius::WiMAXTLV::CAPABILITY_HOTLINE_RULE                        = 0x02;
$Radius::WiMAXTLV::CAPABILITY_HOTLINE_HTTP_REDIRECTION            = 0x04;
$Radius::WiMAXTLV::CAPABILITY_HOTLINE_IP_REDIRECTION              = 0x08;

# Idle-Mode notification capabilities
$Radius::WiMAXTLV::CAPABILITY_IDLE_MODE_NOTIFICATION              = 0x01;

# QoS-Descriptor TLVs
$Radius::WiMAXTLV::QOSD_ID                                        = 1;
$Radius::WiMAXTLV::QOSD_GLOBAL_SERVICE_CLASS_NAME                 = 2;
$Radius::WiMAXTLV::QOSD_SERVICE_CLASS_NAME                        = 3;
$Radius::WiMAXTLV::QOSD_SCHEDULE_TYPE                             = 4;
$Radius::WiMAXTLV::QOSD_TRAFFIC_PRIORITY                          = 5;
$Radius::WiMAXTLV::QOSD_MAX_SUSTAINED_TRAFFIC_RATE                = 6;
$Radius::WiMAXTLV::QOSD_MIN_RESERVED_TRAFFIC_RATE                 = 7;
$Radius::WiMAXTLV::QOSD_MAX_TRAFFIC_BURST                         = 8;
$Radius::WiMAXTLV::QOSD_TOLERATED_JITTER                          = 9;
$Radius::WiMAXTLV::QOSD_MAX_LATENCY                               = 10;
$Radius::WiMAXTLV::QOSD_REDUCED_RESOURCES_CODE                    = 11;
$Radius::WiMAXTLV::QOSD_MEDIA_FLOW_TYPE                           = 12;
$Radius::WiMAXTLV::QOSD_UNSOLICITED_GRANT_INTERVAL                = 13;
$Radius::WiMAXTLV::QOSD_SDU_SIZE                                  = 14;
$Radius::WiMAXTLV::QOSD_UNSOLICITED_POLLING_INTERVAL              = 15;

# Packet-Flow-Descriptor TLVs
$Radius::WiMAXTLV::PFD_PACKET_DATA_FLOW_ID                        = 1;
$Radius::WiMAXTLV::PFD_SERVICE_DATA_FLOW_ID                       = 2;
$Radius::WiMAXTLV::PFD_SERVICE_PROFILE_ID                         = 3;
$Radius::WiMAXTLV::PFD_DIRECTION                                  = 4;
$Radius::WiMAXTLV::PFD_ACTIVATION_TRIGGER                         = 5;
$Radius::WiMAXTLV::PFD_TRANSPORT_TYPE                             = 6;
$Radius::WiMAXTLV::PFD_UPLINK_QOS_ID                              = 7;
$Radius::WiMAXTLV::PFD_DOWNLINK_QOS_ID                            = 8;
$Radius::WiMAXTLV::PFD_UPLINK_CLASSIFIER                          = 9;
$Radius::WiMAXTLV::PFD_DOWNLINK_CLASSIFIER                        = 10;

#####################################################################
sub new
{
    my ($class, $s) = @_;

    my $self = {};
    bless $self, $class;

    @{$self->{Attributes}} = (); # Define an empty array
    $self->parse($s) if defined $s;

    return $self;
}

#####################################################################
# Returns a list of unknown mandatory attributes that were present
sub parse
{
    my ($self, $data) = @_;

    # Unpack PAC packets
    while (length $data) 
    {
	my ($type, $length) = unpack 'C C', $data;
	my $datalength = $length - 2;
	my ($val) = unpack("x2 a$datalength", $data);

	$self->add($type, $val);

	# Remove the attribute we just parsed. 
	$data = substr($data, $length);
    }
}

#####################################################################
sub add
{
    my ($self, $type, $val) = @_;

    push(@{$self->{Attributes}}, [ $type, $val ]);
}

#####################################################################
# Gets the values of the named attribute.
# In list context, returns an array of values in the same order
# In scalar context, returns the value of the first matching attr
# returns undef if no matching attrs found
sub get
{
    my ($self, $type) = @_;

    return map {$_->[0] == $type ? $_->[1] : ()} @{$self->{Attributes}}
        if wantarray;

    map {return $_->[1] if ($_->[0] == $type)} @{$self->{Attributes}};
    return; # Not found
}

#####################################################################
# Pack a single TLV
sub pack_one
{
    my ($type, $val) = @_;

    return pack('C C a*', $type, length($val)+2, $val);
}

#####################################################################
# Pack all the attributes into a TLV string and return it
sub pack
{
    my ($self) = @_;

    my $ret;
    map {$ret .= pack_one(@$_);} @{$self->{Attributes}};
    return $ret;
}


