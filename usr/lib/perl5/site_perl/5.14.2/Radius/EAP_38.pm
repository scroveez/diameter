# EAP_38.pm
#
# Module for  handling Authentication via EAP type 38 
# (EAP-TNC)
#
# See RFCs 2869 2284 1994
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001 Open System Consultants
# $Id: EAP_38.pm,v 1.13 2012/06/27 23:27:18 mikem Exp $

package Radius::EAP_38;
use Radius::TNC;
use strict;

# RCS version number of this module
$Radius::EAP_38::VERSION = '$Revision: 1.13 $';

$Radius::EAP_38::FLAG_LENGTH    = 0x10;
$Radius::EAP_38::FLAG_MOREFRAGS = 0x8;
$Radius::EAP_38::FLAG_START     = 0x4;
$Radius::EAP_38::VERSION_1      = 1;

$Radius::EAP_38::MAX_FRAGMENT_SIZE = 65535;

#####################################################################
# Called by EAP.pm when the caller wants to know the EAP type name this class supports
sub type_name
{
    my ($classname) = @_;

    return 'TNC';
}

#####################################################################
# request
# Called by EAP.pm when a request is received for this protocol type
sub request
{
    my ($classname, $self, $context, $p, $data) = @_;

    return $self->eap_error('Unexpected EAP request');
}

#####################################################################
# Called by EAP.pm when an EAP Response/Identity is received
sub response_identity
{
    my ($classname, $self, $context, $p) = @_;

    
    $context->{tnc} = Radius::TNC->new();
    $context->{eap_tnc_recommendation} = undef;
    # Send an EAP start
    $self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_TNC, 
		       pack('C', 
			    (  $Radius::EAP_38::FLAG_START << 3) 
			     | $Radius::EAP_38::VERSION_1));
    return ($main::CHALLENGE, 'EAP TNC Challenge');
}

#####################################################################
# Called by EAP.pm when an EAP Response (other than Identity)
# is received
sub response
{
    my ($classname, $self, $context, $p, $type, $typedata) = @_;

    my ($flagver, $data) = unpack('C a*', $typedata);
    my $flags = $flagver >> 3;
    my $version = $flagver & 0x7;

    if (!$context->{tnc})
    {
	$context->{tnc} = Radius::TNC->new();
	$context->{eap_tnc_recommendation} = undef;
    }
    if ($version != $Radius::EAP_38::VERSION_1)
    {
	# Error, unsupported version
	$self->eap_failure($p->{rp}, $context);
	return ($main::REJECT, 'EAP TNC unsupported version');
    }
    else
    {
	if ($flags & $Radius::EAP_38::FLAG_LENGTH)
	{
	    # First message of a fragmented stream has the data length
	    my $datalength; # Not really needed 'for buffer management' in perl
	    ($datalength, $data) = unpack('N a*', $data);
	    $context->{eap_tnc_indatalength} = $datalength;
	    $context->{eap_tnc_indata} .= $data;
	}
	else
	{
	    # No data length
	    $context->{eap_tnc_indata} .= $data;
	}
	if ($flags & $Radius::EAP_38::FLAG_MOREFRAGS)
	{
	    # This is a message fragment, more fragments follow. ACK
	    $self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_TNC, 
			       pack('C', $Radius::EAP_38::VERSION_1));
	    return ($main::CHALLENGE, 'EAP TNC Challenge (ACK)');
	}
	elsif (length($context->{eap_tnc_indata}) == 0
	       && length($context->{eap_tnc_outdata}))
	{
	    # Ack for a fragment we sent earlier, send the next bit
	    # Get the next fragment
	    my $data = substr($context->{eap_tnc_outdata}, 0, 
			      $Radius::EAP_38::MAX_FRAGMENT_SIZE, '');
	    my $flags = 0;
	    $flags |= $Radius::EAP_38::FLAG_MOREFRAGS
		if length($context->{eap_tnc_outdata}); # Any more after this?

	    $self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_TNC, 
			       pack('Ca*', $flags << 3 | $Radius::EAP_38::VERSION_1,
				    $data));
	    return ($main::CHALLENGE, 'EAP TNC Challenge (Next Fragment)');
	}
	elsif (length($context->{eap_tnc_indata}) == 0)
	{
	    # Empty reply, clinet has nothing for us
	    return send_recommendation($self, $context, $p);
	}
	else
	{
	    # Last or only fragment, $context->{eap_tnc_indata}
	    # has the whole message, pass it to TNC
	    ($context->{eap_tnc_recommendation}, $context->{eap_tnc_outdata}) 
		= $context->{tnc}->receiveBatch($context->{eap_tnc_indata});
	    $context->{eap_tnc_indata} = ''; # Used that incoming data now

	    # Pack up any reply batch
	    if ($context->{eap_tnc_outdata} ne '')
	    {
		# Send reply back to client, consider fragmenting
		my $datalength = length($context->{eap_tnc_outdata});
		my $data = substr($context->{eap_tnc_outdata}, 0, 
				  $Radius::EAP_38::MAX_FRAGMENT_SIZE, '');
		my $flags = 0;
		if (length($context->{eap_tnc_outdata})) # Any more after this?
		{
		    $flags |= $Radius::EAP_38::FLAG_MOREFRAGS | $Radius::EAP_38::FLAG_LENGTH;
		    $self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_TNC, 
				       pack('CNa*', 
					    $flags << 3 | $Radius::EAP_38::VERSION_1,
					    $datalength, 
					    $data));
		}
		else
		{
		    $self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_TNC, 
				       pack('Ca*', 
					    $flags << 3 | $Radius::EAP_38::VERSION_1,
					    $data));
		}
		return ($main::CHALLENGE, 'EAP TNC Challenge (Next Fragment)');
	    }
	    else
	    {
		# Empty reply, IMV has nothing for us
		return send_recommendation($self, $context, $p);
	    }
	}
    }
}

# Set up reply attributes
sub send_recommendation
{
    my ($self, $context, $p) = @_;

    if ($context->{eap_tnc_recommendation} == $Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_ALLOW)
    {
	&main::log($main::LOG_DEBUG, 'EAP-TNC recommendation: ALLOW');
	foreach (&Radius::Util::splitAttrVals($self->{TNCAllowReply}))
	{
	    $p->{rp}->add_attr(${$_}[0], ${$_}[1]);
	}
	return ($main::ACCEPT, 'EAP-TNC Allow');
    }
    elsif ($context->{eap_tnc_recommendation} == $Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_ISOLATE)
    {
	&main::log($main::LOG_DEBUG, 'EAP-TNC recommendation: ISOLATE');
	foreach (&Radius::Util::splitAttrVals($self->{TNCIsolateReply}))
	{
	    $p->{rp}->add_attr(${$_}[0], ${$_}[1]);
	}
	return ($main::ACCEPT, 'EAP-TNC Isolate');
    }
    elsif ($context->{eap_tnc_recommendation} == $Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION
	   && $context->{eap_tnc_outdata} eq '')
    {
	# Cant decide and dont know how to proceed, since TNC did not ask for 
	# anything so reject them
	foreach (&Radius::Util::splitAttrVals($self->{TNCNoRecommendationReply}))
	{
	    $p->{rp}->add_attr(${$_}[0], ${$_}[1]);
	}
	return ($main::REJECT, 'EAP-TNC Could not make a recommendation');
    }
    elsif ($context->{eap_tnc_recommendation} == $Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_NO_ACCESS)
    {
	return ($main::REJECT, 'EAP-TNC recommendation: NO ACCESS');
    }
}

1;
