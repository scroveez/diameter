# TNC.pm
#
# Object for handling TNC (Trusted Network Computing) details
# through the IF-IMV interface of the TNC specification
# See https://www.trustedcomputinggroup.org/downloads/TNC/
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2006 Open System Consultants
# $Id: TNC.pm,v 1.25 2008/05/08 07:56:36 mikem Exp $

package Radius::TNC;
use Radius::OSC_IMV;
use MIME::Base64;
use strict;

# RCS version number of this module
$Radius::TNC::VERSION = '$Revision: 1.25 $';

# Recommendation codes
# these will move somewhere else one day
$Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_ALLOW             = 0;
$Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_NO_ACCESS         = 1;
$Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_ISOLATE           = 2;
$Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION = 3;

# OSC IMC Message types from libtnc
$Radius::TNC::OSC_VENDORID = 9048;
$Radius::TNC::OSC_MESSAGE_OS_DETAILS         
    = ($Radius::TNC::OSC_VENDORID << 8) | 1;
$Radius::TNC::OSC_MESSAGE_PACKAGE_STATUS_REQUEST
    = ($Radius::TNC::OSC_VENDORID << 8) | 2;
$Radius::TNC::OSC_MESSAGE_PACKAGE_STATUS_REPLY
    = ($Radius::TNC::OSC_VENDORID << 8) | 3;
$Radius::TNC::OSC_MESSAGE_USER_MESSAGE 
    = ($Radius::TNC::OSC_VENDORID << 8) | 4;
$Radius::TNC::OSC_MESSAGE_FILE_STATUS_REQUEST
    = ($Radius::TNC::OSC_VENDORID << 8) | 5;
$Radius::TNC::OSC_MESSAGE_FILE_STATUS_REPLY
    = ($Radius::TNC::OSC_VENDORID << 8) | 6;
$Radius::TNC::OSC_MESSAGE_REGISTRY_REQUEST
    = ($Radius::TNC::OSC_VENDORID << 8) | 7;
$Radius::TNC::OSC_MESSAGE_REGISTRY_REPLY
    = ($Radius::TNC::OSC_VENDORID << 8) | 8;
$Radius::TNC::OSC_MESSAGE_EXTCOMMAND_REQUEST
    = ($Radius::TNC::OSC_VENDORID << 8) | 9;
$Radius::TNC::OSC_MESSAGE_EXTCOMMAND_REPLY
    = ($Radius::TNC::OSC_VENDORID << 8) | 10;

# OPen1X messages types
$Radius::TNC::OPEN1X_VENDORID = 28383;
$Radius::TNC::OPEN1X_MESSAGE_PERSONALITY         
    = ($Radius::TNC::OPEN1X_VENDORID << 8) | 1;
$Radius::TNC::OPEN1X_MESSAGE_FILE_STATUS_REQUEST         
    = ($Radius::TNC::OPEN1X_VENDORID << 8) | 2;
$Radius::TNC::OPEN1X_MESSAGE_FILE_STATUS_REPLY      
    = ($Radius::TNC::OPEN1X_VENDORID << 8) | 3;

# We keep a hash of objects, indexed by an integer connectionId, so 
# that we can recover the object given the connectionId, 
# which is all that is passed up from IF-IMV
my $nextConnectionId = 0;
my %currentConnections;

#####################################################################
# Represents a single IMC-IMV connection
sub new
{
    my ($class) = @_;

    my $self = {};

    # Maintain a hash of objects indexed by connectionId
    $self->{connectionId} = $nextConnectionId++;
#    $currentConnections{$self->{connectionId}} = $self;

    bless $self, $class;
    $self->set_rec($Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION);
    return $self;
}

#####################################################################
# Get received messages and pass them to the IMV
sub receiveMessages
{
    my ($self, $p) = @_;

    my $batch = $p->get_attr('OSC-Integrity-Message');
    $batch = '' unless defined $batch;
    my ($recommendation, $replybatch) = $self->receiveBatch($batch);
    $p->{rp}->add_attr('OSC-Integrity-Message', $replybatch) 
	if defined $replybatch;
    
    return $recommendation;
}

#####################################################################
sub receiveBatch
{
    my ($self, $batch) = @_;
    
    # Should use real XML parsing here
    my $messages = '';
    my $imc_imv_count = 0;
    my $imv_imc_count = 0;
    my $batchid = 1;

    if ($batch =~ /^\s*<\?xml version="1.0"\?>\s*\<TNCCS-Batch\s+BatchId="(\d+)"\s+Recipient="TNCS"/)
    {
	$batchid = $1;
	while ($batch =~ /<IMC-IMV-Message>\s*<Type>([0-9a-fA-F]+)<\/Type>\s*<Base64>([^<]+)<\/Base64>\s*<\/IMC-IMV-Message>/gs)
	{
	    my ($message_type, $msg) = (hex($1), MIME::Base64::decode_base64($2));
#	    print "decoded to $message_type, $msg\n";
	    $imc_imv_count++;
	    if ($message_type == $Radius::TNC::OSC_MESSAGE_OS_DETAILS)
	    {
		# sysname:nodename:release:version:machine:LANG:username
		# username is the user name of the supplicant process owner
		if ($msg =~ /^Windows/)
		{
		    ($self->{clientval}{System}{''}{name}, 
		     $self->{clientval}{System}{''}{majorversion}, 
		     $self->{clientval}{System}{''}{minorversion},
		     $self->{clientval}{System}{''}{buildnumber}, 
		     $self->{clientval}{System}{''}{platformid}, 
		     $self->{clientval}{System}{''}{csdversion}, 
		     $self->{clientval}{System}{''}{servicepackmajor}, 
		     $self->{clientval}{System}{''}{servicepackminor}, 
		     $self->{clientval}{System}{''}{suitemask}, 
		     $self->{clientval}{System}{''}{producttype})
			= split(/\|/, $msg);
		}
		else
		{
		    ($self->{clientval}{System}{''}{name}, 
		     $self->{clientval}{System}{''}{nodename}, 
		     $self->{clientval}{System}{''}{release}, 
		     $self->{clientval}{System}{''}{version}, 
		     $self->{clientval}{System}{''}{machine}, 
		     $self->{clientval}{System}{''}{lang}, 
		     $self->{clientval}{System}{''}{user})
			= split(/\|/, $msg);
		}
	    }
	    elsif ($message_type == $Radius::TNC::OSC_MESSAGE_PACKAGE_STATUS_REPLY)
	    {
		# packagename:verifystatus:version
		my ($packagename, $verifystatus, $version)
		    = $msg =~ /^(.*?)\|(\d+)\|(.*)/;
		
		$self->{clientval}{Package}{$packagename}{status} = $verifystatus;
		$self->{clientval}{Package}{$packagename}{version}{$packagename} = $version;
	    }
	    elsif ($message_type == $Radius::TNC::OSC_MESSAGE_FILE_STATUS_REPLY)
	    {
#		print "got file status $msg\n";
		# filename:status:size:mode
		# status is the result of stat. 0 is OK
		my ($filename, $status, $dummy, $size, $mode)
		    = $msg =~ /^(.*?)\|(\d+)(\|(\d+)\|(\d+))?/;

		$self->{clientval}{File}{$filename}{status} = $status;
		$self->{clientval}{File}{$filename}{size}   = $size;
		$self->{clientval}{File}{$filename}{mode}   = $mode;
	    }
	    elsif ($message_type == $Radius::TNC::OSC_MESSAGE_REGISTRY_REPLY)
	    {
		# key:value
		my ($key, $type, $value)
		    = $msg =~ /^(.*?)\|(.*?)\|(.*)/;

		$self->{clientval}{Registry}{$key}{type} = $type;
		$self->{clientval}{Registry}{$key}{value} = $value;
#		print "got reg $key, $type, $value\n";
	    }
	    elsif ($message_type == $Radius::TNC::OSC_MESSAGE_EXTCOMMAND_REPLY)
	    {
		# key:status:resultstring
		my ($key, $status, $result)
		    = $msg =~ /^(.*?)\|(.*?)\|(.*)/;

#		print "got extcommand $key, $status, $result\n";
		$self->{clientval}{Extcommand}{$key}{status} = $status;
		$self->{clientval}{Extcommand}{$key}{result} = $result;
	    }

	    # Open1X messages:
	    elsif ($message_type == $Radius::TNC::OPEN1X_MESSAGE_PERSONALITY)
	    {
#		print "TNC personality\n";
		$self->{OSName} = $1
		    if ($msg =~ /^<Personality>.*<OSName>(.*)<\/OSName>.*<\/Personality>/);
		$self->{OSVersion} = $1
		    if ($msg =~ /^<Personality>.*<OSVersion>(.*)<\/OSVersion>.*<\/Personality>/);
		$self->{SupplicantName} = $1
		    if ($msg =~ /^<Personality>.*<SupplicantName>(.*)<\/SupplicantName>.*<\/Personality>/);
		$self->{SupplicantVersion} = $1
		    if ($msg =~ /^<Personality>.*<SupplicantVersion>(.*)<\/SupplicantVersion>.*<\/Personality>/);
		# Bad message format
		return ($self->set_rec($Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION))
		    unless defined $self->{OSName};
#		print "pers: $self->{OSName} $self->{OSVersion}\n";
	    }
	    elsif ($message_type == $Radius::TNC::OPEN1X_MESSAGE_FILE_STATUS_REPLY)
	    {
#		print "TNC file status $msg\n";
		while ($msg =~ /<FileStatus>(.*?)<\/FileStatus>/gs)
		{
		    my $status = $1;
#		    print "processing $status\n";
		    my $filename;
		    if ($status =~ /^<FileName>(.*?)<\/FileName>/)
		    {
			$filename = $1;
		    }
		    # Bad message format
		    return ($self->set_rec($Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION))
			if $filename eq '';

		    $self->{FileSize}{$filename} = $1
			if ($status =~ /<FileSize>(.*?)<\/FileSize>/);
		    $self->{FileExists}{$filename} = $1
			if ($status =~ /<FileExists>(.*?)<\/FileExists>/);
		    $self->{FileMode}{$filename} = $1
			if ($status =~ /<FileMode>(.*?)<\/FileMode>/);
#		    print "got status $self->{FileSize}{$filename}\n";
		}
	    }
	    else
	    {
		&main::log($main::WARNING, "TNC never heard of type $message_type");
	    }
	}
    }

    # Empty batch from the client?, we're done
#    print "checking $imc_imv_count, $self->{recommendation}\n";
    return ($self->{recommendation})
	if ($imc_imv_count == 0);

    # Now have processed all the incoming IMC-IMV messages in the batch
    # now see if we have to send a batch back to the client with requests
    # for (more) data
    
    # See if the IMV needs more data:
    if (defined $self->{OSName})
    {
	return $self->check_open1x_imv($batchid);
    }
    elsif (defined $self->{clientval}{System}{''}{name})
    {
	return $self->check_osc_imv($batchid);
    }
    else
    {
	# Never got either an OSC_MESSAGE_OS_DETAILS, or a
	# OPEN1X_PERSONALITY, isolate them
	return ($self->set_rec($Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_ISOLATE));
    }
}

sub check_open1x_imv
{
    my ($self, $batchid) = @_;

    my $filename;
#    print "Checking open1x tnc: $self->{OSName}\n";
    if ($self->{OSName} =~ /Microsoft/)
    {
	$filename = 'C:\PostureFlag';
    }
    elsif ($self->{OSName} =~ /Linux/)
    {
	$filename = '/tmp/PostureFlag';
    }
    else
    {
	# Dont know what sort of OS
	return ($self->set_rec($Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_ISOLATE));
    }

    # Now know the platform specific filename, test for its presence
    # on the client
    if (!defined $self->{FileExists}{$filename})
    {
	my $messages = $self->make_open1x_file_request($filename);
	return ($Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION, $self->make_batch($batchid + 1, $messages));
    }
    elsif ($self->{FileExists}{$filename})
    {
	return ($self->set_rec($Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_ALLOW));
    }
    else
    {
	return ($self->set_rec($Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_ISOLATE));
    }
}

# Evaluate responses from an OSC IMC, according to the configured policy
sub check_osc_imv
{
    my ($self, $batchid) = @_;

    $self->{requests} = undef;
    &Radius::OSC_IMV::evaluate($self);
    if (defined $self->{requests})
    {
	# Have to ask the client some stuff
	return ($Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION, $self->make_batch($batchid + 1, $self->{requests}));
    }
    
    # No messages to the IMC, must be time for a recommendation
    $self->{recommendation} = $Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_NO_ACCESS 
	unless defined $self->{recommendation};
    return ($self->{recommendation}, $self->make_batch($batchid + 1, $self->make_recommendation($self->{recommendation})));
}

sub OLDcheck_osc_imv
{
    my ($self, $batchid) = @_;

    my $messages = '';
    my (@packagelist, @filelist, @registrylist);
    if ($self->{clientval}{System}{''}{name} eq 'Windows')
    {
	@registrylist = ("SOFTWARE\\Trusted Computing Group\\TNC\\IMCs\\OSC Sample Imc\\Description");
	@filelist = ("C:\\xxx.txt");
    }
    elsif ($self->{clientval}{System}{''}{name} eq 'Linux')
    {
	if ($self->{clientval}{System}{''}{release} !~ /^2\.6\./)
	{
	    $messages .= $self->make_user_message("You do not seem to be running a suitable version of the Linux kernel.\nYou need to be running kernel version 2.6 or later.\nYou will be connected to the Remediation network, where you can upgrade your kernel.");
	    $self->set_rec($Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_ISOLATE);
	    goto finished;
	}
	@packagelist = ('rpm');
	@filelist = ('/etc/tnc_config');
    }
    
    # keep going, need more info
    foreach (@registrylist)
    {
	if (!$self->{askfor}{Registry}{$_})
	{
	    $self->{askfor}{Registry}{$_}++;
	    $messages .= $self->make_registry_request($_);
	}
    }
    foreach (@packagelist)
    {
	if (!$self->{askfor}{Package}{$_})
	{
	    $self->{askfor}{Package}{$_}++;
	    $messages .= $self->make_package_request($_);
	}
    }
    foreach (@filelist)
    {
	if (!$self->{askfor}{File}{$_})
	{
	    $self->{askfor}{File}{$_}++;
	    $messages .= $self->make_file_request($_);
	}
    }
    goto finished if $messages;
    
    my (@badpackages, @badfiles);
    foreach (@packagelist)
    {
	push(@badpackages, $_) 
	    if defined $self->{clientval}{Package}{$_}{status} 
	&& $self->{clientval}{Package}{$_}{status} != 0;
    }
    foreach (@filelist)
    {
	push(@badfiles, $_) 
	    if defined $self->{clientval}{File}{$_}{status} 
	&& $self->{clientval}{File}{$_}{status} != 0;
    }
    
    if (@badpackages || @badfiles)
    {
	if (@badpackages)
	{
	    $messages .= $self->make_user_message("Your installation of the following packages is missing or corrupt:\n@badpackages\nYou will be connected to the Remediation network, where you can reinstall these package(s).");
	}
	if (@badfiles)
	{
	    $messages .= $self->make_user_message("Your installation does not include the following files:\n@badfiles\nYou will be connected to the Remediation network, where you can reinstall these files(s).");
	}
	$self->set_rec($Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_ISOLATE);
    }
    else
    {
	$self->set_rec($Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_ALLOW);
    }
    
  finished:
    if ($messages ne '')
    {
	# Send the next batch back to the client
	return ($Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION, $self->make_batch($batchid + 1, $messages));
    }
    elsif ($self->{recommendation} != $Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION)
    {
	# No messages to the IMC, must be time for a recommendation
	return ($self->{recommendation}, $self->make_batch($batchid + 1, $self->make_recommendation($self->{recommendation})));
    }
    else
    {
	# REVISIT: ERROR
	return ($self->{recommendation});
    }
}

#####################################################################
# Convenience function to set and return the recommendation for this context
sub set_rec
{
    my ($self, $recommendation) = @_;

    return $self->{recommendation} = $recommendation;
}

#####################################################################
sub make_batch
{
    my ($self, $batchid, $messages) = @_;

    return qq|<?xml version="1.0"?>
<TNCCS-Batch BatchId="$batchid" Recipient="TNCC" xmlns="http://www.trustedcomputinggroup.org/IWG/TNC/1_0/IF_TNCCS#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemalocation="http://www.trustedcomputinggroup.org/IWG/TNC/1_0/IF_TNCCS#https://www.trustedcomputinggroup.org/XML/SCHEMA/TNCCS_1.0.xsd">$messages</TNCCS-Batch>|;
}

#####################################################################
sub make_imc_imv_message
{
    my ($self, $type, $data) = @_;

    my $hextype = sprintf "%lx", $type;
    my $base64data = MIME::Base64::encode_base64($data);
    return "<IMC-IMV-Message><Type>$hextype</Type><Base64>$base64data</Base64></IMC-IMV-Message>";
}

#####################################################################
sub make_user_message
{
    my ($self, $message) = @_;

    return $self->make_imc_imv_message($Radius::TNC::OSC_MESSAGE_USER_MESSAGE, $message);
}

#####################################################################
sub make_package_request
{
    my ($self, $package) = @_;

    return $self->make_imc_imv_message($Radius::TNC::OSC_MESSAGE_PACKAGE_STATUS_REQUEST, $package);
}

#####################################################################
sub make_file_request
{
    my ($self, $filename) = @_;

    return $self->make_imc_imv_message($Radius::TNC::OSC_MESSAGE_FILE_STATUS_REQUEST, $filename);
}

#####################################################################
sub make_registry_request
{
    my ($self, $name) = @_;

    return $self->make_imc_imv_message($Radius::TNC::OSC_MESSAGE_REGISTRY_REQUEST, $name);
}

#####################################################################
sub make_extcommand_request
{
    my ($self, $name) = @_;

    return $self->make_imc_imv_message($Radius::TNC::OSC_MESSAGE_EXTCOMMAND_REQUEST, $name);
}

#####################################################################
sub make_open1x_file_request
{
    my ($self, $filename) = @_;

    return $self->make_imc_imv_message($Radius::TNC::OPEN1X_MESSAGE_FILE_STATUS_REQUEST, "<FileStatusRequest><FileName>$filename</FileName></FileStatusRequest>");
}
#####################################################################
sub make_recommendation
{
    my ($self, $recommendation) = @_;

    my $type = ($recommendation == $Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_ALLOW)
	? 'allow'
	: ($recommendation == $Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_ISOLATE)
	? 'isolate'
	: 'none';
    return qq|<TNCC-TNCS-Message><Type>00000001</Type><XML><TNCCS-Recommendation type="$type"></TNCCS-Recommendation></XML></TNCC-TNCS-Message>|;
}


#####################################################################
#
sub delete
{
    my ($self) = @_;

    # Destroy any hanging references to this object so it will DESTROY
#    delete $currentConnections{$self->{connectionId}};
}

1;
