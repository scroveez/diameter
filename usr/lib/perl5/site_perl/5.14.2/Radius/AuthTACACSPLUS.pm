# AuthTACACSPLUS.pm
#
# Object for handling Authentication via TACACSPLUS passwords.
#
# This file will be 'require'd only one time when the first Realm 
# with an AuthType of TACACSPLUS is found in the config file
#
# This module can check an TACACSPLUS user password, but cant do any
# check or reply items. It can handle CHAP, PAP or ASCII authentication
# type. Accounting packets are ignored.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthTACACSPLUS.pm,v 1.14 2013/08/13 20:58:45 hvn Exp $

package Radius::AuthTACACSPLUS;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Authen::TacacsPlus;   
use strict;

%Radius::AuthTACACSPLUS::ConfigKeywords = 
('AuthType' => 
 ['string', 'This optional parameter allows you to force the type of authentication to be used in the Tacacs+ request sent to the Tacacs+ server. Options are "PAP" and "ASCII". The default is to choose PAP if the version of Authen::TacacsPlus is 0.16 or greater, otherwise ASCII.', 1],

 'Host'     => 
 ['string', 'This optional parameter specifies the name of the host where the TacacsPlus server is running. It can be a DNS name or an IP address. Defaults to "localhost".', 0],

 'Key'      => 
 ['string', 'This mandatory parameter specifies the encryption key to be used to encrypt the connection to the TacacsPlus server. You must specify this. There is no default. It must match the key specified in the TacacsPlus server configuration file.', 0],

 'Port'     => 
 ['string', 'This optional parameter specifies the TCP port to be used to connect to the TacacsPlus server. It can be a service name as specified in /etc/services or an integer port number. Defaults to "tacacs" (TCP port 49). You should not need to change this unless your TacasPlus server is listening on a non-standard port.', 1],

 'Timeout'  => 
 ['integer', 'This optional parameter specifies the number of seconds timeout. Defaults to 15. You would only need to change this under unusual circumstances.', 1],

 );

# RCS version number of this module
$Radius::AuthTACACSPLUS::VERSION = '$Revision: 1.14 $';

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    $self->log($main::LOG_WARNING, 
	       "No Key defined for AuthTACACSPLUS in '$main::config_file'")
	unless defined $self->{Key};

    $self->SUPER::check_config();
    return;
}

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();
}

#####################################################################
# Do per-instance default initialization
# This is called by Configurable during Configurable::new before
# the config file is parsed. Its a good place initialize instance 
# variables
# that might get overridden when the config file is parsed.
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{Host} = 'localhost';
    $self->{Timeout} = 15;
    $self->{Port} = 'tacacs';
}

#####################################################################
# Handle a request
# This function is called for each packet. $p points to a Radius::
# packet
# Accounting is ignored
# Access requests are validated by checking the user password
# only. No check items are checked, no reply
# items are returned
sub handle_request
{
    my ($self, $p, $dummy, $extra_checks) = @_;

    $self->log($main::LOG_DEBUG, "Handling with TACACSPLUS $self->{Host}, $self->{Key}", $p);
    return ($main::IGNORE, "Ignored due to IgnoreAuthentication")
	if $self->{IgnoreAuthentication} 
           && $p->code eq 'Access-Request';
    return ($main::IGNORE, "Ignored due to IgnoreAccounting")
	if $self->{IgnoreAccounting} 
           && $p->code eq 'Accounting-Request';

    if ($p->code eq 'Access-Request')
    {
	my $tac = new Authen::TacacsPlus(Host=>$self->{Host},
					 Key=>$self->{Key},
					 Timeout=>$self->{Timeout},
					 Port=>$self->{Port});
	
	if (!$tac)
	{
	    $self->log($main::LOG_ERR, "Could not connect to TACACSPLUS Host $self->{Host}: " . Authen::TacacsPlus::errmsg(), $p);
	    return ($main::IGNORE, 'Software failure');
	}
	my $user_name = $p->getUserName;
	$user_name =~ s/@[^@]*$//
	    if $self->{UsernameMatchesWithoutRealm};
	
	my ($tac_result, $result, $reason, $attr, $submitted_pw, $authtype);

	# See if they want to do it by CHAP
	if (defined ($attr = $p->getAttrByNum($Radius::Radius::CHAP_PASSWORD)))
	{
	    if ($Authen::TacacsPlus::VERSION > 0.15)
	    {
		# Version 0.16 and better can handle CHAP
		# The challenge is sent by the client in 
		# CHAP-Challenge. 
		# If that is not set, the challenge is in 
		# the authenticator
		my $chap_challenge = $p->getAttrByNum
		    ($Radius::Radius::CHAP_CHALLENGE);
		$chap_challenge = $p->authenticator 
		    if !defined $chap_challenge;
		my $chap_id = substr($attr, 0, 1);
		my $chap_response = substr($attr, 1);
		    
		my $chap_string = $chap_id . $chap_challenge . $chap_response;
		$tac_result = $tac->authen
		    ($user_name, 
		     $chap_string, 
		     &Authen::TacacsPlus::TAC_PLUS_AUTHEN_TYPE_CHAP);
		
	    }
	    else
	    {
		# Cant do CHAP with this version
		$self->log($main::LOG_ERR, "Cant do CHAP authentication with this Tacacs.pm. Please upgrade", $p);
		
	    }

	}
	elsif (defined $p->getAttrByNum
	       ($Radius::Radius::USER_PASSWORD))
	{
	    # The submitted password is encoded plaintext,
	    # decode it to get the plaintext back
	    $submitted_pw = $p->decodedPassword();
	    # Version 0.16 and better can handle PAP, else take the
	    # old version default, which is ASCII
	    # The authentication type can be override with 'AuthType'
	    # to prevent Radiator choosing the type from the version of
	    # the TacacsPlus package.
	    if (defined($self->{AuthType}))
	    {
		if ($self->{AuthType} =~ /PAP/i)
		{
		    $authtype = &Authen::TacacsPlus::TAC_PLUS_AUTHEN_TYPE_PAP;
		}
		elsif ($self->{AuthType} =~ /ASCII/i)
		{
		    $authtype = &Authen::TacacsPlus::TAC_PLUS_AUTHEN_TYPE_ASCII;
		}
		elsif ($self->{AuthType} =~ /CHAP/i)
		{
		    $self->log($main::LOG_ERR, "There is no CHAP challenge in the request.");
		}
		else
		{
		    $self->log($main::LOG_ERR, "Unknown TacacsPlus authentication type. Remove it and let Radiator guess it.");
		}
	    }
	    if (!defined($authtype))
	    {
		# $authtype is undefined or incorrect -> try to guess it
		$authtype = $Authen::TacacsPlus::VERSION > 0.15
	 	  ? &Authen::TacacsPlus::TAC_PLUS_AUTHEN_TYPE_PAP 
		  : &Authen::TacacsPlus::TAC_PLUS_AUTHEN_TYPE_ASCII;
	    }
	    $tac_result = $tac->authen
	      ($user_name,
	      $submitted_pw,
	      $authtype);
	}
	if ($tac_result)
	{                   
	    # Add and strip attributes before replying
	    $self->adjustReply($p);
	    
	    # Password OK, run the extra_checks, perhaps there
	    # is a Group item we have to check?
	    return $self->checkAttributes($extra_checks, $p)
		if $extra_checks;
		
	    $p->{Handler}->logPassword($user_name, $submitted_pw, 'TACACSPLUS', 1, $p) if $p->{Handler};
	    $result = $main::ACCEPT;
	} 
	else 
	{     
	    $p->{Handler}->logPassword($user_name, $submitted_pw, 'TACACSPLUS', 0, $p) if $p->{Handler};
	    $result = $main::REJECT;
	    $reason = Authen::TacacsPlus::errmsg();
	}                 
	$tac->close();
	return ($result, $reason);
    }
    else
    {
	# Might be an Accounting-Request, or something else
	# Send a generic reply on our behalf
	return ($main::ACCEPT);
    }
}

#####################################################################
# This function may be called during operation to 
# reinitialize this module
# it is expected to reload any state, perhaps by rereading files, 
# reconnecting to a database or something like that.
# Its not actually called yet, but it as well to be prepared 
# for the day
# when it will be.
sub reinitialize
{
    my ($self) = @_;
}

1;
