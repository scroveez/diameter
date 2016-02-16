# AuthIPASS.pm
#
# Object for handling Authentication via iPASS
#
# This file will be 'require'd only one time when the first Realm 
# with an AuthType of IPASS is found in the config file
#
# This module requires the Ipass module which is a wrapper
# around a C library provided by iPASS. The iPASS C library
# passes authentication and accounting requests to the iPASS servers
#
# This module always forks to handle each request, since 
# the iPASS system may take on the order of several seconds to reply.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthIPASS.pm,v 1.18 2007/12/18 21:23:50 mikem Exp $

package Radius::AuthIPASS;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Ipass;
use strict;

%Radius::AuthIPASS::ConfigKeywords = 
('Debug'  => 
 ['flag', 'Debug causes the operation of the iPASS libraries to be traced. The output is usually in /usr/ipass/logs/iprd.trace unless you change it with the Trace parameter. ', 1],

 'Config' => 
 ['string', 'Sets the location of the iPASS configuration file. Defaults to /usr/ipass/ipass.conf. You can use the special filename formats. ', 0],

 'Trace'  => 
 ['flag', 'Sets the location of the iPASS trace file. Defaults to /usr/ipass/logs/iprd.trace. You can use the special filename formats. ', 1],

 'Home'   => 
 ['string', 'Sets the location of the iPASS installation directory for locating SSL certificate and key files. Defaults to /usr/ipass. You can use the special filename formats.', 0],

 );

# RCS version number of this module
$Radius::AuthIPASS::VERSION = '$Revision: 1.18 $';

# Translates IPASS_SERV service identifiers to Radius
# Service-Type number
my %ipass_serv_to_radius =
(
 &Ipass::IPASS_SERV_PPP => 2,       # Framed-User
 &Ipass::IPASS_SERV_TELNET => 1,    # Login-User
 );

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
    $self->{Fork} = 1;
}

#####################################################################
# Handle a request
# This function is called for each packet. $p points to a Radius::
# packet, with the reply packet $p->{rp} ready to go
# All requests are munged and then passed tothe iPASS library
# to be handled remotely. We always fork to handle
# iPASS requests because they can be very slow.
sub handle_request
{
    my ($self, $p, $dummy, $extra_checks) = @_;

    $self->log($main::LOG_DEBUG, "Handling with IPASS", $p);
    return ($main::IGNORE, "Ignored due to IgnoreAuthentication")
	if $self->{IgnoreAuthentication} 
           && $p->code eq 'Access-Request';
    return ($main::IGNORE, "Ignored due to IgnoreAccounting")
	if $self->{IgnoreAccounting} 
           && $p->code eq 'Accounting-Request';

    if (!$self->{Intialized})
    {
        Ipass::debug(1) if $self->{Debug};
	  
	if (defined $self->{Config})
	{
	    my $d = &Radius::Util::format_special($self->{Config}, $p);
	    $ENV{IPASS_CONFIG} = $d;
	}
	if ($self->{Trace})
	{
	    my $d = &Radius::Util::format_special($self->{Trace}, $p);
	    $ENV{IPASS_TRACE} = $d;
	}
	if (defined $self->{Home})
	{
	    my $d = &Radius::Util::format_special($self->{Home}, $p);
	    $ENV{IPASS_HOME} = $d;
	}
	if (Ipass::init() != &Ipass::IPASS_STATUS_OK)
	{
	    $self->log($main::LOG_ERR, 
		       "Initialization of iPASS library failed", $p);
	    return ($main::IGNORE, 'Software failure');
	}
	$self->{Intialized}++;
    }

    if ($p->code eq 'Access-Request')
    {
	my $user_name = $p->getUserName;
	$user_name =~ s/@[^@]*$//
	    if $self->{UsernameMatchesWithoutRealm};
	my $nas_ip = $p->getNasId();
	my $nas_port = $p->getAttrByNum($Radius::Radius::NAS_PORT);
	my $nas_ses_id = $p->getAttrByNum($Radius::Radius::ACCT_SESSION_ID);
	# REVISIT: Figure out how to translate service type
	# to IPASS_SERV_*. IN the meantime, pretend everything is PPP
	my $service = &Ipass::IPASS_SERV_PPP;
	my $nas_port_type = $p->getAttrByNum
	    ($Radius::Radius::NAS_PORT_TYPE);
	my $called_station_id = $p->getAttrByNum
	    ($Radius::Radius::CALLED_STATION_ID);
	my $calling_station_id = $p->getAttrByNum
	    ($Radius::Radius::CALLING_STATION_ID);

	# Now we fork before sending the request to IPASS
	# since it will usually take a long time and we need
	# to continue responding. 
	return ($main::IGNORE, 'Forked')
	    if $self->{Fork} && !$self->handlerFork();

	my $password;
	my ($errcode, $auth_reply, $serv_req, 
	    $host_ip, $host_port, $sesslimit, $authttl);
	if (defined ($password = $p->getAttrByNum($Radius::Radius::CHAP_PASSWORD)))
	{
	    # Handle CHAP-Password
	    # The first byte of CHAP-Password is the chap_ident,
	    # and the rest is the MD5 encrypted password
	    my $chap_password = substr($password, 1);
	    my $chap_ident = substr($password, 0, 1);
	    my $chap_challenge = $p->getAttrByNum($Radius::Radius::CHAP_CHALLENGE);

	    ($errcode, $auth_reply, $serv_req, 
		$host_ip, $host_port, $sesslimit, $authttl) 
		= Ipass::remote_auth_chap
		    ($nas_ip, $nas_port, 
		     $nas_ses_id, time, 
		     &Ipass::IPASS_DIR_IN, $service,
		     $user_name, $chap_password,
		     $chap_challenge, $chap_ident,
		     $nas_port_type, 
		     $called_station_id, $calling_station_id);
	}
	else
	{
	    # Handle an ordinary password
	    $password = $p->decodedPassword();
	    ($errcode, $auth_reply, $serv_req, 
		$host_ip, $host_port, $sesslimit, $authttl) 
		= Ipass::remote_auth
		    ($nas_ip, $nas_port, 
		     $nas_ses_id, time, 
		     &Ipass::IPASS_DIR_IN, $service,
		     $user_name, $password,
		     $nas_port_type, 
		     $called_station_id, $calling_station_id);
	}

	# See if the request got to the other end and back
	if ($errcode != &Ipass::IPASS_STATUS_OK)
	{
	    $self->log($main::LOG_ERR, 
		       "Ipass::remote_auth failed with code $errcode", $p);
	    return ($main::IGNORE, "Ipass failed with code $errcode");
	}
	# Now see if the authentication succeeded or failed
	if ($auth_reply == &Ipass::IPASS_AUTH_FAIL
	    || $auth_reply == &Ipass::IPASS_AUTH_PWEXP)
	{
	    $self->log($main::LOG_DEBUG, 
		       "Ipass::remote_auth returned AUTH_FAIL", $p);
	    return ($main::REJECT, 'Ipass failed');
	}
	else
	{
	    $self->log($main::LOG_DEBUG, 
		       "Ipass::remote_auth returned $auth_reply: '$serv_req', '$host_ip', '$host_port', '$sesslimit'", $p);
	    # Put interesting stuff into the reply packet

	    # Translate $serv_req (one of IPASS_SERV_*) into
	    # a radius Service-Type number. There is not a one
	    # to one mapping, so not all values are
	    # supported
	    $serv_req = $ipass_serv_to_radius{$serv_req};

	    $p->{rp}->addAttrByNum($Radius::Radius::SERVICE_TYPE, 
			      $serv_req) if $serv_req;
	    $p->{rp}->addAttrByNum($Radius::Radius::LOGIN_IP_HOST, $host_ip)
		if $host_ip ne '0.0.0.0';
	    $p->{rp}->addAttrByNum($Radius::Radius::LOGIN_TCP_PORT, $host_port)
		if $host_port;
	    $p->{rp}->addAttrByNum($Radius::Radius::SESSION_TIMEOUT, $sesslimit);


	    # Add and strip attributes before replying
	    $self->adjustReply($p);

	    return ($main::ACCEPT);
	}
    }
    elsif ($p->code eq 'Accounting-Request')
    {
	my $user_name = $p->getUserName;
	my $nas_ip = $p->getNasId();
	my $nas_port = $p->getAttrByNum($Radius::Radius::NAS_PORT);
	my $nas_ses_id = $p->getAttrByNum($Radius::Radius::ACCT_SESSION_ID);
	# REVISIT: Figure out how to translate service type
	# to IPASS_SERV_*. IN the meantime, pretend everything is PPP
	my $service = &Ipass::IPASS_SERV_PPP;
	my $acct_status = $p->getAttrByNum($Radius::Radius::ACCT_STATUS_TYPE);
	my $nas_port_type = $p->getAttrByNum
	    ($Radius::Radius::NAS_PORT_TYPE);
	my $called_station_id = $p->getAttrByNum
	    ($Radius::Radius::CALLED_STATION_ID);
	my $calling_station_id = $p->getAttrByNum
	    ($Radius::Radius::CALLING_STATION_ID);
	my $acct_type;
	if ($acct_status eq 'Start')
	{
	    $acct_type = &Ipass::IPASS_ACCT_START;
	}
	elsif ($acct_status eq 'Stop')
	{
	    $acct_type = &Ipass::IPASS_ACCT_STOP;
	}
	else
	{
	    # iPASS cant handle anything else, just ACK it
	    return ($main::ACCEPT);
	}

	my $ses_len = $p->getAttrByNum($Radius::Radius::ACCT_SESSION_TIME);
	my $ip = $p->getAttrByNum($Radius::Radius::ACCT_INPUT_PACKETS);
	my $op = $p->getAttrByNum($Radius::Radius::ACCT_OUTPUT_PACKETS);
	my $ic = $p->getAttrByNum($Radius::Radius::ACCT_INPUT_OCTETS);
	my $oc = $p->getAttrByNum($Radius::Radius::ACCT_OUTPUT_OCTETS);
	my $user_ip = $p->getAttrByNum($Radius::Radius::FRAMED_IP_ADDRESS);
	my $user_mask = $p->getAttrByNum($Radius::Radius::FRAMED_IP_NETMASK);

	# Now we fork before sending the request to IPASS
	# since it will usually take a long time and we need
	# to continue responding. 
	return ($main::IGNORE, 'Forked')
	    if $self->{Fork} && !$self->handlerFork();

	my $errcode 
	    = Ipass::remote_acct($nas_ip, $nas_port, 
				 $nas_ses_id, time, 
				 &Ipass::IPASS_DIR_IN, 
				 $service,
				 $user_name, 
				 $acct_type,
				 $ses_len,
				 $ip, $op, $ic, $oc,
				 $user_ip, $user_mask,
				 $nas_port_type, 
				 $called_station_id, 
				 $calling_station_id);

	if ($errcode != &Ipass::IPASS_STATUS_OK)
	{
	    $self->log($main::LOG_ERR, 
		       "Ipass::remote_acct failed with code $errcode", $p);
	    return ($main::IGNORE, "Ipass failed with code $errcode");
	}
	return ($main::ACCEPT); # Everything is OK
    }
    else
    {
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
