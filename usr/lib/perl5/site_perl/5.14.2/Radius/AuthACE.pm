# AuthACE.pm
#
# Object for handling Authentication via ACE/Server from
# RSA Security (www.rsasecurity.com). ACE/Server
# provides a token-based one-time-password system
#
# This module issues Challenges during some
# authentications, so users need to be logging in with PAP
# via a terminal window.
#
# Requires the Authen::ACE4 module available from CPAN
# or http://www.open.com.au/free-downloads
# Authen::ACE4 works on Unix and Windows, and so does
# this module
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001 Open System Consultants
# $Id: AuthACE.pm,v 1.28 2013/01/03 01:13:21 mikem Exp $

package Radius::AuthACE;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Authen::ACE4;
use strict;

# These are not the same as the EAP context
%Radius::AuthACE::contexts = ();

# Make sure we get reinitialized on sighup
push(@main::reinitFns, \&reinitialize);
$Radius::AuthACE::initialised = undef;

%Radius::AuthACE::ConfigKeywords = 
('ConfigDirectory'     => 
 ['string', 'Specifies the location of the ACE Agent sdconf.rec file, which the ACE Agent client libraries use to find the location of the ACE server. The file sdconf.rec must be present on the machine where AuthBy ACE is running. Defaults to the the value of the VAR_ACE environment variable, if set, else /var/ace. This parameter has no effect on Windows.', 0],
 'Timeout'             => 
 ['integer', 'Specifies the maximum time that a single ACE authentication is allowed to take. A typical ACE authentication will require several Radius transactions, involving multiple requests and challenges until the final Access-Accept is sent, and there is no guaranteee that the user will conplete the authentication process. If the total time for the authentication exceeds this number of seconds, the authentication will be abandoned. ', 1],
 'EnableFastPINChange' => 
 ['flag', 'Some NASs, notably some Juniper devices, have non-standard behaviour in New Pin Mode: when the user is asked whether they want to set their PIN, the NAS automatically gets the new PIN from the user and returns it to the Radiator server, which is expected to use it to set the PIN immediately. This flag enables compatibility with this behaviour if the user/device enters a PIN instead of \'y\' or \'n\'.', 1],
 );

# RCS version number of this module
$Radius::AuthACE::VERSION = '$Revision: 1.28 $';

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();

    $ENV{VAR_ACE} = $self->{ConfigDirectory} 
        if defined $self->{ConfigDirectory};
#    &Authen::ACE4::AceInitialize(); # Causes hangs in a forked environment
}

#####################################################################
# Do per-instance default initialization
# This is called by Configurable during Configurable::new before
# the config file is parsed. Its a good place initialize instance 
# variables
# that might get overridden when the config file is parsed.
# Do per-instance default initialization. This is called after
# construction is complete
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{NoDefault} = 1;
    $self->{Timeout} = 300; # Max time that context lives for
}

#####################################################################
# This is a bogus findUser that basically does nothing but does not
# fail
sub findUser
{
    return Radius::User->new();
}

#####################################################################
# We subclass this to do nothing: there are no check items
# except the password, and only if its not an EAP
sub checkUserAttributes
{
    my ($self, $user, $p) = @_;

    # Short circuit authentication in EAP requests ?
    return ($main::ACCEPT) 
      if $p->getAttrByNum($Radius::Radius::EAP_MESSAGE);

    return $self->check_plain_password
	($p->getUserName(), $p->decodedPassword(), undef, $p);
}

#####################################################################
# $submitted_pw is the password being authenticated
# $pw is the correct password if known
# $user is the user name to be authenticated
sub check_plain_password
{
    my ($self, $user, $submitted_pw, $pw, $p, $encrypted) = @_;

    return ($main::ACCEPT) if $self->{NoCheckPassword};

    # This receives the state from any previous
    # cycle of authentication
    my $state = $p->getAttrByNum($Radius::Radius::STATE);
    my ($info, $handle);
    
    if ($state =~ /^SECURID=(-?\d+)$/)
    {
	return $self->continue($1, $submitted_pw, $p);
    }
    else
    {
	# This is a new request, start a new authentication
	&Authen::ACE4::AceInitialize() unless $Radius::AuthACE::initialised++;

	my ($result, $handle, $moreData, $echoFlag, $respTimeout, $nextRespLen, $prompt) 
	    = Authen::ACE4::AceStartAuth($user);

	# Sigh, ACE/Agent V 5 leaves trailing NULs
	$prompt =~ s/\000*$//;

	my $clean_prompt = $prompt; # For logging
	$clean_prompt =~ s/\n/ /g;

	return ($main::REJECT, "AceStartAuth failed: $clean_prompt")
	    if $result != Authen::ACE4::ACM_OK;

	# The context will time out automatically if
	# the auth never completes
	$self->saveContext($handle);
		
	# Maybe they have supplied the password already
	# if so, try to authenticate it
	if (   $prompt =~ /^Enter PASSCODE/
	    && $submitted_pw ne '')
	{
	    return $self->continue($handle, $submitted_pw, $p);
	}
	elsif (   $self->{EnableFastPINChange}
	       && $prompt =~ /Are you ready to enter a new PIN/)
	{
	    return $self->continue($handle, 'y', $p);
	}
	elsif (   $self->{EnableFastPINChange}
	       && $prompt =~ /Do you want the system to generate/)
	{
	    return $self->continue($handle, 'n', $p);
	}
	else
	{
	    # Ask them a question
	    $p->{rp}->addAttrByNum($Radius::Radius::STATE, "SECURID=$handle");
	    $p->{rp}->addAttrByNum($Radius::Radius::REPLY_MESSAGE, $prompt);
	    return ($main::CHALLENGE, $clean_prompt);
	}
    }
}

#####################################################################
sub continue
{
    my ($self, $handle, $resp, $p) = @_;

    return ($main::REJECT, 'Stale AuthACE context')
	if !defined $Radius::AuthACE::contexts{$handle};

  fakeresponse:
    my ($result, $moreData, $echoFlag, $respTimeout, $nextRespLen, $prompt) 
	= Authen::ACE4::AceContinueAuth($handle, $resp);

    # Sigh, ACE/Agent V 5 leaves trailing NULs
    $prompt =~ s/\000*$//;

    my $clean_prompt = $prompt; # For logging
    $clean_prompt =~ s/\n/ /g;

    $self->log($main::LOG_DEBUG, "AceContinueAuth($resp): $result, $moreData, $echoFlag, $respTimeout, $nextRespLen, $clean_prompt");
    return ($main::REJECT, "AceContinueAuth failed: $clean_prompt")
	if $result != Authen::ACE4::ACM_OK;

    if ($moreData)
    {
	# See if we need to short circuit
	if ($self->{EnableFastPINChange})
	{
	    if ($prompt =~ /Are you ready to enter a new PIN/)
	    {
		$resp = 'y';
		goto fakeresponse;
	    }
	    elsif ($prompt =~ /Do you want the system to generate/)
	    {
		$resp = 'n';
		goto fakeresponse;
	    }
	}
	# AM7.1 has misleading messages
	if ($prompt =~ /Your screen will automatically clear in 10 seconds\.\s+Your new PIN is: (\S+)/s)
	{
	    $prompt = "Your new PIN is: $1";
	}

	# Have to ask the user another question
	$p->{rp}->addAttrByNum($Radius::Radius::STATE,
			  "SECURID=$handle");
	$p->{rp}->addAttrByNum($Radius::Radius::REPLY_MESSAGE,
			  $prompt);
	return ($main::CHALLENGE, $clean_prompt);
    }
    else
    {
	# Auth finished, maybe OK, maybe not
	my $status;

	($result, $status) = Authen::ACE4::AceGetAuthenticationStatus($handle);
	$self->log($main::LOG_DEBUG, "AceGetAuthenticationStatus: $result, $status");
	$self->deleteContext($handle);
	if ($result == Authen::ACE4::ACE_SUCCESS
	    && $status == Authen::ACE4::ACM_OK)
	{
	    return ($main::ACCEPT);
	}
	else
	{
	    return ($main::REJECT, $clean_prompt);
	}
    }
}

#####################################################################
sub saveContext
{
    my ($self, $id) = @_;

    my $timeouthandle = &Radius::Select::add_timeout
	(time + $self->{Timeout},
	 \&handle_timeout, $self, $id);

    $Radius::AuthACE::contexts{$id} = $timeouthandle;
}

#####################################################################
sub deleteContext
{
    my ($self, $id) = @_;

    my $timeouthandle = $Radius::AuthACE::contexts{$id};
    &Radius::Select::remove_timeout($timeouthandle);
    delete $Radius::AuthACE::contexts{$id};
    &Authen::ACE4::AceCloseAuth($id);
}

#####################################################################
# Called whenever a contect has been active for too long
sub handle_timeout
{
    my ($handle, $self, $id) = @_;

    $self->deleteContext($id);
}

#####################################################################
# Reinitialize this instance
sub reinitialize
{
    my ($self) = @_;
    
    %Radius::AuthACE::contexts = ();
}

#####################################################################
# This is also called by the EAP_6 GTC code
# Return (2, challenge) for a challenge
#        (1, message) for success
#        (0, message) for failure
sub gtc_start
{
    my ($self, $eapcontext, $user) = @_;

    # This is a new request, start a new authentication
    &Authen::ACE4::AceInitialize() unless $Radius::AuthACE::initialised++;

    my ($result, $handle, $moreData, $echoFlag, $respTimeout, $nextRespLen, $prompt) 
	= Authen::ACE4::AceStartAuth($user);
    $eapcontext->{ace_handle} = $handle;

    # The context will time out automatically if
    # the auth never completes
    $self->saveContext($handle);

    # Sigh, ACE/Agent V 5 leaves trailing NULs
    $prompt =~ s/\000*$//;

    my $clean_prompt = $prompt; # For logging
    $clean_prompt =~ s/\n/ /g;

    return (0, "AceStartAuth failed: $clean_prompt")
	if $result != Authen::ACE4::ACM_OK;

    # Ask them a question
    return (2, 'CHALLENGE=' . $prompt);
}

#####################################################################
# This is also called by the EAP_6 GTC code
# Return (2, challenge) for a challenge
#        (1, message) for success
#        (0, message) for failure
sub gtc_continue
{
    my ($self, $eapcontext, $user, $data, $p) = @_;

  fakeresponse:
    my ($result, $moreData, $echoFlag, $respTimeout, $nextRespLen, $prompt) 
	= Authen::ACE4::AceContinueAuth($eapcontext->{ace_handle}, $data);
	    
    # Sigh, ACE/Agent V 5 leaves trailing NULs
    $prompt =~ s/\000*$//;

    my $clean_prompt = $prompt; # For logging
    $clean_prompt =~ s/\n/ /g;

    $self->log($main::LOG_DEBUG, "AceContinueAuth($data): $result, $moreData, $echoFlag, $respTimeout, $nextRespLen, $clean_prompt");
    return (0, "AceContinueAuth failed: $clean_prompt")
	if $result != Authen::ACE4::ACM_OK;

    if ($moreData)
    {
	# See if we need to short circuit
	if ($self->{EnableFastPINChange})
	{
	    if ($prompt =~ /Are you ready to enter a new PIN/)
	    {
		$data = 'y';
		goto fakeresponse;
	    }
	    elsif ($prompt =~ /Do you want the system to generate/)
	    {
		$data = 'n';
		goto fakeresponse;
	    }
	}
	# AM7.1 has misleading messages
	if ($prompt =~ /Your screen will automatically clear in 10 seconds\.\s+Your new PIN is: (\S+)/s)
	{
	    $prompt = "Your new PIN is: $1";
	}

	# Have to ask the user another question
	return (2, $prompt);
    }
    else
    {
	# Auth finished, maybe OK, maybe not
	my $status;

	($result, $status) = Authen::ACE4::AceGetAuthenticationStatus($eapcontext->{ace_handle});
	return (1)
	    if ($result == Authen::ACE4::ACE_SUCCESS && $status == Authen::ACE4::ACM_OK);
	#else
	return (0, $clean_prompt);
    }
}

#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_end
{
    my ($self, $eapcontext, $user) = @_;

    $self->deleteContext($eapcontext->{ace_handle});
}

1;
