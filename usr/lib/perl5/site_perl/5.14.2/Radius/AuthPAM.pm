# AuthPAM.pm
#
# Object for handling Authentication via PAM passwords.
#
# This file will be 'require'd only one time when the first Realm 
# with an AuthType of PAM is found in the config file
#
# This module can check an PAM user password, but cant do any
# check or reply items. Cant handle CHAP, only PAP
# Accounting packets ar ignored.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthPAM.pm,v 1.19 2009/10/04 06:27:57 mikem Exp $

package Radius::AuthPAM;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Authen::PAM;   
use strict;

%Radius::AuthPAM::ConfigKeywords = 
('Service'   => 
 ['string', 'This optional parameter specifies the PAM service to be used to authenticate the user name. If not specified, it defaults to "login".', 0],

 'UsePamEnv' => 
 ['flag', 'This optional parameter allow you to get UID, GID etc. if your PAM supports it, and your Authen::PAM was compiled with -DHAVE_PAM_ENV_FUNCTIONS. This can be useful with some PAM authenticators like Encotone\'s TeleId, which can supply the UID and GID of the user.', 1],

 );

# RCS version number of this module
$Radius::AuthPAM::VERSION = '$Revision: 1.19 $';

# This hold a pointer to the current request packet. Its used to pass that
# data to the PAM conversatin function. There is no other way.

my $current_request;

# This holds text messages from the PAM conversation function
my $last_message;

# This is a list of secondary groups for the most recently
# authenticated user
my $last_groups;

# This is the primary group for the most recently
# authenticated user
my $last_group;

# This is password prompt expected from the PAM module
my $password_prompt;

# This has tells how to translate PAM env variables to Radius
# reply attributes.
# REVISIT: should be configurable
my %env_map = (
	       'UID' => 'OSC-Uid',
	       'GID' => 'OSC-Gid',
	       'HOME' => 'OSC-Home',
	       'SHELL' => 'OSC-Shell',
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
    $self->{Service} = 'login';
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

    $p->{PacketTrace} = $self->{PacketTrace} 
        if defined  $self->{PacketTrace}; # Optional extra tracing

    $self->log($main::LOG_DEBUG, "Handling with PAM service $self->{Service}", $p);

    # Now we might fork before processing the request
    # Should only do this for "slow" authentication methods
    return ($main::IGNORE, 'forked')
	if $self->{Fork} && !$self->handlerFork();

    if ($p->code eq 'Access-Request')
    {
	my $user_name = $p->getUserName;
	# PAM on Solaris can get into an infinite loop if there is no username
	return ($main::REJECT, 'PAM requires User-Name')
	    unless length $user_name;

	$user_name = $p->get_attr($self->{AuthenticateAttribute})
            if $self->{AuthenticateAttribute};
	$user_name =~ s/@[^@]*$//
	    if $self->{UsernameMatchesWithoutRealm};
	$password_prompt = $self->{PasswordPrompt};
	my $password = $p->decodedPassword();
	my ($result, $reason, $res);
	my $pamh = new Authen::PAM($self->{Service}, $user_name, \&pam_conv_func);

	if (!ref($pamh))
	{
	    $self->log($main::LOG_ERR, "Could not connect to PAM service $self->{Service}", $p);
	    return ($main::IGNORE, 'Software failure');
	}
	# Theres nowhere to pass any context to the conversation function, so we will
	# pass it in a module variable. Gag. Dont forget to undef it later
	# else its a temporary memory leak (only one packet is ever held)
	$current_request = $p;
	$last_message = undef;
	if (   ($res = $pamh->pam_authenticate(0)) 
	          == Authen::PAM::PAM_SUCCESS
	    && ($res = $pamh->pam_acct_mgmt(0)) 
	          == Authen::PAM::PAM_SUCCESS)
	{ 
	    # Password is correct and no account restrictions apply

	    # Maybe get PAM env variables and turn them into
	    # reply attributes
	    if ($self->{UsePamEnv}
		&& Authen::PAM::HAVE_PAM_ENV_FUNCTIONS()) 
	    {
		my %env = $pamh->pam_getenvlist();
		my $env;
		foreach $env (keys %env)
		{
#		    print "trying $env, $env{$env}\n";
		    my $attr = $env_map{$env};
		    $p->{rp}->add_attr($attr, $env{$env}) if defined $attr;
		    if ($env eq 'GROUPS')
		    {
			# List of secondary groups the user is in
			$last_groups = $env{$env};
		    }		    
		    elsif ($env eq 'GROUP')
		    {
			# Primary groups the user is in
			$last_group = $env{$env};
		    }
		}
	    }

	    # Forget about that request;
	    $current_request = undef;

	    # Add and strip attributes before replying
	    $self->adjustReply($p);
		
	    # Password OK, run the extra_checks, perhaps there
	    # is a Group item we have to check?
	    return $self->checkAttributes($extra_checks, $p)
		if $extra_checks;
	    
	    $p->{Handler}->logPassword($user_name, $password, 'PAM', 1, $p) if $p->{Handler};
	    $result = $main::ACCEPT;
	} 
	else 
	{     	    
	    $p->{Handler}->logPassword($user_name, $password, 'PAM', 0, $p) if $p->{Handler};
	    $result = $main::REJECT;
	    $reason = $pamh->pam_strerror($res) . ': ' . $last_message;
	    # Forget about that request;
	    $current_request = undef;
	}    
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
# This is the conversation function that will be called by pam_authenticate to 
# get the users password and any other details it needs
sub pam_conv_func 
{
    my @res;
    while ( @_ ) 
    {
	# Find out what PAM wants
        my $type = shift;
        my $msg = shift;

	$msg =~ s/:\s*$//; # Strip the trailing colon and whitespace
	&main::log($main::LOG_DEBUG, "PAM is asking for $type: '$msg'", $current_request);
	my $answer;

	if ($type == Authen::PAM::PAM_PROMPT_ECHO_OFF 
	    && $msg =~ /$password_prompt/i)
	{
	    # PAM wants the decoded password
	    $answer = $current_request->decodedPassword();
	}
	elsif ($type == Authen::PAM::PAM_PROMPT_ECHO_ON)
	{
	    # PAM wants something else, try to find it in the incoming request
	    $answer = $current_request->get_attr($msg);
	}
	elsif ($type == Authen::PAM::PAM_ERROR_MSG
	       || $type == Authen::PAM::PAM_TEXT_INFO)
	{
	    # PAM is telling us something, use it in handle_request
	    $answer = '';
	    $last_message = $msg;
	}

        push @res, (0, $answer);  # Mandatory: no other options are supported
    }
    push @res, Authen::PAM::PAM_SUCCESS; # Let PAM know the function succeeded
    return @res;
}

#####################################################################
# Check if the user is in the group
# $user is a user name and $group is a group name
sub userIsInGroup
{
    my ($self, $user, $group) = @_;

    # We see if the user appears in the comma separated list of users
    # in the group entry
    # If they are not there perhaps this site has exceeded the 
    # max number of group entries, then check their primary
    # group
    return 1 if grep { $_ eq $group } split(/\s+/, $last_groups);

    # Check the primary group. We have cached the group ID
    return defined $last_group && $group == $last_group;
}

 
1;
