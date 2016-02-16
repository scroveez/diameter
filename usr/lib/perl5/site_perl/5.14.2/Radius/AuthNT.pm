# AuthNT.pm
#
# Object for handling Authentication via NT passwords.
#
# This file will be 'require'd only one time when the first Realm 
# with an AuthType of NT is found in the config file
#
# This module can check an NT user password, but cant do any
# check or reply items. Cant handle CHAP, only PAP
# Accounting packets are ignored.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthNT.pm,v 1.36 2007/12/18 21:23:50 mikem Exp $

package Radius::AuthNT;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;

if ($^O eq 'MSWin32')
{
    # Running on Win95 or NT
    require Win32::NetAdmin;
    import Win32::NetAdmin;
    require Win32::AuthenticateUser;
    import Win32::AuthenticateUser;
}
else
{
    # Running on Unix
    require Authen::Smb;
}

use strict;

%Radius::AuthNT::ConfigKeywords = 
('Domain'               => 
 ['string', 'Specifies the name of the NT user domain that is to be checked for the user name and password (this is not necessarily the same as a DNS domain). The Domain Controller for the Domain you specify is consulted for account details, passwords and Group membership. The default for Domain is undefined, which means (on NT) to check passwords for the default domain for the host where Radiator is running. When running Radiator on Unix, you must specify the Domain.', 0],

 'DomainController'     => 
 ['string', 'This optional parameter allows you to specify the name of your Domain Controller. If you don\'t specify DomainController when running Radiator on NT, Radiator will attempt to determine the name of your Domain Controller by polling the network. You would not normally need to set this when running Radiator on NT. If you do set it, it must be set to the network name of the domain controller, including the leading backslashes (\).', 0],

 'IgnoreAccountDisable' => 
 ['flag', 'On Windows, this optional parameter causes AuthBy NT to ignore the NT Account Disabled flag.', 1],

 'IgnoreAccountLockout' => 
 ['flag', 'On Windows, this optional parameter causes AuthBy NT to ignore the NT Account Lockout flag.', 1],

 'IgnoreAccountExpiry'  => 
 ['flag', 'On Windows, this optional parameter causes AuthBy NT to ignore the NT Account Expiry flag.', 1],

 'IgnorePasswordExpiry' => 
 ['flag', 'On Windows, this optional parameter causes AuthBy NT to ignore the NT password Expiry flag.', 1],

 'IgnorePasswordChange' => 
 ['flag', 'On Windows, this optional parameter causes AuthBy NT to ignore the NT password change required flag.', 1],

 'CheckGroupServer'     => 
 ['string', 'The name of an NT server that will be used to determine group memberships if GroupRequired or CheckGroup parameters are specified.', 1],

 'CheckGroup'           => 
 ['stringarray', 'This optional parameter allows you to specify a RADIUS Class attribute that depends on Windows group membership. AuthBy NT may contain 0 or more CheckGroup lines. Each line is in the format:
<p><code><pre>groupname,classname</pre></code>', 1],

 'GroupRequired'        => 
 ['string', 'On Windows, this optional parameter causes AuthBy NT to ensure that the user is a member of the named group during authentication. The NT server named by the CheckGroupServer parameter will be consulted, and CheckGroupServer must be defined in order to use GroupRequired or CheckGroup.', 1],

 );

# RCS version number of this module
$Radius::AuthNT::VERSION = '$Revision: 1.36 $';

# These are strings for the error codes returned by 
# Authen::Smb::authen
my %errorNames = ( 
		   '0', 'No Error',
		   '1', 'Server Error',
		   '2', 'Protocol Error',
		   '3', 'Logon Error',
		   );

#####################################################################
# Override the keyword function in Configurable
sub keyword
{
    my ($self, $file, $keyword, $value) = @_;

    if ($keyword eq 'HonourDialinPermission')
    {
	$self->{HonourDialinPermission}++;
	if ($^O eq 'MSWin32')
	{
	    # Running on Win95 or NT
	    require Win32::RasAdmin;
	    import Win32::RasAdmin;
	}
	return 1;
    }
    else
    {
	return $self->SUPER::keyword($file, $keyword, $value);
    }
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

    $self->log($main::LOG_DEBUG, "Handling with NT", $p);
    return ($main::IGNORE, "Ignored due to IgnoreAuthentication")
	if $self->{IgnoreAuthentication} 
           && $p->code eq 'Access-Request';
    return ($main::IGNORE, "Ignored due to IgnoreAccounting")
	if $self->{IgnoreAccounting} 
           && $p->code eq 'Accounting-Request';


    # Now we might fork before processing the request
    # ON Windows, the password check can be slow for bad passwords
    return ($main::IGNORE, 'forked')
	if $self->{Fork} && !$self->handlerFork();

    if ($p->code eq 'Access-Request')
    {
	# Maybe we have to handle EAP?
	if (defined $p->getAttrByNum($Radius::Radius::EAP_MESSAGE))
	{
	    my ($result, $reason);
	    eval {require Radius::EAP; 
		  ($result, $reason) = $self->authenticateUserEAP($p)};
	    if ($@)
	    {
		$self->log($main::LOG_ERR, "Could not handle an EAP request: $@");
		return ($main::REJECT, 'Could not handle an EAP request');
	    }
	    $self->log($main::LOG_DEBUG, "EAP result: $result, $reason", $p);
	    return ($result, $reason);
	}

	my $user_name = $p->getUserName;
	$user_name =~ s/@[^@]*$//
	    if $self->{UsernameMatchesWithoutRealm};
	my $password = $p->decodedPassword();

	if ($^O eq 'MSWin32')
	{
	    # Find out the server name for our domain controller
	    # Note: this can take 20 secs if there is no domain
	    # controller defined for you
	    if (!defined $self->{DomainController})
	    {
		my $serverName;
		&Win32::NetAdmin::GetDomainController('', 
						      $self->{Domain},
						      $serverName);
		# We use an empty server name if there is no domain
		# controller
		$self->{DomainController} = "$serverName";
		$self->log($main::LOG_DEBUG, "Domain Controller name is $self->{DomainController}", $p);
	    }
	    
	    # First find out some things about the account
	    my ($GetUserfullname, 
		$Getpassword, $GetpasswordAge, $Getprivilege, 
		$GethomeDir, $Getcomment, $Getflags, $Getscriptpath);
	    my $result = Win32::NetAdmin::UserGetAttributes
		($self->{DomainController}, $user_name,
		 $Getpassword, $GetpasswordAge, $Getprivilege, 
		 $GethomeDir, $Getcomment, $Getflags, $Getscriptpath);
	    my $error = &Win32::NetAdmin::GetError();
	    if ($error != 0) # ERROR_SUCCESS
	    {
		my $msg = Win32::FormatMessage($error);
		$msg = "No such user" if $error == 2221; # Undocumented
		return ($main::REJECT, "NT GetAttributes failed: $error: $msg");
	    }
	    # Got user details OK, check some interesting flags
	    if ($Getflags & &UF_ACCOUNTDISABLE
		&& !$self->{IgnoreAccountDisable})
	    {
		return ($main::REJECT, "Account is disabled");
	    }
	    if ($Getflags & &UF_LOCKOUT
		&& !$self->{IgnoreAccountLockout})
	    {
		return ($main::REJECT, "Account is Locked");
	    }

	    # Maybe check if the user has dialin permission set?
	    if ($self->{HonourDialinPermission}
		&& $^O eq 'MSWin32')
	    {
		# Running on Win95 or NT
		require Win32::RasAdmin;
		import Win32::RasAdmin;

		my %rasinfo;
	        Win32::RasAdmin::UserGetInfo($self->{Domain}, $user_name, \%rasinfo);
		return ($main::REJECT, "No Dialin Privilege")
		    unless $rasinfo{Privilege} & &RASPRIV_DialinPrivilege;
	    }

	    if (!$self->{NoCheckPassword})
	    {
		# OK, the account exists, and no flags prevent its use, so
		# check the password. 
		$result = Win32::AuthenticateUser::AuthenticateUser
		    ($self->{Domain}, $user_name, $password);
		$error = &Win32::GetLastError();
		# 1793 is account expired
		# 1330 is password expired
		# 1907 is user must change password
		if (!$result 
		    && !($self->{IgnoreAccountExpiry} && $error == 1793)
		    && !($self->{IgnorePasswordExpiry} && $error == 1330)
		    && !($self->{IgnorePasswordChange} && $error == 1907))
		{
		    $p->{Handler}->logPassword($user_name, $password, 'NT', 0, $p) if $p->{Handler};
		    my $message = &Win32::FormatMessage($error);
		    return ($main::REJECT, "NT AuthenticateUser failed: $message");
		}
		else
		{
		    $p->{Handler}->logPassword($user_name, $password, 
					       'NT', 1, $p);
		}
	    }

	    # If GroupRequired is set, make sure user is a member
	    # Mark Motley <mark.motley@earthtech.com>
	    if (defined $self->{GroupRequired} && defined $self->{CheckGroupServer})
	    {
		require Win32::NetAdmin;
		if (! Win32::NetAdmin::GroupIsMember
		    ($self->{CheckGroupServer},
		     $self->{GroupRequired},
		     $user_name))
		{
		    $self->log($main::LOG_DEBUG, "$user_name is not a member of required group $self->{GroupRequired}, access denied", $p);
		    return ($main::REJECT, "User not member of $self->{GroupRequired}");
		}
	    }
	    
	    # Begin group checking, contributed by 
	    # Michael Audet <audet@vectorcore.com>
	    if (defined $self->{CheckGroup}
	    && defined $self->{CheckGroupServer})
	    {
		require Win32::NetAdmin;
		
		my $ref;
		foreach $ref (@{$self->{CheckGroup}}) 
		{
		    my ($groupname, $groupreply) = split (/\s*,\s*/, $ref, 2);
		    
		    if (Win32::NetAdmin::GroupIsMember
			($self->{CheckGroupServer},
			 $groupname, $user_name)) 
		    {
			$self->log($main::LOG_DEBUG, "$user_name is member of $groupname group, assigning Class $groupreply", $p);
			$p->{rp}->add_attr("Class", $groupreply);
			last;
		    } 
		}
	    }
	
	    # Add and strip attributes before replying
	    $self->adjustReply($p);
	    
	    # Password OK, run the extra_checks, perhaps there
	    # is a Group item we have to check?
	    return $self->checkAttributes($extra_checks, $p)
		if $extra_checks;
	    
	    return ($main::ACCEPT);
	}
	else
	{
	    # On Unix, use Authen::Smb
	    if (!$self->{NoCheckPassword})
	    {
		my $authResult = Authen::Smb::authen
		    ($user_name, 
		     $password,
		     $self->{DomainController}, # Primary
		     $self->{DomainController}, # Secondary
		     $self->{Domain});

		if ($authResult == 0) # Authen::Smb::NTV_NO_ERROR
		{
		    $p->{Handler}->logPassword($user_name, $password, 'NT', 1, $p) if $p->{Handler};
		}
		else
		{
		    $p->{Handler}->logPassword($user_name, $password, 'NT', 0, $p) if $p->{Handler};
		    return ($main::REJECT,
			    "NT Authentication failed: $errorNames{$authResult} ($authResult)");
		}
	    }
	    # Hmmm, if NoCheckPasssword is set on Unix,
	    # there are no check items applied!
	    # All OK, Add and strip attributes before replying
	    $self->adjustReply($p);
	    
	    # Password OK, run the extra_checks, perhaps there
	    # is a Group item we have to check?
	    return $self->checkAttributes($extra_checks, $p)
		if $extra_checks;
	    
	    return ($main::ACCEPT);
	}
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

#####################################################################
# Check if the user is in the global group
sub userIsInGroup
{
    my ($self, $user, $group) = @_;

    if ($^O eq 'MSWin32') 
    {
        return Win32::NetAdmin::GroupIsMember($self->{DomainController}, $group, $user)
	    || Win32::NetAdmin::LocalGroupIsMember($self->{DomainController}, $group, $user);
    } 
    else 
    {
        # Running on Unix
	# There's no NT Group checking with Authen::SMB so ignore
	# by default.
        return 1;
    }
}


1;
