# AuthLSA.pm
#
# Object for handling Authentication via Windows LSA functions
# This module supports PAP, CHAP, MSCHAP, MSCHAPV2 and LEAP authentication for
# dialup and wireless.
#
# Windows LSA is available on Windows 200, 2003 and XP, so this
# AuthBy only works on those platforms.
# It can authenticate against any local or remote Active Directory or NT domain.
#
# Requires Win32-Lsa 1.0 or better from Open System Consultants
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2003 Open System Consultants
# $Id: AuthLSA.pm,v 1.36 2013/02/15 21:24:40 mikem Exp $

package Radius::AuthLSA;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Radius::MSCHAP;
use Win32::Lsa;
use strict;

%Radius::AuthLSA::ConfigKeywords =
('Domain'           => 
 ['string', 'This optional parameter specifies which Windows domain will be used to authenticate passwords, regardless of whether the user supplies a domain when they log in. It can be the name of any valid domain in your network. The default is to authenticate against local accounts on the machine that Radiator is running on. Special characters are permitted.', 0],

 'DefaultDomain'    => 
 ['string', 'DefaultDomain
This optional parameter specifies the Windows Domain to use if the user does not specify a domain in their username. Special characters are supported. Can be an Active directory domain or a Windows NT domain controller domain name. Empty string (the default) means the local machine.', 1],

 'Workstation'      => 
 ['string', 'This optional parameter specifies a workstation name that will be used to check against workstation logon restrictions in the users account. If the user has any workstation restrictions specified in their account, this is the workstation name that will be used to check the restriction. Defaults to an empty string, which means that LSA will not check any workstation logon restrictions.', 1],

 'ProcessName'      => 
 ['string', 'This optional parameter specifies a process name for LSA internal logging. Defaults to "IAS". If the name is other than IAS, then NTLMV2 auuthentication may fail.', 1],

 'Origin'           => 
 ['string', 'This optional parameter specifies a request origin name for LSA internal logging. Defaults to "Radiator".', 1],

 'Source'           => 
 ['string', 'This optional parameter specifies a source name for LSA internal logging. Defaults to "Radiator".', 1],

 'Group'            => 
 ['stringarray', 'This optional parameter allows you to specify that each user must be the member of at least one of the named Windows Global or Local groups. More than one required group can be specified, one per Group line. Requires Win32::NetAdmin (which is installed by default with ActivePerl). If no Group parameters are specified, then Group checks will not be performed. ', 1],

 'DomainController' => 
 ['string', 'This optional parameter is used only if one or more Group check parameters are set. It specifies the name of the Windows Domain Controller that will be used to check each users Group membership. If no Group parameters are specified, DomainController will not be used. Defaults to empty string, meaning the default controller of the host where this instance of Radiator is running.', 1],

 );

# RCS version number of this module
$Radius::AuthLSA::VERSION = '$Revision: 1.36 $';

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();

    # Make sure we have privelege to 'run as part of the operating system'
    # (SE_TCB_PRIVILEGE = 7)
    my $status;
    if (($status = &Win32::Lsa::AdjustPrivilege(7, 1)) != 0)
    {
	my $msg = Win32::FormatMessage(&Win32::Lsa::NtStatusToWinError($status));
	$self->log($main::LOG_ERR, "Could not AdjustPrivilege SE_TCB_PRIVILEGE: $msg");
	return;
    }

    if (($status = &Win32::Lsa::RegisterLogonProcess($self->{ProcessName})) != 0)
    {
	my $msg = Win32::FormatMessage(&Win32::Lsa::NtStatusToWinError($status));
	$self->log($main::LOG_ERR, "Could not RegisterLogonProcess: $msg");
	return;
    }
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
    $self->{ProcessName} = 'IAS'; # Required for NTLMV2 LsaLogonUser to work :-(
    $self->{Origin}      = 'Radiator';
    $self->{Source}      = 'Radiator';
    $self->{Workstation} = '';
    $self->{NoDefault}   = 1;
}

#####################################################################
# This is a bogus findUser that basically does nothing but does not
# fail
sub findUser
{
    return Radius::User->new();
}

#####################################################################
# We subclass this to do special checks: there are no check items
# except the password, and only if its not an EAP
sub checkUserAttributes
{
    my ($self, $user, $p) = @_;
    
    my $userName = $p->getUserName();

    # Check for required group membership
    if (defined $self->{Group})
    {
	my $ismember;
	foreach (@{$self->{Group}})
	{
	    $ismember++, last if $self->userIsInGroup($userName, $_);
	}
	return ($main::REJECT, 'AuthBy LSA User is not a member of any Group') 
	    unless $ismember;
    }

    # Short circuit authetication in EAP requests ?
    return ($main::ACCEPT) 
	if $p->getAttrByNum($Radius::Radius::EAP_MESSAGE);

    return ($main::ACCEPT) if $self->check_password($p, $p->decodedPassword(), $userName);
    return ($main::REJECT, 'AuthBy LSA Password check failed');
}

#####################################################################
# $username is the users (rewritten) name
sub check_plain_password
{
    my ($self, $username, $submitted_pw, $correct_pw, $p) = @_;
    
    my ($domain, $user) = $self->crack_name($username, $p);
    $user =~ s/@[^@]*$// if $self->{UsernameMatchesWithoutRealm};
    my $status = &Win32::Lsa::LogonUserNetworkPAP
	($self->{Origin}, $self->{Source}, 
	 Radius::MSCHAP::ASCIItoUnicode($domain), 
	 Radius::MSCHAP::ASCIItoUnicode($user), 
	 Radius::MSCHAP::ASCIItoUnicode($self->{Workstation}), 
	 Radius::MSCHAP::ASCIItoUnicode($submitted_pw), lc($submitted_pw));
    
    if ($status != 0)
    {
	my $msg = Win32::FormatMessage(&Win32::Lsa::NtStatusToWinError($status));
	$msg = Win32::FormatMessage(&Win32::Lsa::NtStatusToWinError(&Win32::Lsa::getLastSubStatus())) 
	    if $status == 0xc000006e; #STATUS_ACCOUNT_RESTRICTION
	$self->log($main::LOG_WARNING, "Could not LogonUserNetworkPAP: $msg", $p);
	return;
    }

    return 1;
}

#####################################################################
# Overrideable function that checks a CHAP password response
# Also used by EAP_4.
# $p is the current request
# $username is the users (rewritten) name
# $pw is the ascii plaintext version of the correct password if known
sub check_chap
{
    my ($self, $p, $username, $pw, $chapid, $challenge, $response) = @_;

    my ($domain, $user) = $self->crack_name($username, $p);
    $user =~ s/@[^@]*$// if $self->{UsernameMatchesWithoutRealm};

    my $status = &Win32::Lsa::LogonUserNetworkCHAP
	($self->{Origin}, $self->{Source}, 
	 Radius::MSCHAP::ASCIItoUnicode($domain), 
	 Radius::MSCHAP::ASCIItoUnicode($user), 
	 Radius::MSCHAP::ASCIItoUnicode($self->{Workstation}), 
	 ord($chapid), $challenge, $response);
    
    if ($status != 0)
    {
	my $msg = Win32::FormatMessage(&Win32::Lsa::NtStatusToWinError($status));
	$msg = Win32::FormatMessage(&Win32::Lsa::NtStatusToWinError(&Win32::Lsa::getLastSubStatus())) 
	    if $status == 0xc000006e; #STATUS_ACCOUNT_RESTRICTION
	$self->log($main::LOG_WARNING, "Could not LogonUserNetworkCHAP: $msg", $p);
	return;
    }

    return 1;
}

#####################################################################
# Overrideable function that checks a MSCHAP password response
# $p is the current request
# $username is the users (rewritten) name
# $nthash is the NT Hashed of the correct password
# $usersessionkeydest is a ref to a string that will received the users session key
# $lanmansessionkeydest is a ref to a string that will received the Lanman session key
sub check_mschap
{
    my ($self, $p, $username, $nthash, $challenge, $response, 
	$usersessionkeydest, $lanmansessionkeydest) = @_;

    my ($domain, $user) = $self->crack_name($username, $p);
    $user =~ s/@[^@]*$// if $self->{UsernameMatchesWithoutRealm};
    my ($usersessionkey, $lanmansessionkey); # returned from LogonUserNetworkMSCHAP
    my $status = &Win32::Lsa::LogonUserNetworkMSCHAP
	($self->{Origin}, $self->{Source}, 
	 Radius::MSCHAP::ASCIItoUnicode($domain), 
	 Radius::MSCHAP::ASCIItoUnicode($user), 
	 Radius::MSCHAP::ASCIItoUnicode($self->{Workstation}), 
	 $challenge, $response, $usersessionkey, $lanmansessionkey);

    if ($status != 0)
    {
	my $msg = Win32::FormatMessage(&Win32::Lsa::NtStatusToWinError($status));
	$msg = Win32::FormatMessage(&Win32::Lsa::NtStatusToWinError(&Win32::Lsa::getLastSubStatus())) 
	    if $status == 0xc000006e; #STATUS_ACCOUNT_RESTRICTION
	$self->log($main::LOG_WARNING, "Could not LogonUserNetworkMSCHAP: $msg", $p);
	return;
    }
    $$usersessionkeydest   = $usersessionkey   if defined $usersessionkeydest;
    $$lanmansessionkeydest = $lanmansessionkey if defined $lanmansessionkeydest;
    return 1;
}

#####################################################################
# Overrideable function that checks a MSCHAP password response
# $p is the current request
# $username is the users (rewritten) name
# $nthash is the NT Hashed of the correct password
# $usersessionkeydest is a ref to a string that will received the users session key
# $lanmansessionkeydest is a ref to a string that will received the Lanman session key
sub check_mschapv2
{
    my ($self, $p, $username, $nthash, $authchallenge, $peerchallenge, $response, 
	$mppekeys_dest, $authenticator_responsedest, $lanmansessionkeydest) = @_;

    my ($usersessionkey, $lanmansessionkey); # returned from LogonUserNetworkMSCHAP
    my ($domain, $user) = $self->crack_name($username, $p);
    my $challenge = &Radius::MSCHAP::ChallengeHash
	($peerchallenge, $authchallenge, $user);

    # If this is obviously a host name, convert it to an NT host name format
    # so we can do machine authentication
    # user name for session key calculations For machine auth, must be done on the
    # original user name, not the result of UsernameFormat or machine name rewriting.
    # for user auth must be the cracked name (no domain)
    my $kuser = $user; 
    if ($user =~ /^host\/([^\.]+)/) { $user = "$1\$"; }
    $user =~ s/@[^@]*$// if $self->{UsernameMatchesWithoutRealm};

    my $status = &Win32::Lsa::LogonUserNetworkMSCHAP
	($self->{Origin}, $self->{Source}, 
	 Radius::MSCHAP::ASCIItoUnicode($domain), 
	 Radius::MSCHAP::ASCIItoUnicode($user), 
	 Radius::MSCHAP::ASCIItoUnicode($self->{Workstation}), 
	 $challenge, $response, $usersessionkey, $lanmansessionkey);

    if ($status != 0)
    {
	my $msg = Win32::FormatMessage(&Win32::Lsa::NtStatusToWinError($status));
	my $substatus = &Win32::Lsa::getLastSubStatus();
	$msg = Win32::FormatMessage(&Win32::Lsa::NtStatusToWinError($substatus)) if $status == 0xc000006e;
	$self->log($main::LOG_WARNING, "Could not LogonUserNetworkMSCHAP (V2): $status, $substatus, $msg", $p);
	return;
    }

    # Maybe generate MPPE keys. 
    $$mppekeys_dest = Radius::MSCHAP::mppeGetKey($usersessionkey, $response, 16)
	if defined $mppekeys_dest;

    # Maybe generate an MSCHAP authenticator response. 
    $$authenticator_responsedest = &Radius::MSCHAP::GenerateAuthenticatorResponseHash
	($usersessionkey, $response, $peerchallenge, $authchallenge, $kuser)
        if defined $authenticator_responsedest;
    $$lanmansessionkeydest = $lanmansessionkey if defined $lanmansessionkeydest;
    return 1;
}


#####################################################################
# Check if the user is in the global group
sub userIsInGroup
{
    my ($self, $user, $group) = @_;

    require Win32::NetAdmin;
    import Win32::NetAdmin;

    my ($domain, $username) = $self->crack_name($user);
    # If this is obviously a host name, strip the host part
    # so we can check group membership
    if ($username =~ /^host\/([^\.]+)/)
    {
	$username = "$1\$";
    }
    $username =~ s/@[^@]*$// if $self->{UsernameMatchesWithoutRealm};

    # Find the controller to use
    my $controller = $self->{DomainController};
    if (!defined $controller)
    {
	$controller = $self->{controllers}{$domain};
	if (!defined $controller)
	{
	    &Win32::NetAdmin::GetAnyDomainController(undef, $domain, $controller);
	    $self->{controllers}{$domain} = $controller;
	}
    }
    $self->log($main::LOG_DEBUG, "Checking LSA Group membership for $controller, $group, $username");
    return &Win32::NetAdmin::GroupIsMember($controller, $group, $username)
	|| &Win32::NetAdmin::LocalGroupIsMember($controller, $group, $username);
}


1;
