# AuthNTLM.pm
#
# Object for handling Authentication via the Samba ntlm_auth program,
# which allows Radiator running on UNix or Linux to autyenticate to a Windows domain controller.
#
# This module supports PAP, CHAP, MSCHAP, MSCHAPV2 and LEAP authentication for
# dialup and wireless.
#
# Requires ntlm_auth and winbindd programs to be installed and properly configured, 
# which are part of the Samba suite (www.samba.org). Se goodies/smb.conf.winbindd for an example config 
# for winbindd that will allow authentiaiton to a remote PDC
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2003-2005 Open System Consultants
# $Id: AuthNTLM.pm,v 1.28 2013/10/07 21:04:03 hvn Exp $

package Radius::AuthNTLM;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Radius::MSCHAP;
use IPC::Open2;
use MIME::Base64;
use POSIX ":sys_wait_h";
use strict;

%Radius::AuthNTLM::ConfigKeywords =
('NtlmAuthProg'                => 
 ['string', 'This optional parameter specifies the path name and arguments for the ntlm_auth program. Defaults to "/usr/bin/ntlm_auth --helper-protocol=ntlm-server-1".', 1],

 'Domain'                      => 
 ['string', 'This optional parameter specifies which Windows domain will be used to authenticate passwords, regardless of whether the user supplies a domain when they log in. It can be the name of any valid domain in your network. Special characters are permitted. The default is to use the domain configured into winbindd.', 0],

 'DefaultDomain'               => 
 ['string', 'This optional parameter specifies the Windows Domain to use if the user does not specify a domain in their username. Special characters are supported. Can be an Active directory domain or a Windows NT domain controller domain name. Empty string (the default) means the domain configured into winbindd.', 1],

 'UsernameFormat'              => 
 ['string', 'Controls how the user name that will be sent to NTLM will be derived from User-Name.', 1],

 'DomainFormat'                => 
 ['string',  'Controls how the domain name that will be sent to NTLM will be derived from User-Name.', 1],

 );

# RCS version number of this module
$Radius::AuthNTLM::VERSION = '$Revision: 1.28 $';

# Make sure we get reinitialized on sighup. When this happens the
# authby instances can be found from the array.
push(@main::reinitFns, \&reinitialize);
my @authbys;

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
    $self->{NoDefault}   = 1;
    $self->{NtlmAuthProg} = '/usr/bin/ntlm_auth --helper-protocol=ntlm-server-1';
    $self->{UsernameFormat} = '%0';
    $self->{DomainFormat} = '%0';
  
    # Add to list of current authby instances.
    push @Radius::AuthNTLM::authbys, $self;

    return;
}

#####################################################################
# This function is called automatically during a SIGHUP,
# Make sure we dont retain any references to registered objects.
# If we do not do waitpid(), we will have ntlm_auth zombies.
sub reinitialize
{
    foreach my $authby (@Radius::AuthNTLM::authbys)
    {
	next unless $authby->{child_pid};

	close ($authby->{read_handle})  if $authby->{read_handle};
	close ($authby->{write_handle}) if $authby->{write_handle};
	$authby->{read_handle} = $authby->{write_handle} = undef;

	# Make sure we do not wait forever if ntlm_auth is stuck
	Radius::Util::exec_timeout(2,
	       sub {
		   waitpid($authby->{child_pid}, 0); # Reap it
		   });
    }
    @Radius::AuthNTLM::authbys = ();

    return;
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

    # Short circuit authetication in EAP requests ?
    return ($main::ACCEPT) 
	if $p->getAttrByNum($Radius::Radius::EAP_MESSAGE);

    return ($main::ACCEPT) if $self->check_password($p, $p->decodedPassword(), $userName);
    return ($main::REJECT, 'AuthBy NTLM Password check failed');
}

#####################################################################
sub check_plain_password
{
    my ($self, $username, $submitted_pw, $correct_pw, $p) = @_;
    
    my ($domain, $user) = $self->crack_name($username, $p);
    $user =~ s/@[^@]*$// if $self->{UsernameMatchesWithoutRealm};
    $user = &Radius::Util::format_special($self->{UsernameFormat}, $p, undef, $user);
    $domain = &Radius::Util::format_special($self->{DomainFormat}, $p, undef, $domain);

    my %result = $self->do_ntlm_io
	($p,
	 'Username:'  => encode_base64($user, ''),
	 'NT-Domain:' => encode_base64($domain, ''),
	 'Password:'  => encode_base64($submitted_pw, ''));
			    
    if ($result{'Authenticated'} ne 'Yes')
    {
	$result{'Authentication-Error'} = 'Unknown' unless defined $result{'Authentication-Error'};
	$self->log($main::LOG_WARNING, "NTLM Could not authenticate user: $result{'Authentication-Error'}", $p);
	return;
    }

    return 1;
}

#####################################################################
# Overrideable function that checks a CHAP password response
# $p is the current request
# $username is the users (rewritten) name
# $pw is the ascii plaintext version of the correct password if known
sub check_chap
{
    my ($self, $p, $username, $pw, $chapid, $challenge, $response) = @_;

    $self->log($main::LOG_WARNING, 'NTLM cannot authenticate with CHAP. Rejecting', $p);
    return;
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
    $user = &Radius::Util::format_special($self->{UsernameFormat}, $p, undef, $user);
    $domain = &Radius::Util::format_special($self->{DomainFormat}, $p, undef, $domain);

    my %result = $self->do_ntlm_io
	($p,
	 'Username:'                  => encode_base64($user, ''),
	 'NT-Domain:'                 => encode_base64($domain, ''),
	 'LANMAN-Challenge'           => unpack('H*', $challenge),
	 'NT-Response'                => unpack('H*', $response),
	 'Request-User-Session-Key'   => 'Yes',
	 'Request-LanMan-Session-Key' => 'Yes');
			    
    if ($result{'Authenticated'} ne 'Yes')
    {
	$result{'Authentication-Error'} = 'Unknown' unless defined $result{'Authentication-Error'};
	$self->log($main::LOG_WARNING, "NTLM Could not authenticate user: $result{'Authentication-Error'}", $p);
	return;
    }
    $$usersessionkeydest = pack('H*', $result{'User-Session-Key'})     if defined $usersessionkeydest;
    $$lanmansessionkeydest = pack('H*', $result{'LANMAN-Session-Key'}) if defined $lanmansessionkeydest;
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

    my ($domain, $user) = $self->crack_name($username, $p);
    my $challenge = &Radius::MSCHAP::ChallengeHash($peerchallenge, $authchallenge, $user); 
    # If this is obviously a host name, convert it to an NT host name format
    # so we can do machine authentication
    # Unfortunately, winbindd does not yet handle machine authentication: in samba/source/rpc_client/cli_netlogon.c, 
    # cli_netlogon_sam_network_logon() function
    # the param_ctrl flags passed to init_id_info2() are always set to 0 but
    # should be set to 0x800 (MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT) 
    # to enable machine auth.
    # Otherwise we get Authentication-Error: No logon workstation trust account
    # from ntlm_auth
    # user name for session key calculations For machine auth, must be done on the
    # original user name, not the result of UsernameFormat or machine name rewriting.
    # for user auth must be the cracked name (no domain)
    my $kuser = $user; 
    if ($user =~ /^host\/([^\.]+)/) { $user = "$1\$"; }
    $user =~ s/@[^@]*$// if $self->{UsernameMatchesWithoutRealm};

    $user = &Radius::Util::format_special($self->{UsernameFormat}, $p, undef, $user);
    $domain = &Radius::Util::format_special($self->{DomainFormat}, $p, undef, $domain);
    
    my %result = $self->do_ntlm_io
	($p,
	 'Username:'                  => encode_base64($user, ''),
	 'NT-Domain:'                 => encode_base64($domain, ''),
	 'LANMAN-Challenge'           => unpack('H*', $challenge),
	 'NT-Response'                => unpack('H*', $response),
	 'Request-User-Session-Key'   => 'Yes',
	 'Request-LanMan-Session-Key' => 'Yes');
			    
    if ($result{'Authenticated'} ne 'Yes')
    {
	$self->log($main::LOG_WARNING, "NTLM Could not authenticate user '$username': $result{'Authentication-Error'}", $p);
	return;
    }

    # Maybe generate MPPE keys. 
    my $usersessionkey = pack('H*', $result{'User-Session-Key'});
    $$mppekeys_dest = Radius::MSCHAP::mppeGetKey($usersessionkey, $response, 16)
	if defined $mppekeys_dest;

    # Maybe generate an MSCHAP authenticator response. 
    $$authenticator_responsedest = &Radius::MSCHAP::GenerateAuthenticatorResponseHash
	($usersessionkey, $response, $peerchallenge, $authchallenge, $kuser)
        if defined $authenticator_responsedest;
    $$lanmansessionkeydest = pack('H*', $result{'LANMAN-Session-Key'}) if defined $lanmansessionkeydest;
    return 1;
}

#####################################################################
# Perhaps connect to the child program, pass it some request strings, followed by a single
# . and pass back the results
# Keys in %args that end in ':' are in base64, else in plaintext
sub do_ntlm_io
{
    my ($self, $p, %args) = @_;

    # Maybe (re)start the child
    if (!$self->{read_handle})
    {
	# Not connected, connect now
	$self->log($main::LOG_INFO, "Starting NtlmAuthProg: $self->{NtlmAuthProg}", $p);
	$self->{child_pid} = open2($self->{read_handle}, $self->{write_handle}, $self->{NtlmAuthProg});
    }

    # Push the input arguments onto the childs stdin
    foreach (keys %args)
    {
	# We always encode to base 64, becuase theres no guaranteee there are not silly binary chars
	# even in Username and Password
	my $attr = "$_: $args{$_}";
	$self->log($main::LOG_DEBUG, "Passing attribute $attr", $p);
	if (!print {$self->{write_handle}} "$attr\n")
	{
	    my $err = $!;
	    $self->log($main::LOG_ERR, "sending to NtlmAuthProg failed: $err", $p);
	    $self->{read_handle} = $self->{write_handle} = undef;
	    waitpid($self->{child_pid}, &main::WNOHANG); # Reap it
	    return ('Authentication-Error' => "sending to NtlmAuthProg failed: $err");
	}
    }
    if (!print {$self->{write_handle}} ".\n") # Tell ntlm_auth thats the end of the input
    {
	my $err = $!;
	$self->log($main::LOG_ERR, "sending to NtlmAuthProg failed: $err", $p);
	$self->{read_handle} = $self->{write_handle} = undef;
	waitpid($self->{child_pid}, &main::WNOHANG); # Reap it
	return ('Authentication-Error' => "sending . to NtlmAuthProg failed: $err");
    }

    # Now get back the reply attrs from stdout of the child
    my %result;
    # Sigh: ntlm_auth version 3.0.10 and others sends _2_ '.' lines if authentication fails.
    my $got_some_results;
    while ( defined ($_ = readline($self->{read_handle})))
    {
	chomp;
	$self->log($main::LOG_DEBUG, "Received attribute: $_", $p);
	if ($_ eq '.')
	{
	    # End of results, return, but absorm the . if we have had no results yet
	    return %result if $got_some_results;
	}
	elsif (/^(.*): (.*)$/)
	{
	    # Add a new result
	    $got_some_results++;
	    $result{$1} = $2;
	}
	else
	{
	    $self->log($main::LOG_WARNING, "Unexpected output from NtlmAuthProg: $_", $p);
	}
    }
    if (eof)
    {
	$self->log($main::LOG_WARNING, 'EOF from NtlmAuthProg', $p);
	$self->{read_handle} = $self->{write_handle} = undef;
    }
    return %result;
}

1;
