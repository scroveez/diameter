# AuthSAFEWORD.pm
#
# Object for handling Authentication via One-Time-Passwords
# This module handles generic SAFEWORD authentication for either dialup 
# EAP-OTP or EAP-GTC. It connects to a SafeWork PremmierAccess server
# using XML and sends queries to that server.
#
# CAUTION: in order to support CHAP with fixed passwords, 
# the user must be configured in 
# SafeWord Premier Access to use a 
# fixed password profile that has 'Passwords are case sensitive' enabled. This will
# usually involve creating a new Fixed Password profile, and assigning that
# as the fixed password profile, then setting or resetting the users password.
# 
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001-2006 Open System Consultants
# $Id: AuthSAFEWORD.pm,v 1.11 2012/05/22 22:03:41 mikem Exp $

package Radius::AuthSAFEWORD;
@ISA = qw(Radius::AuthGeneric);
use IO::Socket::SSL;
use Radius::AuthGeneric;
use Radius::Context;
use strict;

%Radius::AuthSAFEWORD::ConfigKeywords =
(
 'Host'                   => 
 ['string', 'This parameter specifies the name or address of the SafeWord PremierAccess server to connect to. The connection will be made with SSL. Defaults to "localhost".', 0],

 'Port'                   => 
 ['string', 'This parameter specifies the port name or number to connect to on Host. Defaults to 5031, the default SafeWord EASSP2 port.', 0],

 'LocalAddr'              => 
 ['string', 'Local host bind address.', 1],

 'Timeout'                => 
 ['integer', 'This optional parameter specifies a timeout in seconds. If the connection to the SAFEWORD server is not complete within this time, the authentication will fail with REJECT. ', 1],

 'SSLVerify'              => 
 ['string', 'This optional parameter specifies what sort of SSL client verification that AuthBy SAFEWORD will provide to the SAFEWORD server.', 1],

 'SSLCAFile'              => 
 ['string', 'If you want to verify that the SAFEWORD server certificate has been signed by a reputable certificate authority, then you should use this option to locate the file containing the certificate(s) of the reputable certificate authorities if it is not already in the OpenSSL file certs/my-ca.pem. Special characters are permitted.', 1],

 'SSLCAPath'              => 
 ['string', 'If you are unusually friendly with the OpenSSL documentation, you might have set yourself up a directory containing several trusted certificates as separate files as well as an index of the certificates. If you want to use that directory for validation purposes, and that directory is not ca/, then use this option to specify the directory. There is no need to set both SSLCAFile and  SSLCAPath. Special characters are permitted.', 1],

 'SSLCAClientCert'        => 
 ['string', 'This optional parameter specifies the location of the SSL client certificate that AuthBy SAFEWORD will use to verifiy itself with the SAFEWORD server. If SSL client verification is not required, then this option does not need to be specified. Special characters are permitted.', 1],

 'SSLCAClientKey'         => 
 ['string', 'This optional parameter specifies the location of the SSL private key that AuthBy SAFEWORD will use to communicate with the SAFEWORD server. If SSL client verification is not required, then this option does not need to be specified. Special characters are permitted.', 1],

 'SSLCAClientKeyPassword' => 
 ['string', 'If the SSLCAClientKey contains an encrypted private key, then you must specifiy the decryption password with this parameter. If a key is required, you will generally have been given the password by whoever provided the private key and certificate.', 1],

 'ProtocolVersion'        => 
 ['string', 'Specifies the protocll version this AuthBy SAFEWORD implements. You should  not change this', 2],

 'AgentName'              => 
 ['string', 'The Agent Name used in communiocations with the Safeword server. Defaults to "Radiator". You should not need to chnage this.', 1],

 'GroupReply'             =>
 ['stringhash', 'Maps SafeWord group names to reply items', 2],
 );

# RCS version number of this module
$Radius::AuthSAFEWORD::VERSION = '$Revision: 1.11 $';

# Result codes from Authentication SDK Reference Guide
my %resultCodeStrings = 
    (
     0  => 'Authentication process did not complete',
     1  => 'Passed authentication',
     2  => 'Unknown user ID',
     3  => 'Failed authentication, invalid password',
     4  => 'Used up usage quota',
     5  => 'Wrong time of day',
     6  => 'Wrong date',
     7  => 'Wrong day of week',
     8  => 'Attack lock triggered ',
     9  => 'Incorrect system clock setting',
     10 => 'Insufficient privilege for access',
     11 => 'Failed tamper testing',
     14 => 'Passed but used a duress PIN',
     15 => 'Passed but used a bad PIN',
     16 => 'Someone is editing the user\'s SafeWord database record',
     17 => 'User took too long to respond',
     18 => 'Process terminated',
     19 => 'Invalid new fixed password',
     20 => 'Passed but must set new password',
     21 => 'Server failed during authentication',
     26 => 'No service allowed: the authentication context has disqualified the user',
     27 => 'User has no authenticators',
     28 => 'User\'s authenticator strength is too weak',
     29 => 'Account disabled',
     );

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
    $self->{Host}    = 'localhost';
    $self->{Port}    = 5031;
    $self->{Timeout} = 10;
    $self->{ProtocolVersion} = 201;
    $self->{AgentName} = 'Radiator';
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

    return $self->check_response($p->getUserName(), $p->decodedPassword(), undef, $p);
}

#####################################################################
# Overrideable function that checks a CHAP password response
# $p is the current request
# $username is the users (rewritten) name
# $pw is the coorrect password if known
# CAUTION: to support CHAP, SafeWord PremierAcccess must be configured with a 
# fixed password profile that has CASE SENSITIVE PASSWORDS ENABLED
sub check_chap
{
    my ($self, $p, $username, $pw, $chapid, $challenge, $response) = @_;

    # Build an authentication request message
    my $reply = $self->send_get_reply($p, $self->authenRequestMsg($username));
    if (!$reply)
    {
	$self->log($main::LOG_ERR, 'SafeWord server communications error');
	return;
    }

    # Could get a result message here or a challenge message
    if ($reply =~ /\<AuthenChallengeMsg\>/)
    {
	if ($reply =~ /\<DynamicPwdChallenge (.+)\/\>/s)
	{
	    # Cant do chap with dynamic tokens
	    $self->log($main::LOG_INFO, 'User requested CHAP for SafeWord token (not supported)');
	    return;
	} 
	elsif ($reply =~ /\<FixedPwdChallenge (.+)\/\>/s)
	{
	    my $chdetails = $1;
	    my ($authenNumber) = $chdetails =~ /authenNumber\=\"(\d+)\"/;
	    my $responsehex    = uc unpack('H*', $response);
	    my $challengehex   = uc unpack('H*', $challenge);
	    my $chapidhex      = uc unpack('H*', $chapid);
	    my $response = "<FixedPwdResponse authenNumber=\"$authenNumber\" pwd=\"$responsehex\" chapChallenge=\"$challengehex\" chapID=\"$chapidhex\"/>";

	    $reply = $self->send_get_reply($p, $self->authenResponseMsg($username, $response));
	    if (!$reply)
	    {
		$self->log($main::LOG_ERR, 'SafeWord server communications error');
		return;
	    }
	}
    }

    return 1
	if $reply =~ /\<AuthenResultMsg\>.*\<AuthenResult.*result="passed".*resultCode="1"/s;
    # Failure
    my ($resultCode) = $reply =~ /resultCode\=\"(\d+)\"/;
    my ($statusMsg)  = $reply =~ /\<StatusMsg\>\<\!\[CDATA\[(.*)\]\]\>\<\/StatusMsg\>/;
    my $resultCodeString = $resultCodeStrings{$resultCode} 
        || "Unknown result code: $resultCode";
    
    $self->log($main::LOG_INFO, "SafeWord authentication failed: $resultCodeString");
    return;
}

#####################################################################
# Overrideable function that checks a MSCHAP password response
# $p is the current request
# $username is the users (rewritten) name
# $nthash is the NT Hashed of the correct password
# $context may be present some persistent storage for handles etc
sub check_mschap
{
    my ($self, $p, $username, $nthash, $challenge, $response, 
	$usersessionkeydest, $lanmansessionkeydest, $context) = @_;

    # Not supported by SAFEWORD
    $self->log($main::LOG_INFO, 'User requested MSCHAP for SafeWord token (not supported)');
    return 0;
}

#####################################################################
# Overrideable function that checks a MSCHAP password response
# $p is the current request
# $username is the users (rewritten) name
# $nthash is the NT Hashed of the correct password
# $sessionkeydest is a ref to a string where the sesiosn key for MPPE will be returned
# $context may be present some persistent storage for handles etc
sub check_mschapv2
{
    my ($self, $p, $username, $nthash, $authchallenge, $peerchallenge, $response, 
	$mppekeys_dest, $authenticator_responsedest, $lanmansessionkeydest) = @_;

    # Not supported by SAFEWORD
    $self->log($main::LOG_INFO, 'User requested MSCHAPV2 for SafeWord token (not supported)');
    return 0;
}

#####################################################################
# $submitted_pw is the response being authenticated
# $pw is the correct password if known
# $user is the user name to be authenticated
sub check_response
{
    my ($self, $username, $submitted_pw, $pw, $p, $encrypted) = @_;

    return ($main::ACCEPT) if $self->{NoCheckPassword};

    my ($result, $reason, $attr, $challenge);

    # Cant really do this in a way that is compatible with 
    # AuthGeneric::check_plain_password
    # since we need to CHALLENGE sometimes
    if (defined ($attr = $p->getAttrByNum($Radius::Radius::CHAP_PASSWORD)))
    {
	# Its a conventional CHAP request
	$challenge = $p->getAttrByNum($Radius::Radius::CHAP_CHALLENGE);
	$challenge = $p->authenticator unless defined $challenge;
	my $chapid = substr($attr, 0, 1);
	my $response = substr($attr, 1);
	$submitted_pw = 'UNKNOWN-CHAP';
	$result = $self->check_chap($p, $username, $pw, $chapid, $challenge, $response)
	    ? $main::ACCEPT : $main::REJECT;
    }
    elsif (   ($attr = $p->get_attr('MS-CHAP-Response'))
	   && ($challenge = $p->get_attr('MS-CHAP-Challenge')))
    {
	# Its an MS-CHAP request
	$result = $main::REJECT;
	$reason = 'MS-CHAP authentication not supported by AuthBy SAFEWORD';
	$submitted_pw = 'UNKNOWN-MS-CHAP';
    }
    elsif (   ($attr = $p->get_attr('MS-CHAP2-Response'))
	   && ($challenge = $p->get_attr('MS-CHAP-Challenge')))
    {
	# Its an MS-CHAP V2 request
	$result = $main::REJECT;
	$reason = 'MS-CHAPV2 authentication not supported by AuthBy SAFEWORD';
	$submitted_pw = 'UNKNOWN-MS-CHAP-V2';
    }
    else
    {
	# Plaintext password
	($result, $reason) = check_plain_password($self, $username, $submitted_pw, 
						  undef, $p);
    }
    # Log the password
    $p->{Handler}->logPassword($username, $submitted_pw, 'SafeWord', 
			       $result == $main::ACCEPT, $p)
	if $p->{Handler};
    
    return ($result, $reason);
}

#####################################################################
# $submitted_pw is the password being authenticated
# $pw is the correct password if known
# $user is the user name to be authenticated
sub check_plain_password
{
    my ($self, $username, $submitted_pw, $pw, $p, $encrypted) = @_;

    return ($main::ACCEPT) if $self->{NoCheckPassword};

    # Build an authentication request message
    my $reply = $self->send_get_reply($p, $self->authenRequestMsg($username));
    return ($main::IGNORE, 'SafeWord server communications error') 
	unless $reply;

    # Could get a result message here or a challenge message
    if ($reply =~ /\<AuthenChallengeMsg\>/)
    {
	if ($reply =~ /\<DynamicPwdChallenge (.+)\/\>/s)
	{
	    my $chdetails = $1;
	    my ($authenName)   = $chdetails =~ /authenName\=\"(.*?)\"/;
	    my ($authenNumber) = $chdetails =~ /authenNumber\=\"(\d+)\"/;

	    if (!length($submitted_pw))
	    {
		# No password sent, prompt for it
		my $message = "Enter your $authenName password";
		$p->{rp}->addAttrByNum($Radius::Radius::REPLY_MESSAGE, $message);
		return ($main::CHALLENGE, "Request $authenName password");
	    }
	    else
	    {
		my $response = "<DynamicPwdResponse authenNumber=\"$authenNumber\" pwd=\"$submitted_pw\"/>";
                $reply = $self->send_get_reply($p, $self->authenResponseMsg($username, $response));
	    }
	} 
	elsif ($reply =~ /\<FixedPwdChallenge (.+)\/\>/s)
	{
	    my $chdetails = $1;
	    my ($authenName)   = $chdetails =~ /authenName\=\"(.*?)\"/;
	    my ($authenNumber) = $chdetails =~ /authenNumber\=\"(\d+)\"/;
	    my $isnew          = $chdetails =~ /newPwdRequired=\"true\"/;

	    # Allow them to change their password in a way that is 
	    # compatible with the safeword Radius server:
	    # Oldpw\cNewpw,Newpw
	    my ($oldpw, $newpw1, $newpw2) = $submitted_pw =~ /(.*?)\\c(.*?),(.*)/;		
	    if ($isnew && !defined $newpw2)
	    {
		my $message = "Your password has expired and must be changed.\n\nTo change your password, enter the following in the password field:\nOldpassword\\cNewpassword,Newpassword\n";
		$p->{rp}->addAttrByNum($Radius::Radius::REPLY_MESSAGE, $message);
		return ($main::CHALLENGE, "Request $authenName password");
	    }
	    elsif (!length($submitted_pw))
	    {
		# No password sent, prompt for it
		my $message = "Enter your SafeWord $authenName password";
		$p->{rp}->addAttrByNum($Radius::Radius::REPLY_MESSAGE, $message);
		return ($main::CHALLENGE, "Request $authenName password");
	    }
	    else
	    {
		my $response = "<FixedPwdResponse authenNumber=\"$authenNumber\" pwd=\"$submitted_pw\"/>";
		if (defined $newpw2)
		{
		    if ($newpw1 ne $newpw2)
		    {
			my $message = "New passwords do not match";
			$p->{rp}->addAttrByNum($Radius::Radius::REPLY_MESSAGE, $message);
			return ($main::REJECT, 'Attempt to change SafeWord fixed password, but new passwords dont match');
		    }
		    $response = "<FixedPwdResponse authenNumber=\"$authenNumber\" pwd=\"$oldpw\" newPwd=\"$newpw1\"/>";
		}

                $reply = $self->send_get_reply($p, $self->authenResponseMsg($username, $response));
	    }
	}
    }

    return ($main::IGNORE, 'SafeWord server communications reply error') 
	unless $reply;
    if ($reply =~ /\<AuthenResultMsg\>.*\<AuthenResult.*result="passed".*resultCode="1"/s)
    {
	# Look for ActionData groups in the reply and map them to reply attrsibutes
	# according to GroupReply maps
	if ($reply =~ /\<ActionData\>\<\!\[CDATA\[group\=(.*?)\]\]\>\<\/ActionData\>/)
	{
	    my $groupname = $1;
	    if (exists $self->{GroupReply}->{$groupname})
	    {
		$self->addReplyItems($p, &Radius::Util::splitAttrVals($self->{GroupReply}->{$groupname}))
	    }
	}
	return ($main::ACCEPT);
    }
    # Failure
    my ($resultCode) = $reply =~ /resultCode\=\"(\d+)\"/;
    my ($statusMsg)  = $reply =~ /\<StatusMsg\>\<\!\[CDATA\[(.*)\]\]\>\<\/StatusMsg\>/;
    my $resultCodeString = $resultCodeStrings{$resultCode} 
        || "Unknown result code: $resultCode";
    return ($main::REJECT, "SafeWord authentication failed: $resultCodeString");

}

#####################################################################
# Send a request to the server, after encapsulating it, then wait for the 
# servers reply and return it
sub send_get_reply
{
    my ($self, $p, $content) = @_;

    # Server might drop our connection unexpectedly
    my $retry_count;
    while ($retry_count++ < 5)
    {
	$self->{sock} = $self->get_socket($p) 
	    unless $self->{sock} && $self->{sock}->connected();
	return unless $self->{sock};

	# TaskID is not strictly necessary for this synchronous interface
	my $taskid = ++($self->{task_id});
	my $request = "Content-length: " . length($content) . "\nTask-id: $taskid\nContent-type: AUTH_MSG\n\n" . $content;
	
	$self->log($main::LOG_EXTRA_DEBUG, "Sending request to SafeWord: $request");
	
	# Send the request to the server
	if (syswrite($self->{sock}, $request) != length($request))
	{
	    $self->log($main::LOG_ERR, "AuthBy SAFEWORD write error, disconnecting: $!");
	    $self->{sock} = undef;
	    next; # retry
	}
    
	# Now get the servers response, first see how many bytes are waiting for us
	my $reply;
	my $bytes_to_read = $self->{sock}->peek($reply, 512);
	if (sysread($self->{sock}, $reply, $bytes_to_read) <= 0)
	{
	    $self->log($main::LOG_ERR, "AuthBy SAFEWORD read error, disconnecting: $!");
	    $self->{sock} = undef;
	    next; # retry
	}
	$self->log($main::LOG_EXTRA_DEBUG, "Got reply from SafeWord: $reply");
	if ($reply !~ /^Content-type:AUTH_MSG\s+Task-id:(\d+)/)
	{
	    $self->log($main::LOG_ERR, "AuthBy SAFEWORD Incorrect response, disconnecting: $!");
	    $self->{sock} = undef;
	    return;
	}
	# Check the returned task ID
	if ($1 != $taskid)
	{
	    $self->log($main::LOG_ERR, "AuthBy SAFEWORD Incorrect task id, disconnecting: $!");
	    $self->{sock} = undef;
	    return;
	}
    
	return $reply;
    }
    # Retries exceeded
    return;
}

#####################################################################
# Generate a SafeWord AuthenRequestMsg
sub authenRequestMsg
{
    my ($self, $username) = @_;

    return <<END_OF_CONTENT;
<?xml version=\'1.0\' encoding="UTF-8"?>

<AuthenRequestMsg>
<Protocol version="$self->{ProtocolVersion}"/>
<ID type="name"><![CDATA[$username]]></ID>
<SafeWordSystem name="STANDARD"/>
<Agent name="$self->{AgentName}" type="RADIUS"/>
<AgentComment><![CDATA[Radiator Radius Server AuthBy SAFEWORD]]></AgentComment>
</AuthenRequestMsg>
END_OF_CONTENT

# could add
#<ClientLocation ipAddress="203.63.154.29" hostName=""/>
#<ClientType name="RADIUS"/>

}

#####################################################################
# Generate a SafeWord AuthenResponseMsg
sub authenResponseMsg
{
    my ($self, $username, $response) = @_;

    return <<END_OF_CONTENT;
<?xml version=\'1.0\' encoding="UTF-8"?>
<AuthenResponseMsg>
<Protocol version="$self->{ProtocolVersion}"/>
<SafeWordSystem name="STANDARD"/>
<ID type="name"><![CDATA[$username]]></ID>
<Responses>
$response
</Responses>
<Agent name="$self->{AgentName}" type="RADIUS"/>
<AgentComment><![CDATA[Radiator Radius Server AuthBy SAFEWORD]]></AgentComment>
</AuthenResponseMsg>
END_OF_CONTENT
}

#####################################################################
# This is also called by the EAP_5 OTP code
# It has to do whatever is required to possibly generate a OTP, possibly send it to the
# user and return a challenge string that may be helpful to the user
# in determining or fetching their OTP
# ChallengeHook is expected to return ("challenge string")
sub otp_challenge
{
    my ($self, $user, $p, $context) = @_;

    return $self->safeword_start($context, $user, $p);
}

#####################################################################
# This is also called by the EAP_5 OTP code
# VerifyHook is expected to return (1) on success and (0) on failure
sub otp_verify
{
    my ($self, $user, $submitted_pw, $p, $context) = @_;

    my ($result, $reason) = $self->safeword_continue($context, $user, $submitted_pw, $p);
    $p->{Handler}->logPassword($user, $submitted_pw, 'SafwWord', $result == 1, $p) 
	if $p->{Handler};
    return $result;

    # Build an authentication request message
    my $reply = $self->send_get_reply($p, $self->authenRequestMsg($user));
    return unless $reply;

    # Could get a result message here or a challenge message
    if ($reply =~ /\<AuthenChallengeMsg\>/)
    {
	if ($reply =~ /\<DynamicPwdChallenge (.+)\/\>/s)
	{
	    my $chdetails = $1;
	    my ($authenName)   = $chdetails =~ /authenName\=\"(.*?)\"/;
	    my ($authenNumber) = $chdetails =~ /authenNumber\=\"(\d+)\"/;

	    my $response = "<DynamicPwdResponse authenNumber=\"$authenNumber\" pwd=\"$submitted_pw\"/>";
	    $reply = $self->send_get_reply($p, $self->authenResponseMsg($user, $response));
	} 
	elsif ($reply =~ /\<FixedPwdChallenge (.+)\/\>/s)
	{
	    my $chdetails = $1;
	    my ($authenName)   = $chdetails =~ /authenName\=\"(.*?)\"/;
	    my ($authenNumber) = $chdetails =~ /authenNumber\=\"(\d+)\"/;
	    my $isnew          = $chdetails =~ /newPwdRequired=\"true\"/;

	    # Allow them to change their password in a way that is 
	    # compatible with the safeword Radius server:
	    # Oldpw\cNewpw,Newpw
	    my ($oldpw, $newpw1, $newpw2) = $submitted_pw =~ /(.*?)\\c(.*?),(.*)/;		
	    my $response = "<FixedPwdResponse authenNumber=\"$authenNumber\" pwd=\"$submitted_pw\"/>";
	    if (defined $newpw2)
	    {
		if ($newpw1 ne $newpw2)
		{
		    $self->log($main::LOG_ERR, 'AuthBy SAFEWORD EAP-OTP user entered new passwords that do not match');
		    return;
		}
		$response = "<FixedPwdResponse authenNumber=\"$authenNumber\" pwd=\"$oldpw\" newPwd=\"$newpw1\"/>";
	    }
	    $reply = $self->send_get_reply($p, $self->authenResponseMsg($user, $response));
	}
    }

    if (!defined $reply)
    {
	$self->log($main::LOG_ERR, 'SafeWord server communications reply error');
	return;
    }
    return 1
	if $reply =~ /\<AuthenResultMsg\>.*\<AuthenResult.*result="passed".*resultCode="1"/s;
    # Failure
    my ($resultCode) = $reply =~ /resultCode\=\"(\d+)\"/;
    my ($statusMsg)  = $reply =~ /\<StatusMsg\>\<\!\[CDATA\[(.*)\]\]\>\<\/StatusMsg\>/;
    my $resultCodeString = $resultCodeStrings{$resultCode} 
        || "Unknown result code: $resultCode";
    $self->log($main::LOG_INFO, "SafeWord EAP-OTP authentication failed: $resultCodeString");
    return;
}

#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_start
{
    my ($self, $context, $user, $p) = @_;

    return $self->safeword_start($context, $user, $p);
}

#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_continue
{
    my ($self, $context, $user, $data, $p) = @_;

    return $self->safeword_continue($context, $user, $data, $p);
}

#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_end
{
    my ($self, $context, $user, $p) = @_;
}

#####################################################################
sub safeword_start
{
    my ($self, $context, $user, $p) = @_;

    # Build an authentication request message
    my $reply = $self->send_get_reply($p, $self->authenRequestMsg($user));
    return (0, 'SafeWord server communications error') unless $reply;

    # Could get a result message here or a challenge message
    if ($reply =~ /\<AuthenChallengeMsg\>/)
    {
	if ($reply =~ /\<DynamicPwdChallenge (.+)\/\>/s
	    || $reply =~ /\<FixedPwdChallenge (.+)\/\>/s)
	{
	    my $chdetails = $1;
	    my ($authenName)   = $chdetails =~ /authenName\=\"(.*?)\"/;
	    my ($authenNumber) = $chdetails =~ /authenNumber\=\"(\d+)\"/;
	    my $isnew          = $chdetails =~ /newPwdRequired=\"true\"/;
	    return (2, $isnew ? 
		    "CHALLENGE=Enter your $authenName password\nYour password has expired and must be changed.\n\nTo change your password, enter the following:\nOldpassword\\cNewpassword,Newpassword\n"
		    : "CHALLENGE=Enter your $authenName password");
	}
    }
    # Should not happen
    return (0, 'SafeWord server did not reply with a valid AuthenChallengeMsg');
}

#####################################################################
sub safeword_continue
{
    my ($self, $context, $user, $submitted_pw, $p) = @_;

    # Build an authentication request message
    my $reply = $self->send_get_reply($p, $self->authenRequestMsg($user));
    return (0, 'SafeWord server communications error') unless $reply;

    # Could get a result message here or a challenge message
    if ($reply =~ /\<AuthenChallengeMsg\>/)
    {
	if ($reply =~ /\<DynamicPwdChallenge (.+)\/\>/s)
	{
	    my $chdetails = $1;
	    my ($authenName)   = $chdetails =~ /authenName\=\"(.*?)\"/;
	    my ($authenNumber) = $chdetails =~ /authenNumber\=\"(\d+)\"/;

	    my $response = "<DynamicPwdResponse authenNumber=\"$authenNumber\" pwd=\"$submitted_pw\"/>";
	    $reply = $self->send_get_reply($p, $self->authenResponseMsg($user, $response));
	} 
	elsif ($reply =~ /\<FixedPwdChallenge (.+)\/\>/s)
	{
	    my $chdetails = $1;
	    my ($authenName)   = $chdetails =~ /authenName\=\"(.*?)\"/;
	    my ($authenNumber) = $chdetails =~ /authenNumber\=\"(\d+)\"/;
	    my $isnew          = $chdetails =~ /newPwdRequired=\"true\"/;

	    # Allow them to change their password in a way that is 
	    # compatible with the safeword Radius server:
	    # Oldpw\cNewpw,Newpw
	    my ($oldpw, $newpw1, $newpw2) = $submitted_pw =~ /(.*?)\\c(.*?),(.*)/;		
	    my $response = "<FixedPwdResponse authenNumber=\"$authenNumber\" pwd=\"$submitted_pw\"/>";
	    if (defined $newpw2)
	    {
		if ($newpw1 ne $newpw2)
		{
		    $self->log($main::LOG_ERR, 'AuthBy SAFEWORD EAP-OTP user entered new passwords that do not match');
		    return;
		}
		$response = "<FixedPwdResponse authenNumber=\"$authenNumber\" pwd=\"$oldpw\" newPwd=\"$newpw1\"/>";
	    }
	    $reply = $self->send_get_reply($p, $self->authenResponseMsg($user, $response));
	}
    }

    return (0, 'SafeWord server communications reply error')
	unless defined $reply;

    return (1)
	if $reply =~ /\<AuthenResultMsg\>.*\<AuthenResult.*result="passed".*resultCode="1"/s;
    # Failure
    my ($resultCode) = $reply =~ /resultCode\=\"(\d+)\"/;
    my ($statusMsg)  = $reply =~ /\<StatusMsg\>\<\!\[CDATA\[(.*)\]\]\>\<\/StatusMsg\>/;
    my $resultCodeString = $resultCodeStrings{$resultCode} 
        || "Unknown result code: $resultCode";
    return (0, "SafeWord EAP-OTP authentication failed: $resultCodeString");
}

#####################################################################
# Connect to the SafeWord server and return the socket
sub get_socket {
    my ($self, $p) = @_;

    my ($sock, %args);

    $args{Proto}   = 'tcp';
    $args{Timeout} = $self->{Timeout} if defined $self->{Timeout};

    $args{PeerHost} = &Radius::Util::format_special($self->{Host}, $p)
	if defined $self->{Host};
    $args{PeerPort} = &Radius::Util::format_special($self->{Port}, $p)
	if defined $self->{Port};
    $args{LocalAddr} = &Radius::Util::format_special($self->{LocalAddr}, $p)
	if defined $self->{LocalAddr};

    # Different OpenSSL verify modes.
    my %ssl_verify = ( 'none' => 0, 'optional' => 1, 'require' => 3 );

    $args{PeerPort} ||= 5031;
    
    $args{SSL_verify_mode} = $ssl_verify{ lc( $self->{SSLVerify} ) }
    if defined $self->{SSLVerify};

    $args{SSL_ca_file} = &Radius::Util::format_special($self->{SSLCAFile}, $p)
	if defined $self->{SSLCAFile};
    $args{SSL_ca_path} = &Radius::Util::format_special($self->{SSLCAPath}, $p)
	if defined $self->{SSLCAPath};
    $args{SSL_cert_file} = &Radius::Util::format_special($self->{SSLCAClientCert}, $p)
	if defined $self->{SSLCAClientCert};
    $args{SSL_key_file} = &Radius::Util::format_special($self->{SSLCAClientKey}, $p)
	if defined $self->{SSLCAClientKey};
    $args{SSL_passwd_cb} = sub { return $self->{SSLCAClientKeyPassword} }
    if defined $self->{SSLCAClientKeyPassword};
    
    $self->log( $main::LOG_DEBUG, "AuthBy SAFEWORD connecting to $args{PeerHost}:$args{PeerPort}", $p );
    
    unless ($sock = IO::Socket::SSL->new(%args)) 
    {
	my $errstr = IO::Socket::SSL::errstr();
	$self->log( $main::LOG_WARNING, "Could not create SSL connection to SafeWord server at $args{PeerHost}:$args{PeerPort}: $errstr: $!");
	return;
    }
    return $sock;
}

1;
