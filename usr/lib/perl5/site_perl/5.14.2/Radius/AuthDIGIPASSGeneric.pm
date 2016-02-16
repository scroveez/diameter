# AuthDIGIPASSGeneric.pm
#
# Object for handling Authentication of DIGIPASS tokens (www.vasco.com)
# Subclass for specific database types by overriding GetDigipassData and 
# UpdateDigipassData.
# Requires Authen-Digipass 1.4 or better from Open System Consultants.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001-2006 Open System Consultants
# $Id: AuthDIGIPASSGeneric.pm,v 1.20 2013/08/13 20:58:45 hvn Exp $

package Radius::AuthDIGIPASSGeneric;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Radius::Context;
use Authen::Digipass;
use strict;

%Radius::AuthDIGIPASSGeneric::ConfigKeywords = 
('ITimeWindow'            => 
 ['integer', 'Specifies the size of the window of opportunity that a token can login with (this is counted in multiples of one-time password "rollovers" in the token. Value can be 2 to 1000. Default is 100 (that means +- 30 mins for default tokens)', 2],
 'IThreshold'             => 
 ['integer', 'Specifies the number of times that a person can unsuccessfully try to login before being locked out. 0 means disabled. ', 2],
 'SyncWindow'             => 
 ['integer', 'Specifies the size of the larger window that is created for use the first time after a token has been reset. This means that if a token gets out of sync (which isn\'t a common occurrence), the user can\'t login so the admin resets the token, then a larger sync window is produced after the reset so that the token can be recognized and calibrated by the software to allow subsequent use. This parameter is expressed in hours. ', 2],
 'CheckChallenge'         => 
 ['integer', 'Specifies whether or not to check if the challenge has been corrupted before validation. Value can be 0 to 4:', 2],
 'ChkInactDays'           => 
 ['integer', 'Specifies number of days of token inactivity. Past this number of days, the token will have to be reset. Values from 0 to 1024. Default is 0, which means the feature is disabled.', 2],
 'DeriveVector'           => 
 ['integer', 'This optional advanced parameter can be used to make data encryption unique for a host. Defaults to 0x00000000.', 2],
 'EventWindow'            => 
 ['integer', 'This optional advanced parameter specifies the Event Window size by number of iterations. Represents the acceptable event counter difference between Digipass token a and the host. It only applies to event-based operating modes. From 10 to 1000. ', 2],
 'HSMSlotId'              => 
 ['integer', 'This optional advanced parameter specifies the HSM slot ID which will be used to store the Storage and Transport keys. 0 to 60. ', 2],
 'StorageKeyId'           => 
 ['integer', 'This optional advanced parameter specifies the key which will be used to decrypt the Digipass data retrieved from the database. 0x00000000 to 0xffffffff. Defaults to 0x00000000.', 2],
 'TransportKeyId'         => 
 ['integer', 'This optional advanced parameter specifies the key which will be used to encrypt the Digipass data written to the database. 0x00000000 to 0xffffffff. Defaults to 0x00000000.', 2],
 'StorageDeriveKey1'      => 
 ['integer', 'These optional advanced parameters specify the derivation keys used to make data encryption unique for a host.', 2],
 'StorageDeriveKey2'      => 
 ['integer', 'These optional advanced parameters specify the derivation keys used to make data encryption unique for a host.', 2],
 'StorageDeriveKey3'      => 
 ['integer', 'These optional advanced parameters specify the derivation keys used to make data encryption unique for a host.', 2],
 'StorageDeriveKey4'      => 
 ['integer', 'These optional advanced parameters specify the derivation keys used to make data encryption unique for a host.', 2],
 'ChallengeMessage'       => 
 ['string', 'This parameter allows you to customise or internationalise the Reply-Message sent when the user is challenged to enter a Digipass tokencode. %0 is replaced with the digipass challenge string. ', 1],
 'SupportVirtualDigipass' => 
 ['flag', 'This optional parameter causes this modulesupport Vasco Virtual Digipass tokens. ', 1],
 'VirtualTokencodeHook'   => 
 ['hook', 'Perl code that is called whenever a Virtual Digipass tokencode is to be sent to a user. The hook is expected to transmit the tokencode to the user over some prompt, secure out-of-band method, such as SMS', 2],
 'ChallengeTimeout'      => 
 ['integer', 'The maximum period of time that a challenge from a Challenge-Response (CR) token will be valid for. Time is in seconds and defaults to 300 seconds (5 minutes)', 2],

 );

# RCS version number of this module
$Radius::AuthDIGIPASSGeneric::VERSION = '$Revision: 1.20 $';

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
    $self->{NoDefault}         = 1;
    $self->{ITimeWindow}       = 100;
    $self->{IThreshold}        = 0;
    $self->{SyncWindow}        = 6;
    $self->{CheckChallenge}    = 1;
    $self->{ChkInactDays}      = 0;
    $self->{DeriveVector}      = 0;
    $self->{EventWindow}       = 100;
    $self->{HSMSlotId}         = 0;
    $self->{StorageKeyId}      = 0;
    $self->{TransportKeyId}    = 0x7fffff;
    $self->{StorageDeriveKey1} = 0;
    $self->{StorageDeriveKey2} = 0;
    $self->{StorageDeriveKey3} = 0;
    $self->{StorageDeriveKey4} = 0;
    $self->{ChallengeMessage} = 'Digipass Challenge: %0';
    $self->{ChallengeTimeout} = 300;
}

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    $self->SUPER::check_config();
    return;
}

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();

    $self->{kparms} = Authen::Digipass::KernelParms->new
	(ITimeWindow       => $self->{ITimeWindow},
	 IThreshold        => $self->{IThreshold},
	 SyncWindow        => $self->{SyncWindow},
	 CheckChallenge    => $self->{CheckChallenge},
	 ChkInactDays      => $self->{ChkInactDays},
	 DeriveVector      => $self->{DeriveVector},
	 EventWindow       => $self->{EventWindow},
	 HSMSlotId         => $self->{HSMSlotId},
	 StorageKeyId      => $self->{StorageKeyId},
	 TransportKeyId    => $self->{TransportKeyId},
	 StorageDeriveKey1 => $self->{StorageDeriveKey1},
	 StorageDeriveKey2 => $self->{StorageDeriveKey2},
	 StorageDeriveKey3 => $self->{StorageDeriveKey3},
	 StorageDeriveKey4 => $self->{StorageDeriveKey4});
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

    my $user_name = $p->getUserName;
    $user_name =~ s/@[^@]*$//
	if $self->{UsernameMatchesWithoutRealm};
    return $self->check_response($user_name, $p->decodedPassword(), undef, $p);
}

#####################################################################
# Overrideable function that checks a CHAP password response
# $p is the current request
# $username is the users (rewritten) name
# $pw is the coorrect password if known
sub check_chap
{
    my ($self, $p, $username, $pw, $chapid, $challenge, $response) = @_;

    my $result;
    my ($data, $digipass, $error) = $self->GetDigipassData($username, $p);
    if (!defined $data)
    {
	$self->log($main::LOG_ERR, "Digipass GetDigipassData failed for $username: $error");
	return;
    }
 
    my $ret = Authen::Digipass::VerifyPasswordCHAP($data, $self->{kparms}, $username, $chapid . $response, undef, $challenge);
    if ($ret != 0)
    {
	my $err = Authen::Digipass::AAL2GetErrorMsg($ret);
	$self->log($main::LOG_ERR, "Digipass VerifyPasswordCHAP failed: $err");
    }
    else
    {
	$result = 1; # Success
    }
    # Now update the Digipass database with the new data
    $self->log($main::LOG_ERR, 'Digipass UpdateDigipassData failed')
	unless $self->UpdateDigipassData($data, $digipass, $p);

    return $result;
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

    # Strip off any DOMAIN, else the mschapv2 auth response will fail
    $username =~ s/^(.*)\\//;

    my $result;
    my ($data, $digipass, $error) = $self->GetDigipassData($username, $p);
    if (!defined $data)
    {
	$self->log($main::LOG_ERR, "Digipass GetDigipassData failed for $username: $error");
	return;
    }
    
    my ($usersessionkey, $lanmansessionkey);
    my $ret = Authen::Digipass::VerifyPasswordMSCHAP
	($data, $self->{kparms}, $username, 
	 $challenge . $response, undef, 
	 $usersessionkey, $lanmansessionkey);
    if ($ret != 0)
    {
	my $err = Authen::Digipass::AAL2GetErrorMsg($ret);
	$self->log($main::LOG_ERR, "Digipass VerifyPasswordMSCHAPV2 failed: $err");
    }
    else
    {
	$result = 1; # Success
    }
    # Now update the Digipass database with the new data
    $self->log($main::LOG_ERR, 'Digipass UpdateDigipassData failed')
	unless $self->UpdateDigipassData($data, $digipass, $p);

    $$usersessionkeydest = $usersessionkey if defined $usersessionkeydest;
    $$lanmansessionkeydest = $lanmansessionkey if defined $lanmansessionkeydest;
    return $result;
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

    # Strip off any DOMAIN, else the mschapv2 auth response will fail
    $username =~ s/^(.*)\\//;

    my $result;
    my ($data, $digipass, $error) = $self->GetDigipassData($username, $p);
    if (!defined $data)
    {
	$self->log($main::LOG_ERR, "Digipass GetDigipassData failed for $username: $error");
	return;
    }
    
    my ($usersessionkey, $authenticator_response, $lanmansessionkey);
    my $ret = Authen::Digipass::VerifyPasswordMSCHAPV2
	($data, $self->{kparms}, $username, 
	 $authchallenge . $peerchallenge . $response, undef, 
	 $usersessionkey, $authenticator_response, $lanmansessionkey);
    if ($ret != 0)
    {
	my $err = Authen::Digipass::AAL2GetErrorMsg($ret);
	$self->log($main::LOG_ERR, "Digipass VerifyPasswordMSCHAPV2 failed: $err");
    }
    else
    {
	$result = 1; # Success
    }
    # Now update the Digipass database with the new data
    $self->log($main::LOG_ERR, 'Digipass UpdateDigipassData failed')
	unless $self->UpdateDigipassData($data, $digipass, $p);

    $$mppekeys_dest = Radius::MSCHAP::mppeGetKey($usersessionkey, $response, 16)
	if defined $mppekeys_dest;
    $$authenticator_responsedest = $authenticator_response 
	if defined $authenticator_responsedest;
    $$lanmansessionkeydest = $lanmansessionkey if defined $lanmansessionkeydest;
    return $result;
}

#####################################################################
# $submitted_pw is the response being authenticated
# $pw is the correct password if known
# $user is the user name to be authenticated
sub check_response
{
    my ($self, $user, $submitted_pw, $pw, $p, $encrypted) = @_;

    return ($main::ACCEPT) if $self->{NoCheckPassword};

    my ($result, $reason, $attr, $challenge);

    # Cant really do this in a way that is compatible with AuthGeneric::check_plain_password
    # since we need to CHALLENGE sometimes
    if (defined ($attr = $p->getAttrByNum($Radius::Radius::CHAP_PASSWORD)))
    {
	# Its a conventional CHAP request
	$challenge = $p->getAttrByNum($Radius::Radius::CHAP_CHALLENGE);
	$challenge = $p->authenticator unless defined $challenge;
	my $chapid = substr($attr, 0, 1);
	my $response = substr($attr, 1);
	$submitted_pw = 'UNKNOWN-CHAP';
	$result = $self->check_chap($p, $user, $pw, $chapid, $challenge, $response) ? $main::ACCEPT : $main::REJECT;
    }
    elsif (   ($attr = $p->get_attr('MS-CHAP-Response'))
	   && ($challenge = $p->get_attr('MS-CHAP-Challenge')))
    {
	# Its an MS-CHAP request
	eval {require Radius::MSCHAP};
	if ($@)
	{
	    $self->log($main::LOG_ERR, "Could not load Radius::MSCHAP to handle an MS-CHAP request: $@");
	    return 0;
	}

	# Unpack as per rfc2548
	my ($ident, $flags, $lmresponse, $ntresponse) = unpack('C C a24 a24', $attr);
	if ($flags == 1)
	{
	    my ($usersessionkey, $lanmansessionkey);

	    # use the NT-Response
	    $result = $self->check_mschap($p, $user, undef, $challenge, $ntresponse, \$usersessionkey, \$lanmansessionkey) ? $main::ACCEPT : $main::REJECT;
	    # Maybe automatically send back MS-CHAP-MPPE-Keys
	    # based on the password.
	    if ($result  == $main::ACCEPT && $self->{AutoMPPEKeys})
	    {
		$p->{rp}->add_attr
		    ('MS-CHAP-MPPE-Keys', pack('a8 a16', $lanmansessionkey, $usersessionkey), $p->{Client}->{Secret});
	    }
	}
	else
	{
	    # use the LM-Response
	    $self->log($main::LOG_ERR, "MS-CHAP LM-response not implemented");
	}
	$submitted_pw = 'UNKNOWN-MS-CHAP';
    }
    elsif (   ($attr = $p->get_attr('MS-CHAP2-Response'))
	   && ($challenge = $p->get_attr('MS-CHAP-Challenge')))
    {
	# Its an MS-CHAP V2 request
	# See draft-ietf-radius-ms-vsa-01.txt,
	# draft-ietf-pppext-mschap-v2-00.txt, RFC 2548, RFC3079
	eval {require Radius::MSCHAP};
	if ($@)
	{
	    $self->log($main::LOG_ERR, "Could not load Radius::MSCHAP to handle an MS-CHAP2 request: $@");
	    return $main::REJECT;
	}

	# Unpack as per rfc2548
	my ($ident, $flags, $peerchallenge, $reserved, $response) = unpack('C C a16 a8 a24', $attr);

	# authenticator_response is 42 octets, effective result of GenerateAuthenticatorResponseHash	
	my ($mppekeys, $authenticator_response);
	$result = $self->check_mschapv2($p, $user, undef, $challenge, $peerchallenge, $response, \$mppekeys, \$authenticator_response) ? $main::ACCEPT : $main::REJECT;

	if ($result == $main::ACCEPT && $p->{rp})
	{
	    # MS CHAP V2 requires a specific response in the reply
	    $p->{rp}->add_attr('MS-CHAP2-Success', pack('C a42', $ident, $authenticator_response));

	    if ($self->{AutoMPPEKeys})
	    {
		my ($send, $recv) = unpack('a16 a16', $mppekeys);
		# These will be encoded later by the client
		$p->{rp}->add_attr('MS-MPPE-Send-Key', $send);
		$p->{rp}->add_attr('MS-MPPE-Recv-Key', $recv);
	    }
	}
	$submitted_pw = 'UNKNOWN-MS-CHAP-V2';
    }
    else
    {
	my ($data, $digipass, $error) = $self->GetDigipassData($user, $p);
	return ($main::REJECT, $error)
	    unless defined $data;

	# Plaintext PAP
	if ($submitted_pw eq '')
	{
	    my $challenge = '';
	    if ($self->{SupportVirtualDigipass})
	    {
		# Generate the correct password and send it to the user out-of-band
		my $ret = Authen::Digipass::AAL2GenPassword($data, $self->{kparms}, 
							    $challenge, '');
		if ($ret != 0)
		{
		    my $err = Authen::Digipass::AAL2GetErrorMsg($ret);
		    return ($main::REJECT, "Digipass::AAL2GenPassword failed: $err");
		}

		# Maybe call a hook to deliver the tokencode to the user
		my ($error) = $self->runHook('VirtualTokencodeHook', $p, $self, $user, 
					     $challenge, $p);
		return ($main::REJECT, "Virtual Digipass tokencode could not be delivered to user by VirtualTokencodeHook: $error")
		    if $error;
	    }
	    else
	    {
		# First time, issue a challenge containing the DIGIPASS
		# challenge string. If the token does not support CR, 
		# will get an error from AAL2GenerateChallenge
		my $ret = Authen::Digipass::AAL2GenerateChallenge($data, $self->{kparms}, 
								  $challenge);
		if ($ret != 0)
		{
		    my $err = Authen::Digipass::AAL2GetErrorMsg($ret);
		    return ($main::REJECT, "Digipass::AAL2GenerateChallenge failed: $err");
		}
		# Save the last challenge in a context
		my $chal_context = &Radius::Context::get("digipass_Challenge:$digipass", $self->{ChallengeTimeout});
		$chal_context->{last_challenge} = $challenge;
	    }
	    # Now $challenge is the challenge or the correct tokencode for VDP
	    # Allow the challenge mesasge to be customised or internationalised
	    my $chmsg = &Radius::Util::format_special($self->{ChallengeMessage}, $p, 
						      undef, $challenge);
	    $p->{rp}->addAttrByNum($Radius::Radius::REPLY_MESSAGE, $chmsg);
	    $result = $main::CHALLENGE; # Continue and update the database
	}
	else
	{
	    # Maybe get the previous challenge from a context. Destroy it
	    # afterwards to prevent reuse
	    my $key = "digipass_Challenge:$digipass";
	    my $chal_context = &Radius::Context::find($key);
	    my $challenge = $chal_context->{last_challenge} if $chal_context;
	    &Radius::Context::destroy($key);
	    my $ret = Authen::Digipass::AAL2VerifyPassword($data, $self->{kparms}, $submitted_pw, $challenge);
	    if ($ret != 0)
	    {
		my $err = Authen::Digipass::AAL2GetErrorMsg($ret);
		$result = $main::REJECT;
		$reason = "Digipass Authentication failed: $err";
	    }
	    else
	    {
		$result = $main::ACCEPT; # Continue and update the database
	    }
	}

	# Now update the Digipass database with the new data
	return ($main::REJECT, 'Database update failure')
	    unless $self->UpdateDigipassData($data, $digipass, $p);
    }
    # Log the password
    $p->{Handler}->logPassword($user, $submitted_pw, 'DIGIPASS', $result == $main::ACCEPT, $p)
	if $p->{Handler};
    
    return ($result, $reason);
}

#####################################################################
# This is also called by the EAP_5 OTP code
sub otp_challenge
{
    my ($self, $user, $p, $context) = @_;

    my ($data, $digipass, $error) = $self->GetDigipassData($user, $p);
    return "Challenge failed: $error"
	unless defined $data;

    my $challenge;
    if ($self->{SupportVirtualDigipass})
    {
	# Generate the correct password and send it to the user out-of-band
	my $ret = Authen::Digipass::AAL2GenPassword($data, $self->{kparms}, 
						    $challenge, '');
	if ($ret != 0)
	{
	    my $err = Authen::Digipass::AAL2GetErrorMsg($ret);
	    return "Digipass::AAL2GenPassword failed: $err";
	}
	
	# Maybe call a hook to deliver the tokencode to the user
	my ($error) = $self->runHook('VirtualTokencodeHook', $p, $self, $user, 
				     $challenge, $p);
	return "Virtual Digipass tokencode could not be delivered to user by VirtualTokencodeHook: $error"
	    if $error;
	my $chal_context = &Radius::Context::get("digipass_Challenge:$digipass", $self->{ChallengeTimeout});
	$chal_context->{last_challenge} = $challenge;
	return "Enter your Virtual Digipass tokencode";
    }
    else
    {
	my $ret = Authen::Digipass::AAL2GenerateChallenge($data, $self->{kparms}, $challenge);
	if ($ret == 137)
	{
	    # Challenge Not Supported
	    return "Enter Digipass code";
	}
	elsif ($ret != 0)
	{
	    my $err = Authen::Digipass::AAL2GetErrorMsg($ret);
	    return "Challenge Digipass::AAL2GenerateChallenge failed: $err";
	}
	return 'Database update failure'
	    unless $self->UpdateDigipassData($data, $digipass, $p);
	# Save the last challenge in a context
	my $chal_context = &Radius::Context::get("digipass_Challenge:$digipass", $self->{ChallengeTimeout});
	$chal_context->{last_challenge} = $challenge;
	return "Digipass challenge: $challenge";
    }
}

#####################################################################
# This is also called by the EAP_5 OTP code
sub otp_verify
{
    my ($self, $user, $submitted_pw, $p, $context) = @_;

    my ($data, $digipass, $error) = $self->GetDigipassData($user, $p);
    return
	unless defined $data;

    my $result;
    my $key = "digipass_Challenge:$digipass";
    my $chal_context = &Radius::Context::find($key);
    my $challenge = $chal_context->{last_challenge} if $chal_context;
    &Radius::Context::destroy($key);
    my $ret = Authen::Digipass::AAL2VerifyPassword($data, $self->{kparms}, $submitted_pw, $challenge);
    if ($ret != 0)
    {
	my $err = Authen::Digipass::AAL2GetErrorMsg($ret);
	$p->{Handler}->logPassword($user, $submitted_pw, 'DIGIPASS', 0, $p) if $p->{Handler};
	$self->log($main::LOG_INFO, "Digipass authentication failed for $user: $err");
    } 
    else
    {
	$p->{Handler}->logPassword($user, $submitted_pw, 'DIGIPASS', 1, $p) if $p->{Handler};
	$result = 1;
    }
    return
	unless $self->UpdateDigipassData($data, $digipass, $p);
    return $result;
}

#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_start
{
    my ($self, $context, $user, $p) = @_;

    my ($data, $digipass, $error) = $self->GetDigipassData($user, $p);
    return (0, "GTC Start failed: $error")
	unless defined $data;

    my $challenge;
    if ($self->{SupportVirtualDigipass})
    {
	# Generate the correct password and send it to the user out-of-band
	my $ret = Authen::Digipass::AAL2GenPassword($data, $self->{kparms}, 
						    $challenge, '');
	if ($ret != 0)
	{
	    my $err = Authen::Digipass::AAL2GetErrorMsg($ret);
	    return (0, "Digipass::AAL2GenPassword failed: $err");
	}
	
	# Maybe call a hook to deliver the tokencode to the user
	my ($error) = $self->runHook('VirtualTokencodeHook', $p, $self, $user, 
				     $challenge, $p);
	return (0, "Virtual Digipass tokencode could not be delivered to user by VirtualTokencodeHook: $error")
	    if $error;
	# Save the last challenge in a context
	my $chal_context = &Radius::Context::get("digipass_Challenge:$digipass", $self->{ChallengeTimeout});
	$chal_context->{last_challenge} = $challenge;
	return (2, "Enter your Virtual Digipass tokencode");
    }
    else
    {
	my $ret = Authen::Digipass::AAL2GenerateChallenge($data, $self->{kparms}, $challenge);
	if ($ret == 137)
	{
	    # Challenge Not Supported
	    return (2, "Enter Digipass code");
	}
	elsif ($ret != 0)
	{
	    my $err = Authen::Digipass::AAL2GetErrorMsg($ret);
	    return (0, "Challenge Digipass::AAL2GenerateChallenge failed: $err");
	}
	return (0, 'Database update failure')
	    unless $self->UpdateDigipassData($data, $digipass, $p);
	# Save the last challenge in a context
	my $chal_context = &Radius::Context::get("digipass_Challenge:$digipass", $self->{ChallengeTimeout});
	$chal_context->{last_challenge} = $challenge;
	return (2, "CHALLENGE=Enter Digipass code.\r\nDigipass challenge is $challenge");
    }
}
#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_continue
{
    my ($self, $context, $user, $submitted_pw, $p) = @_;

    my ($data, $digipass, $error) = $self->GetDigipassData($user, $p);
    return (0, "GTC Continue failed: $error")
	unless defined $data;

    my ($result, $reason);
    # Maybe get the previous challenge from a context. Destroy it
    # afterwards to prevent reuse
    my $key = "digipass_Challenge:$digipass";
    my $chal_context = &Radius::Context::find($key);
    my $challenge = $chal_context->{last_challenge} if $chal_context;
    &Radius::Context::destroy($key);
    my $ret = Authen::Digipass::AAL2VerifyPassword($data, $self->{kparms}, $submitted_pw, $challenge);
    if ($ret != 0)
    {
	my $err = Authen::Digipass::AAL2GetErrorMsg($ret);
	$p->{Handler}->logPassword($user, $submitted_pw, 'DIGIPASS', 0, $p) if $p->{Handler};
	$result = 0;
	$reason = "Digipass authentication failed for $user: $err";
    } 
    else
    {
	$p->{Handler}->logPassword($user, $submitted_pw, 'DIGIPASS', 1, $p) if $p->{Handler};
	$result = 1;
    }
    return (0, 'Database update failure')
	unless $self->UpdateDigipassData($data, $digipass, $p);
    return ($result, $reason);
}

#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_end
{
    my ($self, $context, $user) = @_;
}

#####################################################################
# Return ($data, $digipass, $error)
# $data is the raw digipass data block
# $digipass is a key that identifies the record where the data is stored,
# it is not used by the caller except to pass back to UpdateDigipassData
sub GetDigipassData
{
    my ($self, $user, $p) = @_;

    $self->log($main::LOG_ERR, "Someone forgot to override GetDigipassData", $p);
    return (undef, undef, undef, 'Software Author Failure')
}

#####################################################################
# $digipass is the key identifying the record where the data is to be stored,
# must be the same as was returned by GetDigipassData.
sub UpdateDigipassData
{
    my ($self, $data, $digipass, $p) = @_;

    $self->log($main::LOG_ERR, "Someone forgot to override UpdateDigipassData", $p);
}

1;
