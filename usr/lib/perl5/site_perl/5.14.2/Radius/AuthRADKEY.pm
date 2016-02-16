# AuthRADKEY.pm
#
# Object for handling Authentication and accounting with the
# RadKey authentiocation system from Open System Consultants
# See http://www.open.com.au/radkey/
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthRADKEY.pm,v 1.13 2013/08/13 20:58:45 hvn Exp $

package Radius::AuthRADKEY;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use strict;

%Radius::AuthRADKEY::ConfigKeywords = 
('ChallengeFormat'        => 
 ['string', '', 1],

 'Secret'                 => 
 ['string', '', 1],

 'ResponseLength'         => 
 ['integer', '', 1],

 'ChallengeHistoryLength' => 
 ['integer', '', 1],

 );

# RCS version number of this module
$Radius::AuthRADKEY::VERSION = '$Revision: 1.13 $';

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    # Check that Radiator is configured with a company secret
    $self->log($main::LOG_ERR, "No Secret defined for AuthRADKEY in '$main::config_file'")
	unless defined $self->{Secret};

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
# This is called by Configurabel during Configurable::new before
# the config file is parsed. Its a good place initalze 
# instance variables
# that might get overridden when the config file is parsed.
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{ResponseLength} = 8; 
    $self->{ChallengeHistoryLength} = 100; 
}

#####################################################################
# Handle a request
# This function is called for each packet. $p points to a Radius::
# packet
sub handle_request
{
    my ($self, $p, $dummy, $extra_checks) = @_;

    my $type = ref($self);
    $self->log($main::LOG_DEBUG, "Handling with $type");
    return ($main::IGNORE, "Ignored due to IgnoreAuthentication")
	if $self->{IgnoreAuthentication} 
           && $p->code eq 'Access-Request';
    return ($main::IGNORE, "Ignored due to IgnoreAccounting")
	if $self->{IgnoreAccounting} 
           && $p->code eq 'Accounting-Request';

    my $user_name = $p->getUserName;
    if ($p->code eq 'Access-Request')
    {
	my $pw = $p->decodedPassword();
#	print "Password is $pw\n";
	if ($pw =~ /^1:(.{6})(.{8})/)
	{
	    # Radkey Radius authentication style 1. First field is the 
	    # 6 chars of the challenge, 
	    # and the second is the first 8 chars 
	    # of the hexified response resulting from the 
	    # challenge, username and company secret
	    # examples: 
	    # 1:OYxSXq8fc01946
	    # 1:B2sLXs651dfb4d
	    # 1:e5uTPt7b0db20d
	    my $challenge = $1;
	    my $actualResponse = $2;

	    # Check for replay attacks. We keep a record of
	    # the last ChallengeHistoryLength challenges for the user
	    # in memory. Any duplicates earn an immediate
	    # rejection
	    my $oldchal;
	    foreach $oldchal (@{$self->{ChallengeHistory}->{$user_name}})
	    {
		if ($oldchal eq $challenge)
		{
		    return ($main::REJECT, "Duplicate challenge. Replay attack?");
		}
	    }
	    # Add this challenge to the head of the history
	    unshift(@{$self->{ChallengeHistory}->{$user_name}}, $challenge);
	    # And trim the array to ChallengeHistoryLength entries
	    splice(@{$self->{ChallengeHistory}->{$user_name}}, $self->{ChallengeHistoryLength});
	    
	    # The correct response, 16 bytes of binary
	    my $rs = MakeDigest($challenge, 
				$user_name, 
				$self->{Secret});
	    
	    # Get the first ResponseLength chars of the 
	    # hexified response
	    my $correctResponse = unpack 'H*', $rs;
	    $correctResponse = substr($correctResponse, 0, $self->{ResponseLength});

	    if ($actualResponse eq $correctResponse)
	    {
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
		return ($main::REJECT, "Incorrect RadKey response. Check username and Company Secret.");
	    }
	}
	elsif ($pw =~ /^Digest/i)
	{
	    # Its coming from an Apache or Squid doing Digest,
	    # probably with RadKey algorithm, as implemented by
	    # RadKey Challenger on IE5

	    if ($self->check_digest_password($user_name, $pw, $self->{Secret}))
	    {
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
		return ($main::REJECT, 'Digest password check failed');
	    }
	}
	else
	{
	    # Unknown password style, probably they arent
	    # using RadKey at all
	    return ($main::REJECT, 'Unknown RadKey authentication type. Perhaps the user is not using RadKey authentication?');
	}
    }
    elsif ($p->code eq 'Accounting-Request')
    {
	return ($main::ACCEPT); 
    }
}

#####################################################################
# This function may be called during operation to reinitialize 
# this module
# it is expected to reload any state, perhaps by rereading files, 
# reconnecting to a database or something like that.
# Its not actually called yet, but it as well to be 
# prepared for the day
# when it will be.
sub reinitialize
{
    my ($self) = @_;
}

# Hash the challenge string using the username and company secret
# in the OSC RadKey approved way, ie with the user name and then 
# with the company secret
sub MakeDigest
{
    my ($challenge, $username, $company_secret) = @_;

    my $digest = Radius::AuthGeneric::hmac_md5($username, $challenge);
    my $digest2 = Radius::AuthGeneric::hmac_md5($company_secret, $digest);
    return $digest2;
}

# Converts up to 16 bytes of binary digest into an easy to type reponse
# string suitable for the end user
# Each byte is converted into a consonant followed by a vowel.
# This must match the algorithm in the RadKey Challenger application 
# in ChallengeDlg.cpp
sub ConvertDigestToResponseString
{
    my ($self, $digest) = @_;

    # 32 consonants for the top 5 bits 
    # and 8 vowels for the lower 3 bits
    my $consonants = 'BBCCDDFFGGJJKKLLMMNNPPRRSTTVWWZZ';
    my $vowels = 'AAEEIIOU';

    my ($i, $response);
    for ($i = 0; $i < $self->{ResponseLength}; $i++)
    {
	if ($i %2 == 0)
	{
	    # Top 5 bits select a consonant:
	    my $c = ord(substr($digest, $i / 2, 1)) >> 3; 
	    $response .= substr($consonants, $c, 1);
	}
	else
	{
	    # Low 3 bits select a vowel
	    my $v = ord(substr($digest, $i / 2, 1)) & 0x7;
	    $response .= substr($vowels, $v, 1);
	}
    }
    return $response;
}

###################################################################
# Generate a challenge based on the template in $format
my %permittedCharsForFormat =
    (
     'a', 'aeiou',
     'A', 'AEIOU',
     'b', 'bcdfgjklmnprstvz',
     'B', 'BCDFGJKLMNPRSTVZ',
     '9', '0123456789',
     );
sub generateChallenge
{
    my ($format) = @_;
    my $result;

    my $type;
    foreach $type (split(//, $format))
    {
	my $permitted = $permittedCharsForFormat{$type};
	if (defined $permitted)
	{
	    $result .= &selectRandomChar($permitted);
	}
	else
	{
	    $result .= $type;
	}
    }
    return $result;
}
sub selectRandomChar
{
    my ($string) = @_;

    return substr($string, (int rand(32767)) % length($string), 1);
}

1;
