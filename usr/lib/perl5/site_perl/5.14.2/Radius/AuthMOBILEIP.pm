# AuthMOBILEIP.pm
#
# Object for handling Authentication for 3GPP2 Mobile IP
#
# Add this to your authentication chain _after_ the user or HA
# authentication modules, with AuthByPolicy of ContinueWhileAccept
# When this module runs, it will determine whether it is a HA
# key distribution requets or an FA authenticaiotn request and set
# additional attributes in the reply as necessary.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthMOBILEIP.pm,v 1.4 2007/12/18 21:23:50 mikem Exp $

package Radius::AuthMOBILEIP;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use strict;

# This is hashed by "$fa.$ha". Each entry is an array of 3 items,
# skey, expiry timestamp and keyid
%Radius::AuthMOBILEIP::skeys = ();

# Can make sure we get reinitialized on sighup
push(@main::reinitFns, \&reinitialize);

#####################################################################
# This hash describes all the standards types of keywords understood by this
# class. If a keyword is not present in ConfigKeywords for this
# class, or any of its superclasses, Configurable will call sub keyword
# to parse the keyword
# See Configurable.pm for the list of permitted keywordtype
%Radius::AuthMOBILEIP::ConfigKeywords = 
(
 'SLifetime'        => 
 ['integer', 'Maximum lifetime of internally generated S keys in seconds', 1],

 'SLength'          => 
 ['integer', 'You can control the length (in octets) of internally generated S keys with SLength, defaults to 16', 1],

 'DefaultHAAddress' => 
 ['string', 'If a user does not have their own 3GPP2-Home-Agent-Address, this will be used as the IP address for 3GPP2-Home-Agent-Address. If a user has no 3GPP2-Home-Agent-Address, and there is no DefaultHAAddress, they will be rejected. If the address is 0.0.0.0, then any suggested 3GPP2-Home-Agent-Address in the request will be used', 0],

 'HandleHARequests' => 
 ['flag', 'You can stop MOBILEIP from handling HA key distribution requests by setting HandleHARequests to off', 1],

 'HandleFARequests' => 
 ['flag', 'You can stop MOBILEIP from handling FA user authentication requests by setting HandleFARequests to off', 1],
 );

# RCS version number of this module
$Radius::AuthMOBILEIP::VERSION = '$Revision: 1.4 $';

#####################################################################
# Do per-instance default initialization
# This is called by Configurable during Configurable::new before
# the config file is parsed. Its a good place initialize instance 
# variables
# that might get overridden when the config file is parsed.
# If it doesnt do anything, you can omit it.
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{SLifetime} = 3600;
    $self->{SLength} = 16;
    $self->{HandleHARequests} = 1;
    $self->{HandleFARequests} = 1;
}

#####################################################################
# Handle a request
sub handle_request
{
    my ($self, $p, $dummy, $extra_checks) = @_;
    $p->{PacketTrace} = $self->{PacketTrace} 
        if defined  $self->{PacketTrace}; # Optional extra tracing
    my $type = ref($self);
    $self->log($main::LOG_DEBUG, "Handling with $type: $self->{Identifier}", $p);
    # Now we might fork before processing the request
    # Should only do this for "slow" authentication methods
    return ($main::IGNORE, 'forked')
	if $self->{Fork} && !$self->handlerFork();

    # We only doing special things with access requests
    return ($main::ACCEPT)
	if ($p->code ne 'Access-Request');

    my $nas_id = $p->getNasId();
    my $user_name = $p->getUserName();
    if ($self->{HandleHARequests}
	&& $user_name =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/
	&& $2 eq $nas_id)
    {
	$self->log($main::LOG_DEBUG, "Handling Mobile IP HA key dist for $1->$2", $p);
	# Its a key distribution request from an HA
	# Get or generate the S Key for this FA/HA pair 
	# and its expiry timestamp
	my ($skey, $expiry, $keyid) = $self->getGenSKey($1, $2);
	
	# Add reply attributes for the S Key and it expiry
	$p->{rp}->add_attr('3GPP2-S-Key', $skey);
	$p->{rp}->add_attr('3GPP2-S-Lifetime', $expiry);
    }
    elsif ($self->{HandleFARequests})
    {
	# Its an authentication request from an FA for a user.
	$self->log($main::LOG_DEBUG, "Handling Mobile IP FA authentication", $p);

	# First, need to work
	# out the HA address for this user
	my $ha = $p->{rp}->get_attr('3GPP2-Home-Agent-Address');
	$ha = $self->{DefaultHAAddress} unless $ha;

	if ($ha eq '0.0.0.0')
	{
	    # Use the one in the request
	    $ha = $p->get_attr('3GPP2-Home-Agent-Address');
	}

	if ($ha eq '')
	{
	    # 
	    $self->log($main::LOG_DEBUG, "Could not determine Home Agent Address. Rejecting", $p);
	    return($main::REJECT, 'No Home Agent Address');
	}
	$p->{rp}->change_attr('3GPP2-Home-Agent-Address', $ha);

	# Now see if they want a pre-shared-secret
	if ($p->get_attr('3GPP2-Pre-Shared-Secret-Request') eq 'Yes')
	{
	    my ($skey, $expiry, $keyid) = $self->getGenSKey($nas_id, $ha);
	    my $pss = &Radius::Util::hmac_md5($skey, $keyid . $expiry);
	    $p->{rp}->add_attr('3GPP2-Pre-Shared-Secret', $pss);
	    $p->{rp}->add_attr('3GPP2-Key-Id', $keyid);
	}

    }
    return ($main::ACCEPT)
}

#####################################################################
# Find or generate the skey, expiry timestamp nad keyid for this FA/HA pair
# $fa and $ha are dotted quad strings
# If the required skey does not exist or if it has expired, generate
# a new skey.
sub getGenSKey
{
    my ($self, $fa, $ha) = @_;

    my $hashkey = "$fa.$ha";
    if (!exists $Radius::AuthMOBILEIP::skeys{$hashkey}
	|| $Radius::AuthMOBILEIP::skeys{$hashkey}[1] < time)
    {
	#generate a new skey
	my $skey = &Radius::Util::random_string($self->{SLength});
	my $expiry = time + $self->{SLifetime};
	my $keyid = pack('a8 a8 N', 
			 sprintf('%08x', unpack('N', &Socket::inet_aton($ha))),
			 sprintf('%08x', unpack('N', &Socket::inet_aton($fa))),
			 $expiry);
	$Radius::AuthMOBILEIP::skeys{$hashkey} = [$skey, $expiry, $keyid];
    }
    # Return the key as an array
    return @{$Radius::AuthMOBILEIP::skeys{$hashkey}};
}

#####################################################################
# Called when the server is HUPd
sub reinitialize
{
    %Radius::AuthMOBILEIP::skeys = ();
}

1;
