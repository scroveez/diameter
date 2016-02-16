# AuthDYNADDRESS.pm
#
# Object for allocating IP addresses
# Calls the subclass of AddressAllocatorGeneric named
# by the Allocator parameter. The allocator is required 
# to provide 3 functions: allocate(), confirm() and deallocate().
# allocate() is called when a new address is required during
#  an Access-Request.
# confirm() is called when an Accounting Start and Accounting Alive
#  packet is received
# deallocate() is called when an Accounting Stop is received and the
#  allocated address is no longer required.
#
# The allocator may behave in a synchronous (eg allocates an address
# immediately) or asynchronous fashion (eg make a request
# to a remote address allocator, which may reply some time later)
#
# The allocator should behave like this:
# For synchronous operation:
# allocate: find addresses and other interesting info, put them
# in a has, and call its caller's (ie our) allocateDone() function,
# passing the hash. allocate() returns ACCEPT or REJECT, telling
# the calling handler whether to accept or reject.
# confirm: Confirm the address is in use, call its caller's (ie our) 
# confirmDone() function. confirm() returns ACCEPT or REJECT, telling
# the calling handler whether to accept or reject.
# deallocate: Deallocate the address so it is availbale for future use,
# call its caller's (ie our) 
# deallocateDone() function. deallocate() returns ACCEPT or REJECT, 
# telling
# the calling handler whether to accept or reject.
#
# For an asynchronous operation:
# allocate: start the allocation process and return IGNORE. Some time
# later when the results of the allocation are available, call
# the callers (ie our) allocate done, then call sendReplyTo to
# send the reply to the original requester
# confirm: start the confirm process and return IGNORE. Some time
# later when any confirm is done, call
# the callers (ie our)  confirmDone, then call sendReplyTo to
# send the reply to the original requester.
# deallocate: start the deallocate process and return IGNORE. Some time
# later when any deallocation is complete, call
# the callers (ie our)  deallocateDone, then call sendReplyTo to
# send the reply to the original requester.
#
# It is permitted to mix synchronous and asynchronous operation,
# eg the allocator might do an async allocate() but a sync confirm()
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthDYNADDRESS.pm,v 1.15 2014/02/06 21:36:44 hvn Exp $

package Radius::AuthDYNADDRESS;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Radius::AddressAllocatorGeneric;
use Radius::User;
use strict;

%Radius::AuthDYNADDRESS::ConfigKeywords = 
('PoolHint'         => 
 ['string', 'specifies how the pool hint is derived. A pool hint is generally used by an AddressAllocator to determine which pool to allocate an address from. The value of the pool hint will therefore depend on what type of Address Allocator you are using, and usually which pools are available.', 0],
 'MapAttribute'     => 
 ['stringhash', 'This optional parameter allows you to specifiy how the results of the address allocation are to be placed in the reply. If the yiaddr attribute (usually Framed-IP-Address)  is already set in the reply, then AuthBy DYNADDRESS will not allocate an addresss, and will just ACCEPT the request. This means that if a user record has a fixed IP address in it, then AuthBy DYNADDRESS will not allocate an address for that user.', 1],
 'AddressAllocator' => 
 ['formatobjectlist', 'List of AddressAllocator objects, specifies which Address Allocation engine will be used to allocate the addresses. Special formatting characters are permitted.', 0],
 );

# RCS version number of this module
$Radius::AuthDYNADDRESS::VERSION = '$Revision: 1.15 $';

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    $self->log($main::LOG_ERR, "No Allocator defined for AuthDYNADDRESS in '$main::config_file'")
	unless defined $self->{AddressAllocator};

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
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    # By default, we derive the pool name from a pseudo reply
    # attribute defined by a previous AuthBy
    $self->{PoolHint} = '%{Reply:PoolHint}';
    
    # By default, we just use the allocated IP address
    # and put it into Framed-IP-Address
    $self->{MapAttribute}{yiaddr} = 'Framed-IP-Address';
    $self->{MapAttribute}{subnetmask} = 'Framed-IP-Netmask';
}

#####################################################################
# Override the keyword function in Configurable
sub keyword
{
    my ($self, $file, $keyword, $value) = @_;

    if ($keyword eq 'Allocator')
    {
	# Find the address allocator named. Deprecated, use
	# AddressAllocator instead.
	# REVISIT: remove support one day
	$self->findAndUse('AddressAllocator', $value);
    }
    else
    {
	return $self->SUPER::keyword($file, $keyword, $value);
    }
    return 1;
}

#####################################################################
# Handle a request
# This function is called for each packet. $p points to a Radius::
# packet
# REVISIT:should we fork before handling. There might be long timeouts?
sub handle_request
{
    my ($self, $p, $dummy, $extra_checks) = @_;

    my $type = ref($self);
    $self->log($main::LOG_DEBUG, "Handling with $type", $p);

    my $user_name = $p->getUserName;
    if ($p->code eq 'Access-Request')
    {
	# REVISIT: first confirm that there is no 
	# address present yet in the reply. yiaddr gives the
	# name of the radius attribute where the allocated address
	# would be put if we got that far.
	return ($main::ACCEPT) # Do nothing
	    if $p->{rp}->get_attr($self->{MapAttribute}{yiaddr});

	$user_name =~ s/@[^@]*$//
	    if $self->{UsernameMatchesWithoutRealm};
	my $pool_hint = &Radius::Util::format_special($self->{PoolHint}, $p);
	return $self->allocate($user_name, $pool_hint, $p)
	    if $pool_hint ne '';

	# No pool hint: complain but return ACCEPT
	$self->log($main::LOG_DEBUG, "No PoolHint found. No address will be allocated");
	return ($main::ACCEPT);
	
    }
    elsif ($p->code eq 'Accounting-Request')
    {
	my $address = $p->getAttrByNum
	    ($Radius::Radius::FRAMED_IP_ADDRESS);
	my $type = $p->getAttrByNum($Radius::Radius::ACCT_STATUS_TYPE);

	if ($type eq 'Start')
	{
	    # Its a start, confirm the address is in use
	    return $self->confirm($address, $p);
	}
	elsif ($type eq 'Alive')
	{
	    # Its an alive, confirm the address is still in use
	    return $self->confirm($address, $p);
	}
	elsif ($type eq 'Stop')
	{
	    # Its a stop, deallocate the address
	    return $self->deallocate($address, $p);
	}
	# Catch everything else
	return ($main::ACCEPT); 
    }
    else
    {
	# Send a generic reply on our behalf
	return ($main::ACCEPT); 
    }
}

#####################################################################
# Called by the allocator when the allocation has been done
sub allocateDone
{
    my ($self, $p, $result) = @_;

    # Allocation succeeded, map the results to the reply
    $self->mapResult($result, $p->{rp});
    # Add any AuthBy specific attributes
    $self->adjustReply($p);
}

#####################################################################
# Called by the allocator when the confirm has been done
sub confirmDone
{
    my ($self, $p, $result) = @_;

}

#####################################################################
# Called by the allocator when the deallocation has been done
sub deallocateDone
{
    my ($self, $p, $result) = @_;

}

#####################################################################
# Take an allocation result, and map it into redius reply 
# attributes
sub mapResult
{
    my ($self, $result, $p) = @_;

    # Now go through the list of allocation results that
    # we have to map into radius reply attribtues
    my $name;
    foreach $name (sort keys %{$self->{MapAttribute}})
    {
	# If there is a definition for this result,
	# and the corresponding radius reply attribute
	# is not already set in the reply, and we
	# actually have a value for it, then set it
	my $value;
	if ($self->{MapAttribute}{$name} ne ''
	    && $$result{$name} ne ''
	    && ! $p->get_attr($name))
	{
	    $p->add_attr($self->{MapAttribute}{$name}, $$result{$name});
	}
    }
}


#####################################################################
# Shortcuts for accessing our allocator
sub allocate
{
    my ($self, @args) = @_;
    return $self->{AddressAllocator}[0]->allocate($self, @args);
}

sub deallocate
{
    my ($self, @args) = @_;
    return $self->{AddressAllocator}[0]->deallocate($self, @args);
}

sub confirm
{
    my ($self, @args) = @_;
    return $self->{AddressAllocator}[0]->confirm($self, @args);
}

1;
