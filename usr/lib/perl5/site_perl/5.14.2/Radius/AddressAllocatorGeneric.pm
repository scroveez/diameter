# AuthGeneric.pm
#
# Object for handling generic address allocation
#
# Module for allocating addresses from an SQL database.
# Address allocation modules like this are required to implement32 
# functions:
#
# allocate takes a user name, pool hint and returns a hash of allocated
# values. The keys in the returned hash may include:
#  yiaddr: the allocated IP address
#  subnetmask: a subnet mask that goes with the address
#  dnsserver: the address of a DNS server
#
# confirm takes a previously allocated address and confirms that it
# is still in use
#
# deallocate takes a previously allocated address and deallocates it
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AddressAllocatorGeneric.pm,v 1.3 2007/09/25 11:31:13 mikem Exp $

package Radius::AddressAllocatorGeneric;
@ISA = qw(Radius::Configurable);
use Radius::Configurable;
use strict;

# RCS version number of this module
$Radius::AddressAllocatorGeneric::VERSION = '$Revision: 1.3 $';

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{ObjType} = 'AddressAllocator'; # Maintain an Identifier directory
}

#####################################################################
# Find the allocator module with the identifier name given
sub find
{
    return &Radius::Configurable::find('AddressAllocator', $_[0]);
}

1;
