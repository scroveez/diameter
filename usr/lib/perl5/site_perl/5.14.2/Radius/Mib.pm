# Mib.pm
#
# A Mib object is just a dictionary. Each node inside the mib
# is an entry in the hash.
#
# A MIB is arranged as a tree, with the root at .
# Each node in the tree is either:
# 1. A ref to a Mib object (ie a dictionary)
# 2. A ref to an array. Index 0 is a get fn, index 1 is a getnext fn, 
#    index 2 is a set fn, index 3 is an arbitrary arg that will be passed to 
#    all functions as the first argument. If the set function is not defined
#    the tree under that virtual node is assumed to be read-only. If the
#    getnext funciton is undefined, then it is assumed that there is no
#    subtree under the virtual node, and it is therefore a leaf.
#    that will service any subtree under that (virtual) node.
#    The get function is called like
#       ($error, $value, @pathused) = get_fn($arg, @path);
#    The getnext function is called like
#       ($error, $value, @pathused) = getnext_fn($arg, @path);
#    The set function is called like
#       ($error, $resultingvalue, @pathused) 
#            = set_fn($arg, $newvalue, @path);
# 3. A reference to a scalar. 
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: Mib.pm,v 1.5 2007/09/25 11:31:13 mikem Exp $


package Radius::Mib;
use strict;

# RCS version number of this module
$Radius::Mib::VERSION = '$Revision: 1.5 $';

# These need to match the definitions in @error_status_code
# in SNMP_Session.pm
$Radius::Mib::ERROR_OK = 0;
$Radius::Mib::ERROR_TOOBIG = 1;
$Radius::Mib::ERROR_NOSUCHNAME = 2;
$Radius::Mib::ERROR_BADVALUE = 3;
$Radius::Mib::ERROR_READONLY = 4;
$Radius::Mib::ERROR_GEN_ERR = 5;
$Radius::Mib::ERROR_NOACCESS = 6;
$Radius::Mib::ERROR_WRONGTYPE = 7;
$Radius::Mib::ERROR_WRONGLENGTH = 8;
$Radius::Mib::ERROR_WRONGENCODING = 9;
$Radius::Mib::ERROR_WRONGVALUE = 10;
$Radius::Mib::ERROR_NOCREATION = 11;
$Radius::Mib::ERROR_INCONSISTENTVALUE = 12;
$Radius::Mib::ERROR_RESOURCEUNAVAILABLE = 13;
$Radius::Mib::ERROR_COMMITFAILED = 14;
$Radius::Mib::ERROR_UNDOFAILED = 15;
$Radius::Mib::ERROR_AUTHORIZATIONERROR = 16;
$Radius::Mib::ERROR_NOTWRITABLE = 17;
$Radius::Mib::ERROR_INCONSISTENTNAME = 18;

#####################################################################
# Create a new Mib structure
# Its just an empty dictionary to start with
sub new
{
    my ($class) = @_;

    my $self = {};
    bless $self, $class;

    return $self;
}

#####################################################################
# createPath(@path, $object)
# Adds an object to the Mib at the position indicated by path
# path is an array of oids
# object is one of the permitted object types in a Mib
sub create
{
    my ($self, $object, @path) = @_;

    my $oid = shift(@path);
    if (@path)
    {
	# Add another sub Mib, if not one there already
	if (!exists($self->{$oid}))
	{
	    $self->{$oid} = new Radius::Mib;
	}
	# Else its already there
	$self->{$oid}->create($object, @path);
    }
    else
    {
	# All done, now refer to the object
	$self->{$oid} = $object;
    }
}

#####################################################################
# get(\$root, @path)
# Get the value at the node given by @path relative to the
# root node.
# Returns ($error, $value, @pathused)
# pathused is the portion of @path that was used to get the value
# Usually its the same as @path, unless an error occurred
# This is recursive, and only searches _one_ level of the tree
# 
sub get
{
    my ($self, @path) = @_;

    my $oid = shift(@path);
    if (ref($self->{$oid}) eq 'Radius::Mib')
    {
	# Get the value from the sub Mib
	my ($error, $value, @path) = $self->{$oid}->get(@path);
	return ($error, $value, $oid, @path);
    }
    elsif (ref($self->{$oid}) eq 'SCALAR')
    {
	# Just return the value, and the place we are at
	return ($Radius::Mib::ERROR_OK, ${$self->{$oid}}, ($oid));
    }
    elsif (ref($self->{$oid}) eq 'ARRAY')
    {
	# Its an array of functions, which are to be called
	# to process the rest of the path
	# Call the get function (index 0) and pass it the remaining path
	my $fn = $self->{$oid}[0]; # Be defensive
        return ($Radius::Mib::ERROR_GEN_ERR, undef, ($oid))
            unless defined $fn;

	my ($error, $value, @path_used) 
	    = &{$fn}($self->{$oid}[3], @path);

	# Return the value and the total path that was used
	return ($error, $value, ($oid, @path_used));
    }
    else
    {
	# Perhaps we are not at a leaf node. Anyways its an error
	# REVISIT: what kind of error?
	return ($Radius::Mib::ERROR_NOSUCHNAME, undef, ($oid));
    }
}

#####################################################################
# getnext(\$root, @path)
# Get the next value starting at the node given by @path relative to the
# root node. Root _must_ me a ref to a dictionary.
# Returns ($error, $value, @pathused)
# pathused is the path of the next value that we found
# This is recursive, and only searches _one_ level of the tree
# 
sub getnext
{
    my ($self, @path) = @_;

    my $oid = shift(@path);
    my $node;
    foreach $node (sort { $a <=> $b } keys %$self)
    {
	if (!defined $oid || $node >= $oid)
	{
	    # If we have gone past the last one, then @path must be cleared
	    @path = () if $node > $oid;

	    my $newnode = $self->{$node};
	    if (ref($newnode) eq 'Radius::Mib')
	    {
		# Recursively descend into this dictionary
		my ($error, $retvalue, @path_used) 
		    = $newnode->getnext(@path);
	        # If we found the next one, return it, else keep going
	        return ($error, $retvalue, ($node, @path_used))
		    if $error == $Radius::Mib::ERROR_OK;
		
	    }
	    elsif (ref($newnode) eq 'SCALAR')
	    {
		# If this is the "last" ignore it: its the next 
		# one we are interested in
		next if $node == $oid;

		# Gone past the last value, so take the next one we see
		# Just return the value, and the place we are at
		return ($Radius::Mib::ERROR_OK, $$newnode, ($node));
	    }
	    elsif (ref($newnode) eq 'ARRAY')
	    {
		# Its an array of functions, which are to be called
		# to process the rest of the path
		# Call the getnext function (index 1) and pass it the 
		# remaining path
		my $fn = $$newnode[1]; # Be defensive

		# if no getnext function, then it must be a leaf
		# and we can decide whether its the "next" one,
		# and then call the get function directly
		if (!defined $fn)
		{
		    next if !defined $fn && $node == $oid;
		    $fn = $$newnode[0]; # Be defensive
		    return ($Radius::Mib::ERROR_GEN_ERR, undef, ($oid))
			unless defined $fn;
		}
		
		my ($error, $retvalue, @path_used) 
		    = &{$fn}($$newnode[3], @path);
		# If we found the next one, return it, else keep going
		return ($error, $retvalue, ($node, @path_used))
		    if $error == $Radius::Mib::ERROR_OK;
		
	    }
	    else
	    {
		# Perhaps we are not at a leaf node. Anyways its an error
		# REVISIT: what kind of error?
		return ($Radius::Mib::ERROR_NOSUCHNAME, undef, ($node));
	    }
	}
    }
    # Not found in this level or lower
    return ($Radius::Mib::ERROR_NOSUCHNAME, undef, ($oid));
}

#####################################################################
# set(\$root, $value, @path)
# Set the value at the node given by @path relative to the
# root node.
# Returns ($error, $value, @pathused)
# pathused is the portion of @path that was used to set the value
# $value is the result after doing the set
# Usually its the same as @path, unless an error occurred
# This is recursive, and only searches _one_ level of the tree
# 
sub set
{
    my ($self, $value, @path) = @_;

    my $oid = shift(@path);

    if (ref($self->{$oid}) eq 'Radius::Mib')
    {
	# Get the value from the sub Mib
	my ($error, $value, @path) = $self->{$oid}->set($value, @path);
	return ($error, $value, $oid, @path);
    }
    elsif (ref($self->{$oid}) eq 'SCALAR')
    {
	# Just return the value, and the place we are at
	${$self->{$oid}} = $value;
	return ($Radius::Mib::ERROR_OK, ${$self->{$oid}}, ($oid));
    }
    elsif (ref($self->{$oid}) eq 'ARRAY')
    {
	# Its an array of functions, which are to be called
	# to process the rest of the path
	# Call the set function (index 2) and pass it the remaining path
	my $fn = $self->{$oid}[2];
        return ($Radius::Mib::ERROR_READONLY, undef, ($oid))
            unless defined $fn;

	my ($error, $retvalue, @path_used) 
            = &{$fn}($self->{$oid}[3], $value, @path);

	# Return the value set and the total path that was used
	return ($error, $retvalue, ($oid, @path_used));
    }
    else
    {
	# Perhaps we are not at a leaf node. Anyways its an error
	# REVISIT: what kind of error?
	return ($Radius::Mib::ERROR_NOSUCHNAME, undef, ($oid));
    }
}

#####################################################################
# These functions are the equivalent of the above, but they use
# pretty paths in the form '1.2.3.4.5', both in an out
#
sub createPretty
{
    my ($self, $object, $path) = @_;
    return $self->create($object, split(/\./, $path));
}

sub getPretty
{
    my ($self, $path) = @_;

    my ($error, $value, @pathused) = $self->get(split(/\./, $path));
    return ($error, $value, join('.', @pathused));
}

sub getnextPretty
{
    my ($self, $path) = @_;

    my ($error, $value, @pathused) = $self->getnext(split(/\./, $path));
    return ($error, $value, join('.', @pathused));
}

sub setPretty
{
    my ($self, $nvalue, $path) = @_;

    my ($error, $value, @pathused) = $self->set($nvalue, split(/\./, $path));
    return ($error, $value, join('.', @pathused));
}


1;
