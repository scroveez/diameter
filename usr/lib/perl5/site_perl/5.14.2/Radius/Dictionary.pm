# Dictionary.pm
#
# Routines for managing the Diameter attibute dictionary, and 
# for packing and unpacking data according to the dictionary specifications
# Also vendor name/numbers etc
#
# Data structures are:
#
# AttrNum{vendornum}->{attrnum} -------> [attrname, attrtype, attrnum, vendornum, flags]
# AttrName{attrname}------------------->
#
# ValName{attrnum}->{valuenum}---------> [valuename, value, attributename]
# ValNum{attrname}->{valuenum}--------->
#
# VendorName{vendorname}---------------> [vendorname, vendornum, extras]
# VendorNum{vendornum}----------------->
#
# Part of the Radius project.
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2004 Open System Consultants
# $Id: Dictionary.pm,v 1.6 2014/02/10 22:25:11 hvn Exp $

package Radius::Dictionary;
use base ('Radius::Logger');
use strict;

# RCS version number of this module
$Radius::Dictionary::VERSION = '$Revision: 1.6 $';

$Radius::Dictionary::default = undef;

#####################################################################
# Parse a dictionary file
sub load_file
{
    my ($self, $filename) = @_;

    &main::log($main::LOG_DEBUG, "Reading dictionary file '$filename'");
    if (!open(FILE, $filename))
    {
	&main::log($main::LOG_ERR, "Could not open dictionary file '$filename': $!");
	return;
    }
    $self->load_handle(*FILE, "file $filename");
    close(FILE);
    return 1;
}

#####################################################################
# Parse any sort of dictionary handle
# $name is a desciptive name for error logging
sub load_handle
{
    my ($self, $handle, $handledesc) = @_;

    while (<$handle>)
    {
	s/#.*$//;          # Remove comments
	next if /^\s*$/;   # Skip blank lines
	chomp;

	# ATTRIBUTE name number type [flags]
	if (/^ATTRIBUTE\s+(\S+)\s+(\d+)\s+(\S+)(\s+(\S+))?\s*(\S+)?$/)
	{
	    main::log($main::LOG_WARNING, "Ignoring trailing garbage '$6' in Diameter dictionary $handledesc")
		if defined $6;
	    $self->defineAttr($2, 0, $1, $3, $5);
	}
	# VENDORATTR|VSA|VENDOR_ATTRIBUTE vendornum name number type [flags]
	elsif (/^(VENDORATTR|VSA|VENDOR_ATTRIBUTE)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(\s+(\S+))?\s*(\S+)?$/)
	{
	    my ($vendor, $name, $attrnum, $type, $flags, $garbage) = ($2, $3, $4, $5, $7, $8);

	    main::log($main::LOG_WARNING, "Ignoring trailing garbage '$8' in Diameter dictionary $handledesc")
		if defined $8;

	    # Convert vendor name to number if needed
	    $vendor = $self->{VendorName}{$2}[1]
		if $vendor !~ /^\d+$/ 
		    && defined $self->{VendorName}{$2};
	    # Handle oct and hex
	    $attrnum = oct $attrnum if $attrnum =~ /^0/; 
	    $self->defineAttr($attrnum, $vendor, $name, $type, $flags);
	}
	# VALUE attrname valname valnum
	elsif (/^VALUE\s+(\S+)\s+(\S+)\s+(\d+)/)
	{
	    $self->defineVal($1, $2, $3);
	}
	# Compatibility with Merit.
	# VENDOR_CODE  name number extra-info
	elsif (/^VENDOR\s+(\S+)\s+(\S+)\s*(.*)/
	       || /^VENDOR_CODE\s+(\S+)\s+(\S+)\s*(.*)/)
	{
	    $self->defineVendor($1, $2, $3);
	}
	elsif (/^NAS_TYPE\s+(\d+)\s+(\S+)\s+(.*)/)
	{
	    # $1 = value-as-int, $2 = Vendor-Code, $3 = Description
	}
	elsif (/^TACACS_VALUE\s+(\S+)\s+(\S+)\s+(\d+)/)
	{
	    # $1 = Tac-Attrib, $2 = field name, $3 = function
	}
	elsif (/^ATTRIB_TACACS\s+(\S+)\s+(\S+)\s+(\S+)/)
	{
	    # $1 = Tac-Attrib, $2 = value, $3 = type
	}
	else
	{
	    &main::log($main::LOG_ERR, "Bad format in dictionary $handledesc at line $.: $_");
	}

    }

    return 1;
}

#####################################################################
# Return 1 if we know this type. Return 0 otherwise. We make a
# subclass of this in case Dictionary will someday be a base for
# RADIUS dictionary too.
sub is_known_type
{
    my ($self, $type) = @_;

    $self->log($main::LOG_ERR, 'Someone forgot to override Dictionary::is_known_type');
    return 0;
}

#####################################################################
# Return flags in suitable format for the type of Dictionary. For
# example, bitmap for Diameter. We make a subclass of this in case
# Dictionary will someday be a base for RADIUS dictionary too.
sub resolve_flags
{
    my ($self, $name, $vendor, $flags) = @_;

    $self->log($main::LOG_ERR, 'Someone forgot to override Dictionary::resolve_flags');
    return 0;
}

#####################################################################
# defineAttr
# Define a new attribute
sub defineAttr
{
    my ($self, $number, $vendor, $name, $type, $flags) = @_;

    unless ($self->is_known_type($type))
    {
	main::log($main::LOG_WARNING, "Bad type $type for attribute $name in dictionary. Encoding and decoding this attribute may fail.");
    }

    my $resolvedflags = $self->resolve_flags($name, $vendor, $flags);
    $vendor = 0 unless defined $vendor;
    my $a = [$name, $type, $number, $vendor, $resolvedflags];

    # Clobbers any previously existing defs
    $self->{AttrNum}->{$vendor}->{$number} = $a;
    $self->{AttrName}->{$name} = $a;

    return $a;
}

#####################################################################
# defineVal
# Define a new named value
sub defineVal
{
    my ($self, $attrname, $valname, $value) = @_;

    my $v = [ $valname, $value, $attrname ];
    # Clobber any previously existing defs
    $self->{ValName}->{$attrname}->{$valname} = $v;
    $self->{ValNum}->{$attrname}->{$value} = $v;

    return $v;
}

#####################################################################
# defineVendor
# Define a new Vendor
sub defineVendor
{
    my ($self, $name, $number, @extras) = @_;

    my $a = [$name, $number, @extras ]; 

    # Clobber any previously existing defs
    $self->{VendorNum}->{$number} = $a;
    $self->{VendorName}->{$name} = $a;

    return $a;
}

#####################################################################
# Return all the details of an attribute given its name
# The array is (name, type, number, vendorid, flags)
sub attrByName
{
    my ($self, $name) = @_;

    return @{$self->{AttrName}->{$name}} if exists $self->{AttrName}->{$name};
    return;
}

#####################################################################
# Return all the attribute details for an attribute
# given the attribute number and vendor
# The array is (name, type, number, vendorid, flags)
sub attrByNum
{
    my ($self, $number, $vendor) = @_;

    $vendor += 0;
    return @{$self->{AttrNum}->{$vendor}->{$number}}
        if (exists $self->{AttrNum}->{$vendor}->{$number});
	    
    return ("Attr-$vendor-$number", 'OctetString', $number, $vendor);
}

#####################################################################
# Return the value name given the attritbue name and the value number
# return (valname, value, attrname )
sub valByNum
{
    my ($self, $attrname, $valnum) = @_;

    return @{$self->{ValNum}->{$attrname}->{$valnum}}
	if (exists $self->{ValNum}->{$attrname}->{$valnum});
    return;
}

#####################################################################
# Return the value number given the atribute name and value name
# If its already an integer, dont to anything
sub valByName
{
    my ($self, $attrname, $valname) = @_;

    # maybe Hex conversion, too
    return ($attrname, hex($1), $valname)
	if ($valname =~ /^0x([0-9a-fA-F]+)$/i);

    return @{$self->{ValName}->{$attrname}->{$valname}}
	if (exists $self->{ValName}->{$attrname}->{$valname});
    
    return;
}

#####################################################################
# Return a list of all the valid value names for a given attribute name
sub valuesForAttribute
{
    my ($self, $attrname) = @_;

    return sort keys %{$self->{ValName}->{$attrname}};
}

#####################################################################
# Return a list of all known vendor numbers
sub vendorNums
{
    my ($self) = @_;

    return sort keys %{$self->{VendorNum}}
}

#####################################################################
# Return vendor data from vendor number
# Returns [vendorname, vendornumber, @extras ]; 
sub vendorByNum
{
    my ($self, $vendornum) = @_;

    return @{$self->{VendorNum}->{$vendornum}}
	if (exists $self->{VendorNum}->{$vendornum});
    
    return;
}
#####################################################################
# Return vendor data from vendor name
# Returns [vendorname, vendornumber, @extras ]; 
sub vendorByName
{
    my ($self, $vendorname) = @_;

    return @{$self->{VendorName}->{$vendorname}}
	if (exists $self->{VendorName}->{$vendorname});
    
    return;
}


1;

