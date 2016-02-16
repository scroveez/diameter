# RDict.pm
#
# Objects for handling radius dictionaries
#
# Attribute types are stored at RAttr objects
# RDict has 2 hashes for retreving them:
#  AttrNum hashes (attribute number, vendor ID) to RAttr
#  AttrName hashes atribute name to RAttr
# 
# Values are stored as RVal objects
# RDict has 2 hashes for retreving them:
#  ValName hashes (attribute name, value name) to RVAl
#  ValNum hashes (attribute name, value number) to RVal
#
# For non-vendor specific attributes and values, Vendor ID is undef.
# An RAttr is an array with the following items:
#  0 Attribute Name
#  1 Attribute number
#  2 Attribute type
#  3 Vendor ID
#  4 Optional flags
#
# An RVal is an array with the following items:
#  0 Value name
#  1 Value number
#  2 Attribute name
#
# This code is loosely inspired by Dictionary.pm by 
# Christopher Masto, chris@netmonger.net, but has been conmpletely rewritten 
# especially to include vendor-specific attributes
# 
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: RDict.pm,v 1.45 2014/01/09 21:56:31 hvn Exp $

package Radius::RDict;
use Radius::Util;
use File::Basename;
use strict;

# RCS version number of this module
$Radius::RDict::VERSION = '$Revision: 1.45 $';

#####################################################################
# Create a new dictionary object. If one or more files names are supplied, 
# parse them. If any parsing fails, returns undef.
sub new
{
    my ($class, @files) = @_;

    my $self = {};
    bless $self, $class;
    $self->{AttrNum} = {}; # Hash of 
    $self->{AttrName} = {}; # Hash of 
    $self->{ValNum} = {};
    $self->{ValName} = {};
    $self->{VendorNum} = {}; # Vendor codes by number
    $self->{VendorName} = {}; # Vendor codes by name
    $self->{TLV} = {}; # Sub-Dictionary for each TLV
    foreach (@files)
    {
	$self->parse($_);
    }
    return $self;
}

#####################################################################
# Parse a dictionary file
sub parse
{
    my ($self, $filename) = @_;

    &main::log($main::LOG_DEBUG, "Reading dictionary file '$filename'");

    local (*FILE);
    if (!open(FILE, $filename))
    {
	&main::log($main::LOG_ERR, "Could not open dictionary file '$filename': $!");
	return;
    }
    $self->parse_handle(*FILE, $filename);
    close(FILE);
    return 1;
}

#####################################################################
# parse_handle
# Parse a dictionary file
sub parse_handle
{
    my ($self, $handle, $handledesc) = @_;

    my $current_vendor = undef;
    my $current_tlv = undef;
    my @tlvs = (); # TLVs and therefore TLV dictionaries can be nested :-(
    while (<$handle>)
    {
	s/#.*$//;          # Remove comments
	next if /^\s*$/;   # Skip blank lines
	chomp;

#	print "Doing $_\n";
	# ATTRIBUTE name number type [flags]
	if (/^ATTRIBUTE\s+(\S+)\s+(\S+)\s+(\S+)(\s+(\S+))?/)
	{
	    my $dict = $current_tlv || $self;
	    my $vendor = $current_tlv ? 0 : $current_vendor; # TLVs dont have vendor numbers
	    main::log($main::LOG_WARNING, "Failed to add attribute $1 in dictionary '$handledesc' line $. Ignored")
		unless $dict->defineAttr($1, $2, $3, $vendor, $5);
	}
	# VENDORATTR|VSA|VENDOR_ATTRIBUTE vendornum name number type [flags]
	elsif (/^(VENDORATTR|VSA|VENDOR_ATTRIBUTE)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(\s+(\S+))?/)
	{
	    my ($vendor, $name, $attrnum, $type, $flags) = ($2, $3, $4, $5, $7);
	    # Convert vendor name to number if needed
	    $vendor = $self->{VendorName}{$vendor}[1]
		if $vendor !~ /^\d+$/ 
		    && defined $self->{VendorName}{$vendor};
	    # Handle oct and hex
	    $attrnum = oct $attrnum if $attrnum =~ /^0/; 
	    main::log($main::LOG_WARNING, "Failed to add attribute $name in dictionary '$handledesc' line $. Ignored")
		unless $self->defineAttr($name, $attrnum, $type, $vendor, $flags);
	}
	# VALUE attrname valname valnum
	elsif (/^VALUE\s+(\S+)\s+(\S+)\s+(\d+)/)
	{
	    my $dict = $current_tlv || $self;
	    if (defined $dict->{AttrName}->{$1})
	    {
		$dict->defineVal($1, $2, $3);
	    }
	    else
	    {
		# Dont complain too loud about these: some dictionaries are
		# guilty of it
		&main::log($main::LOG_WARNING, "There is no attribute named $1 in dictionary '$handledesc' before line $. Ignored");
	    }
	}
	# Compatibility with Merit.
	# VENDOR_CODE  name number extra-info
	elsif (/^VENDOR(_CODE)?\s+(\S+)\s+(\S+)\s*(.*)/)
	{
	    $self->defineVendor($2, $3, $4);
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
	elsif (/^BEGIN-VENDOR\s+(\S+)/i)
	{
	    # FreeRadius
	    my @vdetails = $self->vendorByName($1);
	    $current_vendor = $vdetails[1];
	}
	elsif (/^END-VENDOR/i)
	{
	    # FreeRadius
	    $current_vendor = undef;
	}
	elsif (/^BEGIN-TLV\s+(\S+)/i)
	{
	    push(@tlvs, $current_tlv); # Save the current TLV dictionary
	    my $dict = $current_tlv || $self;
	    $current_tlv = Radius::RDict->new();
	    $dict->{TLV}{$1} = $current_tlv;
	}
	elsif (/^END-TLV/i)
	{
	    # FreeRadius
	    $current_tlv = pop(@tlvs);
	}
	elsif (/^include\s+(.*)/)
	{
	    # Radiator style include
	    # May be a glob
	    foreach (glob(&Radius::Util::format_special($1)))
	    {
		$self->parse($_);
	    }
	}
	elsif (/^\$INCLUDE\s+(.*)/)
	{
	    # Freeradius style include, relative to this file
	    my $path = $1;
	    # RElative path
	    $path = dirname($handledesc) . '/' . $path
		unless $path =~ /^\//;
	    $self->parse($path);
	}
	else
	{
	    &main::log($main::LOG_ERR, "Bad format in dictionary '$handledesc' at line $.: $_");
	}

    }
    return 1;
}


#####################################################################
# defineAttr
# Define a new attribute
sub defineAttr
{
    my ($self, $name, $number, $type, $vendor, $flags) = @_;

    if ($name =~ /^Unknown/)
    {
	main::log($main::LOG_WARNING, "Attribute $name starts with reserved prefix 'Unknown', ignoring");
	return;
    }

    $vendor += 0;
    my $a = [$name, $number, $type, $vendor, $flags ]; 
    my $key = "$number,$vendor";
    # Clobber any previously existing defs
    $self->{AttrNum}->{$key} = $a;
    $self->{AttrName}->{$name} = $a;

    return $a;
}

#####################################################################
# defineVal
# Define a new named value
sub defineVal
{
    my ($self, $attribute, $name, $number) = @_;

    my $v = [ $name, $number, $attribute ];
    # Clobber any previously existing defs
    $self->{ValName}->{$attribute}->{$name} = $v;
    $self->{ValNum}->{$attribute}->{$number} = $v;

    return $v;
}

#####################################################################
# defineAttr
# Define a new attribute
sub defineVendor
{
    my ($self, $name, $number, $extras) = @_;

    my $a = [$name, $number, $extras ]; 

    # Clobber any previously existing defs
    $self->{VendorNum}->{$number} = $a;
    $self->{VendorName}->{$name} = $a;

    return $a;
}

sub vendorByName
{
    my ($self, $name) = @_;
    return @{$self->{VendorName}->{$name}};
}

sub vendorByNum
{
    my ($self, $num) = @_;
    return @{$self->{VendorNum}->{$num}};
}

#####################################################################
# Return all the details of an attribute given its name
# The array is (name, number, type, vendorid)
sub attrByName
{
    my ($self, $name) = @_;

    return exists $self->{AttrName}->{$name}
           ? @{$self->{AttrName}->{$name}} : undef;
}

#####################################################################
# Return all the attribute details for an attribute
# given the attribute number and vendor
# The returned array is (name, number, type, vendorid, flags)
sub attrByNum
{
    my ($self, $number, $vendor) = @_;

    $vendor += 0;
    my $key = "$number,$vendor";

    return @{$self->{AttrNum}->{$key}}
        if (exists $self->{AttrNum}->{$key});

    my $msg = '';
    $msg = " (vendor $vendor)" if $vendor;
    &main::log($main::LOG_ERR, "Attribute number $number$msg is not defined in your dictionary");
    return ('Unknown', $number, undef, undef, undef);
}

#####################################################################
# Return all the attribute details for an attribute given the
# attribute number and vendor. For unknown attributes return special
# name Unknown-vendor-number where vendor is 0 for IANA type space.
# The returned array is (name, number, type, vendorid, flags, is_unknown)
sub attrOrUnknownByNum
{
    my ($self, $number, $vendor) = @_;

    $vendor += 0;
    my $key = "$number,$vendor";

    return (@{$self->{AttrNum}->{$key}}, 0)
        if (exists $self->{AttrNum}->{$key});

    # Unknown attribute from IANA type space (vendor 0) or unknown vendor attribute
    return ("Unknown-$vendor-$number", $number, 'binary', $vendor, undef, 1);
}

#####################################################################
# Return the value name given the attritbue name and the value number
sub valNumToName
{
    my ($self, $attrname, $valnum) = @_;

    return $self->{ValNum}->{$attrname}->{$valnum}->[0]
	if (defined $valnum && exists $self->{ValNum}->{$attrname}->{$valnum});

    return undef;
}

#####################################################################
# Return the value number given the atribute name and value name
# IF its already an integer, dont to anything
sub valNameToNum
{
    my ($self, $attrname, $val) = @_;

    if ($val =~ /^0x([0-9a-fA-F]+)$/i)
    {
	# Hex
	$val = hex($1);
    }
    else
    {
	# It might be a decimal integer, or it might be a VALUE with an integer name,
	# such as Tunnel-Medium-Type=802
	if (exists $self->{ValName}->{$attrname}->{$val})
	{
	    $val = $self->{ValName}->{$attrname}->{$val}->[1];
	}
	else
	{
	    # Is there a (possibly negative) decimal integer?
	    if ($val !~ /^-?\d+$/)
	    {
		&main::log($main::LOG_ERR, 
			   "There is no value named $val for attribute $attrname. Using 0.");
		$val = 0;
	    }
	}
    }
    return $val;
}

#####################################################################
# Return a list of all the valid value names for a given attribute name
sub valuesForAttribute
{
    my ($self, $attrname) = @_;

    return sort keys %{$self->{ValName}->{$attrname}};
}

#####################################################################
# Returns the subdictionary for a TLV
sub dictForTLV
{
    my ($self, $tlvname) = @_;

    return $self->{TLV}{$tlvname};
}
1;
