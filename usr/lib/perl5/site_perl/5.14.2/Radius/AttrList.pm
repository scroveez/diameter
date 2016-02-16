# AttrList.pm
#
# Routines for storing lists of attributes
#
# Each attribute is stored in raw (on-the-wire) format, as an array in $self->{Attributes}
# each entry in the array is like:
#  [attrnum, vendornum, flags, value]
# (flags may or may not be relevant to your app)
#
# These routines permit attributes to be added, inserted, removed and accessed.
# Attributes are always accessed using attribute numbers and vendor numbers.
# Values are always passed in and out as raw perl strings, already packed values.
# They do not understand integers or floats: every value is an octet string.
#  append($attrnum, $vendornum, $flags, @values)
#  insert($attrnum, $vendornum, $flags, @values)
#  @($attrnum, $vendornum, $flags, $value) = delete($attrnum, $vendornum)
#  ($attrnum, $vendornum, $flags, $value) = delete_n($index)
#  @values = get($attrnum, $vendornum)
#  $value = get($attrnum, $vendornum) # Gets the first match only
#  ($attrnum, $vendornum, $flags, $value) = get_details($attrnum, $vendornum) # first match only
#  ($attrnum, $vendornum, $flags, $value) = get_n($index)
#  change_n($index, $attrnum, $vendornum, $flags, $value)
#
# The following set of routines work on decoded attribute values. The
# subclass must define the encoding and decoding functions.
#
# Specify attribute number, vendor number and flags.
#  add_attr($attrnum, $vendornum, $flags, $value)
#  @values = get_attrs($attrnum, $vendornum)
#  $value = get_attr($attrnum, $vendornum) # Gets the first match only
#
# Use dictionary names and flags defined in dictionary.
#  add_attr_d($attrname, $attrval)
#  @values = get_attrs_d($attrname)
#  $value = get_attr_d($attrname) # Gets the first match only
#
# Part of the Radius project.
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2005 Open System Consultants
# $Id: AttrList.pm,v 1.8 2014/02/10 22:25:11 hvn Exp $

package Radius::AttrList;
use strict;

# RCS version number of this module
$Radius::AttrList::VERSION = '$Revision: 1.8 $';

#####################################################################
sub new
{
    my ($class, @args) = @_;

    my $self = {@args};
    bless $self, $class;
    return $self;
}

#####################################################################
sub append
{
    my ($self, $attrnum, $vendornum, $flags, @data) = @_;

    $vendornum = 0 unless defined $vendornum;
    map {push(@{$self->{Attributes}}, [$attrnum, $vendornum, $flags, $_])} (@data)
}

#####################################################################
sub insert
{
    my ($self, $attrnum, $vendornum, $flags, @data) = @_;

    $vendornum = 0 unless defined $vendornum;
    map {unshift(@{$self->{Attributes}}, [$attrnum, $vendornum, $flags, $_])} (@data)
}

#####################################################################
# Returns an array or the first attribute data that matches attrnum and vendor
sub get
{
    my ($self, $attrnum, $vendornum) = @_;

    $vendornum = 0 unless defined $vendornum;
    return map {($_->[0] == $attrnum && $_->[1] == $vendornum) ? $_->[3] : ()} 
        @{$self->{Attributes}} if wantarray;
    
    foreach (@{$self->{Attributes}})
    {
	return $_->[3] if ($_->[0] == $attrnum && $_->[1] == $vendornum);
    }
    # not found
    return;
}

#####################################################################
# Returns the data and flag of the first matching attribute
# Format is (attrnum, vendornum, flags, data)
sub get_details
{
    my ($self, $attrnum, $vendornum) = @_;

    $vendornum = 0 unless defined $vendornum;
    foreach (@{$self->{Attributes}})
    {
	return (@$_) if ($_->[0] == $attrnum && $_->[1] == $vendornum);
    }
    # not found
    return;
}

#####################################################################
# Returns the data and details of the nth attribute
# Format is (attrnum, vendornum, flags, data)
sub get_n
{
    my ($self, $n) = @_;

    return unless exists $self->{Attributes}[$n];
    return (@{$self->{Attributes}[$n]});
}

#####################################################################
# Delete all attributes that match
# Return an array of the details of each on that matched
sub delete
{
    my ($self, $attrnum, $vendornum) = @_;

    my $i;
    my @ret;
    for ($i = 0; $i < @{$self->{Attributes}}; $i++)
    {
	if ($self->{Attributes}->[$i]->[0] == $attrnum
	    && $self->{Attributes}->[$i]->[1] == $vendornum)
	{
	    push(@ret, @{$self->{Attributes}[$i]});
	    splice(@{$self->{Attributes}}, $i--, 1);
	}
    }
    return @ret;
}

#####################################################################
sub delete_n
{
    my ($self, $n) = @_;

    return unless exists $self->{Attributes}[$n];
    my @ret = @{$self->{Attributes}->[$n]};
    splice(@{$self->{Attributes}}, $n, 1);
    return @ret;
}

#####################################################################
# Change the nth attribute. Return the original
sub change_n
{
    my ($self, $n, $attrnum, $vendornum, $flags, $value) = @_;

    $vendornum = 0 unless defined $vendornum;
    return unless exists $self->{Attributes}[$n];
    my @ret = @{$self->{Attributes}[$n]};
    $self->{Attributes}[$n] = [$attrnum, $vendornum, $flags, $value];
    return @ret;
}

#####################################################################
# Pretty-Print all the attributes, with no special knowledge of their internal structure
# If dict is supplied, try to format with special knowledge
sub format
{
    my ($self, $dict, $prefix) = @_;

    # in this map, $_ = [attrnum, vendornum, flags, value]
    $prefix = '' unless defined $prefix; # prevent warnings
    return join("\n", map {$prefix . $self->format_one(@$_,$prefix)} (@{$self->{Attributes}}));
}

#####################################################################
# Copies all the attributes from $from  to $self
sub copy
{
    my ($self, $from) = @_;

    map {push (@{$self->{Attributes}}, [ @$_ ])} (@{$from->{Attributes}});
    return $self;
}

#####################################################################
# Copies matching attributes from $from  to $self
sub copy_attr
{
    my ($self, $from, $attrnum, $vendornum) = @_;

    $vendornum = 0 unless defined $vendornum;
    map {push (@{$self->{Attributes}}, [ @$_ ]) if $_->[0] == $attrnum && $_->[1] == $vendornum} 
        (@{$from->{Attributes}});
    return $self;
}

#####################################################################
# Find and call the type-specific attribute formatters
# If one cant be found, pack the same as an OctetString (ie, no packing)
sub format_one
{
    my ($self, $attrnum, $vendornum, $flags, $value) = @_;

    my $dict = $self->{Dictionary};
    my @attrdesc = $dict && $dict->attrByNum($attrnum, $vendornum);
    # (name, type, number, vendorid, flags)

    $vendornum += 0;
    my $attrname = $attrdesc[0] || "Attr-$vendornum-$attrnum";
    # Make sure all characters are printable
    $value = '' unless defined $value;
    $value =~ s/([\000-\037\177-\377])/<${\ord($1)}>/g;
    return "    $attrname: $flags, $value,";
}

#####################################################################
# Encode the value and then append the attribute
# Requires the subclass to define encode()
sub add_attr
{
    my ($self, $attrnum, $vendornum, $flags, $value) = @_;

    $value = $self->encode($attrnum, $vendornum, $flags, $value);
    $self->append($attrnum, $vendornum, $flags, $value);
}

#####################################################################
# Encode the value and then insert the attribute
# Requires the subclass to define encode()
sub insert_attr
{
    my ($self, $attrnum, $vendornum, $flags, $value) = @_;

    $value = $self->encode($attrnum, $vendornum, $flags, $value);
    $self->insert($attrnum, $vendornum, $flags, $value);
}

#####################################################################
# Decode the value from the requested attribute using dictionary name.
# Requires the subclass to define decode()
sub get_attr_d
{
    my ($self, $attrname) = @_;

    my ($dname, $dtype, $dnumber, $dvendorid, $dflags) = $self->{Dictionary}->attrByName($attrname);
    if ($dname)
    {
	return $self->get_attr($dnumber, $dvendorid);
    }
    else
    {
	main::log($main::LOG_ERR, "Unknown Diameter attribute name $attrname");
	return undef;
    }
}

#####################################################################
# Decode the value from all instances of the requested attribute using
# dictionary name.
# Requires the subclass to define decode()
sub get_attrs_d
{
    my ($self, $attrname) = @_;

    my ($dname, $dtype, $dnumber, $dvendorid, $dflags) = $self->{Dictionary}->attrByName($attrname);
    if ($dname)
    {
	return $self->get_attrs($dnumber, $dvendorid);
    }
    else
    {
	main::log($main::LOG_ERR, "Unknown Diameter attribute name $attrname");
	return undef;
    }
}

#####################################################################
# Encode the value and then append the attribute. Use attribute and
# value names defined in dictionary.
# Requires the subclass to define encode()
sub add_attr_d
{
    my ($self, $attrname, $attrval) = @_;

    my ($dname, $dtype, $dnumber, $dvendorid, $dflags) = $self->{Dictionary}->attrByName($attrname);
    if ($dname)
    {
	$self->add_attr($dnumber, $dvendorid, $dflags, $attrval);
    }
    else
    {
	main::log($main::LOG_ERR, "Unknown Diameter attribute name $attrname");
    }
}

#####################################################################
# Decode the value from the requested the attribute
# Requires the subclass to define decode()
sub get_attr
{
    my ($self, $attrnum, $vendornum) = @_;

    my ($dattrnum, $dvendornum, $flags, $value) = $self->get_details($attrnum, $vendornum);
    return unless defined $dattrnum;
    return $self->decode($dattrnum, $dvendornum, $flags, $value);
}

#####################################################################
# Decode the value from all instances of the requested the attribute
# Return an array of decoded values
# Requires the subclass to define decode()
sub get_attrs
{
    my ($self, $attrnum, $vendornum) = @_;

    $vendornum = 0 unless defined $vendornum;
    my @ret;
    foreach (@{$self->{Attributes}})
    {
	if ($_->[0] == $attrnum && $_->[1] == $vendornum)
	{
	    # Want this one
	    push(@ret, $self->decode(@$_));
	}
    }
    return @ret;
}

#####################################################################
# Send the message back to the originator by calling the reply function
# at the end of the ReplyFn list and popping it off
# CAUTION: use is deprecated
sub reply
{
    my ($self, @args) = @_;

    my $reply_fn = pop(@{$self->{ReplyFn}});
    &$reply_fn($self, @args) if $reply_fn;
    return $self;
}

#####################################################################
# Append one or more reply functions to the end of the ReplyFn list
# The last one in the list will be popped off and called
# when $self->reply() is called
sub add_reply_fn
{
    my ($self, @args) = @_;

    push(@{$self->{ReplyFn}}, @args);
    return $self;
}

#####################################################################
sub add_attr_by_name
{
    my ($self, $attrname, $flags, $attrval) = @_;

    my $dict = $self->{Dictionary};
    my ($dname, $dtype, $dnumber, $dvendorid, $dflags) = $dict && $dict->attrByName($attrname);
    # (name, type, number, vendorid, flags)
    if ($dname)
    {
	$self->add_attr($dnumber, $dvendorid, $flags, $attrval);
    }
    else
    {
	&main::log($main::LOG_ERR, "Unknown Diameter attribute name $attrname");
    }
}

#####################################################################
# Parse out a text string consisting of attr=val pairs 
# separated by commas
# add each attribute to $self
# Returns the number of pairs found in the string
# The val can have surrounding double quotes, which will be removed
# Use quotes if the value contains embedded commas. Escape embedded
# quotes with \
sub parse
{
    my ($self, $s) = @_;

    my $count;

    $s =~ s/\s*$//; # Strip trailing white space
    while ($s ne '')
    {
	$s =~ s/^[\s,]*//; # Strip leading white space & commas
	if ($s =~ /^([^ =]+) *= *"((\\"|[^"])*)",*/g)
	{
	    # Quoted value
	    my ($attr, $value) = ($1, $2);
	    $s = substr($s, pos $s);
	    $value =~ s/\\"/"/g; # Unescape quotes
	    $value =~ s/\\(\d{3})/chr(oct($1))/ge; # Convert escaped octal
	    $self->add_attr_by_name($attr, 0, $value);
	    $count++;
	}
	elsif ($s =~ /^([^ =]+) *= *([^,]*),*/g)
	{
	    # Unquoted value
	    $self->add_attr_by_name($1, 0, $2);
	    $s = substr($s, pos $s);
	    $count++;
	}
	else
	{
	    &main::log($main::LOG_ERR, "Bad attribute=value pair: $s");
	    last;
	}
	$s =~ s/^\s*//; # Strip leading white space
    }
    return $count;
}

1;
