# AttrVal.pm
#
# Heres a little class for holding attribute value pairs
# Handles multiple instances of the same attribute.
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AttrVal.pm,v 1.27 2010/08/10 22:37:25 mikem Exp $

package Radius::AttrVal;

# RCS version number of this module
$Radius::AttrVal::VERSION = '$Revision: 1.27 $';

#####################################################################
sub new
{
    my ($class, $s) = @_;

    my $self = {};
    bless $self, $class;

    @{$self->{Attributes}} = (); # Define an empty array
    $self->parse($s) if defined $s;

    return $self;
}

#####################################################################
sub add_attr
{
    my ($self, $name, $value) = @_;
    push(@{$self->{Attributes}}, [ $name, $value ]);
}

#####################################################################
# If it was already there, return 1 else add it and return 0
sub add_if_not_exist_attr
{
    my ($self, $name, $value) = @_;

    # Bail if its already there
    map {return 1 if ($_->[0] eq $name)} @{$self->{Attributes}};

    # Not there, so add it
    push(@{$self->{Attributes}}, [ $name, $value ]);
    return;
}

#####################################################################
# Change the value of an attribute.
# If it was already there, change it return 1 else add it and return 0
sub change_attr
{
    my ($self, $name, $value) = @_;

    foreach (@{$self->{Attributes}})
    {
	if ($_->[0] eq $name)
	{
	    $_->[1] = $value;
	    return 1;
	}
    }

    # Not there, so add it
    push(@{$self->{Attributes}}, [ $name, $value ]);
    return;
}

#####################################################################
# Remove all instances of the attribute with the given name 
# from the list
sub delete_attr
{
    my ($self, $name) = @_;

    my $i;
    for ($i = 0; $i < @{$self->{Attributes}}; $i++)
    {
	splice(@{$self->{Attributes}}, $i--, 1)
	    if ($self->{Attributes}->[$i]->[0] eq $name);
    }
}

#####################################################################
# Remove attributes that cause fn to return true
# fn is called like fn($name, $value, @args)
sub delete_attr_fn
{
    my ($self, $fn, @args) = @_;

    my $i;
    for ($i = 0; $i < @{$self->{Attributes}}; $i++)
    {
	splice(@{$self->{Attributes}}, $i--, 1)
	    if (&$fn($self->{Attributes}->[$i]->[0],
		     $self->{Attributes}->[$i]->[1],
		     @args));
    }
}

#####################################################################
# Appends all the items in the AttrVal pointed to by $list 
# to this AttrVal
sub add_attr_list
{
    my ($self, $list) = @_;
    push(@{$self->{Attributes}}, @{$list->{Attributes}});
}

#####################################################################
# Change or appends all the items in the AttrVal pointed to by $list 
# to this AttrVal
sub change_attr_list
{
    my ($self, $list) = @_;
    map {$self->change_attr($_->[0], $_->[1])} @{$list->{Attributes}};
}

#####################################################################
# Gets the values of the named attribute.
# returns a list of all the values
# if called in scalar context, returns the value of the first one found
sub get_attr
{
    my ($self, $name) = @_;

    return map {$_->[0] eq $name ? $_->[1] : ()} @{$self->{Attributes}}
        if wantarray;

    map {return $_->[1] if ($_->[0] eq $name)} @{$self->{Attributes}};
    return; # not found
}

#####################################################################
sub get_attr_val_n
{
    my ($self, $n) = @_;
    no warnings qw(uninitialized);
    return @{$self->{Attributes}[$n]};
}

##################################################################### 
# required for DefaultReply (and someday, DefaultCheck)  ##ptf 
sub attr_count 
{ 
    my ($self) = @_; 
    return scalar @{$self->{Attributes}}; 
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
	    push(@{$self->{Attributes}}, [ $attr, $value ]);
	    $count++;
	}
	elsif ($s =~ /^([^ =]+) *= *([^,]*),*/g)
	{
	    # Unquoted value
	    push(@{$self->{Attributes}}, [ $1, $2 ]);
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

#####################################################################
# idem parse() but add attribute only if it does not exist before
# Contributed by Vincent Gillet <vgi@oleane.net>
sub parse_ifnotexist
{
    my ($self, $s) = @_;

    my $count;
    $s =~ s/\s*$//; # Strip trailing white space
    ATTRIBUT:
    while ($s ne '')
    {
	$s =~ s/^[\s,]*//; # Strip leading white space & commas
	if ($s =~ /^([^ =]+) *= *"((\\"|[^"])*)",*/g)
	{
	    # Quoted value
	    my ($attr, $value) = ($1, $2);
	    my $attrib_ref;
	    foreach $attrib_ref (@{$self->{Attributes}}) {
	    	if ($$attrib_ref[0] eq $attr) {
	    		$s = substr($s, pos $s);
	    		next ATTRIBUT;
	    	}
	    }
	    $value =~ s/\\"/"/g; # Unescape quotes
	    push(@{$self->{Attributes}}, [ $attr, $value ]);
	    $s = substr($s, pos $s);
	    $count++;
	}
	elsif ($s =~ /^([^ =]+) *= *([^,]*),*/g)
	{
	    # Unquoted value
	    my ($attr, $value) = ($1, $2);
	    my $attrib_ref;
	    foreach $attrib_ref (@{$self->{Attributes}}) {
	    	if ($$attrib_ref[0] eq $attr) {
	    		$s = substr($s, pos $s);
	    		next ATTRIBUT;
	    	}
	    }
	    push(@{$self->{Attributes}}, [ $attr, $value ]);
	    $s = substr($s, pos $s);
	    $count++;
	}
	else
	{
	    &main::log($main::LOG_ERR, "Bad attribute=value pair: $s");
	    last;
	}
    }
    return $count;
}

#####################################################################
# Format the list in a pretty way and return it
# Every value is quoted
sub format
{
    my ($self) = @_;

    my $ret;
    map {$ret .= "\t$_->[0] = \"" . pclean($_->[1]) . "\"\n"} @{$self->{Attributes}};
    return $ret;
}

#####################################################################
# Utility functions for printing/debugging
sub pdef { defined $_[0] ? $_[0] : "UNDEF"; }
sub pclean 
{
    my $str = $_[0];
    $str =~ s/([\000-\037\177-\377])/<${\ord($1)}>/g;
    return $str;
}

1;
