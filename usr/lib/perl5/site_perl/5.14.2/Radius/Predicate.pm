# Predicate.pm
#
# Object for storing and testing predicates for matching Radius
# requests
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2005 Open System Consultants
# $Id: Predicate.pm,v 1.3 2007/09/25 11:31:13 mikem Exp $
package Radius::Predicate;
use strict;

# RCS version number of this module
$Radius::Predicate::VERSION = '$Revision: 1.3 $';

#####################################################################
# @args is an array of 0 or more test triplets.
# Each triplet is an array [attrname, operator, value]
# eg ['User-Name', '==', 'fred']
sub new
{    
    my ($class, @args) = @_;
    my $self = [@args];
    bless $self, $class;
    return $self;
}

#####################################################################
# Test whether the Radius request in $p matches the predicate
sub test
{
    my ($self, $p) = @_;

    my ($name, $op, $value, $test, $attr, $matched);
test:
    foreach $test (@$self)
    {
	# Every test in the predicate must match at least one attribute in the request
	($name, $op, $value) = @$test;
	foreach $attr (@{$p->{Attributes}})
	{
	    next unless $attr->[0] eq $name;
	    # Now at an attribute with the same attribute name as the test
	    if ($op eq '=' || $op eq '==')
	    {
		$matched = ($value eq $attr->[1]);
	    }
	    elsif  ($op eq '!=')
	    {
		$matched = ($value ne $attr->[1]);
	    }
	    elsif  ($op eq '<')
	    {
		$matched = ($value lt $attr->[1]);
	    }
	    elsif  ($op eq '<=')
	    {
		$matched = ($value le $attr->[1]);
	    }
	    elsif  ($op eq '>')
	    {
		$matched = ($value gt $attr->[1]);
	    }
	    elsif  ($op eq '>=')
	    {
		$matched = ($value ge $attr->[1]);
	    }
	    elsif  ($op eq '=~' || $op eq 'regexp')
	    {
		# Regexp match can die:
		eval {$matched = ($attr->[1] =~ /$value/);};
		&main::log($main::LOG_ERR, "Bad regexp '$value' in Predicate: $@", $p)
		    if $@;
	    }
	    else
	    {
		&main::log($main::LOG_ERR, "Unknown comparison operator $op in Predicate", $p);
		return;
	    }
	    # Found an attribute that matched, go on to the next test
	    next test if $matched;
	}
	# No attribute in $p matched this test
	return;
    }
    # All tests succeeded
    return 1;
}

#####################################################################
# Convert a string expression into an array of [name, op, value] triplets
# String is in the format name op "value",...
# eg User-Name == "xyz",Framed-Protocol!="PPP"
# CAUTION: this must match the code in RadarGui::Logger::parsePredicate
# for correct interoperation with Radar.
sub parse
{
    my ($self, $s) = @_;

    my $count;

    $s =~ s/\s*$//; # Strip trailing white space
    while ($s ne '')
    {
	$s =~ s/^[\s,]*//; # Strip leading white space & commas
	if ($s =~ /^([^ =]+) *(==|!=|<=|<|>=|>|=~|regexp) *"((\\"|[^"])*)",*/g)
	{
	    # Quoted value
	    my ($attr, $op, $value) = ($1, $2, $3);
	    $s = substr($s, pos $s);
	    $value =~ s/\\"/"/g; # Unescape quotes
	    $value =~ s/\\(\d{3})/chr(oct($1))/ge; # Convert escaped octal
	    push(@$self, [ $attr, $op, $value ]);
	    $count++;
	}
	elsif ($s =~ /^([^ =]+) *(==|!=|<=|<|>=|>|=~|regexpg) *([^,]*),*/g)
	{
	    # Unquoted value
	    my ($attr, $op, $value) = ($1, $2, $3);
	    push(@$self, [ $attr, $op, $value ]);
	    $s = substr($s, pos $s);
	    $count++;
	}
	else
	{
	    &main::log($main::LOG_ERR, "Bad attribute=value pair in Predicate: $s");
	    last;
	}
	$s =~ s/^\s*//; # Strip leading white space
    }
    return $count;

}

1;
