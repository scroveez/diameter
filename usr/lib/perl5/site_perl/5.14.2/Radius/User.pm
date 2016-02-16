# User.pm
#
# Object for handling user details
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: User.pm,v 1.9 2007/09/25 11:31:13 mikem Exp $

package Radius::User;
use Radius::AttrVal;
use strict;

# RCS version number of this module
$Radius::User::VERSION = '$Revision: 1.9 $';

#####################################################################
sub new
{
    my ($class, $name, $check, $reply) = @_;

    my $self = {};
    bless $self, $class;

    $self->{Name} = $name;
    $self->{Check} = Radius::AttrVal->new($check);
    $self->{Reply} = Radius::AttrVal->new($reply);
    return $self;
}

#####################################################################
# Parse a list of attr-value pairs. Each pair is
# separated by a comma. If there is a trailing comma there is more to come
# The first set are stored as the Check items: the items that must be 
# correct in an incoming request. The second set are the attributes to 
# be returned in an Access-Accept
# BUG ALERT: probably wont handle commas embedded in quoted strings 
sub parse
{
    my ($self, $s) = @_;

    if ($self->{GotAllChecks})
    {
	$self->{Reply}->parse($s);
    }
    else
    {
	$self->{Check}->parse($s);
	# A comma at the end of the line signifies more to come
	$self->{GotAllChecks}++
	    unless $s =~ /,\s*$/;
    }
}

#####################################################################
# Returns the check AttrVal
sub get_check
{
    my ($self) = @_;
    return $self->{Check};
}

#####################################################################
# Returns the reply AttrVal
sub get_reply
{
    my ($self) = @_;
    return $self->{Reply};
}

1;
