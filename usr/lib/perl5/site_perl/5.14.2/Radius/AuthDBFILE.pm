# Auth-DBFILE.pm
#
# Object for handling Authentication from DBM files
# Inherits from AuthFILE.
# AuthFILE::handle_request is not overridden, only the routine to
# find a user.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthDBFILE.pm,v 1.28 2007/12/18 21:23:50 mikem Exp $

package Radius::AuthDBFILE;
@ISA = qw(Radius::AuthFILE);
use Radius::AuthFILE;
use Radius::User;
use Fcntl;
use strict;

%Radius::AuthDBFILE::ConfigKeywords = 
    ('DBType' => ['string', 'By default, Radiator and Perl will choose the \`best\' format of DBM file available to you, depending on which DBM modules are installed on your machine. You can override this choice by specifying DBType as the name of one ofg the DBM formats supported on your platform. Be sure to choose a type which is available on your host.', 1],
     );

# RCS version number of this module
$Radius::AuthDBFILE::VERSION = '$Revision: 1.28 $';

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{Filename} = '%D/users';
    $self->{DBType} = 'AnyDBM_File';
}

#####################################################################
# Find a the named user in the database, and construct a User record
# for them.
# Opens an DBM file in similar format as used by Merit radius
# The user records are hashed by user name. The value is 2 strings 
# separated
# by newlines. The first string is the Check attribute values, and the 
# second is the reply attribute values.
# This is called by the generic handle_request. We have to find
# the user and return a User object.
sub findUser
{
    my ($self, $name, $p) = @_;

    return unless defined $name;
    my $type = ref($self);
    my $user; # The return value
    my $filename = &Radius::Util::format_special($self->{Filename}, $p);

    my %users;
    require "$self->{DBType}.pm";
    tie (%users, $self->{DBType}, $filename, O_RDONLY, 0)
	|| ($self->log($main::LOG_WARNING,
	     "Could not open user database file '$filename' in $type: $!", $p), return (undef, 1));
    $DB::single = 1;

    my $s = $users{$name};
    if (defined $s)
    {
	# Create a User, and parse out the Check and Reply attributes
	$user = new Radius::User $name;
	map {$user->parse($_)} split(/\n/, $s);
    }
    untie %users;
    return $user;
}

1;

