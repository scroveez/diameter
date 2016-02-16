# AuthCDB.pm
#
# Object for handling Authentication from CDB files
# Inherits from AuthFILE.
# AuthFILE::handle_request is not overridden, only the routine to
# find a user.
#
# Requires CDB_File module from CPAN
#
# Author: Pedro Melo (melo@ip.pt)
# Adapted from AuthDBFile. Author info from AuthDBFile follows
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) Open System Consultants
# 
# $Id: AuthCDB.pm,v 1.9 2012/12/13 20:19:47 mikem Exp $


package Radius::AuthCDB;
@ISA = qw(Radius::AuthFILE);
use Radius::AuthFILE;
use Radius::User;
use Fcntl;
use CDB_File;     
use strict;

# RCS version number of this module
$Radius::AuthCDB::VERSION = '$Revision: 1.9 $';

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{Filename} = '%D/users.cdb';
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

    my $type = ref($self);
    my $user; # The return value
    my $filename = &Radius::Util::format_special($self->{Filename}, $p);

    my %users;
    tie (%users, 'CDB_File', $filename)
	|| ($self->log($main::LOG_WARNING,
	     "Could not open user database file '$filename' in $type: $!", $p), return (undef, 1));

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

