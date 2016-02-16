# AuthSYSTEM.pm
#
# Object for handling Authentication from getpwnam and getgrent
# This allows you to use password files, shadow files, NIS+
# or whatever is installed on your system transparently
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthSYSTEM.pm,v 1.13 2007/09/25 11:31:13 mikem Exp $

package Radius::AuthSYSTEM;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Radius::User;
use strict;

# RCS version number of this module
$Radius::AuthSYSTEM::VERSION = '$Revision: 1.13 $';

# This keeps a copy of the GID of the last user found locally
my $group_of_last_user_found;

#####################################################################
# Override the keyword function in Configurable
sub keyword
{
    my ($self, $file, $keyword, $value) = @_;

    if ($keyword eq 'UseGetspnam')
    {
	$self->{UseGetspnam}++;
	# Get the extra functions required for getspnams
	require Shadows;
	import Shadows;
    }
    elsif ($keyword eq 'UseGetspnamf')
    {
	$self->{UseGetspnamf}++;
	# Get the extra functions required for getspnams
	require Shadowf;
	import Shadowf;
    }
    else
    {
	return $self->SUPER::keyword($file, $keyword, $value);
    }
    return 1;
}

#####################################################################
# Finds the named user by use getpwnam
sub findUser
{
    my ($self, $look_for, $p) = @_;

    my $type = ref($self);
    
    my $user;

    my ($name, $passwd, $uid, $gid, $quota, $comment, $gcos, $dir, $shell, $dummy, $expires);
    no strict 'refs';
    if (($name, $passwd, $uid, $gid, $quota, $comment, $gcos, $dir, $shell)
	= getpwnam($look_for))
    {
	# Get the real password if we need to
	($name, $passwd) = getspnam($look_for)
	    if $self->{UseGetspnam};

	($name, $passwd, $dummy, $dummy, $dummy, $dummy, 
	 $dummy, $expires) = getspnamf($look_for)
	     if $self->{UseGetspnamf};
	$self->log($main::LOG_DEBUG, "getpwnam got $name, $passwd, $uid, $gid, $quota, $comment, $gcos, $dir, $shell, $expires", $p);
	$user = new Radius::User $name;
	$user->get_check->add_attr('Encrypted-Password', $passwd);
	if ($expires > 0)
	{
	    # Its days since Jan 1 1970
	    my @expires = localtime($expires * 86400); # Secs per day
	    $expires[5] += 1900 if $expires[5] < 1900; # Perl year
	    $user->get_check->add_attr
		('Expiration', 
		 sprintf("%02d/%02d/%d",
			 $expires[3], $expires[4]+1, $expires[5]));
	}
	$group_of_last_user_found = $gid;
	$self->log($main::LOG_INFO, "Empty Encrypted-Password for $name", $p)
	    if $passwd eq '';
    }
    return $user
}

#####################################################################
# Check if the user is in the group
sub userIsInGroup
{
    my ($self, $user, $group) = @_;
    
    my ($name, $passwd, $gid, $members);
    if ((($group =~ /^\d+$/) 
	 && (($name, $passwd, $gid, $members) = getgrgid($group)))
	|| (($name, $passwd, $gid, $members) = getgrnam($group)))
    {
	#print "got group $name, $passwd, $gid, $members\n";
	# Users primary group is this group? We have cached
	# the gourp number for the last user in findUser above
	return 1 
	    if defined $group_of_last_user_found
		&& $group_of_last_user_found == $gid;

	# $members is a space separated list of user names
	return grep { $_ eq $user} split(/ /, $members);
    }
    else
    {
	# No such group
	return 0;
    }
}

1;

