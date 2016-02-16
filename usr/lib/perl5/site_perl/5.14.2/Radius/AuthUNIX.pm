# AuthUNIX.pm
#
# Object for handling Authentication from cached 
# unix style password files
#
# Performance enhancement -- Jamie Hill 9/20/99
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthUNIX.pm,v 1.31 2007/12/18 21:23:50 mikem Exp $

package Radius::AuthUNIX;
@ISA = qw(Radius::AuthFILE);
use Radius::AuthFILE;
use Radius::User;
use strict;

# This keeps a copy of the GID of the last user found locally
my $group_of_last_user_found;

%Radius::AuthUNIX::ConfigKeywords = 
('Match'         => 
 ['string', 'This parameter allows you to use flat files with different formats to the standard Unix password format. Match is a regular expression that is expected to match and extract the username, password and (optional) primary group ID fields from each line in the password file. The default extracts the first two colon separated fields as username and password, followed by a UID, followed by an (optional) primary group ID (i.e. standard Unix password file format).', 1],

 'GroupFilename' => 
 ['string', 'Specifies the name of the group file. The group file is in standard Unix group file format. Used to check "Group=" check items when authentication is cascaded from another module. Defaults to /etc/group.', 1],

 'Filename'        => 
 ['string', 'Specifies the filename of the password file. Defaults to /etc/passwd. The file name can include special formatting characters', 0],
 );

# RCS version number of this module
$Radius::AuthUNIX::VERSION = '$Revision: 1.31 $';

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{Filename} = '/etc/passwd';
    # UNIX style password file, with optional group ID in 
    # the fourth field:
    $self->{Match} = '^([^:]*):([^:]*):?[^:]*:?([^:]*)'; 
    $self->{GroupFilename} = '/etc/group';
}

#####################################################################
# Finds the named user by looking in a Unix style password file
# If Nocache is set, it always reads the file from scratch
# Otherwise it will reread the files whenever mod times change
# Reads Unix password and group files, with optional line format
# specification
sub findUser
{
    my ($self, $look_for, $p) = @_;

    return unless defined $look_for;
    my $type = ref($self);

    # First read the users file
    my $filename = &Radius::Util::format_special($self->{Filename}, $p);

    if ($self->{Nocache} || $self->fileHasChanged($filename))
    {
        # Clear all old passwords
        $self->{Users} = ();
        $self->{UserCache} = ();

        if (open(FILE, $filename))
	{
	    while (<FILE>)
	    {
		chomp;
		
		if (/$self->{Match}/o)
		{
		    next if $self->{Nocache} && $look_for ne $1;
		    $self->{UserCache}{$1} = "$2:$3";
		    last if $self->{Nocache} && $look_for eq $1;
		}
	    }
	    close(FILE);
	}
	else
	{
	    $self->{LastModTime}{$filename} = 0; # Make sure we read it later
            $self->log($main::LOG_ERR, "Could not open password file $filename in $type: $!", $p);
	    return (undef, 1);
	}
    }
    
    # Now maybe read the group file, and for each group found,
    # for each user in the group
    # add the group name as a Group attribute top the user
    # This will be checked in the generic checkAttributes
    $filename = &Radius::Util::format_special($self->{GroupFilename}, $p);
    if ($self->{Nocache} || $self->fileHasChanged($filename))
    {
        # Clear all old passwords
        $self->{Groups} = ();

        $self->log($main::LOG_DEBUG, "Reading group file $filename", $p);
        if (open(FILE, $filename))
	{
	    while (<FILE>)
	    {
		chomp;
		my @fields = split(/:/);
		$self->{Groups}{$fields[0]} = $fields[3];
		$self->{GroupsToGID}{$fields[0]} = $fields[2];
	    }
	    close(FILE);
	}
	else
	{
	    $self->{LastModTime}{$filename} = 0; # Make sure we read it later
            $self->log($main::LOG_ERR, "Could not open group file $filename in $type: $!", $p);
	}
    }

    # Now maybe have the user in the cache, avoid creating a new
    # entry
    if (exists $self->{UserCache}{$look_for})
    {
        if (!defined($self->{Users}{$look_for})) 
	{
            my $user = Radius::User->new($look_for);
            my($p, $g) = split(/:/,$self->{UserCache}{$look_for});
            $user->{Group} = $g;
            $user->get_check->add_attr('Encrypted-Password',$p);
            $self->{Users}{$look_for} = $user;
        }
        
        $group_of_last_user_found = $self->{Users}{$look_for}->{Group};
        return $self->{Users}{$look_for};
    }
    return undef; # Not found
}

#####################################################################
# Check if the user is in the group
# $user is a user name and $group is a group name
sub userIsInGroup
{
    my ($self, $user, $group) = @_;

    # We see if the user appears in the comma separated list of users
    # in the group entry
    # If they are not there perhaps this site has exceeded the 
    # max number of group entries, then check their primary
    # group
    return 1 if grep { $_ eq $user } split(/,/, $self->{Groups}{$group});

    # Check the primary group. We have cached the group ID
    # directly in the User structure in findUser above. Very ugly.

    return defined $group_of_last_user_found
        && $self->{GroupsToGID}{$group} == $group_of_last_user_found;
}

1;


