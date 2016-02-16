# AuthHTGROUP.pm
#
# Object for checking group membership according to an Apache htgroup file
#
# Author: Rodger Allen <rodger@infrasecure.com>
# Copyright (C) 2002 Open System Consultants
# $Id: AuthHTGROUP.pm,v 1.3 2007/12/18 21:23:50 mikem Exp $

package Radius::AuthHTGROUP;
@ISA = qw(Radius::AuthGeneric);

use Radius::AuthGeneric;
use Radius::User;
use Apache::Htgroup;
use strict;

%Radius::AuthHTGROUP::ConfigKeywords = 
(
 'GroupFilename' => 
 ['string', 'Specifies the name of the Apache group file to consult.', 0],

 );

# RCS version number of this module
$Radius::AuthHTGROUP::VERSION = '$Revision: 1.3 $';


#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{NoDefault} = 1;
}


#####################################################################
# Check if the user exists
sub findUser 
{
    return Radius::User->new();
}


#####################################################################
# Check if the user is in the group
# $user is a user name and $group is a group name
sub userIsInGroup
{
    my ($self, $user, $group) = @_;
    my $type = ref($self);

    $self->log($main::LOG_DEBUG, "$type: checking for $user in $group" );

    my $htgroupfile = &Radius::Util::format_special($self->{GroupFilename});

    # reload if changed
    if (!$self->{htgroup} || $self->fileHasChanged( $htgroupfile )) 
    {
        $self->log($main::LOG_DEBUG, "$type: (re)loading ".$htgroupfile);
        eval {$self->{htgroup} = Apache::Htgroup->load($htgroupfile);};
	if ($@)
	{
	    $self->log($main::LOG_ERR, "$type: Apache::Htgroup->load failed: $@");
	    return;
	}
        $self->fileHasChanged( $htgroupfile ); # an assertion
        # reload is really 'revert' - dont use
        #    $self->{htgroup}->reload();
        $self->{HTusers} = undef;
    }
    

    # check membership
    return 1
	if ($self->{htgroup}->ismember($user, $group));

    return;   # not found
}

1;

