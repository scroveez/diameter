# CalledStationId.pm
#
# Object for handling radius CalledStationIds. This is an example
# specialisation of 
# Handler that implements improved performance for finding 
# a handler for an exact Called-Station-Id. It might be
# useful where you have thousands of Called-Station-Ids to match
# and the linear serch that Handler normally does would be too slow
# It chooses an exact Called-Station-Id, and thats not present, tries
# for DEFAULT
#
# Attributes
# Name    the host name the CalledStationId was created with
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: CalledStationId.pm,v 1.4 2007/12/18 21:23:50 mikem Exp $

package Radius::CalledStationId;
@ISA = qw(Radius::Handler);
use Radius::Handler;
use strict;
use vars qw($VERSION @ISA);

# Tell Client.pm how to get to our find function, but make
# sure its called before Handler::find
unshift(@Radius::Client::handlerFindFn, \&find);

# Make sure we get reinitialized on sighup
push(@main::reinitFns, \&reinitialize);


#####################################################################
# $name is the name of the CalledStationId. 
sub new
{
    my ($class, $file, $name, @args) = @_;

    $class->SUPER::new($file, "Called-Station-Id=$name", @args);

    # So we can find by regexp name later:
    if ($name =~ /^\/(.*)\/([ix]?)$/)
    {
        $Radius::CalledStationId::regexp_calledstationids{$name} = $self;
    } 
    else 
    {
    	$Radius::CalledStationId::calledstationids{$name} = $self;
    }

    return $self;
}

#####################################################################
# Find a CalledStationId to handle this request
# This implements a differtent search strategy to the superclass
# for performance reasons
sub find
{
    my ($p, $username, $realm) = @_;

    my $csi = $p->get_attr('Called-Station-Id');
    my $ret = $Radius::CalledStationId::calledstationids{$csi};

    if (!defined $ret)
    {
        # No exact match, look for a regexp match from any CalledStationId
        my $name;
        foreach $name (keys %Radius::CalledStationId::regexp_calledstationids)
        {
            # The calledstationid is a regexp
            # We use an eval so an error in the pattern wont kill us.
            $name =~ /^\/(.*)\/([ix]?)$/;
            my ($expr, $flags) = ($1, $2);
            if (eval{$csi =~ /(?$flags)$expr/})
            {
                $ret = $Radius::CalledStationId::regexp_calledstationids{$name};
                last;
            }
            &main::log($main::LOG_ERR, "Error in regexp CalledStationId $name: $@")
                    if $@;
        }
    }
    # Still not found? Fall back to DEFAULT
    $ret = $Radius::CalledStationId::calledstationids{DEFAULT}
        unless defined $ret;

    return $ret;
}

#####################################################################
# Reinitialize this module
sub reinitialize
{
    # This will DESTROY any objects left from a previous initialization
    $Radius::CalledStationId::calledstationids = ();
    $Radius::CalledStationId::regexp_calledstationids = ();
}


1;

