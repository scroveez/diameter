# Realm.pm
#
# Object for handling radius Realms. TYhis is a specialisation of 
# Handler that implements (for historical reasons) a differnt methiod
# of choosing a handler (first by exact name, second by regexp
# lastly choose 'DEFAULT'
#
# Attributes
# Name    the host name the Realm was created with
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: Realm.pm,v 1.48 2007/11/27 23:14:35 mikem Exp $

package Radius::Realm;
@ISA = qw(Radius::Handler);
use Radius::Handler;
use strict;

# RCS version number of this module
$Radius::Realm::VERSION = '$Revision: 1.48 $';

# Tell Client.pm how to get to our find function, make
# sure its called before Handler::find
unshift(@Radius::Client::handlerFindFn, \&find);

# Make sure we get reinitialized on sighup
push(@main::reinitFns, \&reinitialize);

#####################################################################
# $name is the name of the Realm. Can be an exact realm name 
# a regexp, or DEFAULT
sub new
{
    my ($class, $file, $name, @args) = @_;

    my $self = $class->SUPER::new($file, "Realm=$name", @args);

    # So we can find by realm name later:
    $self->{Realm} = $name;
    return $self;
}

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();
    if ($self->{Realm} =~ /^\/(.*)\/([ix]?)$/)
    {
        $Radius::Realm::regexp_realms{$self->{Realm}} = $self;
    } 
    else
    {
        $Radius::Realm::realms{$self->{Realm}} = $self;
    }
}

#####################################################################
sub destroy
{
    my ($self) = @_;

    if ($self->{Realm} =~ /^\/(.*)\/([ix]?)$/)
    {
        delete $Radius::Realm::regexp_realms{$self->{Realm}};
    } 
    else 
    {
        delete $Radius::Realm::realms{$self->{Realm}};
    }
}

#####################################################################
# Find a Realm that handles $realm
# This implements a differtent search strategy to the superclass
# for historical reasons
sub find
{
    my ($p, $username, $realm) = @_;

    my $ret = $Radius::Realm::realms{$realm};
    if (!defined $ret)
    {
	# No exact match, look for a regexp match from any Realm name
	my $name;
	foreach $name (keys %Radius::Realm::regexp_realms)
	{
	    # The Realm name its a regexp
	    # We use an eval so an error in the pattern wont kill us.
            $name =~ /^\/(.*)\/([ix]?)$/;
	    my ($expr, $flags) = ($1, $2);
	    if (eval {$realm =~ /(?$flags)$expr/})
	    {
	        $ret = $Radius::Realm::regexp_realms{$name};
	        last;
	    }
	    &main::log($main::LOG_ERR, "Error in regexp Realm name $name: $@")
		    if $@;
	}
    }
    # Still not found? Fall back to DEFAULT
    $ret = $Radius::Realm::realms{DEFAULT}
        unless defined $ret;

    return $ret;
}

#####################################################################
# Reinitialize this module
sub reinitialize
{
    # This will DESTROY any objects left from a previous initialization
    %Radius::Realm::realms = ();
    %Radius::Realm::regexp_realms = ();
}


1;

