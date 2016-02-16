# AuthLogGeneric.pm
#
# Generic superclass for handling authentication logging
# Author: contributed by Dave Lloyd <david@freemm.org>
# Copyright (C) Open System Consultants
# $Id: AuthLogGeneric.pm,v 1.11 2014/09/19 19:56:39 hvn Exp $
package Radius::AuthLogGeneric;
@ISA = qw(Radius::Configurable);
use Radius::Configurable;
use strict;

%Radius::AuthLogGeneric::ConfigKeywords = 
('LogSuccess' => 
 ['flag', 'Indicates whether authentication successes are to be logged. Default is not to log success.', 0],

 'LogFailure' => 
 ['flag', 'Indicates whether authentication failures are to be logged. Default is to log failures.', 0],

 'LogFormatHook' =>
 ['hook',
  'Specifies an optional Perl hook that will be run for each log message when defined. By default no Hook is defined.',
  1],

 );

# RCS version number of this module
$Radius::AuthLogGeneric::VERSION = '$Revision: 1.11 $';

#####################################################################
# Do per-instance default initialization
# This is called by Configurable during Configurable::new before
# the config file is parsed. Its a good place initialize instance 
# variables
# that might get overridden when the config file is parsed.
# Do per-instance default initialization. This is called after
# construction is complete
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{LogSuccess} = 0;
    $self->{LogFailure} = 1;
    $self->{ObjType} = 'AuthLog'; # Automatically register this object
}

#####################################################################
# Log a success/failure
# $s is $main::REJECT, or $main::ACCEPT
# $r is the reason, $p is the request packet
sub authlog
{
    my ($self, $s, $r, $p) = @_;

    $self->log($main::LOG_ERR, "You did not override authlog() in AuthLogGeneric", $p);
}

#####################################################################
# Find the AuthLog module with a given identifier
sub find
{
    my ($id) = @_;
    
    return &Radius::Configurable::find('AuthLog', $id);
}

1;
