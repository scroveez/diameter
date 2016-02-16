# AuthSQLDIGIPASS.pm
#
# Object for handling Authentication of DIGIPASS tokens (www.vasco.com)
# from an SQL database
#
# Requires Authen-Digipass 1.4 or better from Open System Consultants.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001-2006 Open System Consultants
# $Id: AuthSQLDIGIPASS.pm,v 1.7 2013/08/13 20:58:45 hvn Exp $

package Radius::AuthSQLDIGIPASS;
@ISA = qw(Radius::AuthDIGIPASSGeneric Radius::SqlDb);
use Radius::AuthDIGIPASSGeneric;
use Radius::SqlDb;
use strict;

%Radius::AuthSQLDIGIPASS::ConfigKeywords = 
('AuthSelect'            => 
 ['string', 'SQL query that will be used to fetch Digipass data from the database. Special characters are permitted, and %0 is replaced with the quoted user name. ', 0],
 'UpdateQuery'           => 
 ['string', 'SQL query that will be used to store Digipass token data back to the database after authentication. ', 0],
 );

# RCS version number of this module
$Radius::AuthSQLDIGIPASS::VERSION = '$Revision: 1.7 $';

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    $self->Radius::AuthDIGIPASSGeneric::check_config();
    $self->Radius::SqlDb::check_config();
    return;
}

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
    $self->Radius::SqlDb::initialize();
    $self->{AuthSelect}        = 'select DP_DATA, DIGIPASS from TBL_VASCODP where USER_ID=%0';
    $self->{UpdateQuery}       = 'update TBL_VASCODP set DP_DATA=\'%0\' where DIGIPASS=\'%1\'';
}


#####################################################################
# Return ($data, $digipass, $error)
# $data is the raw digipass data block
# $digipass is a key that identifies the record where the data is stored,
# it is not used by the caller except to pass back to UpdateDigipassData
sub GetDigipassData
{
    my ($self, $user, $p) = @_;

    my $qname = $self->quote($user);
    my $q = &Radius::Util::format_special($self->{AuthSelect}, $p, $self, $qname);
    my $sth = $self->prepareAndExecute($q);
    return (undef, undef, 'Database failure')
	unless $sth;
    
    my ($data, $digipass) = $self->getOneRow($sth);
    return (undef, undef, "No such user $user in Digipass database")
	unless defined $data;

    $self->log($main::LOG_DEBUG, "Found Digipass $digipass for user $user", $p);

    # Else can get die in Authen-Digipass later:
    return (undef, undef, "Bad Digipass token data for user $user $user")
	unless length $data == 248;
    
    return ($data, $digipass);
}

#####################################################################
# $digipass is the key identifying the record where the data is to be stored,
# must be the same as was returned by GetDigipassData.
sub UpdateDigipassData
{
    my ($self, $data, $digipass, $p) = @_;

    my $q = &Radius::Util::format_special($self->{UpdateQuery}, $p, $self, $data, $digipass);
    return $self->do($q);
}

1;
