# StatsLogSQL.pm
#
# Log statistics to an SQL database
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2002 Open System Consultants
# $Id: StatsLogSQL.pm,v 1.5 2013/08/13 20:58:45 hvn Exp $

package Radius::StatsLogSQL;
@ISA = qw(Radius::StatsLogGeneric Radius::SqlDb);
use Radius::StatsLogGeneric;
use Radius::SqlDb;
use strict;

%Radius::StatsLogSQL::ConfigKeywords = 
('InsertQuery' => 
 ['string', 'This optional parameter specifies the SQL query to be used for each log. It can include special formatting characters as described in Section 5.2 on page 16. %0 to %23 are replaced by statistics data as described in the Radiator Reference manual. If InsertQuery is not defined then a standard set of statistics wil be logged', 1],

 'TableName' => 
 ['string', 'Name of the SQL table to insert into. Defaults to RADSTATSLOG', 1],

 );

# RCS version number of this module
$Radius::StatsLogSQL::VERSION = '$Revision: 1.5 $';

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    $self->Radius::StatsLogGeneric::check_config();
    $self->Radius::SqlDb::check_config();
    return;
}

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->Radius::StatsLogGeneric::activate();
    $self->Radius::SqlDb::activate();
}

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->Radius::StatsLogGeneric::initialize();
    $self->Radius::SqlDb::initialize();
    $self->{TableName} = 'RADSTATSLOG';
}

#####################################################################
# Log all the Statistics from one object
sub logObject
{
    my ($self, $object) = @_;

    return unless $self->reconnect;
    my $time = time;
    my $type = $object->{ObjType} || (split(/:/, ref($object)))[2];
    my $id = $object->{Identifier} || $object->{Name} || 'unknown';

    my $q;
    no warnings "uninitialized";
    if (defined $self->{InsertQuery})
    {
	$q = &Radius::Util::format_special
	    ($self->{InsertQuery}, undef, undef,
	     $time, $type, $id,
	     map 0+$object->{Statistics}{$_}, 
	     sort keys %Radius::ServerConfig::statistic_names);
    }
    else
    {
	my $cols = join(',', 'TIME_STAMP', 'TYPE', 'IDENTIFIER',
			map uc $_, sort keys %Radius::ServerConfig::statistic_names);
	my $vals = join(',', $time, $self->quote($type), $self->quote($id),
			map 0 + $object->{Statistics}{$_}, 
			sort keys %Radius::ServerConfig::statistic_names);
	$q = "insert into $self->{TableName} ($cols) values ($vals)";
    }
    $self->do($q);
}

1;
