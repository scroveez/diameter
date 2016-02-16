# StatsLogFILE.pm
#
# Log statistics to a file.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2002 Open System Consultants
# $Id: StatsLogFILE.pm,v 1.4 2007/12/18 21:23:50 mikem Exp $

package Radius::StatsLogFILE;
@ISA = qw(Radius::StatsLogGeneric);
use Radius::StatsLogGeneric;
use strict;

%Radius::StatsLogFILE::ConfigKeywords = 
('Filename' => 
 ['string', 'This is the name of the file to log statistics to. Defaults to %L/statistics. The file name can include special formatting characters as described in Section 5.2 on page 16, although data from the current request or reply are never available (logging is never done in the context of a current request).', 0],

 'Format'   => 
 ['string', 'This optional parameter specifies the format for each logging line. You can use this to control exactly what statistics are logged and in what order they appear.<p>
If Format is not defined, statistics data will be logged in the following order (also shown is the special character that is available for that data in the Format specification). All fields will be colon separated.
<p>See the Radiator Reference manual for more information', 1],

 'Header'   => 
 ['string', 'This optional parameter allows you to customize the Header line that is logged before each set of statistics. It can be useful for describing the contents of each column when importing into Excel etc.', 1],

 );

# RCS version number of this module
$Radius::StatsLogFILE::VERSION = '$Revision: 1.4 $';

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{Filename} = '%L/statistics';
}

#####################################################################
# Open a logging file, call the superclass to do the object traversal
# then close the file. Our sub log will be called for each object
# requiring logging
sub logAll
{
    my ($self) = @_;

    my $filename = &Radius::Util::format_special($self->{Filename});
    if (!open(STATSLOG, ">>$filename"))
    {
	$self->log($main::LOG_ERR, 
		   "Could not open user statistics log file $filename: $!");
	return;
    }

    # Print a header line, if there is one
    if (defined $self->{Header})
    {
	# Let them eliminate the header
	print STATSLOG $self->{Header}, "\n"
	    if $self->{Header} ne '';
    }
    else
    {
	print STATSLOG '#time_stamp:type:identifier:', join(':', sort keys %Radius::ServerConfig::statistic_names), "\n";
    }

    $self->SUPER::logAll();

    close(STATSLOG);
}

#####################################################################
# Log all the Statistics from one object
sub logObject
{
    my ($self, $object) = @_;

    my $time = time;
    my $type = $object->{ObjType} || (split(/:/, ref($object)))[2];
    my $id = $object->{Identifier} || $object->{Name} || 'unknown';

    no warnings "uninitialized";
    if (defined $self->{Format})
    {
	print STATSLOG &Radius::Util::format_special
	    ($self->{Format}, undef, undef,
	     $time, $type, $id,
	     map 0+$object->{Statistics}{$_}, 
	     sort keys %Radius::ServerConfig::statistic_names), "\n";
    }
    else
    {
	print STATSLOG "$time:$type:$id:", 
	join(':', map 0 + $object->{Statistics}{$_}, 
	     sort keys %Radius::ServerConfig::statistic_names), "\n";
    }
}

1;
