# Diameter.pm
#
# Low level routines for sending and receiving Diameter requests
# over a TCP stream.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2005 Open System Consultants
# $Id: Diameter.pm,v 1.4 2012/12/13 20:19:47 mikem Exp $

package Radius::Diameter;
@ISA = qw(Radius::Stream);
use Radius::Stream;
use strict;

# RCS version number of this module
$Radius::Diameter::VERSION = '$Revision: 1.4 $';

#####################################################################
# Called by Stream.pm when there is some pending data in inbuffer
# Process as many complete messages as possible, calling the superclass recv()
# for each one
sub read_data
{
    my ($self) = @_;

    while (length $self->{inbuffer} >= 4)
    {
	# Have a DIAMETER header at least
	my  ($verslen) = unpack('N', $self->{inbuffer}); # 1 octet of version, 3 of length
	my $length = $verslen & 0xffffff;
	my $version = $verslen >> 24;

	# Make some trivial checks on the request
	if ($length > $self->{MaxBufferSize})
	{
	    $self->log($main::LOG_ERR, "Diameter received a request with excessive length $length. Disconnecting");
	    $self->stream_disconnected();
	}
	if ($version != 1)
	{
	    $self->log($main::LOG_ERR, "Diameter received a request with unsupported version $version. Disconnecting");
	    $self->stream_disconnected();
	}

	# Have at least one complete message yet?
	last unless length($self->{inbuffer}) >= $length;
	
	# Have the entire request
	# Get, clear and handle this request.
	# Superclass is expected to implment recv_diameter()
	$self->recv_diameter(substr($self->{inbuffer}, 0, $length, ''));
    }
}

1;

