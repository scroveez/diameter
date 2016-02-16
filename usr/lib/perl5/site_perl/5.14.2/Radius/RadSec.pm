# RadSec.pm
#
# Low level routines for sending and receiving Radius request
# over a TCP stream.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2005 Open System Consultants
# $Id: RadSec.pm,v 1.7 2007/11/27 23:14:35 mikem Exp $

package Radius::RadSec;
@ISA = qw(Radius::Stream);
use Radius::Stream;
use strict;

# RCS version number of this module
$Radius::RadSec::VERSION = '$Revision: 1.7 $';


#####################################################################
# Called by Stream.pm when there is some pending data in inbuffer
# Process as many complete messages as possible, calling the superclass recv()
# for each one
sub read_data
{
    my ($self) = @_;

    while (length $self->{inbuffer} >= 4)
    {
	# Have a RADSEC header at least
	my ($code, $id, $length) = unpack('CCn', $self->{inbuffer});
	# Make some trivial checks on the request
	if ($length > $self->{MaxBufferSize})
	{
	    $self->log($main::LOG_ERR, "RadSec received a reply with excessive length $length. Disconnecting");
	    $self->stream_disconnected();
	}
	# Have at least one complete message yet?
	last unless length($self->{inbuffer}) >= $length;
	
	# Have the entire request
	# Get, clear and handle this request.
	# Superclass is expected to implment recv()
	$self->recv(substr($self->{inbuffer}, 0, $length, ''));
    }
}

1;

