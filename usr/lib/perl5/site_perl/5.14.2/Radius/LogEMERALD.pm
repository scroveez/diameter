# LogEMERALD.pm
#
# Log to the Emerald SQL RadLogs logging table
#
# Caution: The Emerald RadLogs table has a timestamp with a resolution
# of 1 minute. Therefore if Radiator tries to log the same message
# twice in the same minute, the insert will fail.
# Therefore, level 4 (DEBUG) logging will probably result in many insertion
# failures
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: LogEMERALD.pm,v 1.10 2007/09/25 11:31:13 mikem Exp $

package Radius::LogEMERALD;
@ISA = qw(Radius::LogSQL);
use Radius::LogSQL;
use strict;

# RCS version number of this module
$Radius::LogEMERALD::VERSION = '$Revision: 1.10 $';

# Catch recursion in calls to log
# LogEMERALD needs its own private recursion protection, because
# it inherits from SQlDb, which does $self->log()
my $in_log = 0;

sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{LogQuery} = 'insert into RadLogs (RadLogMsgID, LogDate,
Username, Data) values (%4, \'%5\', %6, %2)';
    $self->{MaxMessageLength} = 50;
}

#####################################################################
# Log some messages to the logging table. Only some of our Radiator
# messages fit the canned message format that Emerald uses,
# sadly we have to do some sort of mapping
# $r is the current request packet, if any
sub log
{
    my ($self, $priority, $s, $p) = @_;

    # Catch recursion
    return if $in_log++;

    if ($self->willLog($priority, $p) && $self->reconnect())
    {
	# We also insert into our database
	# These will be inserted 
	my ($radlogmsgid, $logdate, $data, $nasidentifier);
	my $username = 'Radiator';
	
	if ($s =~ /Access rejected for (\S*): No such user/)
	{
	    $radlogmsgid = 10;
	    $username = $1;
	}
	elsif ($s =~ /Access rejected for (\S*): Bad Password/)
	{
	    $radlogmsgid = 11;
	    $username = $1;
	}
	elsif ($s =~ /Access rejected for (\S*): Expiration date has passed/)
	{
	    $radlogmsgid = 12;
	    $username = $1;
	}
	elsif ($s =~ /Access rejected for (\S*): Simultaneous-Use of (\d+) exceeded/)
	{
	    $radlogmsgid = 14;
	    $username = $1;
	    $data = $2;
	}
	elsif ($s =~ /Access rejected for (\S*): User (\S+) has no more time left/)
	{
	    $radlogmsgid = 15;
	    $username = $1;
	}
	elsif ($s =~ /Bad authenticator in request from (\S*) \((\S*)\)/)
	{
	    $radlogmsgid = 53;
	    $data = $2;
	}
	elsif ($priority <= $main::LOG_ERR)
	{
	    $radlogmsgid = 1;
	    $data = $s;
	}
	else
	{
	    $radlogmsgid = 0;
	    $data = $s;
	}
	
	if (defined $radlogmsgid)
	{
	    my $logdate = $self->formatDate(time);

	    # truncate to length of Data column
	    $data = substr($data, 0, $self->{MaxMessageLength}) if $self->{MaxMessageLength};
	    
	    my $q = &Radius::Util::format_special
		($self->{LogQuery}, $p, undef,
		 $priority,
		 $Radius::Log::priorityToString[$priority],
		 $self->quote($data),
		 $self->{Table},
		 $radlogmsgid,
		 $logdate,
		 $self->quote($username));
	    $self->do($q);
	}
    }
    $in_log = 0;
}

1;
