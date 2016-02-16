# SessDBM.pm
#
# Implement the session database as an external DBM file
# Having the session database externally allows us to synchronise
# the simultaneous-use limits across several instances of Radiator
#
# The key in the database is NAS-IP-Address:NAS-Port
# The data is User-Name:Acct-Session-Id:Timestamp:Framed-IP-Address:Service-Type:NAS-Port-Type.

#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: SessDBM.pm,v 1.25 2007/12/18 21:23:50 mikem Exp $

package Radius::SessDBM;
@ISA = qw(Radius::SessGeneric);
use Radius::SessGeneric;
use Radius::Client;
use Fcntl;
use strict;

%Radius::SessDBM::ConfigKeywords = 
('Filename' => 
 ['string', 'Specifies the filename that holds the Session Database. Defaults to %D/online, The actual file names will depend on which DBM format Perl selects for you, but will usually be something like online.dir and online.pag in DbDir. The file name can include special formatting characters', 0],

 'DBType' => ['string', 'By default, Radiator and Perl will choose the \`best\' format of DBM file available to you, depending on which DBM modules are installed on your machine. You can override this choice by specifying DBType as the name of one ofg the DBM formats supported on your platform. Be sure to choose a type which is available on your host.', 1],
 );

# RCS version number of this module
$Radius::SessDBM::VERSION = '$Revision: 1.25 $';

my $mode = 0666; # Mode to use for file creation

#####################################################################
# Contruct a new Session database handler
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();
    require "$self->{DBType}.pm";
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
    $self->{Filename} = '%D/online';
    $self->{DBType} = 'AnyDBM_File';
}

#####################################################################
sub add
{
    my ($self, $name, $nas_id, $nas_port, $p) = @_;

    $self->log($main::LOG_DEBUG, 
	       "$self->{Identifier} Adding session for $name, $nas_id, $nas_port", $p);
    my $filename = &Radius::Util::format_special($self->{Filename}, $p);

    my %online;
    tie (%online, $self->{DBType}, $filename, O_CREAT | O_RDWR, $mode)
	|| $self->log($main::LOG_WARNING,
		      "$self->{Identifier} Could not open DBM online database file '$filename': $!", $p);

    my $key = "$nas_id:$nas_port";
    my $session_id = $p->getAttrByNum($Radius::Radius::ACCT_SESSION_ID);
    my $timestamp = $p->get_attr('Timestamp');
    my $framed_address = $p->getAttrByNum($Radius::Radius::FRAMED_IP_ADDRESS);
    my $service_type = $p->getAttrByNum($Radius::Radius::SERVICE_TYPE);
    my $port_type = $p->getAttrByNum($Radius::Radius::NAS_PORT_TYPE);
    $online{$key} = "$name:$session_id:$timestamp:$framed_address:$service_type:$port_type";
    untie %online;
}

sub delete
{
    my ($self, $name, $nas_id, $nas_port, $p) = @_;

    $self->log($main::LOG_DEBUG, 
	       "$self->{Identifier} Deleting session for $name, $nas_id, $nas_port", $p);
    my $filename = &Radius::Util::format_special($self->{Filename}, $p);

    my %online;
    tie (%online, $self->{DBType}, $filename, O_CREAT | O_RDWR, $mode)
	|| $self->log($main::LOG_WARNING,
			     "$self->{Identifier} Could not open DBM online database file '$filename': $!", $p);

    delete $online{"$nas_id:$nas_port"};
    untie %online;
}

sub clearNas
{
    my ($self, $nas_id, $p) = @_;

    $self->log($main::LOG_DEBUG, 
	       "$self->{Identifier} Deleting all sessions for $nas_id", $p);
    my $filename = &Radius::Util::format_special($self->{Filename}, $p);

    my %online;
    tie (%online, $self->{DBType}, $filename, O_CREAT | O_RDWR, $mode)
	|| $self->log($main::LOG_WARNING,
			     "$self->{Identifier} Could not open DBM online database file '$filename': $!", $p);

    # Must search every entry for matches on $nas_id. This is expensive
    my ($key, $this_nas_id, $this_nas_port);
    foreach $key (keys %online)
    {
	($this_nas_id, $this_nas_port) = split(/:/, $key);
	delete $online{$key} if $this_nas_id eq $nas_id;
    }
    untie %online;
}

sub exceeded
{
    my ($self, $max, $name, $p) = @_;

    my $filename = &Radius::Util::format_special($self->{Filename}, $p);
    my %online;
    tie (%online, $self->{DBType}, $filename, O_CREAT | O_RDWR, $mode)
	|| $self->log($main::LOG_WARNING,
			     "$self->{Identifier} Could not open DBM online database file '$filename': $!", $p);

    my $count = 0; # Number of current simultaneous sessions for the user
    # Must search every entry for matches on $nas_id:$nas_port. This is expensive
    my ($key, $value);
    while (($key, $value) = each %online)
    {
	my ($this_name, $dummy) = split(/:/, $value);
	$count++ if $name eq $this_name;
    }

    if ($count >= $max)
    {
	# Hmmm, looks like we have to double check: go through them all again
	# Double check by asking the Client who owns the NAS
	while (($key, $value) = each %online)
	{
	    my ($nas_id, $nas_port) = split(/:/, $key);
	    my ($this_name, $session_id, $timestamp, $framed_address, 
		$service_type, $port_type) 
		= split(/:/, $value);

	    if ($name eq $this_name)
	    {
		my $client;
		if ($client = &Radius::Client::findAddress(Radius::Util::inet_pton($nas_id)))
		{
		    if (!$client->isOnline
			($name, $nas_id, $nas_port, $session_id,
			 $framed_address))
		    {
			# Hmmm they are not online anymore, remove this session
			$self->log($main::LOG_INFO, 
				   "$self->{Identifier} Session for $name at $nas_id:$nas_port has gone away", $p);
			$self->delete($name, $nas_id, $nas_port, $p);
			$count--;
			last if $count < $max;
		    }
		}
		else
		{
		    $self->log($main::LOG_WARNING, 
			       "$self->{Identifier} Could not find a Client for NAS $nas_id to double-check Simultaneous-Use. Perhaps you do not have a reverse DNS for that NAS?", $p);
		}
	    }
	}
    }
    return $count >= $max ;
}

1;
