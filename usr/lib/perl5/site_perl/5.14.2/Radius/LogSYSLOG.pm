# LogSYSLOG.pm
#
# Log to syslog
# You need to have syslog.ph built using h2ph before you can use this
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: LogSYSLOG.pm,v 1.22 2014/08/18 21:27:13 hvn Exp $

package Radius::LogSYSLOG;
@ISA = qw(Radius::LogGeneric);
use File::Path;
use File::Basename;
use Radius::LogGeneric;
use Sys::Syslog qw(:DEFAULT setlogsock);
use strict;

%Radius::LogSYSLOG::ConfigKeywords = 
('Facility' => 
 ['string', 'The name of the syslog facility that will be logged to. The default is "user".', 0],

 'LogSock'  => 
 ['string', 'This optional parameter specifies what type of socket to use to connect to the syslog server. Allowable values are unix, inet, tcp, udp. Defaults to unix. The option inet means to try tcp first, then udp. The default is to use the Sys::Syslog default of tcp, udp, unix, stream, console.', 1],

 'LogIdent' => 
 ['string', 'This optional parameter specifies an alternative ident name to be used for logging. Defaults to the executable name used to run radiusd. Special characters are suported.', 1],

 'LogOpt'      => 
 ['string', 'This optional comma separated parameter specifies an alternative set of options for openlog(3). Defaults to \'pid\'. Special characters are suported.', 1],

 'LogHost'  => 
 ['string', 'When LogSock is set to tcp or udp or inet, this optional parameter specifies the name or address of the syslog host. Defaults to the local host. Special characters are suported.', 1],

 );

# RCS version number of this module
$Radius::LogSYSLOG::VERSION = '$Revision: 1.22 $';

# Maps our LOG_* numbers into Syslog priority levels
my @priorityToSyslog  = ('ERR', 'WARNING', 'NOTICE', 'INFO', 'DEBUG');


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
    $self->{Facility} = 'user';
    $self->{LogIdent} = $0;
    $self->{LogOpt} = 'pid';
}

sub check_config
{
    my ($self) = @_;

    # Validate LogOpt. LogOpt can be empty.
    map
    {
	main::log($main::LOG_ERR, "Invalid LogOpt '$_' in Log SYSLOG $self->{Identifier}")
	    unless ($_ =~ /^(cons|ndelay|nofatal|nowait|perror|pid)$/)
    } split /,/, $self->{LogOpt};

    $self->SUPER::check_config();
    return;
}

#####################################################################
# Log a message 
# $priority is the message priority, $s is the message
# $r is the current request packet, if any
my $in_log;
sub log
{
    my ($self, $priority, $s, $p) = @_;

    # Catch recursion
    return if $in_log++;
    if ($self->willLog($priority, $p))
    {
	$s = substr($s, 0, $self->{MaxMessageLength}) if $self->{MaxMessageLength};
	$s =~ s/%/%%/g; # Make sure to escape any % signs that would be interpreted as printf
	my $ident = &Radius::Util::format_special($self->{LogIdent}, $p);
	my $logopt = &Radius::Util::format_special($self->{LogOpt}, $p);
	my $loghost = &Radius::Util::format_special($self->{LogHost}, $p);
	eval 
	{
	    # We reset these here in case there are multiple SYSLOG callers with different configs
            # Caution: there is no way to reset logsock back to the default, so if you
            # have multiple SYSLOG clauses, if any one has LogSock defined, 
            # they must all have LogSock defined
	    setlogsock($self->{LogSock}) if defined $self->{LogSock};
	    $Sys::Syslog::host = $loghost;
	    openlog($ident, $logopt, $self->{Facility});
	    syslog("$priorityToSyslog[$priority]", $s);
	    closelog()
	};
	&main::log($main::LOG_ERR, "Error while doing Log SYSLOG: $@")
	    if $@;
    }
    $in_log = 0;
}

1;
