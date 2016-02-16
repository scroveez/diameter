# AuthLogSYSLOG.pm
#
# Specific class for logging authentication to SYSLOG
#
# Changed from AuthLogSQL.pm, AuthLogFILE.pm and LogSYSLOG.pm
# by Carlos Canau <canau@kpnqwest.pt>
# Copyright (C) Open System Consultants
#
# version 2000/12/11
#
# AuthLogSQL.pm Author: contributed by Dave Lloyd <david@freemm.org>
#

package Radius::AuthLogSYSLOG;
@ISA = qw(Radius::AuthLogGeneric);
use Radius::AuthLogGeneric;
use Radius::Configurable;
use Sys::Syslog qw(:DEFAULT setlogsock);
use strict;

%Radius::AuthLogSYSLOG::ConfigKeywords = 
('Facility'      => 
 ['string', 'The name of the syslog facility that will be logged to. The default is \'user\'.', 1],

 'Priority'      => 
 ['string', 'The syslog priority level that will be used for each log message. Default is \'info\'.', 1],

 'SuccessFormat' => 
 ['string', 'The format for success messages. You can use any of the special characters. Defaults to \'%l:%U:%P:OK\'.', 1],

 'FailureFormat' => 
 ['string', 'The format for failure messages. You can use any of the special characters. Defaults to \'%l:%U:%P:FAIL\'.', 1],

 'LogSock'       => 
 ['string', 'This optional parameter specifies what type of socket to use to connect to the syslog server. Allowable values are unix, inet, tcp, udp. Defaults to unix. The option inet means to try tcp first, then udp. The default is to use the Sys::Syslog default of tcp, udp, unix, stream, console.', 1],

 'LogIdent'      => 
 ['string', 'This optional parameter specifies an alternative ident name to be used for logging. Defaults to the executable name used to run radiusd. Special characters are suported.', 1],

 'LogOpt'      => 
 ['string', 'This optional comma separated parameter specifies an alternative set of options for openlog(3). Defaults to \'pid\'. Special characters are suported.', 1],

 'LogHost'       => 
 ['string', 'When LogSock is set to tcp or udp or inet, this optional parameter specifies the name or address of the syslog host. Defaults to the local host. Special characters are suported.', 0],

 );

# RCS version number of this module
$Radius::AuthLogSYSLOG::VERSION = '$Revision: 1.33 $';

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
    $self->{Priority} = 'info';
    $self->{SuccessFormat} = '%l:%U:%P:OK';
    $self->{FailureFormat} = '%l:%U:%P:FAIL';
    $self->{LogIdent} = $0;
    $self->{LogOpt} = 'pid';
}

sub check_config
{
    my ($self) = @_;

    # Validate LogOpt. LogOpt can be empty.
    map
    {
	main::log($main::LOG_ERR, "Invalid LogOpt '$_' in AuthLog SYSLOG $self->{Identifier}")
	    unless ($_ =~ /^(cons|ndelay|nofatal|nowait|perror|pid)$/)
    } split /,/, $self->{LogOpt};

    $self->SUPER::check_config();
    return;
}

#####################################################################
# Log a message 
sub authlog
{
    my ($self, $s, $reason, $p) = @_;

    my $message;
    if (defined($self->{SuccessFormat}) 
	and $self->{LogSuccess} 
	and $s == $main::ACCEPT ) 
    {
	$message = &Radius::Util::format_special
	    ($self->{SuccessFormat}, $p, undef, $s, $reason);
    } 
    elsif (defined($self->{FailureFormat}) 
	   and $self->{LogFailure} 
	   and $s == $main::REJECT ) 
    {
	    $message = &Radius::Util::format_special
		($self->{FailureFormat}, $p, undef, $s, $reason);
    } 
    else 
    {
    	return;
    }

    # syslog can die:
    $message =~ s/%/%%/g; # Make sure to escape any % signs that would be interpreted as printf
    my $ident = &Radius::Util::format_special($self->{LogIdent}, $p);
    my $logopt = &Radius::Util::format_special($self->{LogOpt}, $p);
    my $loghost = &Radius::Util::format_special($self->{LogHost}, $p) if length $self->{LogHost};
    eval {
	    # We reset these here in case there are multiple SYSLOG callers with different configs
            # Caution: there is no way to reset logsock back to the default, so if you
            # have multiple SYSLOG clauses, if any one has LogSock defined, 
            # they must all have LogSock defined
	    setlogsock($self->{LogSock}) if defined $self->{LogSock};
	    $Sys::Syslog::host = $loghost;
	    openlog($ident, $logopt, $self->{Facility});
	    syslog("$self->{Priority}", $message);
	    closelog()
    };
    &main::log($main::LOG_ERR, "Error while doing AuthLog SYSLOG: $@")
	if $@;
}

1;
