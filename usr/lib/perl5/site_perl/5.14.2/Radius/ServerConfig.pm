# ServerConfig.pm
#
# Object for holding configuration for a server
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: ServerConfig.pm,v 1.78 2014/09/30 21:07:22 hvn Exp $

package Radius::ServerConfig;
@ISA = qw(Radius::Configurable);
use Radius::Configurable;
use Radius::ServerRADIUS;
use Radius::RDict;
use Radius::Log;
use Radius::RuntimeChecks;
use File::Basename;
use strict;

%Radius::ServerConfig::ConfigKeywords = 
('AuthPort'           => 
 ['string',
  'Comma separated list of port names or numbers used for RADIUS Authentication requests. Defaults to 1645.',
  0],

 'AcctPort'           => 
 ['string',
  'Comma separated list of port names or numbers used for RADIUS Accounting requests. Defaults to 1646.',
  0],

 'BindAddress'        => 
 ['string',
  'Host IP address to listen on for connections. IPV4 or IPV6 addresses are permitted. Defaults to 0.0.0.0, meaning all the hosts IP addresses.',
  1],

'BindV6Only'   =>
 ['flag',
  'When set, does setsockopt() to turn IPV6_V6ONLY on or off for IPv6 wildcard sockets. See RFC 3493 for details. This option is not set by default and thus no setsockopt() is called and system default is used. Using this option requires support from Perl socket modules.',
  1],

 'Foreground'         => 
 ['flag',
  'Run the program in the foreground instead of as a background server (daemon). Unix only.',
  0],

 'DbDir'              => 
 ['string',
  'Default database directory. Available as special character %D',
  0],

 'LogDir'             => 
 ['string',
  'Default log file directory. Available as special character %L',
  0],

 'LogFile'            => 
 ['string',
  'Default log file name',
  0],

 'LogRejectLevel'            => 
 ['integer',
  'Log level for rejected authentication attempts. Can be overridden by Handler. Defaults to 3.',
  2],

 'DictionaryFile'     => 
 ['string',
  'Name of the RADIUS dictionary to use to translate RADIUS requests',
  1],

 'PidFile'            => 
 ['string',
  'Name of a file that will be used to save the process ID of this process. If not defined, the PID wil not be saved.',
  1],

 'LogStdout'          => 
 ['flag',
  'Controls whether messages will be logged to STDOUT',
  0],

 'SnmpgetProg'        => 
 ['string',
  'Full path name of program used for SNMP get',
  2],

 'SnmpsetProg'        => 
 ['string',
  'Full path name of program used for SNMP set',
  2],

 'SnmpwalkProg'       => 
 ['string',
  'Full path name of program used for SNMP walk',
  2],

 'FingerProg'         => 
 ['string',
  'Full path name of an alternate program used to implement finger. If not defined an internal finger client will be used.',
  2],

 'PmwhoProg'          => 
 ['string',
  'Name of the Livingston SNMP MIB. It is only used if you are using Simultaneous-Use with a NasType of Livingston in one of your Client clauses',
  2],

 'LivingstonMIB'      => 
 ['string',
  'Default bas MIB for extracting login information from Portmaster and Livingston NASs using SNMP',
  2],

 'LivingstonOffs'     => 
 ['integer',
  'Default value of the location where the last S port is before the one or two ports specified in LivingstonHole are skipped. Can be overridden on a per-Client basis.',
  2],

 'LivingstonHole'     => 
 ['integer',
  'The size of the hole in the port list (usually 1 for US, 2 for Europe) that occurs at LivingstonOffs. Can be overridden on a per-Client basis.',
  2],

 'RewriteUsername'    => 
 ['stringarray',
  'Regular expressions that will be used to rewrite User-Name before any Hadnlers or Realms are called. Format is a perl regular expression, such as s/fred/jim/',
  1],

 'SocketQueueLength'  => 
 ['integer',
  'The maximum length of the RADIUS socket queue in octets. Longer queues mean that more RADIUS requests can be waiting to be processed',
  1],

 'LicenseVersion'     => 
 ['string',
  'Specific Radiator version number that this license key applies to. Can be a static version number or a regular expression',
  1],

 'LicenseHostname'    => 
 ['string',
  'Specific hostname that this license key applies to. Can be a static host name or a regular expression',
  1],

 'LicenseMaxRequests' => 
 ['integer',
  'Maximum number of RADIUS requests this license permits. After this number have been processed, all requests will be ignored. 0 means no limit',
  1],

 'LicenseExpires'     => 
 ['string',
  'Date this license expires. Format is yyyy-mm-dd. 0000-00-00 means no expiry.',
  1],

 'LicenseOwner'       => 
 ['string',
  'Name of the owner of this license',
  1],

 'LicenseVendor'      => 
 ['string',
  'Name of the vendor that sold this license to the end user',
  1],

 'LicenseKey'         => 
 ['string',
  'License key string. Case insensitive',
  1],

 'PreClientHook'      => 
 ['hook',
  'Perl hook that is run for each request before despatching to any Client clause',
  2],

 'StartupHook'        => 
 ['hook',
  'Perl hook that is run once when Radiator is started or restarted',
  2],

 'ShutdownHook'       => 
 ['hook',
  'Perl hook that is run when Radiator shuts down cleanly, just prior to exiting',
  2],

 'USR1Hook'           => 
 ['hook',
  'Perl hook that is run when a USR1 signal is received. If this hook is not defined, USR1 increases the global trace level',
  2],

 'USR2Hook'           => 
 ['hook',
  'Perl hook that is run when a USR2 signal is received. If this hook is not defined, USR2 decreases the global trace level',
  2],

 'WINCHHook'          => 
 ['hook',
  'Perl hook that is run when a WINCH signal is received',
  2],

 'UsernameCharset'    => 
 ['string',
  'List of characters permitted in User-Name. Request with User-Name containing characters not in this set are rejected. Perl character set formats are permitted, such as "a-zA-Z0-9" which permits all alphanumeric characters',
  1],

 'MainLoopHook'       => 
 ['hook',
  'Perl hook that is run every time Radiator executes the main event handling loop',
  2],

 'ForkClosesFDs'      => 
 ['flag',
  'Tells Radiator to forcibly close all the child processes files descriptors after a fork() on Unix. This is only necessary in very unusual circumstances where child processes interfere with the parents connections to an SQL database',
  2],

 'User'               => 
 ['string',
  'On Unix, this optional parameter sets the effective user ID (UID) that radiusd will run as, provided radiusd starts as a suitably priveleged user (usually as root). The value can be a valid Unix user name or an integer UID.',
  1],

 'Group'              => 
 ['splitstringarray',
  'On Unix, this optional parameter sets the effective group ID (GID) and supplementary groups that radiusd will run as, provided radiusd starts as a suitably priveleged user (usually as root). The value can be a comma separated list of valid Unix group names or integer GIDs. The first group will be set as the effective group ID.',
  1],

 'AuthBy'             => 
 ['objectlist',
  'List of AuthBy clauses that are referenced by their Identifier in other clauses',
  1],

 'Handler'            => 
 ['objectlist',
  'List of Handlers that will be consulted in order to find how to handle each incoming request. This list will only be consulted if no Realm can be found to handle the request',
  1],

 'Realm'              => 
 ['objectlist','List of Realms that will be consulted in order to find how to handle each incoming request. Realm DEFAULT will be used for requests that dont have a more speific exact or regexp match. If no Realms match, the Handlers list will be consulted',
  0],

 'Client'             => 
 ['objectlist',
  'One or more Client objects which specify which remote clients we will accept requests from',
  0],

 'Server'             => 
 ['objectlist',
  'List of additional servers for handling protocols other than RADIUS.',
  1],

 'Trace'              => 
 ['integer',   # Actually interpreted by sub keyword below
  'Logging trace level. Only messages with the specified or higher priority will be logged',
  0],

 'SnmpNASErrorTimeout' => 
 ['integer',
  'Specifies for how long (in seconds) SNMP simultaneous use checks will be blocked after an SNMP error during communications with a given NAS',
  2],

 'MaxChildren'        => 
 ['integer',
  'Specifies the maximum number of Fork children permitted at any one time. Any attempt by an AuthBy to Fork (if so configured) will fail and the Radius request will be ignored if there are already that many Forked children in existence. 0 Means no limit.',
  1],

 'FarmSize'        => 
 ['string',
  'Specifies the number of Radiator farm instances to run. Each fork runs independently and takes requests from incoming sockets in a round-robin fashion. The main process acts as a supervisor for the farm children. Unix only. The default means just the standard single instance',
  1],

 'FarmChildHook'        => 
 ['hook',
  'Perl hook that is run in each child when FarmSize is used. The hook is run when the child is started or restarted.',
  2],

 'DiameterDictionaryFile'=> 
 ['string',
  'Name of an additional dictionary file to use for translating Diameter requests',
  1],

 'SessionDatabase'=> 
 ['objectlist',
  'List of session databases. By giving the SessionDatabase object an Identifier, you can refer to it by name for individual Realms or Handlers',
  1],

 'StatsLog'=> 
 ['objectlist',
  'List of statistics loggers. Each logger wgill log statistics from every internal Radiator object every Interval seconds',
  1],

 'LogMicroseconds' => 
 ['flag', 
  'In all loggers, when logging, include microseconds in the time (requires Time::HiRes)', 
  1],

 'DefineGlobalVar'  => 
 ['stringarray', 
  'Defines a global variable. Format is \'name value\'. The value is taken literally (ie no special characters are supported or translated in defining the value). The value can be used wherever special characters are supported with the %{GlobalVar:xxxxx} format', 
  2],

 'DefineFormattedGlobalVar'  => 
 ['stringarray', 
  'Defines a global variable. Format is \'name value\'. The value can be defined using special characters. The value can be used wherever special characters are supported with the %{GlobalVar:xxxxx} format', 
  2],

 'ClientHook'      => 
 ['hook',
  'Perl hook that is run for each request after delivery to a Client clause',
  2],

 'DisableMTUDiscovery'      => 
 ['flag',
  'Disables MTU discovery on platforms that support that behaviour (currently Linux only). This can be used to prevent discarding of certain large RADIUS packet fragments on supporting operating systems.',
  2],

 'PacketDumpOmitAttributes'  => 
 ['splitstringarray', 
  'Defines a list of packet attributes that will not be printed in packet dumps in logs.', 
  2],

 'ClientList' => 
 ['objectlist',
  'ClientList objects that are searched for Clients to match each incoming request.',
  2],

 'ProxyUnknownAttributes'      => 
 ['flag',
  'If set, enables proxying unknown attributes in requests and responses received by the server. Defaults to off.',
  2],

 'StatusServer'      =>
 ['string',
  'Global default for Client specific StatusServer parameter. See StatusServer in Client for the details and default value.',
  2],

 'KeepSocketsOnReload' =>
 ['flag',
  'Controls whether opened RADIUS listen sockets should be left intact on a reload request. When enabled, the changes in BindAddress, AuthPort and AcctPort are ignored during reload.',
  2],

 'DisabledRuntimeChecks'      =>
 ['string',
  'Comma separated list of runtime checks that should be disabled. See the reference manual for the currently supported tests.',
  2],

 );

# RCS version number of this module
$Radius::ServerConfig::VERSION = '$Revision: 1.78 $';

# These are the official names and descriptions of various statistics
# we keep in each object listed in $p->StatsTrail
%Radius::ServerConfig::statistic_names =
    (
     requests => 'Total requests',
     droppedRequests => 'Total dropped requests',
     duplicateRequests => 'Total duplicate requests',
     proxiedRequests => 'Total proxied requests',
     proxiedNoReply => 'Total proxied requests with no reply',
     badAuthRequests => 'Total Bad authenticators in requests',
     responseTime => 'Average response time',

     accessRequests => 'Access requests',
     dupAccessRequests => 'Duplicate access requests',
     accessAccepts => 'Access accepts',
     accessRejects => 'Access rejects',
     accessChallenges => 'Access challenges',
     malformedAccessRequests => 'Malformed access requests',
     badAuthAccessRequests => 'Bad authenticators in authentication requests',
     droppedAccessRequests => 'Dropped access requests',

     accountingRequests => 'Accounting requests',
     dupAccountingRequests => 'Duplicate accounting requests',
     accountingResponses => 'Accounting responses',
     malformedAccountingRequests => 'Malformed accounting requests',
     badAuthAccountingRequests => 'Bad authenticators in accounting requests',
     droppedAccountingRequests => 'Dropped accounting requests',
     );

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();

    # We keep the old ServerRADIUS, if any, on reload when KeepSocketsOnReload is set
    # REVISIT: check if $self->{radius_server} is ever defined without KeepSocketsOnReload
    $self->{radius_server}->destroy() if $self->{radius_server} && !$self->{KeepSocketsOnReload};
    $self->{radius_server} = Radius::ServerRADIUS->new
	(undef, undef,
	 'AuthPort'           => $self->{AuthPort},
	 'AcctPort'           => $self->{AcctPort},
	 'BindAddress'        => $self->{BindAddress},
	 'DisableMTUDiscovery' => $self->{DisableMTUDiscovery},
	) unless $self->{radius_server};

    $self->load_dictionary();
    $self->change_uid_gid();
    $self->write_pid();
    $self->check_ipv6_capability();
    Radius::RuntimeChecks::do_startup_checks();
    $self->{radius_server}->activate();
}

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    # REVISIT: should be 1812? see rfc2138
    $self->{AuthPort} = 1645;
    $self->{AcctPort} = 1646;
    $self->{BindAddress} = '0.0.0.0';
    $self->{DbDir} = '/usr/local/etc/raddb';
    $self->{LogDir} = '/var/log/radius'; 
    $self->{LogFile} = '%L/logfile'; 
    $self->{LogRejectLevel} = 3;
    $self->{DictionaryFile} = '%D/dictionary';
    $self->{PidFile} = '%L/radiusd.pid';
    $self->{Foreground} = 0;
    $self->{Trace} = 0;
    $self->{SnmpgetProg} = '/usr/bin/snmpget';
    $self->{SnmpwalkProg} = '/usr/bin/snmpwalk';
    $self->{SnmpsetProg} = '/usr/bin/snmpset';
    $self->{PmwhoProg} = '/usr/local/sbin/pmwho';
    $self->{LivingstonOffs} = 29;
    $self->{LivingstonHole} = 2;
    $self->{LivingstonMIB} = '.iso.org.dod.internet.private.enterprises.307';
    $self->{SnmpNASErrorTimeout} = 60; 
    $self->{MaxChildren} = 0;
    $self->{StatusServer} = 'default'; # Reply to Status-Server with default verbosity
    if ($^O eq 'MacOS')
    {
	$self->{DbDir} = 'Macintosh HD:Applications:Radiator:etc';
	$self->{LogDir} = 'Macintosh HD:Applications:Radiator:etc'; 
	$self->{LogFile} = '%L:logfile'; 
	$self->{DictionaryFile} = '%D:dictionary';
	$self->{PidFile} = '%L:radiusd.pid';
    }
}

#####################################################################
# Override the object function in Configurable. Need this because of the odd
# naming conventions of some Server modules.
sub object
{
    my ($self, $file, $keyword, $name, @args) = @_;

    if ($keyword =~ /^Server/ || $keyword eq 'Monitor')
    {
	my $class = "Radius::$keyword";
	my $o = &Radius::Configurable::load($file, $class, $name, @args);
	if (!$o)
	{
	    $self->log($main::LOG_ERR, "Could not load Server module $class: $@");
	    return;
	}
	push(@{$self->{Server}}, $o);
	return $o;
    }
    elsif ($keyword =~ /^ClientList/)
    {
	my $class = "Radius::$keyword";
	my $o = &Radius::Configurable::load($file, $class, $name, @args);
	if (!$o)
	{
	    $self->log($main::LOG_ERR, "Could not load ClientList module $class: $@");
	    return;
	}
	push(@{$self->{ClientList}}, $o);
	return $o;
    }
    return $self->SUPER::object($file, $keyword, $name, @args);
}


#####################################################################
# Reinitialize this module
sub destroy
{
    my ($self) = @_;
    # This will DESTROY any Server objects left from a previous initialization
    
    $self->{radius_server}->destroy() if $self->{radius_server} && !$self->{KeepSocketsOnReload};
    map $_->destroy, @{$main::config->{Server}};
    map $_->destroy, @{$main::config->{ClientList}};
    map $_->destroy, @{$main::config->{StatsLog}};
    map $_->destroy, @{$main::config->{SessionDatabase}};
}


#####################################################################
# Override the keyword function in Configurable
sub keyword
{
    my ($self, $file, $keyword, $value) = @_;

    if ($keyword eq 'DefineGlobalVar')
    {
	# Deprecated: see DefineFormattedGlobalVar 
	push(@{$self->{$keyword}}, $value);
	my ($name, $v) = split(/\s+/, $value, 2);
	&main::setVariable($name, $v);
	return 1;
    }
    elsif ($keyword eq 'DefineFormattedGlobalVar')
    {
	push(@{$self->{$keyword}}, $value);
	my ($name, $v) = split(/\s+/, $value, 2);
	&main::setVariable($name, &Radius::Util::format_special($v));
	return 1;
    }
    elsif ($keyword eq 'LogFile')
    {
	$self->{LogFile} = $value;
	# Allow the default logger to be rejigged during startup
	&Radius::Log::setupDefaultLogger
	    ($self->{LogFile}, $self->{Trace});
	return 1;
    }
    elsif ($keyword eq 'Trace')
    {
	$self->{Trace} = $value;
	# Allow the default logger to be rejigged during startup
	&Radius::Log::setupDefaultLogger
	    ($self->{LogFile}, $self->{Trace});
	return 1;
    }
    else
    {
	return $self->SUPER::keyword($file, $keyword, $value);
    }
}

#####################################################################
# Here we override Configureable::log, otherwise we get duplicate logging
# of errors from ServerConfig, as the ServerConfig loggers _are_ the global
# loggers.
sub log
{
    my ($self, @args) = @_;

    # Then call any global loggers
    &main::log(@args);
}

#####################################################################
# Recursively save this object and sub-objects named in objectlists
sub save_config
{
    my ($self, $file) = @_;

    my %alreadyseen; # Hash of already seen objects to prevent recursion
    return $self->save_object($file, \%alreadyseen, -1);
}

#####################################################################
# Check if our list of desired groups matches currently effective
# groups. If not, return a string suitable for setting $) or undef
# otherwise.
sub need_setgroups
{
    my ($self, @desired_gids) = @_;

    my $desired_egid = $desired_gids[0];
    my ($current_egid) = split(/ /, $)); # Get the first gid

    # Reading $) can result in long lists like "500 500 400 200". We
    # use a hash to weed out duplicates from the desired new groups
    # and current groups.
    my (%desired_gids, %current_gids);
    map {$desired_gids{$_} = 1} @desired_gids;
    map {$current_gids{$_} = 1} split(/ /, $));

    # Sort and add the egids so that they get compared too
    my $desired = $desired_egid . ' ' . join(' ', sort(keys %desired_gids));
    my $current = $current_egid . ' ' . join(' ', sort(keys %current_gids));

    return ($desired eq $current) ? undef : $desired;
}

#####################################################################
sub change_uid_gid()
{
    my ($self) = @_;

    return if $^O eq 'MSWin32';

    # Change user and group if required
    if (defined $self->{Group} && @{$self->{Group}})
    {
	my (@desired_gids, $failed);
	foreach my $group (@{$self->{Group}})
	{
	    my $gid = $group;
	    $gid = (getgrnam($group))[2] if ($group !~ /^\d+$/);

	    if (defined $gid)
	    {
		push @desired_gids, $gid;
	    }
	    else
	    {
		$failed++;
		$self->log($main::LOG_ERR, "$group is not a valid Group");
	    }
	}
	
	# Only change if it not the same already and we were able to
	# resolve all groups. If resolution fails we may create files
	# with incorrect ownership.
	if (!$failed)
	{
	    my $new_gids = $self->need_setgroups(@desired_gids);
	    if ($new_gids)
	    {
		# Unusual format for $). It requires "gid1 gid1 gid2 gid3 ..."
		$self->log($main::LOG_DEBUG, "Setting groups to $new_gids");
		$) = "$new_gids";

		# Check if we'd still need to do the change
		$new_gids = $self->need_setgroups(@desired_gids);
		$self->log($main::LOG_ERR, "Could not set groups to @desired_gids. Got $) Error: $!")
		    if $new_gids;

		# Try to change log file group if log file exists
		my $logfile = &Radius::Util::format_special($self->{LogFile});
		if (-e $logfile
		    && chown(-1, $desired_gids[0], $logfile) != 1)
		{
		    $self->log($main::LOG_ERR, "Could not change log file $logfile group to $desired_gids[0]: $!");
		}
	    }
	}
	else
	{
	    $self->log($main::LOG_ERR, "Failed to resolve all groups in Group @{$self->{Group}}. Not setting groups.")
	}
    }

    if (defined $self->{User})
    {
	my $uid = $self->{User};
	$uid = (getpwnam($self->{User}))[2]
	    if ($self->{User} !~ /^\d+$/);
	if (defined $uid)
	{
	    # Only change if it not the same already
	    if ($> != $uid)
	    {
               # Try to change log file owner first if log file exists
               my $logfile = &Radius::Util::format_special($self->{LogFile});
               if (-e $logfile
		   && chown($uid, -1, $logfile) != 1)
	       {
		   $self->log($main::LOG_ERR, "Could not change log file $logfile owner to $self->{User}: $!");
               }
	       $self->log($main::LOG_DEBUG, "Setting effective uid to $uid");
	       $> = $uid;
	       $self->log($main::LOG_ERR, "Could not set User to $self->{User} (got $>): $!")
		   unless $> == $uid;
	    }
	}
	else
	{
	    $self->log($main::LOG_ERR, "$self->{User} is not a valid User");
	}
    }
}

#####################################################################
sub write_pid
{
    my ($self) = @_;

    # Write our pid into a file.
    my $pidfile = &Radius::Util::format_special($self->{PidFile});
    return if $pidfile eq '';

    # Make sure the directory exists
    eval {File::Path::mkpath(dirname($pidfile), 0, 0755)} 
        unless -d dirname($pidfile);
    if (open(PIDFILE, ">$pidfile"))
    {
	print PIDFILE "$$\n";
	close(PIDFILE);
	return 1;
    }
    $self->log($main::LOG_ERR, "Could not open pid file '$pidfile': $!");
    return;
}

#####################################################################
sub load_dictionary
{
    my ($self) = @_;

    # multiple comma separated dictionary file names are supported
    my $filename = &Radius::Util::format_special($self->{DictionaryFile});
    return $main::dictionary = Radius::RDict->new(split(/,/, $filename));
}

#####################################################################
# Handle a new request
sub dispatch_request
{
    my ($self, $p) = @_;

    # Apply any global username rewriting rules
    $p->rewriteUsername($self->{RewriteUsername})
	if (defined $self->{RewriteUsername});

    # Make sure config is updated with stats
    push(@{$p->{StatsTrail}}, \%{$self->{Statistics}});

    # Call the PreClientHook, if there is one
    $self->runHook('PreClientHook', $p, \$p);

    # Find out the client that it came from. We iterate
    # through the clientFindFns fn array in order to find
    # a function that will find the right subclass
    # of Client.pm. This allows you to add new subclasses
    # of Client.pm with different behaviour
    my ($client, $finder);
    foreach $finder (@main::clientFindFns)
    {
	if ($client = &$finder($p))
	{
	    # Make sure the client is updated with stats
	    push(@{$p->{StatsTrail}}, \%{$client->{Statistics}});

	    $client->handle_request($p);
	    last;
	}
    }

    # If the handler forked and we are in the child
    # we can now exit.
    exit if $main::handler_forked;

    if (!$client)
    {
	my ($client_port, $client_addr) = Radius::Util::unpack_sockaddr_in($p->{RecvFrom});
	my $client_name = &Radius::Util::inet_ntop($client_addr);
	$self->log($main::LOG_NOTICE, "Request from unknown client $client_name: ignored");
	$p->statsIncrement('invalidClientAddresses');
    }
}

#####################################################################
sub readConfig
{
    my ($self, $filename) = @_;

    $self->{configFilename} = $filename;
    return $self->readFile($filename);
}

#####################################################################
sub check_ipv6_capability
{
    my ($self) = @_;

    my $capability;

    $capability = Radius::Util::get_ipv6_capability();
    if ($capability eq 'none')
    {
	main::log($main::LOG_INFO, "This Perl installation can handle IPv6 attributes in binary format only. IPv6 sockets are not supported. Consider installing Socket6.pm for full IPv6 support.");
    }
    else
    {
	main::log($main::LOG_DEBUG, "This system is IPv6 capable. IPv6 capability provided by: $capability");
    }

    return;
}

1;
