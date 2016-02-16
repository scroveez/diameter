#!/usr/bin/perl
# 
# nntp-redirect.pl
# a Radius-enabled NNTP port authenticator and accountor
# See RFC977 and RFC 2980
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2002 Open System Consultants
# $Id: nntp-redirect.pl,v 1.3 2012/06/27 23:27:18 mikem Exp $

use Getopt::Long;
use Radius::SimpleClient;
use Radius::RDict;
use IO::Socket::INET;
use IO::Select;
use Sys::Hostname;
use strict;

my @options = 
    (
     'h',             # Help, show usage
     'v',             # Print version number
     'dictionary=s',  # Radius dictionary file name
     'trace=n',       # Error logging trace level
     'log_file=s',    # Log file name
     'pid_file=s',    # File where we drop the PID if we are a daemon
     'foreground',    # run in the foreground, not as a daemon
     'log_stdout',    # Log to stdout as well (-foreground required)
     'timeout=i',     # Radius request timeout
     's=s',           # Radius server to send requests to address:port
     'queuesize=n',   # Listener max queue length
     'listen=s',      # Listen for HTTP connections on address:port
     'destination=s', # Default forwarding address:port
     'secret=s',      # Radius shared secret
     'readers=s',     # readers.conf file specifies users/IP addresses not requiring radius authenticaiton
     );

$main::VERSION = '1.3';
my $hostname = hostname();
$main::ident = "nntp-redirect.pl $main::VERSION on $hostname";


&GetOptions(@options) || &usage;
&usage if $main::opt_h;
&version if $main::opt_v;

my $local_addr = '0.0.0.0:1190';
$local_addr = $main::opt_listen if defined $main::opt_listen;
my $listen_queue = 10;
my $destination = 'localhost:119';
$destination = $main::opt_destination if defined $main::opt_destination;
my $realm = "Protected content on $hostname";
$realm = $main::opt_realm if defined $main::opt_realm;
my $authscheme = $main::opt_authscheme =~ /^d/i ? 'DIGEST' : 'BASIC';

my $queuesize = 20;
$queuesize = $main::opt_queuesize if defined $main::opt_queuesize;

# Radius server config
my $radius_server = 'localhost:1645';
$radius_server = $main::opt_s if defined $main::opt_s;
my $secret = 'mysecret';
$secret = $main::opt_secret if defined $main::opt_secret;
my $dictionary = './dictionary';
$dictionary = $main::opt_dictionary if defined $main::opt_dictionary;
my $trace_level = $main::LOG_WARNING;
$trace_level = $main::opt_trace if defined $main::opt_trace;

my %readers; # Hash of users/addresses that dont require radius authentication
&loadAuthReaders($main::opt_readers) if defined $main::opt_readers;

&become_daemon() unless $main::opt_foreground;

my $CRLF = "\015\012";   # "\r\n" is not portable
my $session_id = 1;
$SIG{CHLD} = 'IGNORE'; # Autoreap children

# Initialise Radius libraries
&Radius::SimpleClient::trace_level($trace_level);
my $dict = Radius::RDict->new($dictionary) 
    || &fatal_error("Could not open Radius dictionary $dictionary");


# Create a NNTP server to listen on
&main::log($main::LOG_DEBUG, "Listening on $local_addr");
my $server =  IO::Socket::INET->new(LocalAddr => $local_addr,
				Reuse => 1,
				Listen => $queuesize)
    || &fatal_error("Cant create server on $local_addr: $!");

# For each incoming connection, make a child process to authenticate and manage it
my $client;
while ($client = $server->accept())
{
    $session_id++; # in the parent
    &child($client, $session_id) unless &safeFork();
    $client->close();
}

#####################################################################
# This function manages all the behaviour of the child process
sub child
{
    my ($client, $session_id) = @_;

    my $sockhost = $client->sockhost();
    my $sockport = $client->sockport();
    my $peerhost = $client->peerhost();
    my $peerport = $client->peerport();
    my $acct_session_id = sprintf('%08x', $session_id);
#    $server->close(); # Dont want to listen on the childs copy any more

    # create a radius client to do auth an accounting for this session
    my $radius_client = Radius::SimpleClient->new(Dest => $radius_server,
						  Secret => $secret) 
	|| &fatal_error('Could not create Radius::SimpleClient');
    $client->print("200 nntp-redirect server ready$CRLF");
    my ($password, $request, $class, $idle_timeout, $session_timeout);
    my $username = findAuthReader($peerhost);
    if (!defined $username)
    {
	# Need to ask for a username/password and auth it with radius
	while (1) # Until authenticated
	{
	    my $line = $client->getline();
	    &main::log($main::LOG_DEBUG, "got line from client: $line");
	    
	    if ($line =~ /^AUTHINFO USER (\S*)/i)
	    {
		$username = $1;
	    }
	    elsif ($line =~ /^AUTHINFO PASS (\S*)/i)
	    {
		$password = $1;
	    }
	    elsif ($line =~ /^QUIT/i)
	    {
		$client->print("205 Disconnecting$CRLF"); 
		$client->shutdown(2);
		exit;
	    }
	    elsif ($line =~ /^HELP/i)
	    {
		$client->print("100 Legal commands$CRLF  authinfo user <name>$CRLF  authinfo pass <password>$CRLF  quit$CRLF  help$CRLF"); 
		next;
	    }
	    else
	    {
		# Send a demand for authentication
		$client->print("480 Authentication required$CRLF");
		next;
	    }
	    if (defined $username && defined $password)
	    {
		# Try authenticate the connection
		my $p = Radius::SimpleClient::request
		    ($dict, 
		     'User-Name'       => $username,
		     'User-Password'   => $password,
		     'NAS-IP-Address'  => $sockhost,
		     'NAS-Port'        => $sockport,
		     'Acct-Session-Id' => $acct_session_id,
		     'Login-IP-Host'   => $peerhost,
		     'Login-TCP-Port'  => $peerport,);
		my $r = $radius_client->sendAndWait($p);
		if ($r)
		{
		    if ($r->code() eq 'Access-Accept')
		    {
			$class = $r->get_attr('Class'); # Save for later
			$idle_timeout = $r->get_attr('Idle-Timeout');
			$session_timeout = $r->get_attr('Session-Timeout');
			my $dest_address = $r->get_attr('Login-IP-Host');
			my $dest_port = $r->get_attr('Login-TCP-Port');
			$destination = "$dest_address:$dest_port" 
			    if defined $dest_address || defined $dest_port;
			$client->print("281 Authentication accepted$CRLF");
			last;
		    }
		    else
		    {
			$client->print("502 No permission$CRLF");
		    }
		}
		else
		{
		    $client->print("480 Authentication required$CRLF");
		    &fatal_error("No reply to Access-Request from $radius_server");
		}
	    }
	    else
	    {
		$client->print("381 More authentication information required$CRLF");
	    }
	}
    }

    # OK, they are allowed to connect
    &main::log($main::LOG_INFO, "Redirecting connection for $username to $destination");
    my $dest =  IO::Socket::INET->new(PeerAddr => $destination,
                                      Proto => 'tcp',
                                      Timeout => 20);
    &fatal_error("Could not connect to $destination: $!") unless $dest;

    # OK connected to the target port, send an accounting start
    my $p = Radius::SimpleClient::request
	($dict, 
	 'Code' => 'Accounting-Request',
	 'Acct-Status-Type' => 'Start',
	 'User-Name'        => $username,
	 'NAS-IP-Address'   => $sockhost,
	 'NAS-Port'         => $sockport,
	 'Login-IP-Host'    => $peerhost,
	 'Login-TCP-Port'   => $peerport,	 
         'Acct-Session-Id'  => $acct_session_id,
	 defined $class ? ('Class' => $class) : ());
    my $r = $radius_client->sendAndWait($p);
    &fatal_error("No reply to Accounting-Request from $radius_server") unless $r;

    # Hmmm, absorb any 200 server ready messages. Some clients dont like getting another one
    # after authentication
    my $serverline = $dest->getline();
    
    # OK, have now sent accounting request, go ahead and exchange bytes, counting them
    # as we go
    my $conn_start_time = time;
    my $last_data_time = $conn_start_time;
    my (@input_octets, @output_octets);
    my $selector = IO::Select->new();
    my $terminate_cause = 'User-Request';
    $selector->add($client, $dest);
    while (1)
    {
	my @ready = $selector->can_read(1);
	if (@ready)
	{
	    my $ready;
	    while ($ready = shift @ready)
	    {
		$last_data_time = time;
		my ($buf, $target);
		$ready->recv($buf, 16384, Socket::MSG_DONTWAIT);
		#print "transparent proxy $ready: $buf\n";
		goto end unless length $buf; # something wrong if no bytes read
		if ($ready eq $client)
		{
		    # from client to dest
		    &add31(\@input_octets, length $buf);
		    $target = $dest;
		    if ($buf =~ /^AUTHINFO/i)
		    {
			# Damn, the client is trying to auth again with the dest server. Drop
			# it on the floor, casue the server may not require auth. Should this
			# behaviour be configurable?
			$client->print("281 Authentication accepted$CRLF");
			next;
		    }
		}
		else
		{
		    # from dest to client
		    &add31(\@output_octets, length $buf);
		    $target = $client;
		}
		my $written = $target->send($buf);
		$target->flush();
		goto end unless $written; # something wrong if no bytes written
	    }
	}

	# Look for session timeouts and idle-timeouts
	if ($idle_timeout && time - $last_data_time > $idle_timeout)
	{
	    # Exceeded idle timout
	    $terminate_cause = 'Idle-Timeout';
	    goto end;
	}
	if ($session_timeout && time - $conn_start_time >$session_timeout)
	{
	    # Exceeded session timout
	    $terminate_cause = 'Session-Timeout';
	    goto end;
	}
	# Look for excessive data volumes    
	# REVISIT
    }

    # When we get to here, ready to shut down
  end:
    $client->shutdown(2);
    $dest->shutdown(2);

    # OK connected to the target port, send an accounting start
    $p = Radius::SimpleClient::request
	($dict, 
	 'Code' => 'Accounting-Request',
	 'Acct-Status-Type' => 'Stop',
	 'User-Name'            => $username,
	 'NAS-IP-Address'       => $sockhost,
	 'NAS-Port'             => $sockport,
	 'Login-IP-Host'        => $peerhost,
	 'Login-TCP-Port'       => $peerport,
	 'Acct-Session-Id'      => $acct_session_id,
	 'Acct-Session-Time'    => time - $conn_start_time,
	 'Acct-Input-Octets'    => $input_octets[0] + 0,
	 'Acct-Input-Gigawords' => $input_octets[1] + 0,
	 'Acct-Output-Octets'   => $output_octets[0] + 0,
	 'Acct-Output-Gigawords'=> $output_octets[1] + 0,
	 'Acct-Terminate-Cause' => $terminate_cause,
	 defined $class ? ('Class' => $class) : ());
    $r = $radius_client->sendAndWait($p);
    &fatal_error("No reply to Accounting-Request from $radius_server") unless $r;
    exit 0; # End of the child
}

#####################################################################
# arbitrary precision integer addition
# Maintains an array of 31 bit integers
# index 0 is octets, index 1 is 2**31 octets (gigawords), index 2 is 2**64 octets etc
sub add31
{
    my ($a, $addend) = @_;

    $$a[0] += $addend;
    my $i;
    while ($i < @$a)
    {
	$$a[$i+1]++ if $$a[$i] & 0x80000000;
	$$a[$i++] &= 0x7fffffff;
    }
}

#####################################################################
# Fork safely with much error checking.
# Return pid if in parent
# return 0 which means you are in the child.
# Return undef and warn if an error
sub safeFork
{
    my $pid;
  FORK:
    if ($pid = fork)
    {
	# Parent, remember to wait for this child
	return $pid;
    }
    elsif (defined $pid)
    {
	# Child. 
	return 0;
    }
    elsif ($! =~ /No more process/)
    {
	# EAGAIN, supposedly recoverable fork error
	&main::log($main::LOG_ERR, "Could not fork because no more processes. Waiting for 1 seconds to try again");
	sleep 1;
	redo FORK;
    }
    else
    {
	# Wierd fork error
	&main::log($main::LOG_ERR, "Fork failed in safeFork: $!");
	return;
    }
}

#####################################################################
sub fatal_error
{
    my ($s) = @_;

    &main::log($main::LOG_ERR, $s);
    exit 1;
}

#####################################################################
# Provide a basic implementation of a logger
sub log
{    
    my ($priority, $s, $p) = @_;
    return unless $priority <= $trace_level;
    my $ctime = localtime(time);
    my $pname = $Radius::Log::priorityToString[$priority];
    print STDERR "$ctime: $pname: $s\n" if $main::opt_log_stdout;
    if (defined $main::opt_log_file)
    {
	open(LOGFILE, ">>$main::opt_log_file")
	    || warn "Could not open log file '$main::opt_log_file'";
	print LOGFILE "$ctime: $s\n";
	close(LOGFILE);
    }
}

#####################################################################
sub main::willLog
{    
    my ($priority, $p) = @_;
    return ($priority <=  $trace_level);
}

#####################################################################
# change this process into a daemon by:
# forking (parent exits with status 0) (from programming perl page 167)
# closing unused files
# change working dir to some innocuous and reliable place like /tmp
# become process group leader
# Does nothing on Win95
# 
sub become_daemon
{
    return if $^O eq 'MSWin32';

    # Exit if we are in the parent
    exit if &main::safeFork;

    # In the child here
    if (require POSIX)
    {
	# become process group leader (unless its AIX,
	# which does not support setsid yet)
	&POSIX::setsid() unless &POSIX::uname() =~ /aix/i;
    }
    &write_pid;

    # Detach from controlling terminal. From Jerome Fleury <jerome.fleury@fr.tiscali.com>
    open STDIN, '/dev/null';
    open STDOUT, '>/dev/null';
    open STDERR, '>/dev/null';
}

#####################################################################
sub write_pid
{
    return unless defined $main::opt_pid_file;

    # Write our pid into a file.
    my $pidfile = $main::opt_pid_file;
    # Make sure the directory exists
    mkpath(dirname($pidfile), 0, 0755) unless -d dirname($pidfile);
    open(PIDFILE, ">$pidfile")
	|| warn "Could not open pid file '$pidfile': $!";
    print PIDFILE "$$\n";
    close(PIDFILE);
}

#####################################################################
sub usage
{
    print "usage: $0 [-h] [-v] [-dictionary=file[,file...]
    [-trace 0|1|2|3|4|5] [-log_file filename] [-pid_file filename]
    [-foreground] [-s radiusserver:port] [-secret secret] [-queuesize httpqueuesize]
    [-readers readerconffile]
    [-listen listenaddress:port]
    [-destination destaddress:port]\n";
    exit;
}

#####################################################################
sub version
{
    print "
This is $main::ident

Copyright Open System Consultants

http://www.open.com.au/radiator\n";
    exit;
}

#####################################################################
# Load a readers.conf file and save the details of the auth clauses. Return
# a ref to a hash
# supports the same format is some NNTP readers:
#auth "xyzzy" {
#	hosts: "194.233.145.*, 194.195.237.*, 195.180.143.*"
#	default: <ISPEG> 
#}
sub loadAuthReaders
{
    my ($filename) = @_;

    if (open(READERS, $filename))
    {
	while (<READERS>)
	{
	    next if /^\s*#/;   # Skip comments
	    if (/^\s*auth\s+"(.*)"\s+{/)
	    {
		# Start of an auth clause
		my $name = $1;
		while (<READERS>)
		{
		    next if /^\s*#/;  # Skip comments
		    last if /^\s*\}/; # End of clause
		    chomp;
		    # We only understand the hosts: line
		    if (/^\s*hosts: "(.*)"/)
		    {
			# Hosts line
			@{$readers{$name}} = split(/\s*,\s*/, $1);
		    }
		}
	    }
	}
    }
    else
    {
	&main::log($main::LOG_ERR, "Could not load readers file: $!");
    }
}

#####################################################################
# See if there was a user for the specified address in the readers file
# If the address matches (including wildcard matches, return the user name
sub findAuthReader
{
    my ($address) = @_;

    # This is a linear search. Cont do any better because addresses 
    # can contain wildcards
    my ($name, $addresses);
    while (($name, $addresses) = each %readers)
    {
	foreach (@$addresses)
	{
	    # Turn ? and * wildcards into regexps
	    s/\./\\./g;   # Turn . into \.
	    s/\?/./g;     # Turn ? into .
	    s/\*/.*/g;    # Turn * into .*
	    return $name if $address =~ /$_/;
	}
    }
    return;
}
