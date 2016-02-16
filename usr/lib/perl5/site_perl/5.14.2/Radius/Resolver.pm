# Resolver.pm
#
# Object for handling special DNS name resolution services
# that arent provided by the standard perl DNS API
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2005 Open System Consultants
# $Id: Resolver.pm,v 1.19 2014/04/10 19:37:59 hvn Exp $

package Radius::Resolver;
@ISA = qw(Radius::Configurable);
use Radius::Configurable;
use Radius::Select;
use Net::DNS;
use strict;

%Radius::Resolver::ConfigKeywords =
(
 'Nameservers'                => 
 ['stringarray', 'This optional parameter specifies the name or address of one or more DNS Name Servers to connect to in order to do DNS lookups. Nameservers with IPV6 addresses are supported if the system Perl has IPv6 support. Defaults to the value of nameserver in resolv.conf (see above). Multiple Nameservers will be consulted in order until one does not time out.', 1],

 'Debug'                      => 
 ['flag', 'This optional flag enables debugging within the Net::DNS module. It will print to stdout the details of all DNS requests sent and replies received. Defaults to no debugging', 1],

 'Recurse'                    => 
 ['flag', 'This optional flag enables recursive DNS lookups. Defaults to no recurse.', 1],

 'TCPTimeout'                 => 
 ['integer', 'This optional flag specifies the timeout (in seconds) for DNS lookups over TCP connections. Defaults to 5 seconds.', 1],

 'UDPTimeout'                 => 
 ['integer', 'This optional flag specifies the timeout (in seconds) for DNS lookups over UDP connections. Defaults to 5 seconds.', 1],

 'TCPPersistent'              => 
 ['flag', 'This optional flag tells Net::DNS to keep a TCP socket open for each host:port to which it connects. This is useful if you\'re using TCP and need to make a lot of queries to the same nameserver. Defaults to true.', 1],

 'UDPPersistent'              => 
 ['flag', 'This optional flag tells Net::DNS to keep a single UDP socket open for all DNS queries. This is useful if you\'re using UDP and need to make a lot of queries to the same nameserver. Defaults to true.', 1],

 'UseDNSSEC'                  => 
 ['flag', 'Specifies to use DNSSEC.', 2],

 'GetIPV4'                    => 
 ['flag', 'This optional flag specifies whether Resolver will attempt to find an IPV4 (A) address for any names it discovers. Defaults to true.', 1],

 'GetIPV6'                    => 
 ['flag', 'This optional flag specifies whether Resolver will attempt to find an IPV6 (AAAA)address for any names it discovers. Defaults to true.', 1],

 'GetRadius'                  => 
 ['flag', 'This optional parameter specifies whether Resolver is required to attempt to discover RADIUS servers.', 1],

 'GetRadSec'                  => 
 ['flag', 'This optional parameter specifies whether Resolver is required to attempt to discover RADSEC servers', 1],

 'GetDiameter'                => 
 ['flag', 'This optional parameter specifies whether Resolver is required to attempt to discover RADSEC servers. Not used', 3],

 'DirectAddressLookup'                  => 
 ['flag', 'If DirectAddressLookup is enabled, and if there are no NAPTR records for the requestsed Realm, Resolver will attempt lookups of A and AAAA records for _radsec._sctp.<REALM>, _radsec._tcp.<REALM> and _radius._udp.<REALM>. Enabled by default.', 1],

 'NAPTR-Pattern'                => 
 ['string', 'This optional parameter specifies a pattern for matching NAPTR results in order to determine the type and protocol of the service', 1],

 'NegativeCacheTtl'                 => 
 ['integer', 'This optional value specifies how  long a negative lookup (ie failure to resolve the realm) will be cached until another lookup will be made. Defaults to 21600 seconds (6 hours).', 1],

 'FailureBackoffTime'                 => 
 ['integer', 'If the lookup failed to discover any results and there was a timeout while waiting for the nameserver, this optional value specifies how long Radiator will wait before another lookup is made. Defaults to 3 seconds.', 1],

 );

# RCS version number of this module
$Radius::Resolver::VERSION = '$Revision: 1.19 $';

# The default instance of Resolver (usually the last one created)
$Radius::Resolver::default = undef;

# Cache of previously discovered addresses by realm
%Radius::Resolver::cached_results = ();

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();
    
    $self->{resolver} = Net::DNS::Resolver->new
	(nameservers    => [@{$self->{Nameservers}}], 
	 debug          => $self->{Debug},
	 recurse        => $self->{Recurse},
	 tcp_timeout    => $self->{TCPTimeout},
	 udp_timeout    => $self->{UDPTimeout},
	 persistent_tcp => $self->{TCPPersistent},
	 persistent_udp => $self->{UDPPersistent},
	 dnssec         => $self->{UseDNSSEC},
	 );
    if ($self->{resolver})
    {
	$Radius::Resolver::default = $self;
    }
    else
    {
	$self->log($main::LOG_ERR, "Failed to create Net::DNS resolver: $!");
    }
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
    $self->{Debug}         = 0;
    $self->{Recurse}       = 1;
    $self->{TCPTimeout}    = 5;
    $self->{UDPTimeout}    = 5;
    $self->{TCPPersistent} = 1;
    $self->{UDPPersistent} = 1;
    $self->{UseDNSSEC}     = 0;
    $self->{GetIPV4}       = 1;
    $self->{GetIPV6}       = 1;
    $self->{GetRadius}     = 1;
    $self->{GetRadSec}     = 1;
    $self->{GetDiameter}   = 0;
    $self->{DirectAddressLookup}   = 1;
    $self->{NegativeCacheTtl} = 21600;
    $self->{FailureBackoffTime} = 3;
    @{$self->{Nameservers}} = ();
}

#####################################################################
# Discover addresses for all the servers discovered for the given realm name
# The strategy is to first look for NAPTR records for the given realm, and follow each one. 
# If they point to SRV records, get each one and follow them (remembering the port)
# If there are no NAPTR records, do direct lookup using A and AAAA records of a name based on the realm
# NAPTR type U records (URI) are not yet supported.
# This function is asynchronous, and may involve multiple DNS lookup, some in parallel.
# When done, call the callback
# Rediscover if the cached answer has expired its Ttl
sub discoverServers
{
    my ($self, $realm, $callback) = @_;

    # First check to see if we have a cached from a previous lookup
    # REVISIT: what if it has expired/timedout
    if (exists $Radius::Resolver::cached_results{$realm})
    {
	# If we already have a valid answer, callback now
	my $answer = $Radius::Resolver::cached_results{$realm};
	if ($answer->{waitingfor})
	{
	    # Hmmm, there is a request currently in progress. Add our callback to the
	    # callback list so we will also get called when the answer is known
	    push(@{$answer->{Callback}}, $callback);
	    return;
	}
	return &$callback($answer)
	    unless time > $answer->{Expires};
    }
    
    # Have to do discovery. Eventually, all the results will come in and
    # the callback(s) will be called.
    my $answer = {Results => [], Realm => $realm, Callback => [$callback]};
    $Radius::Resolver::cached_results{$realm} = $answer;
    $self->find_naptr($realm, $answer);
}

#####################################################################
# Do a DNS NAPTR lookup
sub find_naptr
{
    my ($self, $name, $answer, @args) = @_;

    $self->log($main::LOG_DEBUG, "Doing NAPTR lookup for $name, @args");
    my $sock = $self->{resolver}->bgsend($name, 'NAPTR');

    if (!$sock)
    {
	$self->log($main::LOG_ERR, 'Failed to bgsend NAPTR: ' . $self->{resolver}->errorstring());
	return;
    }
    $answer->{waitingfor}++; # Remember how many of these we are waiting for
    # Arrange for us to be called when the socket is ready with results or a timeout
    my $timeout = &Radius::Select::add_timeout(time + $self->{UDPTimeout},
					       \&Radius::Resolver::handle_naptr_socket_read,
					       $self, $sock, $answer);
    
    &Radius::Select::add_file(fileno($sock), 1, undef, undef, 
			      \&Radius::Resolver::handle_naptr_socket_read, $self, $sock, $answer, $timeout);
}


#####################################################################
# Called by Select when there is something to be read from a Net::DNS resolver 
# socket with an answer to an NAPTR request, or if there is a timeout
# If $timeout is set, this the socket ready, and $timeout is the timeout handle
sub handle_naptr_socket_read
{
    my ($fileno, $self, $sock, $answer, $timer_handle) = @_;

    if ($timer_handle)
    {
	# Got a DNS reply, remove the waiting timer
	&Radius::Select::remove_timeout($timer_handle);
	# Dont need this socket callback any more
	&Radius::Select::remove_file($fileno, 1);
	
	my $result = $self->{resolver}->bgread($sock);
	
	if ($result)
	{
	    # Make sure we only get NAPTR records.
	    my (@results, $r);
	    foreach $r ($result->answer())
	    {
		push(@results, $r) if $r->type eq 'NAPTR';
	    }
	    if (@results)
	    {
		# Sort the results in order of 'order' and 'preference'
		@results = sort {$a->order() == $b->order() || $a->preference() <=> $b->preference()} @results;
		my ($matched_order, $r);
		foreach $r (@results) 
		{
		    $self->log($main::LOG_EXTRA_DEBUG, "Found NAPTR record for realm $answer->{Realm}: " . $r->string());
		    
		    # Make sure we dont look at NAPTR records with a later order as perRFC 2915
		    last if defined $matched_order && $r->order() > $matched_order;
		    
		    # Adjust TTL
		    my $ttl = $r->ttl();
		    $answer->{Ttl} = $ttl if !defined $answer->{Ttl} || $answer->{Ttl} > $ttl;
		    
		    # Look for NAPTR records of the form AAA+RADSECS and AAA+RADSECT
		    # The S or T indicates whether the transport is SCTP or TCP 
		    if ($self->{GetRadSec} && $r->service() =~ /^AAA(S?).*\+RADSEC([ST])/i)
		    {
			$matched_order = $r->order();
			my $secure = $1 eq 'S' ? 1 : 0;
			my $transport = $2 eq 'S' ? 'sctp' : 'tcp';
			# Now work out what to do with this record based on the flags
			if ($r->flags() =~ /s/i)
			{
			    # 's' records require an SRV lookup
			    $self->find_srv($r->replacement(), $answer,
					    'Protocol'   => 'radsec',
					    'Transport'  => $transport,
					    'UseTLS'     => $secure,
					    'Order'      => $r->order(),
					    'Preference' => $r->preference());
			}
			if ($r->flags() =~ /a/i)
			{
			    # 'a' records require an A and/or AAAA lookup
			    $self->find_address($r->replacement(), $answer, 
						'Protocol'   => 'radsec',
						'Transport'  => $transport,
						'UseTLS'     => $secure,
						'Order'      => $r->order(),
						'Preference' => $r->preference());
			}
			# REVISIT: add URI support for for type 'u'
		    }
		    # Look for NAPTR records of the form AAA+RADIUSU
		    if ($self->{GetRadius} && $r->service() =~ /^AAA.*\+RADIUS/i)
		    {
			$matched_order = $r->order();
			# Now work out what to do with this record based on the flags
			if ($r->flags() =~ /s/i)
			{
			    # 's' records require an SRV lookup
			    $self->find_srv($r->replacement(), $answer,
					    'Protocol'   => 'radius',
					    'Transport'  => 'udp',
					    'Order'      => $r->order(),
					    'Preference' => $r->preference());
			}
			if ($r->flags() =~ /a/i)
			{
			    # 'a' records require an A and/or AAAA lookup
			    $self->find_address($r->replacement(), $answer, 
						'Protocol'   => 'radius',
						'Transport'  => 'udp',
						'Order'      => $r->order(),
						'Preference' => $r->preference());
			}
			# REVISIT: add URI support for for type 'u'
		    }
		    if (defined $self->{'NAPTR-Pattern'} && $r->service() =~ $self->{'NAPTR-Pattern'})
		    {
			$matched_order = $r->order();
			# First match is the protocol, second is the transport
			my $protocol = defined $1 ? $1 : 'radsec';
			my $transport = defined $2 ? $2 : 'tcp';
			my $usetls = 0;
			if ($transport eq 'tls')
			{
			    $transport = 'tcp';
			    $usetls = 1;
			}
			# Now work out what to do with this record based on the flags
			if ($r->flags() =~ /s/i)
			{
			    # 's' records require an SRV lookup
			    $self->find_srv($r->replacement(), $answer,
					    'Protocol'   => $protocol,
					    'Transport'  => $transport,
					    'UseTLS'     => $usetls,
					    'Order'      => $r->order(),
					    'Preference' => $r->preference());
			}
			if ($r->flags() =~ /a/i)
			{
			    # 'a' records require an A and/or AAAA lookup
			    $self->find_address($r->replacement(), $answer, 
						'Protocol'   => $protocol,
						'Transport'  => $transport,
						'UseTLS'     => $usetls,
						'Order'      => $r->order(),
						'Preference' => $r->preference());
			}
		    }
		}
	    }
	    elsif ($self->{DirectAddressLookup})
	    {
		# Hmm, no matching NAPTR records?
		# Look for some directly derived names for A and AAAA record
		if ($self->{GetRadSec})
		{
		    $self->log($main::LOG_DEBUG, "No RadSec NAPTR records for realm $answer->{Realm}. Trying direct address lookup");
		    $self->find_address("_radsec._sctp.$answer->{Realm}", $answer, Transport => 'sctp');
		    $self->find_address("_radsec._tcp.$answer->{Realm}", $answer, Transport => 'tcp');
		}
		if  ($self->{GetRadius})
		{
		    $self->log($main::LOG_DEBUG, "No Radius NAPTR records for realm $answer->{Realm}. Trying direct address lookup");
		    $self->find_address("_radius._udp.$answer->{Realm}", $answer, Transport => 'udp');
		}
	    }
	}
	else
	{
	    $self->log($main::LOG_ERR, 'DNS Failed to get NAPTR result for realm $answer->{Realm}: ' . $self->{resolver}->errorstring());
	}
	
    }
    else
    {
	$self->log($main::LOG_INFO, "No reply from DNS for NAPTR request for realm $answer->{Realm}");
	# Dont need this socket callback any more
	&Radius::Select::remove_file(fileno($sock), 1);
	$answer->{noreply}++;
    }

    close($sock);
    $answer->{waitingfor}--;
    $self->check_if_done($answer);
}

#####################################################################
# Do a DNS SRV lookup
sub find_srv
{
    my ($self, $name, $answer, @args) = @_;

    $self->log($main::LOG_DEBUG, "Doing SRV lookup for $name, @args");
    my $sock = $self->{resolver}->bgsend($name, 'SRV');
    if (!$sock)
    {
	$self->log($main::LOG_ERR, 'Failed to bgsend SRV: ' . $self->{resolver}->errorstring());
	return;
    }
    $answer->{waitingfor}++; # Remember how many of these we are waiting for
    # Arrange for us to be called when the socket is ready with results or a timeout
    my $timeout = &Radius::Select::add_timeout(time + $self->{UDPTimeout},
					       \&Radius::Resolver::handle_srv_socket_read,
					       $self, $sock, $answer);
    &Radius::Select::add_file(fileno($sock), 1, undef, undef, 
			      \&Radius::Resolver::handle_srv_socket_read, $self, $sock, $answer, $timeout, @args);
}

#####################################################################
# Called by Select when there is something to be read from a Net::DNS resolver 
# socket with an answer to an SRV request
sub handle_srv_socket_read
{
    my ($fileno, $self, $sock, $answer, $timer_handle, @args) = @_;


    if ($timer_handle)
    {
	# Got a DNS reply, remove the waiting timer
	&Radius::Select::remove_timeout($timer_handle);
	# Dont need this socket callback any more
	&Radius::Select::remove_file($fileno, 1);
	
	my $result = $self->{resolver}->bgread($sock);
	if ($result)
	{
	    my @results = $result->answer();
	    my $r;
	    foreach $r (@results) 
	    {
		next unless $r->type eq 'SRV';
		$self->log($main::LOG_EXTRA_DEBUG, "Found SRV record for realm $answer->{Realm}: " . $r->string());
		
		# Adjust Ttl
		my $ttl = $r->ttl();
		$answer->{Ttl} = $ttl if !defined $answer->{Ttl} || $answer->{Ttl} > $ttl;
		$self->find_address($r->target(), $answer, @args, 
				    'Port' => $r->port(), 
				    'Priority' => $r->priority(), 
				    'Weight' => $r->weight(),
		                    'SRVName' => $r->name());
	    }
	}
	else
	{
	    $self->log($main::LOG_ERR, 'DNS Failed to get SRV result for realm $answer->{Realm}: ' . $self->{resolver}->errorstring());
	}
    }
    else
    {
	$self->log($main::LOG_INFO, "No reply from DNS for SRV request for realm $answer->{Realm}");
	# Dont need this socket callback any more
	&Radius::Select::remove_file(fileno($sock), 1);
	$answer->{noreply}++;
    }

    close($sock);
    $answer->{waitingfor}--;
    $self->check_if_done($answer);
}

#####################################################################
# Do a DNS A and/or AAAA lookup
sub find_address
{
    my ($self, $name, $answer, @args) = @_;

    if ($self->{GetIPV4})
    {
	$self->log($main::LOG_DEBUG, "Doing A lookup for $name, @args");
	my $sock = $self->{resolver}->bgsend($name, 'A');
	if (!$sock)
	{
	    $self->log($main::LOG_ERR, 'Failed to bgsend A: ' . $self->{resolver}->errorstring());
	    return;
	}
	$answer->{waitingfor}++; # Remember how many of these we are waiting for
	# Arrange for us to be called when the socket is ready with results or a timeout
	my $timeout = &Radius::Select::add_timeout(time + $self->{UDPTimeout},
						   \&Radius::Resolver::handle_a_socket_read,
						   $self, $sock, $answer);
	&Radius::Select::add_file(fileno($sock), 1, undef, undef, 
				  \&Radius::Resolver::handle_a_socket_read, $self, $sock, $answer, $timeout, Address => $name, @args);
    }
    if ($self->{GetIPV6})
    {
	$self->log($main::LOG_DEBUG, "Doing AAAA lookup for $name, @args");
	my $sock = $self->{resolver}->bgsend($name, 'AAAA');
	if (!$sock)
	{
	    $self->log($main::LOG_ERR, 'Failed to bgsend AAAA: ' . $self->{resolver}->errorstring());
	    return;
	}
	$answer->{waitingfor}++; # Remember how many of these we are waiting for
	# Arrange for us to be called when the socket is ready with results or a timeout
	my $timeout = &Radius::Select::add_timeout(time + $self->{UDPTimeout},
						   \&Radius::Resolver::handle_a_socket_read,
						   $self, $sock, $answer);
	&Radius::Select::add_file(fileno($sock), 1, undef, undef, 
				  \&Radius::Resolver::handle_a_socket_read, $self, $sock, $answer, $timeout, Address => $name, @args);
    }
}

#####################################################################
# Called by Select when there is something to be read from a Net::DNS resolver 
# socket with an answer to an A or AAAA request
sub handle_a_socket_read
{
    my ($fileno, $self, $sock, $answer, $timer_handle, @args) = @_;

    if ($timer_handle)
    {
	# Got a DNS reply, remove the waiting timer
	&Radius::Select::remove_timeout($timer_handle);
	# Dont need this socket callback any more
	&Radius::Select::remove_file($fileno, 1);
	
	my $result = $self->{resolver}->bgread($sock);
	if ($result)
	{
	    my @results = $result->answer();
	    my $r;
	    foreach $r (@results) 
	    {
		my $type = $r->type;
		next unless $type eq 'A' || $type eq 'AAAA';
		$self->log($main::LOG_EXTRA_DEBUG, "Found $type record for realm $answer->{Realm}: " . $r->string());
		# Adjust Ttl
		my $ttl = $r->ttl();
		$answer->{Ttl} = $ttl if !defined $answer->{Ttl} || $answer->{Ttl} > $ttl;
		push(@{$answer->{Results}}, {@args, IPAddress => $r->address()});
	    }
	}
	else
	{
	    $self->log($main::LOG_ERR, 'DNS Failed to get A or AAA result for realm $answer->{Realm}: ' . $self->{resolver}->errorstring());
	}
    }
    else
    {
	$self->log($main::LOG_INFO, "No reply from DNS for A/AAAA request for realm $answer->{Realm}");
	# Dont need this socket callback any more
	&Radius::Select::remove_file(fileno($sock), 1);
	$answer->{noreply}++;
    }

    close($sock);
    $answer->{waitingfor}--;
    $self->check_if_done($answer);
}

#####################################################################
# See if we have all the results for this set of requests and
# whether its time to call the callback
sub check_if_done
{
    my ($self, $answer) = @_;

    if ($answer->{waitingfor} == 0)
    {

	# If the server did not reply to some of the queries
	# because of a timeout, we do not want to use the long
	# NegativeCacheTtl. This might be just a temporary problem.
	my $negttl = ($answer->{noreply} ? $self->{FailureBackoffTime} : $self->{NegativeCacheTtl});

	# Now have all the DNS lookup results we are expecting, call the callback 
	# in the answer. Remember it in the cache
	# Sort results by Preference, Priority, Weight
	@{$answer->{Results}} = sort {   $a->{Preference} <=> $b->{Preference}
				      || $a->{Priority}   <=> $b->{Priority}
				      || $a->{Weight}     <=> $b->{Weight}
				      } @{$answer->{Results}};
	$answer->{Expires} = time + ($answer->{Ttl} || $negttl);
	foreach (@{$answer->{Callback}})
	{
	    &$_($answer);
	}
	@{$answer->{Callback}} = ();
    }
}
1;
