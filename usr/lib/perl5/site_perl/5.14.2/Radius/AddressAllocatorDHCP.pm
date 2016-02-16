# AddressAllocatorDHCP
#
# Implements IP address allocation from DHCP.
# Called by AuthDYNADDRESS.pm
#
# AddressAllocatorDHCP.pm will work with any DHCP
# server, however it works best with the DHCP server
# from the Internet Software Consortium (www.isc.org).
# The ISC DHCP server implements a new option called
# the Subnet Selection Option (documented in RFC 3011),
# which allows inter-server operation such as that 
# implemented by Radiator.
# 
# If a DHCP server that does not implement the Subnet
# Selection Option is used, there is additional configuration
# required on the Radiator host such that virtual interfaces
# from each subnet defined in DHCP must be configured. This 
# virtual interface address must be used in the DHCP request
# to indicate which DHCP address range to allocate from.
#
# There is an example configuration file included in the Radiator
# distribution in the file "goodies/addressallocatordhcp.cfg".
#
# NOTE: the DHCP server cannot run on the same host as Radiator.
# This is due to the fact that Radiator as a DHCP proxy must use
# the same UDP port number as the DHCP server.  
#
# Author: Hugh Irvine (hugh@open.com.au)
# Copyright (C) 2000 Open System Consultants

package Radius::AddressAllocatorDHCP;
@ISA = qw(Radius::AddressAllocatorGeneric);
use Radius::AddressAllocatorGeneric;
use Radius::DHCP;
use Radius::Radius;
use Radius::Select;
use Radius::Context;
use Socket;
use Fcntl;  
use strict;

# This is a hash of requests for which we are awaiting replies
# ie these are the original requests as received from our client
# Each entry is a hash including 2 refs to Radius packets.
# The first element is the original packet we received and 
# the second is the reply packet we are constructing
# and which was originally passed to handle_request.
# Additional elements are added as needed.
my %pendingRequests;

%Radius::AddressAllocatorDHCP::ConfigKeywords = 
('Host'                  => 
 ['string', 'Hostname of the DHCP server to use', 0],
 'Port'                  => 
 ['string', 'Destination UDP port of the DHCP server', 1],
 'ServerPort'            => 
 ['string', 'DHCP Server port. Deprecated, use SourcePort instead', 1],
 'SourcePort'            => 
 ['string', 'Source UDP port to use when sending DHCP requests to the DHCP server', 1],
 'LocalAddress'          => 
 ['string', 'The bind address to use for the DHCP request port', 1],
 'UseClassForAllocationInfo'    => 
 ['flag', 'Information about the allocation is kept in Class attribute instead of in memory. Required for server farm. Defaults to off.', 1],
 'DHCPClientIdentifier'  => 
 ['string', 'The attribute to use in the DHCPv6 Client-Identifier field to identify the RADIUS client to the DHCP server. Special characters are permitted.', 1],
 'DefaultLease'          => 
 ['integer', 'If SessionTimeout is set by a previous AuthBy then that is used as the expiry time. Otherwise DefaultLease (in seconds) is used.', 1],
 'TimeoutMinimum'        => 
 ['integer', 'The starting timeout in seconds', 2],
 'TimeoutMaximum'        => 
 ['integer', 'The maximum timeout in seconds', 2],
 'TimeoutFactor'         => 
 ['integer', 'The factor that the timeout increases by after each unaswered DHCP request', 2],
 'Synchronous'           => 
 ['flag', ' operate synchronously with the DHCP server', 2],
 'SubnetSelectionOption' => 
 ['integer', 'Early versions of the ISC DHCP server use the unofficial option 211', 1],
 'UserClass'             => 
 ['string', 'Optional user class identifier', 1],
 'ClientHardwareAddress'            => 
 ['string', 'The attribute in the incoming address which contains the hex encoded MAC address of the client. If present, it will be used as CHADDR in the DHCP request. If not present, and fake CHADDR based on the request XID will be used. The DHCP server may use this when allocating an address for the client.The MAC address can contain extraneous characters such as . or : as long as it contains the 12 hex characters (case insensitive) of the MAC address. Special characters are permitted.', 1],
     );

# RCS version number of this module
$Radius::AddressAllocatorDHCP::VERSION = '$Revision: 1.21 $';

#####################################################################
# (Re)activate a new Dynamic address allocator for DHCP
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();

    # For backward compatibility
    $self->{LocalPort} = $self->{ServerPort} if defined $self->{ServerPort};

    # If we are using server farm, we can not bind before fork
    $self->socketInit() unless $main::config->{FarmSize};
    $self->{NextIdentifier} = 0;
    $self->{SubnetSelectionOption} = $Radius::DHCP::SUBNET_SELECTION
	if defined $self->{SubnetSelectionOption}
           && $self->{SubnetSelectionOption} eq '';
}

#####################################################################
# This is called by Configurable during Configurable::new before
# the config file is parsed. Its a good place initalize instance 
# variables that might get overridden when the config file is parsed.
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;

    $self->{Host} = '255.255.255.255';
    $self->{Port} = $Radius::DHCP::SERVER_PORT;
    $self->{LocalPort} = $Radius::DHCP::SERVER_PORT;
    $self->{DHCPClientIdentifier} = '%{User-Name}';
    $self->{DefaultLease} = 86400;
    $self->{TimeoutMinimum} = 2;
    $self->{TimeoutMaximum} = 16;
    $self->{TimeoutFactor} = 2;
    my $addr = gethostbyname($main::hostname);
    $self->{LocalAddress} = Socket::inet_ntoa($addr) 
	unless defined $self->{LocalAddress};
    main::addChildInitFn(\&childInit, $self);
    return;
}

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate.
sub check_config
{
    my ($self) = @_;

    $self->log($main::LOG_WARNING, "Consider enabling UseClassForAllocationInfo in AddressAllocatorDHCP when configured with FarmSize")
      if $main::config->{FarmSize} && !$self->{UseClassForAllocationInfo};

    $self->SUPER::check_config();
    return;
}

#####################################################################
# This is called by the main (supervising) server when server farm is
# used. The function is called in each child after it is forked by
# forkFarmInstance
sub childInit
{
    my ($self) = @_;

    # Each child requires separate socket
    $self->socketInit();

    return;
 }

#####################################################################
# Do class level initialization
sub socketInit
{
    my ($self) = @_;

    # We format LocalAddress here so that %O (farm instance) is available
    $self->{LocalAddress} = Radius::Util::format_special($self->{LocalAddress});

    # May be reinitializing
    &Radius::Select::remove_file(fileno($self->{Socket}), 1, undef, undef)
	if $self->{Socket};

    # We could have used FileHandle here, but this is much
    # more lightweight. It makes a reference to a TYPEGLOB
    # and Perl can use a typeglob ref as an IO handle
    $self->{Socket} = do { local *FH };                   

    # Create a socket for us to send through
    socket($self->{Socket}, Socket::PF_INET, Socket::SOCK_DGRAM, 
	   scalar getprotobyname('udp'))
	|| warn "Could not create DHCP socket in AddressAllocatorDHCP: $!";
    binmode($self->{Socket}); # Make safe in UTF environments
    setsockopt($self->{Socket}, Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1);
        
    my $bind_address = $self->{LocalAddress};
    my $port = $self->{LocalPort};
    bind($self->{Socket}, scalar Socket::sockaddr_in
	 ($port, Socket::inet_aton($bind_address)))
         || warn "Could not bind to LocalAddress $bind_address:$port in AddressAllocatorDHCP: $!";
    
    # On some hosts, select sometimes incorrectly says that there
    # is a reply waiting, even when there isnt. 
    # Set the socket non-blocking to prevent waiting forever
    if ($^O ne 'MSWin32')
    {
	# Win95 does not support fcntl or non-blocking sockets yet.
	fcntl($self->{Socket}, F_SETFL, 
	      fcntl($self->{Socket}, F_GETFL, 0) | O_NONBLOCK)
	    || warn "Could not fcntl DHCP socket in AddressAllocatorDHCP: $!";
    }
    # Set the socket to handle broadcasts.
    setsockopt($self->{Socket}, Socket::SOL_SOCKET, Socket::SO_BROADCAST, 1)
    	|| warn "Could not set DHCP socket to handle broadcasts: $!";

    # Add this socket to the list in Radius::Select.
    &Radius::Select::add_file
	(fileno($self->{Socket}), 1, undef, undef, 
	 \&Radius::AddressAllocatorDHCP::handle_dhcp_socket_read, 
	 $self->{Socket});

    $Radius::AddressAllocatorDHCP::initialized = 1;
}

#####################################################################
# Allocate an address for username with the given pool hint
# return a hash of interesting values for AuthBy DYNADDRESS
# to do stuff with
sub allocate
{
    my ($self, $caller, $username, $pool_hint, $p) = @_;

    my $subnet;

    # Verify the pool_hint and if not correct Reject.
    if (&Radius::Util::isIP4Address($pool_hint))
    {
	$subnet = Socket::inet_aton($pool_hint);
    }
    else
    {
	return ($main::REJECT, "Incorrect PoolHint value $pool_hint");
    }

    # Build and send a DHCPDISCOVER
    my %values;

    $values{subnet} = $subnet;
    $values{client_identifier} = &Radius::Util::format_special
	($self->{DHCPClientIdentifier}, $p);
    $values{local_address} = Socket::inet_aton($self->{LocalAddress});
    $values{default_lease} = $self->{DefaultLease};
    my $xid = $self->next_identifier;
    $values{xid} = $xid;
    $values{secs} = 0;

    $values{chaddr} = pack 'C C N C10', 15, 255, $xid, 0;
    # Maybe create CHADDR from a MAC address in the request
    if ($self->{ClientHardwareAddress})
    {
	my $chaddr = &Radius::Util::format_special($self->{ClientHardwareAddress}, $p);
	my $chaddrhex = $chaddr;
	$chaddrhex =~ s/[^a-fA-F0-9]//g;
	if ($chaddrhex =~ m/([a-fA-F0-9]{12})/)
	{
	    $values{chaddr} = pack 'H32', $1;
	}
	else
	{
	    &main::log($main::LOG_WARNING, 
		       "ClientHardwareAddress $chaddr does not look like a MAC address. Reverting to XID for CHADDR");
	}
    }

    $values{sso} = $self->{SubnetSelectionOption}
        if (defined $self->{SubnetSelectionOption});
    $values{user_class} = &Radius::Util::format_special($self->{UserClass}, $p)
        if (defined $self->{UserClass});
    $values{message_type} = $Radius::DHCP::DHCPDISCOVER;

    my $packet = &Radius::DHCP::build_dhcpdiscover(\%values);

    my $port = $self->{Port};
    my $ip = $self->{Host};
    my $addr = Socket::inet_aton($ip);

    # Remember it. We keep a hash where the key is the port and
    # address of the host we sent to, concatenated with the xid
    my $key = $port.$addr.$xid;
    $pendingRequests{$key}{self} = $self;
    $pendingRequests{$key}{p} = $p;
    $pendingRequests{$key}{caller} = $caller;
    $pendingRequests{$key}{values} = \%values;

    my $destport = Socket::pack_sockaddr_in($port, $addr);
 
    $self->log($main::LOG_DEBUG, 
       "Sending DHCPDISCOVER to $ip:$port with xid $xid", $p);

    # and send it
    # Some platforms (eg Linux) will produce "Connection refused"
    # if the desination does not have a port open,
    # so ignore those kinds of errors
    if (!send($self->{Socket}, $packet, 0, $destport))
    {
	$self->log($main::LOG_ERROR, "allocate: send failed: $!", $p)
	    unless $! =~ /^Connection refused/;
    }

    # Arrange for retransmission timeout
    # We remember the timeout handle so we can remove 
    # it if we get a reply
    $pendingRequests{$key}{timeouthandle} = 
	&Radius::Select::add_timeout(time + $self->{TimeoutMinimum},
	   \&Radius::AddressAllocatorDHCP::handle_timeout,
	   $self, $key, $p);

    # Save the destination port and address for
    # later timeout handling together with the
    # initial timeout value
    $pendingRequests{$key}{destport} = $destport;
    $pendingRequests{$key}{timeout} = $self->{TimeoutMinimum};

    if ($self->{Synchronous})
    {
        # Here we process replies until the request we are doing
        # has either been replied to or timed out
        # CAUTION: while this is happening, no other incoming requests
        # will be handled: If the remote server is down
        # you may get a serious performance hit
        # Wait for activity on the reply socket or timeouts
	my $waitfor = 0;
	my $found;
	vec($waitfor, fileno($self->{Socket}), 1) = 1;
	while (!defined $p->{DHCPResult})
	{
            # Wait up to a second for activity on the socket
	    select($found=$waitfor, undef, undef, 1)
		&& &handle_dhcp_socket_read
		(fileno($self->{Socket}), $self->{Socket});
	    &Radius::Select::process_timeouts();
	}
	return ($p->{DHCPResult});
    }
    return($main::IGNORE);
}

#####################################################################
# Confirm a previously allocated address is in use
sub confirm
{    
    my ($self, $caller, $address, $p) = @_;

    return ($main::ACCEPT);
}

#####################################################################
# Free a previously allocated address
# Note that the DHCP server will not reply to a DHCPRELEASE
sub deallocate
{    
    my ($self, $caller, $address, $p) = @_;

    # build and send a DHCPRELEASE
    my %values;

    $values{client_identifier} = &Radius::Util::format_special
	($self->{DHCPClientIdentifier}, $p);
    $values{ciaddr} = Socket::inet_aton($address);
    $values{local_address} = Socket::inet_aton($self->{LocalAddress});
    my $xid = $self->next_identifier;
    $values{xid} = $xid;
    $values{sso} = $self->{SubnetSelectionOption}
        if (defined $self->{SubnetSelectionOption});
    $values{user_class} = &Radius::Util::format_special($self->{UserClass}, $p)
        if (defined $self->{UserClass});

    if ($self->{UseClassForAllocationInfo})
    {
	# Retrieve the saved values from the request Class attribute
	my $class = $p->get_attr('Class');
	unless (defined $class)
	{
	    my $nas = $p->get_attr('NAS-IP-Address') || 'unknown';
	    $self->log($main::LOG_WARNING, "deallocate: No Class from NAS $nas. Can not deallocate $address", $p);
	    return ($main::ACCEPT);
	}

	my($subnet, $chaddr) = split(/-/, $class);
	unless (defined $chaddr &&
		defined $subnet &&
		length($chaddr) == 32 &&  # 16 bytes, 32 hex chars
		Radius::Util::isIP4Address($subnet))
	{
	    my $nas = $p->get_attr('NAS-IP-Address') || 'unknown';
	    $self->log($main::LOG_WARNING, "deallocate: Bad Class value '$class' from NAS $nas. Can not deallocate $address", $p);
	    return ($main::ACCEPT);
	}

	$values{chaddr} = pack('H*', $chaddr);
	$values{subnet} = Socket::inet_aton($subnet);
    } else {
	# Retrieve the chaddr saved when the address was allocated
	my $context_key = "dhcp:$values{client_identifier}:$address";
	my $context = &Radius::Context::find($context_key);
	if (!defined $context)
	{
	    # no context, so just return
	    # this may happen if we get a duplicate accounting stop
	    return ($main::ACCEPT);
	}

	# Use the saved values
	$values{chaddr} = $context->{chaddr};
	$values{subnet} = $context->{subnet};

	# Remove the saved context
	&Radius::Context::destroy($context_key);
    }

    my $packet = &Radius::DHCP::build_dhcprelease(\%values);
    
    my $port = $self->{Port};
    my $ip = $self->{Host};
    my $addr = Socket::inet_aton($ip);

    my $destport = Socket::pack_sockaddr_in($port, $addr);
 
    $self->log($main::LOG_DEBUG, 
       "Sending DHCPRELEASE for $address to $ip:$port with xid $xid", $p);

    # and send it
    # Some platforms (eg Linux) will produce "Connection refused"
    # if the desination does not have a port open,
    # so ignore those kinds of errors
    if (!send($self->{Socket}, $packet, 0, $destport))
    {
	$self->log($main::LOG_ERROR, "deallocate: send failed: $!", $p)
	    unless $! =~ /^Connection refused/;
    }

    # We will never get a reply from the DHCP server
    return ($main::ACCEPT);
}

#####################################################################
# This is called by Select::select whenever our DHCP socket
# becomes readable. Read at most one packet from the socket and
# process it.
# The packets received here will be replies to requests 
# we have forwarded to a DHCP server.
# We have to reply to AuthDYNADDRESS
# and cross the original request off our timeout list.
# We must also save some context for later deallocation.
sub handle_dhcp_socket_read
{
    my ($fileno, $socket) = @_;

    my $whence;
    my $rec;

    if ($whence = recv($socket, $rec, 8192, 0))
    {
	# Get the packet from the DHCP socket and disassemble it.
       	my ($port, $addr) = Socket::unpack_sockaddr_in($whence);
	my $ip = Socket::inet_ntoa($addr);

	my $reply = Radius::DHCP::disassemble_packet($rec);

	&main::log($main::LOG_DEBUG, "Received DHCP reply:\n" . Radius::DHCP::dump($reply));
	
	# Make sure its a server response
	# Can get our own previous request back here on some OSs
	if ($$reply{op_code} != $Radius::DHCP::SERVER_OPCODE)
	{
	    &main::log($main::LOG_DEBUG, 
		       "Non-Server DHCP packet received in AddressAllocatorDHCP from $ip:$port");
	    return 1;
	}

	# Check the MAGIC_COOKIE to verify the contents
	if ($$reply{magic_cookie} ne $Radius::DHCP::MAGIC_COOKIE)
	{
	    &main::log($main::LOG_WARNING, 
		       "Broken DHCP packet received in AddressAllocatorDHCP from $ip:$port");
	    return 1;
	}

	# Get the context that was saved
	my $xid = $$reply{xid};
	my $key = $port.$addr.$xid;

	my $ref = $pendingRequests{$key};

	# Was the packet sent to the broadcast address?
	if (!defined $ref)
	{
	    $addr = Socket::INADDR_BROADCAST;
	    $key = $port.$addr.$xid;

	    $ref = $pendingRequests{$key};
	}

	# Couldn't find a reference
	if (!defined $ref)
	{
	    &main::log($main::LOG_WARNING, 
		       "Unknown reply received in AddressAllocatorDHCP for request $xid from $ip:$port");
	    return 1;
	}
	else
	{
	    &main::log($main::LOG_DEBUG,
		       "Received reply in AddressAllocatorDHCP for req $xid from $ip:$port");
	}

	# Cross it off our timeout list
	&Radius::Select::remove_timeout($pendingRequests{$key}{timeouthandle})
	    || &main::log($main::LOG_ERR, 
		  "Timeout $pendingRequests{$key}{timeouthandle} was not in the timeout list");

	# Extract the context parameters
	my $self = $pendingRequests{$key}{self};
	my $p = $pendingRequests{$key}{p};
	my $caller = $pendingRequests{$key}{caller};
	my $values = $pendingRequests{$key}{values};
	
	# RFC3011 specifies that if the Subnet Selection Option is used,
	# the reply from the DHCP server MUST contain the identical
	# Subnet Selection Option as included in our original request.

	if ((defined($$values{sso}) && ($$values{sso} ne $$reply{sso})) || 
	    ($$values{subnet} ne $$reply{subnet}))
	{
	    $self->log($main::LOG_ERROR, 
		       "Incorrect Subnet Selection Option in DHCP reply for request ID $xid", $p);

	    # Return reject to the NAS
	    $p->{Handler}->handlerResult
		($p, $main::REJECT, 'Incorrect Subnet Selection Option received from DHCP server');

	    # Cross it off our pending list
	    delete $pendingRequests{$key};
	    
	    # Tell Synchronous the result
	    $p->{DHCPResult} = $main::REJECT
		if defined $self->{Synchronous};
	    return 0;
	}

	my $message_type = $$reply{message_type};

	if ($message_type == $Radius::DHCP::DHCPOFFER)
	{
	    # Check whether we have already sent a request.
	    # This may happen if we are using the broadcast
	    # address and another DHCP server has sent an offer.
	    return 1 
		if (defined $pendingRequests{$key}{requested});

	    # We have received an offer from the DHCP server,
	    # so prepare and send a DHCPREQUEST

	    $$values{requested_ip_address} = $$reply{yiaddr};
	    $$values{server_identifier} = $$reply{server_identifier};
	    $$values{message_type} = $Radius::DHCP::DHCPREQUEST;

	    # Build the packet
	    my $packet = Radius::DHCP::build_dhcprequest($values);

            $self->log($main::LOG_DEBUG, 
                "Sending DHCPREQUEST to $ip:$port with xid $xid", $p);

	    # and send it
	    # Some platforms (eg Linux) will produce "Connection refused"
	    # if the desination does not have a port open,
	    # so ignore those kinds of errors
	    if (!send($self->{Socket}, $packet, 0, $whence))
	    {
		$self->log($main::LOG_ERROR, "allocate: send failed: $!", $p)
		    unless $! =~ /^Connection refused/;
	    }

	    # Arrange for retransmission timeout
	    # We remember the timeout handle so we can remove 
	    # it if we get a reply
	    $pendingRequests{$key}{timeouthandle} = 
		&Radius::Select::add_timeout(time + $self->{TimeoutMinimum},
			\&Radius::AddressAllocatorDHCP::handle_timeout,
			     $self, $key, $p);

	    # Save the destination port and address for
	    # later timeout handling together with the
	    # initial timeout value and a requested flag.
	    $pendingRequests{$key}{destport} = $whence;
	    $pendingRequests{$key}{timeout} = $self->{TimeoutMinimum};
	    $pendingRequests{$key}{requested}++;
	}

	elsif ($message_type == $Radius::DHCP::DHCPACK)
	{
	    # We have received an ack from the DHCP server,
	    # so reply to AuthDYNADDRESS with the details
	    my %details;
	    $details{yiaddr} = Socket::inet_ntoa($$reply{yiaddr})
		if defined $$reply{yiaddr};
	    $details{subnetmask} = Socket::inet_ntoa($$reply{subnet_mask})
		if defined $$reply{subnet_mask};
	    $details{dnsserver} = Socket::inet_ntoa($$reply{dns_server})
		if defined $$reply{dns_server};

	    if (defined $$reply{server_identifier})
	    {
		my $server = Socket::inet_ntoa($$reply{server_identifier});
		$details{serveridentifier} = 
		    "DHCP-Server-Identifier = $server";
	    }

	    # Save some context for later use by deallocate()
	    # Save the context in Class attribute or Context object.
	    if ($self->{UseClassForAllocationInfo})
	    {
		my $hex_chaddr = unpack('H*', $$values{chaddr});
		$p->{rp}->add_attr('Class', Socket::inet_ntoa("$$values{subnet}") . "-$hex_chaddr");
	    }
	    else
	    {
		my $context_key = "dhcp:$$values{client_identifier}:$details{yiaddr}";
		my $context = Radius::Context->new($context_key, $$values{default_lease});
		if (defined $context)
		{
		    $context->{subnet} = $$values{subnet};
		    $context->{chaddr} = $$values{chaddr};
		}
	    }

	    # Call the callers allocateDone() function
	    # to process the results
	    $caller->allocateDone($p, \%details);

	    # Now return the reply to the NAS
	    $p->{Handler}->handlerResult($p, $main::ACCEPT);

	    # Cross it off our pending list
	    delete $pendingRequests{$key};

	    # Tell Synchronous the result
	    $p->{DHCPResult} = $main::ACCEPT
		if defined $self->{Synchronous};
	}
	    
	elsif ($message_type == $Radius::DHCP::DHCPNAK)
	{
	    $self->log($main::LOG_WARNING, 
		       "Received DHCPNAK for request ID $xid", $p);

	    # Return reject to the NAS
	    $p->{Handler}->handlerResult
		($p, $main::REJECT, 'DHCPNAK received from server');

	    # Cross it off our pending list
	    delete $pendingRequests{$key};
	    
	    # Tell Synchronous the result
	    $p->{DHCPResult} = $main::REJECT
		if defined $self->{Synchronous};
	}
	return 1; # we got something
    }
}

#####################################################################
# handle_timeout
# This is called from within Select::process_timeouts for each packet
# we have forwarded but not received a reply within the timeout period
# All we do is call the per-instance method for the instance that
# set the timeout. The args are the same as were passed to add_timeout
# fp is the packet we forwarded, $p is the original request packet, 
sub handle_timeout
{
    my ($handle, $self, $key) = @_;

    my $destport = $pendingRequests{$key}{destport};
    my $values = $pendingRequests{$key}{values};
    my $p = $pendingRequests{$key}{p};
    my $secs = $pendingRequests{$key}{timeout};
    my $timeout = $pendingRequests{$key}{timeout} * $self->{TimeoutFactor};

    if ($timeout <= $self->{TimeoutMaximum})
    {
	# Save the new timeout value and elapsed seconds
	$pendingRequests{$key}{timeout} = $timeout;
        $$values{secs} += $secs;

        my $packet;

        # Build a new request
        if ($$values{message_type} == $Radius::DHCP::DHCPDISCOVER)
        {
            $packet = Radius::DHCP::build_dhcpdiscover($values);
        }
        elsif ($$values{message_type} == $Radius::DHCP::DHCPREQUEST)
        {
	    $packet = Radius::DHCP::build_dhcprequest($values);
        }
	
	# We havent exhausted our retries, retransmit
	# Some platforms (eg Linux) will produce "Connection refused"
	# if the desination does not have a port open,
	# so ignore those kinds of errors
	if (!send($self->{Socket}, $packet, 0, $destport))
	{
	    $self->log($main::LOG_ERROR, "timeout: send failed: $!", $p)
		unless $! =~ /^Connection refused/;
	}

	# Arrange for retransmission timeout
	# We remember the timeout handle so we can remove 
	# it if we get a reply
	$pendingRequests{$key}{timeouthandle} = 
	    &Radius::Select::add_timeout(time + $timeout,
		\&Radius::AddressAllocatorDHCP::handle_timeout,
			$self, $key, $p);
    }
    else
    {	
	$self->log($main::LOG_INFO, 
	    "AddressAllocatorDHCP: No reply from DHCP server $self->{Host}", $p);

	# No reply after all the retries, so reject the request
	$p->{Handler}->handlerResult
	    ($p, $main::REJECT, 'No reply from DHCP server');

	# Cross it off our pending list
	delete $pendingRequests{$key};

        # Tell Synchronous the result
	$p->{DHCPResult} = $main::REJECT
	    if defined $self->{Synchronous};
    }  
}

#####################################################################
# next_identifier
# Return the next identifier to be used 
sub next_identifier
{
    my ($self) = @_;

    return $self->{NextIdentifier} = ($self->{NextIdentifier} + 1);
}

1;






