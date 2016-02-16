# Client.pm
#
# Object for handling radius clients
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: Client.pm,v 1.106 2014/10/06 13:18:53 hvn Exp $

package Radius::Client;
@ISA = qw(Radius::Configurable);
use Radius::Configurable;
use Radius::Radius;
use Radius::Nas;
use Socket;
use strict;

%Radius::Client::ConfigKeywords = 
('Secret'                        => 
 ['string', 'This defines the shared secret that will be used to decrypt RADIUS messages that are received from this client. You must define a shared secret for each Client, and it must match the secret configured into the client RADIUS software. ', 0],

 'TACACSPLUSKey'                 => 
 ['string', 'Per-clinet TACACSPLUS key which will be used as the TACACS+ key if there is no Key defined in the Server TACACSPLUS clause', 1],

 'IgnoreAcctSignature'           => 
 ['flag', 'If defined, this parameter prevents the server from checking the "authenticator" (sometimes called the signature) in accounting requests received from this client. (Contrary to its name, it also affects the checking of Message-Authenticator in Access-Request messages). This parameter is useful because some clients (notably early Merit RADIUS servers and the GoRemote (GRIC) server when forwarding) do not send Authenticators that conform to RFC 2139, while some other NASs do not set the authenticator at all. ', 1],

 'DupInterval'                   => 
 ['integer', 'The Duplicate detection interval. If more than 1 RADIUS request is received with the same source and destination IP address, source port, authenticator and and RADIUS Identifier is received within DupInterval seconds, it is deemed to be a duplicate or retransmissions. If the earlier request has already been replied to, then that reply will be resent back to the NAS. Otherwise the duplicate request will be dropped. A value of 0 means duplicates are always accepted, which might not be very wise, except during testing. RFC 5080 recommends a value between 5 and 30 seconds. Default is 10 seconds.', 1],

 'DefaultRealm'                  => 
 ['string', 'This optional parameter can be used to specify a default realm to use for requests that have a User-Name that does not include a realm. The realm can then be used to trigger a specific <Realm> or <Handler> clause. This is useful if you operate a number of NASs for different customer groups and where some or all of your customers log in without specifying a realm.', 1],

 'NasType'                       => 
 ['string', 'This optional parameter specifies the vendor type of this Client. It is required if you want Radiator to directly query the NAS to check on simultaneous sessions.', 1],

 'SNMPCommunity'                 => 
 ['string', 'This optional parameter specifies the SNMP Community name to use to connect to the NAS when NasType uses SNMP. It is ignored for any other NasType. Defaults to "public".', 1],

 'LivingstonOffs'                => 
 ['integer', 'Specifies the value of where the last S port is before the one or tw ports specified in LivingstonHole are skipped (usually 22 for US, 29 for Europe). This optional parameter is only used if you are using Simultaneous-Use with a NasType of Livingston in this Client clause. Defaults to the value of LivingstonOffs in ServerConfig.', 1],

 'LivingstonHole'                => 
 ['integer', 'Specifies the value of the size of the hole in the port list (usually 1 for US, 2 for Europe) that occurs at LivingstonOffs. This optional parameter is only used if you are using Simultaneous-Use with a NasType of Livingston in this Client clause. Defaults to the value of LivingstonOffs from ServerConfig.', 1],

 'FramedGroupBaseAddress'        => 
 ['stringarray', 'This optional parameter is used in conjunction with the Framed-Group reply attribute or the FramedGroup AuthBy parameter to automatically generate IP addresses for users logging in. It is ignored unless the user has a Framed-Group reply item, or unless their AuthBy clause contains a FramedGroup parameter. You can have as many FramedGroupBaseAddress items as you like.', 1],

 'FramedGroupMaxPortsPerClassC'  => 
 ['integer', 'This optional parameter defines the maximum number of ports that can be mapped to a class C or class B FramedGroupBaseAddress. The default is 255, which means that any address from 0 up to 255 in the 3rd or 4th octets will be permitted. It actually specifies the modulus for computing the 3rd and 4th octets of addresses calculated from FramedGroupBaseAddress. You might use this to limit the number of addresses used in each address block, or to prevent the allocation of the last address in a class C address block.', 1],

 'FramedGroupPortOffset'         => 
 ['integer', 'Optional number to subtract from Framed Group port number. May be required for Cisco ISDN port numbers whcih start at a non-standard number ', 2],

 'RewriteUsername'               => 
 ['stringarray', 'This parameter enables you to alter the user name in all authentication and accounting requests from this client before being despatched to any Realm or Handler. ', 1],

 'UseOldAscendPasswords'         => 
 ['flag', 'This optional parameter tells Radiator to decode all passwords received from this Client using the old style (non RFC compliant) method that Ascend used to use on some NASs. The symptom that might indicate a need for this parameter is that passwords longer than 16 characters are not decoded properly.', 1],

 'StatusServerShowClientDetails' => 
 ['flag', 'Normally, when a Status-Server request is received, Radiator will reply with some statistics including the total number of requests handled, the current request rate etc. When you set the optional StatusServerShowClientDetails for a Client, the reply to Status-Server will also include details about that Client. This can result in a lengthy reply packet. Requires StatusServer parameter set to reply with statistics. The default is not to send the additional Client details for any Clients.', 1],

 'StatusServer' => 
 ['string', 'Normally, when a Status-Server request is received, Radiator will reply with some statistics including the total number of requests handled, the current request rate etc. You can control Status-Server response by setting StatusServer to off, minimal or default.', 1],

 'PreHandlerHook'                => 
 ['hook', 'This optional parameter allows you to define a Perl function that will be called during packet processing. PreHandlerHook is called for each request after per-Client username rewriting and duplicate rejection, and before it is passed to a Realm or Handler clause. A reference to the current request is passed as the only argument.', 1],

 'PacketTrace'                   => 
 ['flag', 'This optional flag forces all packets that pass through this module to be logged at trace level 4. This is useful for logging packets that pass through this clause in more detail than other clauses during testing or debugging. The packet tracing will stay in effect until it passes through another clause with PacketTrace set to off or 0.', 1],

 'IdenticalClients'              => 
 ['splitstringarray', 'This optional parameter specifies a list of other clients that have an identical setup. You can use this parameter to avoid having to create separate Client clauses for lots of otherwise identical clients. The value is a list of client names or addresses, separated by white space or comma.  Each client may be be specified as an IP address (IPV4 or IPV6), a MAC address in the form MAC:aa-bb-cc-dd-ee-ff, or an IPV4 CIDR address in the form nn.nn.nn/nn. You can have any number of IdenticalClients lines.', 1],

 'NoIgnoreDuplicates'            => 
 ['counthash', 'This optional parameter specifies one or more RADIUS packet types where duplicates are not ignored. NoIgnoreDuplicates is a comma or space separated list of request types, such as Access-Request,Accounting-Request,Status-Server', 1],

 'DefaultReply'                   => 
 ['string', 
  'Adds attributes to an Access-Accept only if there would otherwise be no reply attributes. StripFromReply will never remove any attributes added by DefaultReply. Value is a list of comma separated attribute value pairs ', 
  1],

 'FramedGroup'                    => 
 ['integer', 
  'If FramedGroup is set and a matching FramedGroupBaseAddress is set in the Client from where the request came, then a Framed-IP-Address reply item is automatically calculated by adding the NAS-Port in the request to the FramedGroupBaseAddress specified by FramedGroup. ', 
  1],

 'StripFromReply'                 => 
 ['string', 
  'Strips the named attributes from Access-Accepts before replying to the originating client. The value is a comma separated list of Radius attribute names. StripFromReply removes attributes from the reply before AddToReply adds any to the reply.', 
  1],

 'AllowInReply'                   => 
 ['string', 
  'Specifies the only attributes that are permitted in an Access-Accept. It is most useful to limit the attributes that will be passed back to the NAS from a proxy server. That way, you can prevent downstream customer Radius servers from sending back illegal or troublesome attributes to your NAS.', 
  1],

 'AddToReply'                     => 
 ['string', 
  'Adds attributes reply packets. Value is a list of comma separated attribute value pairs all on one line, exactly as for any reply item. StripFromReply removes attributes from the reply before AddToReply adds any to the reply. ', 
  1],

 'AddToReplyIfNotExist'           => 
 ['string', 
  'Similar to AddToReply, but only adds an attribute to a reply if and only if it is not already present in the reply. Therefore it can be used to add, but not override a reply attribute.', 
  1],

 'DynamicReply'                   => 
 ['stringarray', 
  'Specifies reply items that will be eligible for run-time variable   substitution. That means that you can use any of the % substitutions in that reply item.', 
  1],

 'AddToRequest'                   => 
 ['string', 
  'Adds attributes to the request before passing it to any authentication modules. Value is a list of comma separated attribute value pairs', 
  1],

 'AddToRequestIfNotExist'         => 
 ['string', 
  'Adds attributes to the request before passing it to any authentication modules. Unlike AddToRequest, an attribute will only be added if it does not already exist in the request. Value is a list of comma separated attribute value pairs ', 
  1],

 'StripFromRequest'               => 
 ['string', 
  'Strips the named attributes from the request before passing it to any authentication modules. The value is a comma separated list of attribute names. StripFromRequest removes attributes from the request before AddToRequest adds any to the request. ', 
  1],

 'ClearTextTunnelPassword'     => 
 ['flag', 
  'Prevents Radiator decrypting and reencrypting Tunnel-Password attributes in replies during proxying. This is provided in order to support older NASs that do not support encrypted Tunnel-Password.', 
  2],

 'ClientHook'      => 
 ['hook',
  'Perl hook that is run for each request when delivered to this Client clause',
  2],

 'UseContentsForDuplicateDetection'     => 
 ['flag', 
  'Causes duplicates to be detected based only on the contents of each request, and ignoring the source port and RADIUS identifier. This is necessary for coorect detection of duplicates in a server-farm environment.', 
  2],

 'RequireMessageAuthenticator'     => 
 ['flag', 
  'Causes this Client to require a (correct) Message-Authenticator attribute to be present in all incoming requests', 
  2],

 );

# RCS version number of this module
$Radius::Client::VERSION = '$Revision: 1.106 $';

# Make sure we get reinitialized on sighup
push(@main::reinitFns, \&reinitialize);

# Tell radiusd how to get to our find function
push(@main::clientFindFns, \&find);

# Patterns for recognising CIDRs
my $ipv4cidrpat = qr/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d+)/;
my $ipv6cidrpat = qr/(.*:.*)\/(\d+)$/;
my @cidrmasks =
(
 0x00000000, # /0
 0x80000000,
 0xc0000000,
 0xe0000000,
 0xf0000000,
 0xf8000000,
 0xfc000000,
 0xfe000000,
 0xff000000,
 0xff800000,
 0xffc00000,
 0xffe00000,
 0xfff00000,
 0xfff80000,
 0xfffc0000,
 0xfffe0000,
 0xffff0000,
 0xffff8000,
 0xffffc000,
 0xffffe000,
 0xfffff000,
 0xfffff800,
 0xfffffc00,
 0xfffffe00,
 0xffffff00,
 0xffffff80,
 0xffffffc0,
 0xffffffe0,
 0xfffffff0,
 0xfffffff8,
 0xfffffffc,
 0xfffffffe,
 0xffffffff, # /32
 );

# IPv6 netmasks are calculated only if there are IPv6 CIDR Clients.
my @ipv6cidrmasks;

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    # Complain if we are building from config file, but there
    # was no secret or TACACS+ key. Dont complain if we are being
    # built by CListSQL
    $self->log($main::LOG_ERR,
        "No Secret or TACACSPLUSKey defined for Client $self->{Name} in '$main::config_file'")
	if !defined $self->{Secret} && !defined $self->{TACACSPLUSKey};

    # See if the names can be resolved to IP addresses and CIDR blocks
    # are correctly specified. Resolve will complain if it fails.
    foreach ($self->{Name},
	     @{$self->{IdenticalClients}})
    {
	$self->resolve($_);
	if ($_ =~ /$ipv4cidrpat/)
	{
	    $self->log($main::LOG_ERR, "Could not resolve address in IPv4 CIDR pattern $_")
		unless Radius::Util::inet_pton($1);
	    $self->log($main::LOG_ERR, "Bad mask length $2 in IPv4 CIDR pattern $_")
		unless $2 >= 0 && $2 <= 32;
	}
	elsif ($_ =~ /$ipv6cidrpat/)
	{
	    # Calculate the IPv6 masks to trigger a warning if there
	    # is nothing but pure Perl BigInt lib available
	    Radius::Client::calculate_ipv6masks()
		unless @Radius::Client::ipv6cidrmasks;

	    $self->log($main::LOG_ERR, "Could not resolve address in IPv6 CIDR pattern $_")
		unless Radius::Util::inet_pton($1);
	    $self->log($main::LOG_ERR, "Bad mask length $2 in IPv6 CIDR pattern $_")
		unless $2 >= 0 && $2 <= 128;
	}
    }

    $self->SUPER::check_config();
    return;
}

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();

    $self->{DupCache} = {};
    $self->{DupCacheOrder} = [];

    # The packed address. We skip Names that can not be resolved from
    # DNS.
    if ($self->{Name} eq 'DEFAULT')
    {
	$self->{Host} = Socket::INADDR_ANY;
    }
    else
    {
	$self->{Host} = $self->resolve($self->{Name});
    }

    # So we can look up either by name/dotted quad or by 
    # packed IP V4 or V6 address or by MAC address
    $self->addClientAddress($self->{Name});

    # Add entries for all the IdenticalClients
    foreach (@{$self->{IdenticalClients}})
    {
	$self->addClientAddress($_);
    }
}

#####################################################################
# Add a Client address to the set of exact matching addresses
# $client_addr is a name or address or a MAC address or a CIDR mask address
sub addClientAddress
{
    my ($self, $client_addr) = @_;

    if ($client_addr =~ /$ipv6cidrpat/)
    {
	my $addr    = $1; # From regexp
	my $masklen = $2; # From regexp

	# Calculate the IPv6 masks when they are first needed.
	Radius::Client::calculate_ipv6masks()
	    unless @Radius::Client::ipv6cidrmasks;

	# We calculate network address and save it for later use when
	# requests need to be matched with Clients.
	$addr = "ipv6:$addr" unless $addr =~ /^ipv6:/i;   # Make sure address starts with ipv6:
	my $addr_int = Radius::Util::inet_pton("$addr"); 
	my $net = Math::BigInt->new("0x" . unpack("H*", $addr_int));   # Address as BigInt
	$net->band($Radius::Client::ipv6cidrmasks[$masklen]);   # Do bitwise and to get network address
	$self->{IPv6AddrMasked} = $net;
    }
    # So we can find with a literal name or address or MAC or CIDR
    $Radius::Client::clients{$client_addr} = $self;

    # Maybe add the packed address too
    my $addr = $self->resolve($client_addr);
    $Radius::Client::clients{$addr} = $self
	if $addr;

    return;
}

#####################################################################
# Try to resolve names and textual IP address to packed addresses
# while skipping DEFAULT, MAC:, CIDR blocks and other valid Client
# names. The callers expect us to complain if resolvation fails.
sub resolve
{
    my ($self, $client_addr) = @_;

    my $addr;
    if (   $client_addr ne 'DEFAULT'
	&& $client_addr !~ /^MAC:/
	&& $client_addr !~ /$ipv4cidrpat/
	&& $client_addr !~ /$ipv6cidrpat/)
    {
 	$addr = Radius::Util::inet_pton($client_addr);
 	$self->log($main::LOG_ERR, "Could not resolve address $client_addr for Client $self->{Name}")
 	    unless defined $addr;
    }

    return $addr;
}

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{DupInterval} = 10;
    $self->{NasType} = 'unknown';   # Default NAS type
    $self->{SNMPCommunity} = 'public';
    $self->{FramedGroupMaxPortsPerClassC} = 255;
    $self->{LivingstonHole} = $main::config->{LivingstonHole};
    $self->{LivingstonOffs} = $main::config->{LivingstonOffs};
    $self->{ObjType} = 'Client'; # Auto register with Configurable
    $self->{StatusServer} = $main::config->{StatusServer};
}

#####################################################################
# Pre-calculate IPv6 netmasks for IPv6 CIDR Clients
sub calculate_ipv6masks
{

    # We use run time eval to make sure use is only called when this
    # function is called. This makes sure any warnings about missing
    # libs are not printed when IPv6 CIDR clients are not configured.
    # Later, when everyone uses recent enough BigInt, we can use try
    # instead of lib to suppress warnings.
    eval ("use Math::BigInt lib => 'Pari,GMP';");

    my $lib = Math::BigInt->config()->{lib};
    main::log($main::LOG_INFO, 'Consider installing Math::BigInt::GMP or Math::BigInt::Pari for faster IPv6 CIDR Client matching. Falling back to pure Perl implementation.')
	if $lib eq 'Math::BigInt::Calc';

    # Create 128 bits for exclusive or (bxor).
    my $max = Math::BigInt->new('0b' . '1' x 128);

    foreach my $masklen (0 .. 128)
    {
	my $mask = Math::BigInt->new('0b' . '1' x 128); # 128 1 bits
	$mask->brsft($masklen);  # Shift bit rights
	$mask->bxor($max);       # Flip them to get the mask
	
	$Radius::Client::ipv6cidrmasks[$masklen] = $mask;
    }

    return;
}

#####################################################################
# Find a Client with the packed Host same as the RecvFrom host
# If not found, try to find one with the MAC address given in Called-Station-Id
# If not found, try to find one for DEFAULT
# REVISIT: Should probably add regexp matching too?
sub find
{
    my ($p) = @_;

    my ($client_port, $client_addr) = Radius::Util::unpack_sockaddr_in($p->{RecvFrom});
    my $ret = $Radius::Client::clients{$client_addr};
    # Look for a IPV4 or IPv6 CIDR match.
    $ret = findCidrAddress($client_addr)
	unless defined $ret;
    if (!defined $ret)
    {
	# Try to deduce a MAC address from Called-Station-Id
	no warnings "uninitialized";
	my $mac = $p->getAttrByNum($Radius::Radius::CALLED_STATION_ID);
	$ret = $Radius::Client::clients{'MAC:' . $1}
  	    if ($mac =~ /^([0-9a-fA-F]{2}-?[0-9a-fA-F]{2}-?[0-9a-fA-F]{2}-?[0-9a-fA-F]{2}-?[0-9a-fA-F]{2}-?[0-9a-fA-F]{2})/);

	# Still nothing, fall back to the default
	$ret = $Radius::Client::clients{DEFAULT}
            unless defined $ret;
    }
    return $ret;
}

#####################################################################
# Converts addresses into 32 bit unsigned ints for IPv4 and 128 bit
# BigInt object for IPv6 and applies CIDR mask
# CAUTION: linear search
sub findCidrAddress
{
    my ($client_addr) = @_;

    my $addr_len = length($client_addr);
    my $client_addr_int = unpack('N', $client_addr);  # For IPv4
    my $client_addr_hex = "0x" . unpack("H*", $client_addr); # For IPv6

    my $key;
    no warnings qw(uninitialized);
    foreach $key (sort { ($b =~ /\/(\d+)/)[0] <=> ($a =~ /\/(\d+)/)[0] } keys %Radius::Client::clients)
    {
	if ($addr_len == 4 && $key =~ /$ipv4cidrpat/)
	{
	    my $addr_int = unpack('N', &Radius::Util::inet_pton($1));
	    return $Radius::Client::clients{$key}
		if (   ($addr_int & $cidrmasks[$2]) 
		    == ($client_addr_int & $cidrmasks[$2]));
	}
	elsif ($addr_len == 16 && $key =~ /$ipv6cidrpat/)
	{
	    my $client = $Radius::Client::clients{$key};
	    my $a = Math::BigInt->new($client_addr_hex);  # Client address as a BigInt
	    $a->band($Radius::Client::ipv6cidrmasks[$2]); # Do bitwise and with CIDR mask
	    return $client
	        if ($client->{IPv6AddrMasked} == $a);
	}
    }
    return; # Not found
}

#####################################################################
# Find a Client with the packed IPv4 or IPv6 address $addr
# If not found, check CIDR Clients and finally try to find one for
# DEFAULT
sub findAddress
{
    my ($addr) = @_;

    my $ret = $Radius::Client::clients{$addr};
    $ret = findCidrAddress($addr)
	unless defined $ret;
    $ret = $Radius::Client::clients{DEFAULT}
	unless defined $ret;
    return $ret;
}

#####################################################################
# Handle a request from a client
sub handle_request
{
    my ($self, $p) = @_;

    # We tuck the Client pointer into the packet
    # so replying will be easier for other modules: they can just call
    # $originalPacket->{Client}->replyTo($originalPacket);
    $p->{Client} = $self;

    $p->{PacketTrace} = $self->{PacketTrace} 
        if defined  $self->{PacketTrace}; # Optional extra tracing

    # Decrypt and unpack attrs from the raw wire
    $p->decode_attrs($self->{Secret}, $p);
    $p->recv_debug_dump($self) if (main::willLog($main::LOG_DEBUG, $p));

    # Call the server config ClientHook, if there is one
    $main::config->runHook('ClientHook', $p, \$p, $self);

    # Call our ClientHook, if there is one
    $self->runHook('ClientHook', $p, \$p);

    # Arrange to deliver replies back to this client
    $p->{replyFn} = [\&replyFn, $self];

    my $code = $p->code;

    # Try real hard to find out who sent this packet
    my $nas_port = $p->getAttrByNum($Radius::Radius::NAS_PORT);

    if (!defined $self->{IgnoreAcctSignature}
	&& !$p->check_authenticator($self->{Secret}, undef, $self->{RequireMessageAuthenticator}))
    {

	# get the NAS id
	my $nas_id = $p->getNasId();
	
	# we might have failed because there is no secret defined for this
	# client but there is a TACACSPLUS Key (which passes the config checks
	# in ->new()
	if (defined $self->{Secret})
	{
	    # Log where this stuff is coming from, hopefully we can fix
	    # it. Contributed by Shawn Instenes <shawni@teleport.com>
	    $self->log($main::LOG_WARNING,
		       "Bad authenticator in request from $self->{Name} ($nas_id)", $p);
	    $p->statsIncrement('badAuthRequests');
	    $p->statsIncrement('badAuthAccessRequests')
		if $code eq 'Access-Request';
	    $p->statsIncrement('badAuthAccountingRequests')
		if $code eq 'Accounting-Request';
	}
	else 
	{
	    $self->log($main::LOG_WARNING,
		       "No secret defined in request from $self->{Name} ($nas_id)", $p);
	}
	$p->statsIncrement('droppedRequests');
	$p->statsIncrement('droppedAccessRequests')
	    if $code eq 'Access-Request';
	$p->statsIncrement('droppedAccountingRequests')
	    if $code eq 'Accounting-Request';
    }
    else
    {
	$p->rewriteUsername($self->{RewriteUsername})
	    if defined $self->{RewriteUsername};

	# Add and strip attributes before forwarding. 
	map {$p->delete_attr($_)} (split(/\s*,\s*/, $self->{StripFromRequest}))
	    if defined $self->{StripFromRequest};

	$p->parse(&Radius::Util::format_special($self->{AddToRequest}, $p))
	    if defined $self->{AddToRequest};

	$p->parse_ifnotexist(&Radius::Util::format_special
			     ($self->{AddToRequestIfNotExist}, $p))
	    if defined $self->{AddToRequestIfNotExist};

	if ($code eq 'Status-Server')
	{
	    $self->handle_status_server($p);
	}
	else
	{
	    # Check that its not a duplicate. dups resulting from
	    # retransmission are ignored. For this client, we keep 
	    # a hash of arrays. The key for the hash is the 
	    # NAS-IP-Address or NAS-Identifier or client IP address
	    # of the incoming packet
	    # the index of the array is the Identifer of the packet. 
	    # The value is the receipt time.
	    
	    # On NAS reboot, forget about all previous identifiers
	    no warnings qw(uninitialized);
	    my $is_reboot;
 	    if (   $p->getAttrByNum($Radius::Radius::ACCT_STATUS_TYPE) 
		   eq 'Accounting-On'
		|| ($p->getAttrByNum($Radius::Radius::ACCT_STATUS_TYPE) 
		    eq 'Start'
		    && $p->getAttrByNum($Radius::Radius::ACCT_SESSION_ID) 
		    eq '00000000')) 
	    {
		# Remove all the recent identifiers from this address only
		$self->clearDuplicateCacheForSource($p->{RecvFromAddress});
		$is_reboot = 1;
 	    }
 		
	    # BUG ALERT: this _wont_ catch retransmissions of
	    # accounting where the Acct-Delay-Time has changed, because
	    # the identifier will also have changed. Radius protocol sucks.
	    my $dup = $self->findDuplicate($p)
		unless $self->{NoIgnoreDuplicates}{$code};
	    if ($dup)
	    {
		if (!$is_reboot)
		{
		    my $id = $p->identifier;
		    my ($udpAddrPrint) = &Radius::Util::inet_ntop($p->{RecvFromAddress});

		    # Its a duplicate. If we have already replied to it
		    # resend the reply, else drop it. See RFC 5080
		    if (exists $dup->{rp}->{Packet})
		    {
			$self->log($main::LOG_INFO, "Duplicate request id $id received from $udpAddrPrint($p->{RecvFromPort}): retransmit reply", $p);
			if ($self->{UseContentsForDuplicateDetection} && $dup->{rp}->identifier != $p->identifier)
			{
			    # Need to change the RADIUS identifier and recompute 
			    # authenticators, repack the request etc
			    $dup->{rp}->set_identifier($p->identifier);
			    $dup->{rp}->set_authenticator($p->authenticator);
			    $dup->{rp}->assemble_packet($self->{Secret}, $p,
			      ClearTextTunnelPassword => $self->{ClearTextTunnelPassword});
			}
			$dup->{rp}->sendReplyTo($p);
			$p->statsIncrement('duplicateRequests');
			$p->statsIncrement('dupAccessRequests')
			    if $code eq 'Access-Request';
			$p->statsIncrement('dupAccountingRequests')
			    if $code eq 'Accounting-Request';
		    }
		    else
		    {
			$self->log($main::LOG_INFO, "Duplicate request id $id received from $udpAddrPrint($p->{RecvFromPort}): ignored", $p);
			$p->statsIncrement('duplicateRequests', 
					   'droppedRequests');
			$p->statsIncrement('dupAccessRequests',
					   ' droppedAccessRequests')
			    if $code eq 'Access-Request';
			$p->statsIncrement('dupAccountingRequests',
					   ' droppedAccountingRequests')
			    if $code eq 'Accounting-Request';
		    }
		}
	    }
	    else
	    {
		# its not a dup, save for later dup checking
		$self->addToDuplicateCache($p)
		    unless $self->{NoIgnoreDuplicates}{$code};

		# Call the PreHandlerHook, if there is one
		$self->runHook('PreHandlerHook', $p, \$p);

		my ($user, $realmName) = split(/@/, $p->getUserName);
		# Maybe use a default realm to find the Realm
		# or Handler later?
		if (defined $user 
		    && $realmName eq '' 
		    && defined $self->{'DefaultRealm'})
		{
		    $realmName = $self->{'DefaultRealm'};
		    $p->changeUserName("$user\@$realmName");
		}

		# Look in the finder array in order until
		# we find a function that knows how to get a 
		# subclass of handler. This allows you to 
		# add new subclasses of Handler that have
		# new more efficinet ways of finding the righty
		# Handler to use
		my ($handler, $finder);
		foreach $finder (@Radius::Client::handlerFindFn)
		{
		    if ($handler = &$finder($p, $user, $realmName))
		    {
			# Make sure the handler is updated with stats
			push(@{$p->{StatsTrail}}, \%{$handler->{Statistics}});

			$handler->handle_request($p);
			last;
		    }
		}
		if (!$handler)
		{
		    $self->log($main::LOG_WARNING, "Could not find a handler for $p->{OriginalUserName}: request is ignored", $p);
		    $p->statsIncrement('droppedRequests');
		    $p->statsIncrement('droppedAccessRequests')
			if $code eq 'Access-Request';
		    $p->statsIncrement('droppedAccountingRequests')
			if $code eq 'Accounting-Request';
		}
	    }
	}
    }

    $p->statsIncrement('requests');
    $p->statsIncrement('accessRequests') 
	if $code eq 'Access-Request';
    $p->statsIncrement('accountingRequests') 
	if $code eq 'Accounting-Request';
}

#####################################################################
# Check whether we have received an identical request in the DupCache
# in the last DupInterval seconds. If so, return it.
sub findDuplicate
{
    my ($self, $p) = @_;

    no warnings qw(uninitialized);
    return unless $self->{DupInterval};
    # First remove old expired requests from the beginning of the 
    # time-ordered list
    my $cutoff = time - $self->{DupInterval};
    while (@{$self->{DupCacheOrder}}
	   && $self->{DupCacheOrder}[0]->{RecvTime} < $cutoff)
    {
	my $oldp = shift(@{$self->{DupCacheOrder}});
	my $oldkey = $oldp->{DupCacheKey};
	if ($self->{UseContentsForDuplicateDetection})
	{
	    delete $self->{DupCache}->{$oldkey};
	}
	else
	{
	    delete $self->{DupCache}->{$oldp->{RecvFromAddress}}->{$oldkey};
	}
    }
    # Then see if there is matching request in our cache
    if ($self->{UseContentsForDuplicateDetection})
    {
	# Look at the packet contents not the envelope
	# The key includes the authenticator, in line with RFC5080
	my $key = $p->authenticator 
	    . $p->getAttrByNum($Radius::Radius::USER_NAME)
	    . $p->getAttrByNum($Radius::Radius::CALLED_STATION_ID)
	    . $p->getAttrByNum($Radius::Radius::CALLING_STATION_ID);
	return $self->{DupCache}->{$key};
    }
    else
    {
	# The key includes the authenticator, in line with RFC5080
	my $key = $p->{RecvFromPort} . $p->authenticator . $p->identifier;
	return $self->{DupCache}->{$p->{RecvFromAddress}}->{$key};
    }
}

#####################################################################
# Add a request to the DupCache
sub addToDuplicateCache
{
    my ($self, $p) = @_;

    return unless $self->{DupInterval};
    if ($self->{UseContentsForDuplicateDetection})
    {
	my $key = $p->authenticator 
	    . $p->getAttrByNum($Radius::Radius::USER_NAME)
	    . $p->getAttrByNum($Radius::Radius::CALLED_STATION_ID)
	    . $p->getAttrByNum($Radius::Radius::CALLING_STATION_ID);
	
	$p->{DupCacheKey} = $key;
	push (@{$self->{DupCacheOrder}}, $p);
	$self->{DupCache}->{$key} = $p;
    }
    else
    {
	# The key includes the authenticator, in line with RFC5080
	my $key = $p->{RecvFromPort} . $p->authenticator . $p->identifier;
	# Add to the end of the ordered time list of recent requests
	$p->{DupCacheKey} = $key;
	push (@{$self->{DupCacheOrder}}, $p);
	$self->{DupCache}->{$p->{RecvFromAddress}}->{$key} = $p;
    }
}

#####################################################################
# Clears the duplicate cache of all requests from a particular source address.
sub clearDuplicateCacheForSource
{
    my ($self, $source) = @_;

    $self->{DupCache}->{$source} = {};
}

#####################################################################
# Assemble the reply packet {rp} in reply to packet $p
# Caution this API changed post 2.19, was $self, $rp, $p
sub replyTo
{
    my ($self, $p) = @_;

    # Honour DefaultReply etc
    $self->adjustReply($p);

    my $code = $p->{rp}->code;
    $p->statsIncrement('accessAccepts')
	if $code eq 'Access-Accept';
    $p->statsIncrement('accessRejects')
	if $code eq 'Access-Reject';
    $p->statsIncrement('accessChallenges')
	if $code eq 'Access-Challenge';
    $p->statsIncrement('accountingResponses')
	if $code eq 'Accounting-Response';
    my $response_time = &Radius::Util::timeInterval($p->{RecvTime}, $p->{RecvTimeMicros}, &Radius::Util::getTimeHires);
    $p->statsAverage($response_time, 'responseTime');

    $p->{rp}->assemble_packet($self->{Secret}, $p,
			      ClearTextTunnelPassword => $self->{ClearTextTunnelPassword});
    $p->{rp}->sendReplyTo($p);
}

#####################################################################
# This fn is called by Handler when the reply to the request is ready to go back
# This works even for delayed or asynch replies.
sub replyFn
{
    my ($p, $self) = @_;
    $self->replyTo($p);
}

#####################################################################
# Reinitialize this module
sub reinitialize
{
    # This will DESTROY any objects left from a previous initialization
    %Radius::Client::clients = ();
}

#####################################################################
# Check whether user is still online at the given NAS, port 
# and session ID
# Returns 1 if they are still online, according to the NAS
# REVISIT: The NAS functions should really be in plug-in modules
# for future extensibility
sub isOnline
{
    my ($self, $name, $nas_id, $nas_port, $session_id, $framed_ip_address) = @_;

    return Radius::Nas::isOnline
	    ($self->{NasType}, $name, $nas_id, $nas_port, 
	     $session_id, $self, $framed_ip_address);
}

#####################################################################
# Process a Status-Server request by sending a reply with interesting 
# statistics in it.
sub handle_status_server
{
    my ($self, $p) = @_;

    return if $self->{StatusServer} eq 'off'; # Ignore Status-Server requests
    return unless $p->get_attr('Message-Authenticator'); # Required by RFC 5997

    $p->{rp} = new Radius::Radius $main::dictionary;
    $p->{rp}->set_code('Access-Accept');
    $p->{rp}->set_identifier($p->identifier);
    $p->{rp}->set_authenticator($p->authenticator);

    # Not off or minimal: the default is to send statistics.
    if ($self->{StatusServer} ne 'minimal')
    {
	# Probably should have a clever way so any module can
	# add to the list of statistics returned
	$p->{rp}->addAttrByNum($Radius::Radius::REPLY_MESSAGE,
			       "Radiator Radius server version $main::VERSION");
	$p->{rp}->addAttrByNum($Radius::Radius::REPLY_MESSAGE,
			       "Running on $main::hostname since " . scalar localtime($main::statistics{start_time}));
	$p->{rp}->addAttrByNum($Radius::Radius::REPLY_MESSAGE,
			       "$main::statistics{packet_rate} Requests in the last second");

	my ($key, $value);
	foreach $key (sort keys %Radius::ServerConfig::statistic_names)
	{
	    $value = 0 + $main::config->{Statistics}{$key};
	    $p->{rp}->addAttrByNum($Radius::Radius::REPLY_MESSAGE,
				   "$value $Radius::ServerConfig::statistic_names{$key}");
	}

	# show statistics for each client if requested
	my $client;
	foreach $client (@{$main::config->{Client}})
	{
	    if ($client->{StatusServerShowClientDetails})
	    {
		$p->{rp}->addAttrByNum($Radius::Radius::REPLY_MESSAGE,
				       "Client $client->{Name}:");
		foreach $key (sort keys %Radius::ServerConfig::statistic_names)
		{
		    $value = 0 + $client->{Statistics}{$key};
		    $p->{rp}->addAttrByNum($Radius::Radius::REPLY_MESSAGE,
					   " $value $Radius::ServerConfig::statistic_names{$key}");
		}
	    }
	}
    }

    # Make sure any Proxy-Sttae is honoured. This is normaly done in Handler
    $p->{rp}->delete_attr('Proxy-State'); # Remove bogus or cached state
    map {$p->{rp}->addAttrByNum($Radius::Radius::PROXY_STATE, $_)} $p->get_attr('Proxy-State');

    $self->replyTo($p);
}

1;
