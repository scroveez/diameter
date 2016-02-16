# AddressAllocatorSQL
#
# Implements IP address allocation from an SQL database.
# Called by AuthDYNADDRESS.pm
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2000 Open System Consultants
# $Id: AddressAllocatorSQL.pm,v 1.28 2014/11/19 21:03:27 hvn Exp $

package Radius::AddressAllocatorSQL;
@ISA = qw(Radius::AddressAllocatorGeneric Radius::SqlDb);
use Radius::AddressAllocatorGeneric;
use Radius::SqlDb;
use Radius::Util;
use Radius::Select;
use strict;

%Radius::AddressAllocatorSQL::ConfigKeywords = 
('DefaultLeasePeriod'     => 
 ['integer', 'If SessionTimeout is set by a previous AuthBy then that is used as the expiry time. Otherwise DefaultLeasePeriod (in seconds) is used.', 1],
 'LeaseReclaimInterval'   => 
 ['integer', 'How often we check the database for expired leases leases can expire if an acounting stop is lost or if the session goes longer than the lease we originally asked for. ', 1],
 'FindQuery'              => 
 ['string', 'SQL query used to find available addresses', 1],
 'FindQueryBindVar'       => 
 ['stringarray', 'Optional list of bind variables to use for FindQuery', 1],
 'AllocateQuery'          => 
 ['string', 'SQL query used to allocate an address', 1],
 'AllocateQueryBindVar'   => 
 ['stringarray', 'Optional list of bind variables to use for AllocateQuery', 1],
 'UpdateQuery'          => 
 ['string', 'SQL query to run when Accounting-Request with Acct-Status-Type of Start or Alive is received', 1],
 'UpdateQueryBindVar'   => 
 ['stringarray', 'Optional list of bind variables to use for UpdateQuery', 1],
 'DeallocateQuery'        => 
 ['string', 'SQL query used to deallocate a previously allocated address', 1],
 'DeallocateQueryBindVar' => 
 ['stringarray', 'Optional list of bind variables to use for DeallocateQuery', 1],
 'CheckPoolQuery'         => 
 ['string', 'SQL query used to check the status of an address', 1],
 'CheckPoolQueryBindVar'  => ['stringarray', 'Optional list of bind variables to use for CheckPoolQuery', 1],
 'AddAddressQuery'        => 
 ['string', 'SQL query used to add a new address to a pool', 1],
 'AddAddressQueryBindVar' => 
 ['stringarray', 'Optional list of bind variables to use for AddAddressQuery', 1],
 'ReclaimQuery'           => 
 ['string', 'SQL query used to reclaim expired leases', 1],
 'ReclaimQueryBindVar'    => 
 ['stringarray', 'Optional list of bind variables to use for ReclaimQuery', 1],
 'AddressPool'            => 
 ['objectlist', 'List of AddressPool objects that define the available address pools', 1],
 );

# RCS version number of this module
$Radius::AddressAllocatorSQL::VERSION = '$Revision: 1.28 $';

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    $self->Radius::AddressAllocatorGeneric::check_config();
    $self->Radius::SqlDb::check_config();
    return;
}

#####################################################################
# (Re)activate a Dynamic address allocator
sub activate
{
    my ($self) = @_;

    $self->Radius::AddressAllocatorGeneric::activate;
    $self->Radius::SqlDb::activate;

    # Make sure all the addresses in all the
    # pools are present in the database.
    foreach (@{$self->{AddressPool}})
    {
	$self->createPool($_);
    }

    $self->reclaimExpired();

    return $self;
}

#####################################################################
# Do per-instance default initialization
# This is called by Configurabel during Configurable::new before
# the config file is parsed. Its a good place initalze 
# instance variables
# that might get overridden when the config file is parsed.
sub initialize
{
    my ($self) = @_;

    $self->Radius::AddressAllocatorGeneric::initialize;
    $self->Radius::SqlDb::initialize;

    $self->{FindQuery} = "select TIME_STAMP, YIADDR, SUBNETMASK, DNSSERVER from RADPOOL 
where POOL='%0' and STATE=0 order by TIME_STAMP";
    $self->{AllocateQuery} = "update RADPOOL set STATE=1, 
TIME_STAMP=%0, 
EXPIRY=%1, USERNAME=%2 where YIADDR='%3' and STATE=0 and TIME_STAMP %4";

    $self->{CheckPoolQuery} = "select STATE from RADPOOL where YIADDR='%0'";

    $self->{AddAddressQuery} = "insert into RADPOOL (STATE, TIME_STAMP,
POOL, YIADDR, SUBNETMASK, DNSSERVER) values (0, %t, '%0', '%1',
'%2', '%3')";
    $self->{DeallocateQuery} = "update RADPOOL set STATE=0, 
TIME_STAMP=%t where YIADDR='%0'";
    $self->{ReclaimQuery} = "update RADPOOL set STATE=0 
where STATE!=0 and EXPIRY < %0";

    $self->{DefaultLeasePeriod}   = 86400; # 1 day
    $self->{LeaseReclaimInterval} = 86400; # 1 day

}

#####################################################################
# Override the object function in Configurable
sub object
{
    my ($self, $file, $keyword, @args) = @_;

    if ($keyword eq 'AddressPool')
    {
	my $pool = Radius::AddressPool->new($file, @args);
	$pool->check_config();
	$pool->activate() unless $pool->isCheckingConfiguration();
	return push(@{$self->{AddressPool}}, $pool);
    }
    return $self->SUPER::object($file, $keyword, @args)
}

#####################################################################
# Allocate an address for username with the given pool hint
# return a hash of interesting values for AuthBy DYNADDRESS
# to do stuff with
sub allocate
{
    my ($self, $caller, $username, $hint, $p) = @_;
    my %details;

    my $now = time;
    # Use the Session-Timeout if its available, else
    # the DefaultLeasePeriod
    my $lease_period = $p->{rp}->getAttrByNum($Radius::Radius::SESSION_TIMEOUT);
    $lease_period = $self->{DefaultLeasePeriod}
        unless defined $lease_period;
    my $expiry = $now + $lease_period;

    # Find the oldest free address in this pool
    my $q = &Radius::Util::format_special
	($self->{FindQuery}, $p, $self, $hint, $username, $expiry);
    my $iterations = 20; # Permit up to 20 collissions

    while ($iterations-- > 0)
    {
	my $sth = $self->prepareAndExecute
	    ($q, map { &Radius::Util::format_special($_, $p, $self, $hint, $username, $expiry)} 
	     @{$self->{FindQueryBindVar}});

	return ($main::IGNORE, 'Address pool database not available')
	    unless $sth;
	my $last_time_stamp;
	if (($last_time_stamp, $details{yiaddr}, $details{subnetmask}, $details{dnsserver})
	    = $self->getOneRow($sth))
	{
	    # Got a new address, update the state and timestamp
	    # and expiry time
	    
	    my $timestamp_compare = $last_time_stamp eq '' ?
		'is NULL' : "=$last_time_stamp";

	    if ($self->{AllocateQuery} ne '')
	    {
		my $allocquery = &Radius::Util::format_special
		    ($self->{AllocateQuery},
		     $p, $self, 
		     $now, $expiry, $self->quote($username), $details{yiaddr},
		     $timestamp_compare);
		
		# If this fails, then its prob because someone else
		# got the same address before us. Try again
		next unless $self->do($allocquery,
				      map { &Radius::Util::format_special
						($_, $p, $self, $now, $expiry, $username, $details{yiaddr},
						 $last_time_stamp)} 
				      @{$self->{AllocateQueryBindVar}}) == 1;
	    }
	    # Call the callers allocateDone() function to process
	    # the results
	    $caller->allocateDone($p, \%details);
	    # And tell the caller to accept immediately
	    return ($main::ACCEPT);
	}
	else
	{
	    # Hmmm, no spare addresses
	    return ($main::REJECT, "No available addresses");
	}
    }
    # Hmmmm, should not happen: too many other people trying 
    # to get addresses at the same time
    return ($main::REJECT, "Too many simultaneous address requests");
}

#####################################################################
# Confirm a previously allocated address is in use
sub confirm
{    
    my ($self, $caller, $address, $p) = @_;

    if ($self->{UpdateQuery})
    {
	my $expiry = time() + $self->{DefaultLeasePeriod};

	my $q = Radius::Util::format_special
	    ($self->{UpdateQuery}, $p, $self, $expiry, $address);
	$self->do($q,
		  map { Radius::Util::format_special($_, $p, $self, $expiry, $address)}
		  @{$self->{UpdateQueryBindVar}});
    }

    return ($main::ACCEPT);
}

#####################################################################
# Free a previously allocated address
sub deallocate
{    
    my ($self, $caller, $address, $p) = @_;

    if ($self->{DeallocateQuery})
    {
	my $q = &Radius::Util::format_special
	    ($self->{DeallocateQuery}, $p, $self, $address);
	$self->do($q,
		  map { &Radius::Util::format_special($_, $p, $self, $address)} 
		  @{$self->{DeallocateQueryBindVar}});
    }
    return ($main::ACCEPT);
}

#####################################################################
# Glue between the timeout callback and the reclaimExpired function
sub reclaimExpiredTimeout
{
    my ($handle, $self) = @_;

    $self->reclaimExpired();
}

#####################################################################
# Arrange for reclamation of expired leases every
# LeaseReclaimInterval seconds
sub reclaimExpired
{
    my ($self) = @_;

    my $now = time;
    if ($self->{ReclaimQuery})
    {
	&main::log($main::LOG_DEBUG, "Reclaiming expired leases");
	my $q = &Radius::Util::format_special
	    ($self->{ReclaimQuery}, undef, $self, $now);
	$self->do($q,
		  map { &Radius::Util::format_special($_, undef, $self, $now)} 
		  @{$self->{ReclaimQueryBindVar}});
    }
    # Arrange to be called again in LeaseReclaimInterval seconds
    &Radius::Select::add_timeout($now + $self->{LeaseReclaimInterval},
				 \&reclaimExpiredTimeout, $self);
}   

#####################################################################
# Ensure all the addresses in an address pool are present
# in the database
sub createPool
{
    my ($self, $pool) = @_;

    # For each range, and for each address in the range
    # make sure it exists in the database
    my ($range, $i4, $address, $state);
    foreach $range (@{$pool->{Range}})
    {
	if ($range =~ /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\s+(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/)
	{
	    # 2 addresses a.b.c.d e.f.g.h
	    my ($l1, $l2, $l3, $l4) = ($1, $2, $3, $4);
	    my ($u1, $u2, $u3, $u4) = ($5, $6, $7, $8);
	    
	    # Some error checking. We only permit the 
	    # last octet to vary
	    if (   $l1 != $u1 || $l1 > 255
		|| $l2 != $u2 || $l2 > 255
		|| $l3 != $u3 || $l3 > 255
		|| ($l4 + $pool->{Step} - 1) > $u4)
	    {
		&main::log($main::LOG_ERR, "Invalid Range $range. Ignored");
		next;
	    }
	    
	    my $lower = ($l1 << 24) + ($l2 << 16) + ($l3 << 8) + $l4;
	    my $upper = ($u1 << 24) + ($u2 << 16) + ($u3 << 8) + $u4;
	    $self->checkAddressRange($pool, $lower, $upper);
	}
	elsif ($range =~ /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})/)
	{
	    # CIDR block a.b.c.d/x  
	    
	    my ($l1, $l2, $l3, $l4, $bs) = ($1, $2, $3, $4, $5);
	    # Some error checking. We only permit the 
	    # last octet to vary
	    if ($l1 > 255 || $l2 > 255 || $l3 > 255 || $l4 > 255
		|| $bs > 32)
	    {
		&main::log($main::LOG_ERR, "Invalid CIDR block $range. Ignored");
		next;
	    }
	    my $lower = ($l1 << 24) + ($l2 << 16) + ($l3 << 8) + $l4;
	    my $mask = (1 << (32 - $bs)) - 1;
	    $lower &= ~$mask;
	    my $upper = $lower | $mask;
	    $self->checkAddressRange($pool, $lower, $upper);
	}
	else
	{
	    &main::log($main::LOG_WARNING, 
		       "Range $range, unknown Range format. Ignored");
	}
    }
}

#####################################################################
# Ensure that a single address exists, else create it
# Return 0 if it was created, else 0
# Address is in the form of an integer
sub checkAddress
{
    my ($self, $pool, $address) = @_;

    if ($self->{CheckPoolQuery} ne '')
    {
	# Convert integer address to a dotted quad
	my $dquad = sprintf("%d.%d.%d.%d", 
			    $address >> 24 & 0xff,
			    $address >> 16 & 0xff,
			    $address >> 8  & 0xff,
			    $address       & 0xff);
	
	# Check whether it already exists
	&main::log($main::LOG_DEBUG, "Checking address $dquad");
	my $q = &Radius::Util::format_special
	    ($self->{CheckPoolQuery}, undef, $self, $dquad);
	my $sth = $self->prepareAndExecute($q, map { &Radius::Util::format_special($_, undef, $self, $dquad)} 
					   @{$self->{CheckPoolQueryBindVar}});
	last unless $sth;
	if (!$self->getOneRow($sth))
	{
	    if ($self->{AddAddressQuery} ne '')
	    {
		# Not there, add it
		$q = &Radius::Util::format_special
		    ($self->{AddAddressQuery},
		     undef, $self,
		     $pool->{Name}, $dquad, $pool->{Subnetmask},
		     $pool->{DNSServer});
		return $self->do($q,
				 map { &Radius::Util::format_special
					   ($_, undef, $self, $pool->{Name}, $dquad, $pool->{Subnetmask},
					    $pool->{DNSServer})} 
				 @{$self->{AddAddressQueryBindVar}});
	    }
	    else
	    {
		&main::log($main::LOG_WARNING, "Address $dquad not present in pool '$pool->{Name}'. Unable to add because AddAddressQuery is not defined");
		
	    }
	}
    }
    return;
}
    
#####################################################################
# Check that all the addresses in the range $lower to $upper
# inclusive exist in the pool, else create them
sub checkAddressRange
{
    my ($self, $pool, $lower, $upper) = @_;

    my $i;
    for ($i = $lower; $i <= $upper; $i += $pool->{Step})
    {
	$self->checkAddress($pool, $i);
    }
}

#####################################################################
#####################################################################
#####################################################################
# This is where we define the companion class AddressPool
# which allows us to tell the database what our pools are
# each AddressPool will be checked out at startup time, to ensure
# it is in the database
package Radius::AddressPool;
@Radius::AddressPool::ISA = qw(Radius::Configurable);

%Radius::AddressPool::ConfigKeywords = 
('Range'      => 
 ['stringarray', 'List of address ranges. Each address range is either a starting and ending address (such as <b>192.1.1.1 192.1.1.50</b>), or a CIDR address specification (such as <b>192.1.2.0/31</b>', 0],
 'Subnetmask' => 
 ['string', 'The subnet mask to use for each address', 1],
 'DNSServer'  => 
 ['string', 'The DNS server to send', 1],
 'Step'       => 
 ['integer', 'The step size to use when creating new addresses', 1],
 );

#####################################################################
# Do per-instance configuration check
sub check_config
{
    my ($self) = @_;

    main::log($main::LOG_ERR, "No Ranges defined for AddressPool $self->{Name} in '$main::config_file'")
	unless defined $self->{Range};
    $self->SUPER::check_config();

    return;
}

#####################################################################
# (Re)activate a new AddressPool
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();
}

#####################################################################
# Do per-instance default initialization
# This is called by Configurabel during Configurable::new before
# the config file is parsed. Its a good place initalze 
# instance variables
# that might get overridden when the config file is parsed.
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{Subnetmask} = '255.255.255.255';
    $self->{Step} = 1; # Range address step size
}

1;
