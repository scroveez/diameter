# UtilSocket6.pm
#
# Utility routines that use Socket6.pm required by Radiator. These
# routines used to be in Util.pm before they were replaced routines
# which use Perl core Socket for IPv6 support.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2013 Open System Consultants
#
#
# $Id: UtilSocket6.pm,v 1.2 2014/01/31 21:34:46 hvn Exp $

package Radius::UtilSocket6;
use Socket ();
use strict;

#####################################################################
# Convert IPV4 or IPV6 addresses from presentation to packed network addresses
# IPV6 addresses are recognised by a leading 'ipv6:' (case insensitive)
# examples:
# 127.0.0.1    IPV4 localhost
# ipv6:::1     IPV6 localhost
sub inet_pton
{
    my ($a) = @_;

    if ($a =~ /ipv6:(.*)/i || $a =~ /(^[0-9a-fA-F:]+$)/ || $a =~ /(^::ffff:.*)/)
    {
	if (!eval{require Socket6;})
	{
	    &main::log($main::LOG_WARNING, 'Need Socket6 to handle IPV6 addresses in inet_pton');
	    return;
	}
	return Socket6::inet_pton(Socket6::AF_INET6(), $1)
    }
    else
    {
	return Socket::inet_aton($a);
    }
}

#####################################################################
# Convert IPV4 or IPV6 addresses from packed network to presentation addresses
# Silly lengths result in undef (Socket routines can crash otherwise)
sub inet_ntop
{
    my ($a) = @_;

    return unless length $a;
    if (length $a == 16)
    {
	# IPV6
	if (!eval{require Socket6;})
	{
	    &main::log($main::LOG_WARNING, 'Need Socket6 to handle IPV6 addresses in inet_ntop');
	    return;
	}
	my $p = Socket6::inet_ntop(Socket6::AF_INET6(), $a);
	# Short circuit for IPV4 addresses received over IPV6
	return $1 if ($p =~ /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
	return $p;
    }
    elsif (length $a == 4)
    {
	# IPV4
	return Socket::inet_ntoa($a); 
    }
    else
    {
	return;
    }
}

#####################################################################
# Unpack packed IPV4 or IPV6 addresses
sub unpack_sockaddr_in
{
    my ($a) = @_;

    if (length $a > 16)
    {
	# IPV6
	if (!eval{require Socket6;})
	{
	    &main::log($main::LOG_WARNING, 'Need Socket6 to handle IPV6 addresses in unpack_sockaddr_in');
	    return;
	}
	return Socket6::unpack_sockaddr_in6($a); 
    }
    elsif (length $a == 16)
    {
	return Socket::unpack_sockaddr_in($a);
    }
    else
    {
	return;
    }
}

#####################################################################
# $a is a packed IPV4 or V6 address
sub pack_sockaddr_in
{
    my ($p, $a) = @_;

    if (length $a > 4)
    {
	if (!eval{require Socket6;})
	{
	    &main::log($main::LOG_WARNING, 'Need Socket6 to handle IPV6 addresses in pack_sockaddr_in');
	    return;
	}
	return Socket6::pack_sockaddr_in6($p, $a);
    }
    else
    {
	return Socket::sockaddr_in($p, $a);
    }
}

#####################################################################
# Convert a host name or address into a packed portaddress and protocol family
# $name is an ASCII name or address, perhaps with a leading 'ipv6:'
# Return (packedportandaddress, protocolfamily)
sub pack_sockaddr_pton
{
    my ($port, $name, $sock_type) = @_;

    if ($name =~ /ipv6:(.*)/i || $name =~ /(^.*:.*$)/) # Covers also ^::ffff:.*
    {
	if (!eval{require Socket6;})
	{
	    &main::log($main::LOG_WARNING, 'Need Socket6 to handle IPV6 addresses in pack_sockaddr_pton');
	    return;
	}

	my ($cname, $aliases, $addrtype, $length, $address);
	# gethostbyname2 can die if not present on a given platform, eg Solaris
	eval {($cname, $aliases, $addrtype, $length, $address) 
		  = Socket6::gethostbyname2($1, Socket6::AF_INET6());};
	if ($@ eq '')
	{
	    # gethostbyname2 is present
	    return unless defined $address;
	    return (&Socket6::pack_sockaddr_in6($port, $address), &Socket6::PF_INET6());
	}

	# gethostbyname2 was not present, maybe Solaris, try getaddrinfo
	my ($sockettype, $proto);
	# Hint required by Solaris version of getaddrinfo:
	$sock_type = &Socket::SOCK_STREAM() unless defined $sock_type; 
	($addrtype, $sockettype, $proto, $address, $cname) = 
	    &Socket6::getaddrinfo($1, $port, &Socket6::PF_INET6(), $sock_type);
	# getaddrinfo packs the portaddress

	return ($address, &Socket6::PF_INET6()) 
	    if defined $address;
    }
    else
    {
	# IPV4
	my ($cname, $aliases, $addrtype, $length, $address) = gethostbyname($name);
	# Nothing in the DNS?, try to convert from presentation to network
	$address = Radius::Util::inet_pton($name)
	    unless defined $address;
	return (scalar &Socket::sockaddr_in($port, $address), &Socket::PF_INET)
	    if defined $address;
    }
    return;
}

#####################################################################
# Get info about an IPV4 or IPV6 name
# returns ($cname, $aliases, $addrtype, $length, @addrs)
sub gethostbyname
{
    my ($name) = @_;

    if ($name =~ /ipv6:(.*)/i || $name =~ /(^.*:.*$)/)
    {
	if (!eval{require Socket6;})
	{
	    &main::log($main::LOG_WARNING, 'Need Socket6 to handle IPV6 addresses in pack_sockaddr_gethostbyname');
	    return;
	}
	my @ret;
	# gethostbyname2 can die if not present on a given platform, eg Solaris
	eval {@ret = Socket6::gethostbyname2($1, Socket6::AF_INET6());};
	return @ret if $@ eq ''; # gethostbyname2 present

	# gethostbyname2 was not present, try getaddrinfo
	my ($family, $sockettype, $proto, $address, $cname) = &Socket6::getaddrinfo($1, undef, &Socket6::AF_INET6());
	return unless defined $address; # Unresolved
	$address = &unpack_sockaddr_in($address);
	return (defined $cname ? $cname : $name, '', &Socket6::AF_INET6(), length($address), $address);
    }

    # IPV4
    return gethostbyname($name);
}

#####################################################################
# $addr is a packed binary address
sub gethostbyaddr
{
    my ($addr) = @_;

    return gethostbyaddr($addr, Socket::AF_INET()) if length $addr == 4;
    if (!eval{require Socket6;})
    {
	&main::log($main::LOG_WARNING, 'Need Socket6 to handle IPV6 addresses in pack_sockaddr_gethostbyaddr');
	return;
    }
    return gethostbyaddr($addr, Socket6::AF_INET6());
}

1;
