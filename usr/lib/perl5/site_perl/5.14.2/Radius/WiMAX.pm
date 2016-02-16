# WiMAX.pm
#
# Utility routines required by WiMAX
# WiMAX_End-to-End_Network_Systems_Architecture_Stage_2-3_Release_1.1.0, 
#  NWG_R1.1.0-Stage-3.pdf
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2007 Open System Consultants
# $Id: WiMAX.pm,v 1.2 2007/12/18 21:23:50 mikem Exp $

package Radius::WiMAX;
use Digest::SHA;
use strict;

#####################################################################
# Generate MIP-RK from the EMSK
# As per 4.3.1.1 Key Generation in NWG_R1.1.0-Stage-3.pdf
# EMSK is 64 octets
# Result is 64 octets
sub mip_rk
{
    my ($emsk) = @_;

    my $keylabel = 'miprk@wimaxforum.org';
    my $usage_data = pack('a* x n', $keylabel, 0x0200);
    my $mip_rk1 = Digest::SHA::hmac_sha256($usage_data . "\001", $emsk);
    my $mip_rk2 = Digest::SHA::hmac_sha256($mip_rk1 . $usage_data . "\002", $emsk);
    return $mip_rk1 . $mip_rk2;
}

#####################################################################
# Generate MIP-SPI from MIP-RK
# As per 4.3.1.1 Key Generation in NWG_R1.1.0-Stage-3.pdf
# MIP-RK is 64 octets.
# Various SPIs can be calculated from MIP-SPI by simple addition:
# SPI-CMIP4 = MIP-SPI
# SPI-PMIP4 = MIP-SPI+1
# SPI-CMIP6 = MIP-SPI+2
# SPI-PMIP6 = MIP-SPI+3
# Result is an integer
sub mip_spi
{
    my ($mip_rk) = @_;

    my $mip_spi = unpack('N', Digest::SHA::hmac_sha256('SPI CMIP PMIP', $mip_rk));
    $mip_spi += 256 if $mip_spi < 256;

    # Loop until we find an SPI that does not collide with some other 
    # currently active SPI. Gymnastics to prevent integer overflow
    while (1)
    {
	if (check_spi_collision($mip_spi))
	{
	    $mip_spi = ($mip_spi + 4);
	}
	else
	{
	    if (0xffffffff - $mip_spi <= 2)
	    {
		$mip_spi = 258 - (0xffffffff - $mip_spi)
	    }
	    else
	    {
		last;
	    }
	}
    }
    return $mip_spi;
}

#####################################################################
# Check whether a proposed SPI collides with any currently active SPI
# ie whether the SPI is within 3 or less of any active SPI
# Return true if there is a collision
# REVISIT: needs application specific implementation?
# This sample implementation always return false
sub check_spi_collision
{
    my ($spi) = @_;
    return;
}

#####################################################################
# Generate FA-RK from MIP-RK, as per 4.3.5.1 in NWG_R1.1.0-Stage-3.pdf
# MIP-RK is 64 octets
# Result is 20 octets
sub fa_rk
{
    my ($mip_rk) = @_;

    return Digest::SHA::hmac_sha1('FA-RK', $mip_rk);
}

#####################################################################
# Generate MN-FA from FA-RK, as per 4.3.5.1 in NWG_R1.1.0-Stage-3.pdf
# FA-RK is 20 octets
# Result is 20 octets
sub mn_fa
{
    my ($fa_rk) = @_;

    return Digest::SHA::hmac_sha1('MN FA', $fa_rk);
}

#####################################################################
# Generate various mobility keys as per 4.3.5.1 in NWG_R1.1.0-Stage-3.pdf
# MIP-RK is 64 octets
# IP addresses are packed binary adresses, 4 octets for IPV4 and 16 octets for IPV6
# MN-NAI is the user NAI provided in the MIP registration request
# REsult is 20 octets
sub mn_ha_cmip4
{
    my ($mip_rk, $ha_ipv4, $mn_nai) = @_;

    return Digest::SHA::hmac_sha1('CMIP4 MN HA' . $ha_ipv4 . $mn_nai, $mip_rk);
}
sub mn_ha_pmip4
{
    my ($mip_rk, $ha_ipv4, $mn_nai) = @_;

    return Digest::SHA::hmac_sha1('PMIP4 MN HA' . $ha_ipv4 . $mn_nai, $mip_rk);
}
sub mn_ha_cmip6
{
    my ($mip_rk, $ha_ipv6, $mn_nai) = @_;

    return Digest::SHA::hmac_sha1('CMIP6 MN HA' . $ha_ipv6 . $mn_nai, $mip_rk);
}

#####################################################################
# Generate FA-HA as per 4.3.5.1 in NWG_R1.1.0-Stage-3.pdf
# HA-RK is 64 octets
# HA-IPV4 is 4 octets packed binary IP address
# FA-CoAv4
# SPI is an integer
# Returns 20 octets
sub fa_ha
{
    my ($ha_rk, $ha_ipv4, $fa_coav4, $spi) = @_;

    return Digest::SHA::hmac_sha1('FA-HA' . $ha_ipv4, $fa_coav4 . pack('N', $spi), $ha_rk);
}

1;



