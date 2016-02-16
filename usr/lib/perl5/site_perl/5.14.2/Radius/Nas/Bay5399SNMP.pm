# Bay5399SNMP.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: Bay5399SNMP.pm,v 1.3 2012/12/13 20:19:47 mikem Exp $

package Radius::Nas::Bay5399SNMP;
use Radius::Nas::Bay;
use strict;

# RCS version number of this module
$Radius::Nas::Bay5399SNMP::VERSION = '$Revision: 1.3 $';

sub isOnline
{
    return &Radius::Nas::Bay::isOnline(@_);
}

1;
