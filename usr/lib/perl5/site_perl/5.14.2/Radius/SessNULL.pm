# SessNULL.pm
#
# Implement a dummy session database. For cases where a session
# database is not needed, using this dummy database method will
# reduce memory consumption and CPU overhead.
#

#
# Author: Daniel Senie, Amaranth Networks Inc. (dts@senie.com)
# Copyright (C) Open System Consultants
#

package Radius::SessNULL;
@ISA = qw(Radius::SessGeneric);
use Radius::SessGeneric;
use strict;

# RCS version number of this module
$Radius::SessNULL::VERSION = '$Revision: 1.5 $';

sub add
{
}

sub delete
{
}

sub clearNas
{
}

sub exceeded
{
    return 0;
}

1;
