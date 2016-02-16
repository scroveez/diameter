# TigrisNew.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) Open System Consultants
# $Id: TigrisNew.pm,v 1.3 2012/12/13 20:19:47 mikem Exp $

package Radius::Nas::TigrisNew;
use Radius::Nas::Tigris;
use strict;

# RCS version number of this module
$Radius::Nas::TigrisNew::VERSION = '$Revision: 1.3 $';

sub isOnline
{
    return &Radius::Nas::Tigris::isOnline(@_);
}

1;
