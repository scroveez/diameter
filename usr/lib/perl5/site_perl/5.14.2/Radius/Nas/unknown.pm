# unknown.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) 1997-2002 Open System Consultants
# Author: Mike McCauley (mike@open.com.au)
# $Id: unknown.pm,v 1.2 2007/09/25 11:38:56 mikem Exp $

package Radius::Nas::unknown;
use strict;

# RCS version number of this module
$Radius::Nas::unknown::VERSION = '$Revision: 1.2 $';

#####################################################################
# Unknown NAS type, assume they are online
sub isOnline
{
    return 1;
}

#####################################################################
# Unknown NAS type, assume they are online
sub activeSessions
{
    return;
}

1;
