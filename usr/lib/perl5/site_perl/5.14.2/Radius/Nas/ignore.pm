# ignore.pm
#
# Implement Radiator routines for communicating with a given type of NAS
#
# Copyright (C) 1997-2002 Open System Consultants
# Author: Mike McCauley (mike@open.com.au)
# $Id: ignore.pm,v 1.2 2007/09/25 11:38:56 mikem Exp $

package Radius::Nas::ignore;
use strict;

# RCS version number of this module
$Radius::Nas::ignore::VERSION = '$Revision: 1.2 $';

#####################################################################
# Always assume that the session database is right and there are
# no multiple logins
sub isOnline
{
    return 0;
}

#####################################################################
# Always assume that the session database is right and there are
# no multiple logins
sub activeSessions
{
    return 1; # Success but no users
}

1;
