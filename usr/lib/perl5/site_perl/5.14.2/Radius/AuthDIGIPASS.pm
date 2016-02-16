# AuthDIGIPASS.pm
#
# Object for handling Authentication of DIGIPASS tokens (www.vasco.com)
# by SQL database. This is exactly equivalent to AuthBy SQLDIGIPASS,
# but for historical reasons, it was originally called AuthBy DIGIPASS,
# and thi module maintains backwards compatibility with that name.
# New installations are encouraged to use  AuthBy SQLDIGIPASS, and
# this module is officially deprecated.
#
# Requires Authen-Digipass 1.4 or better from Open System Consultants.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001-2006 Open System Consultants
# $Id: AuthDIGIPASS.pm,v 1.13 2007/09/25 11:31:13 mikem Exp $

package Radius::AuthDIGIPASS;
@ISA = qw(Radius::AuthSQLDIGIPASS);
use Radius::AuthSQLDIGIPASS;
use strict;

# RCS version number of this module
$Radius::AuthDIGIPASS::VERSION = '$Revision: 1.13 $';

1;
