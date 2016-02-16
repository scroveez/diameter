# RuntimeChecks.pm
#
# A package for runtime checks to run during radiusd startup and
# optionally from Hooks and other code.
#
# Author: Heikki Vatiainen (hvn@open.com.au)
# Copyright (C) 2014 Open System Consultants
# $Id: RuntimeChecks.pm,v 1.2 2014/04/16 10:46:24 hvn Exp $

package Radius::RuntimeChecks;

use strict;
use warnings;

# RCS version number of this module
$Radius::RuntimeChecks::VERSION = '$Revision: 1.2 $';

sub do_startup_checks
{

    check_digest_md4() unless is_disabled('Digest::MD4');
    check_heartbleed() unless is_disabled('CVE-2014-0160');

    return;
}

# Returns 1 when the named runtime check is disabled. This lets any
# new, misspelled and unknown checks to remain active until they are
# disabled.
sub is_disabled
{
    my ($check) = @_;

    my @disabled_checks = split(/\s*,\s*/, Radius::Util::format_special($main::config->{DisabledRuntimeChecks}));

    return 1 if grep { $_ eq $check } @disabled_checks;
    return 0;
}

# Digest::MD4 is needed so often that it is a good idea to always to
# have it installed.
sub check_digest_md4
{
    return if eval {require Digest::MD4;};

    main::log($main::LOG_WARNING, 'Startup check could not load Digest::MD4. See Radiator reference manual for DisabledRuntimeChecks parameter');
    return;
}

# Check for CVE-2014-0160, the OpenSSL Heartbleed vulnerability.
sub check_heartbleed
{
    # We check for Heartbleed only when Net::SSLeay is present
    return unless eval {require Net::SSLeay;};

    my ($ver_number, $ver_string);
    eval
    {
	$ver_number = Net::SSLeay::SSLeay();
	$ver_string = Net::SSLeay::SSLeay_version();
    };

    unless ($ver_number)
    {
	main::log($main::LOG_WARNING, 'Startup check could not determine OpenSSL version while checking for the Heartbleed (CVE-2014-0160) vulnerability. See Radiator reference manual for DisabledRuntimeChecks parameter');

	return; # Can not tell if affected
    }

    if ($ver_number >= 0x1000100f && $ver_number <= 0x1000106f)
    {
	my $hex_ver_number = sprintf("0x%x", $ver_number);
	main::log($main::LOG_WARNING, "Startup check found OpenSSL version $hex_ver_number ($ver_string) while checking for the Heartbleed (CVE-2014-0160) vulnerability. This version may be vulnerable. See Radiator reference manual for DisabledRuntimeChecks parameter");

	return; # Can not tell if affected
    }

    # The OpenSSL version seems not to be affected.
    return;
}

1;
