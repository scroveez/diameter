# DiaUtil.pm
#
# Utility routines required by Radiator Diameter server, client and
# other modules
#
# Author: Heikki Vatiainen (hvn@open.com.au)
# Copyright (C) 2014 Open System Consultants
# $Id: DiaUtil.pm,v 1.4 2014/08/20 20:58:18 hvn Exp $

package Radius::DiaUtil;
use Radius::DiaDict;
use strict;
use warnings;

# RCS version number of this module
$Radius::DiaUtil::VERSION = '$Revision: 1.4 $';

# *ApplicationIds are resolved here. SupportedVendorIds are resolved
# separately since they are looked up from dictionaries which are
# loaded once *ApplicationIds are known.
#
# For VendorAuth- and VendorAcctApplicationIds, we now resolve the
# application names only. Vendor names will be resolved later when we
# have loaded all the dictionaries since the dictionaries may have
# vendor name definitions in them.
#
# Expected format is comma separated values. For Vendor*ApplicationIds
# each value is in vendor:appid format. Names and numbers are accepted.
#
#    $module->{AuthApplicationIds} = "4, Diameter-EAP";
#    $module->{AcctApplicationIds} = "Base Accounting";
#    $module->{VendorAuthApplicationIds} = "3GPP:3GPP-Rx, 3GPP:3GPP-Gx";
#    $module->{VendorAcctApplicationIds} = "3GPP:3GPP-Rx"; # Values just for example purposes
#
sub resolve_application_ids
{
    my ($module) = @_;

    foreach my $id (split(/\s*,\s*/, $module->{AuthApplicationIds}))
    {
	$id = defined $Radius::DiaMsg::appname_to_code{$id} ?
	    $Radius::DiaMsg::appname_to_code{$id} : $id;
	unless ($id =~ /^\d+$/)
	{
	    $module->log($main::LOG_ERR, "Could not resolve $id to numeric Diameter AuthApplicationId");
	    next;
	}
	push @{$module->{Ids}{AuthApplicationIds}}, $id;
    }

    foreach my $id (split(/\s*,\s*/, $module->{AcctApplicationIds}))
    {
	$id = defined $Radius::DiaMsg::appname_to_code{$id} ?
	    $Radius::DiaMsg::appname_to_code{$id} : $id;
	unless ($id =~ /^\d+$/)
	{
	    $module->log($main::LOG_ERR, "Could not resolve $id to numeric Diameter AcctApplicationId");
	    next;
	}
	push @{$module->{Ids}{AcctApplicationIds}}, $id;
    }

    # These two are arrays of references to [vendornum, appnum]
    @{$module->{Ids}{VendorAuthApplicationIds}} =
	resolve_vendor_application_ids($module, $module->{VendorAuthApplicationIds});

    @{$module->{Ids}{VendorAcctApplicationIds}} =
	resolve_vendor_application_ids($module, $module->{VendorAcctApplicationIds});

    return;
}

# Expected format is comma separated values. Names and numbers are
# accepted for SupportedVendorIds with DictVendors being special for
# all VENDORs over all currently loaded dictionaries.
#
# For VendorAuth and AcctApplicationIds, the applications have already
# been resolved. We now resolve the possible vendor names to numeric
# ids in case some of the vendors have been defined in the
# dictionaries that were recently loaded.
#
#    $module->{SupportedVendorIds} = "9048, 3GPP";
# or $module->{SupportedVendorIds} = "DictVendors";
#    $module->{VendorAuthApplicationIds} = "3GPP:3GPP-Rx, 3GPP:3GPP-Gx";
#    $module->{VendorAcctApplicationIds} = "3GPP:3GPP-Rx"; # Values just for example purposes
sub resolve_vendor_ids
{
    my ($module) = @_;

    my %vendor_ids; # Maps vendor names to numeric ids across all dicts

    # Find all VENDORs by looking in on all the dictionaries we have loaded
    foreach my $dictnum (keys %Radius::DiaDict::dicts)
    {
	my $dict = $Radius::DiaDict::dicts{$dictnum};
	foreach my $vendorname (keys %{$dict->{VendorName}})
	{
	    $vendor_ids{$vendorname} = $dict->{VendorName}->{$vendorname}[1];
	}
    }

    # Try to resolve the configured vendor names to numbers
    foreach my $id (split(/\s*,\s*/, $module->{SupportedVendorIds}))
    {
	if ($id eq 'DictVendors')
	{
	    push @{$module->{Ids}{SupportedVendorIds}}, values %vendor_ids;
	    next;
	}

	$id = defined $vendor_ids{$id} ? $vendor_ids{$id} : $id;
	unless ($id =~ /^\d+$/)
	{
	    $module->log($main::LOG_ERR, "Could not resolve $id to numeric Diameter vendor ID");
	    next;
	}
	push @{$module->{Ids}{SupportedVendorIds}}, $id;
    }

    # Earlier we resolved application ids in VendorAuth- and
    # VendorAcctApplicationIds. Now try to resolve the vendor parts.
    foreach my $auth_or_acct (qw(VendorAuthApplicationIds VendorAcctApplicationIds))
    {
	# Get the apps we are configured to support. We empty the
	# current list and rebuild it below with the resolved values.
	my @apps = @{$module->{Ids}{$auth_or_acct}};
	@{$module->{Ids}{$auth_or_acct}} = ();

	foreach my $a (@apps)
	{
	    my $vendor = $a->[0];
	    unless ($vendor =~ /^\d+$/)
	    {
		# Convert name to numeric id and let name defined in
		# dictionary to override values defined in DiaMsg
		my $vendor_name = $vendor;
		$vendor = $Radius::DiaMsg::vendorname_to_id{$vendor_name};
		$vendor = $vendor_ids{$vendor_name} if defined $vendor_ids{$vendor_name};
		unless ($vendor)
		{
		    $module->log($main::LOG_ERR, "Could not resolve vendor $a->[0] in $auth_or_acct to Diameter vendor ID");
		    next;  # Could not resolve the vendor, skip this app
		}
		$a->[0] = $vendor; # Replace name with numeric id
	    }
	    push @{$module->{Ids}{$auth_or_acct}}, $a; # Add to the list of supported apps
	}
    }

    return;
}

# Format is vendor:application_id where names and numbers the both are
# accepted. Returns an array of references to [vendornum, appnum].
#
sub resolve_vendor_application_ids
{
    my ($module, $vendor_appids) = @_;

    return unless $vendor_appids;

    my @Vendor_Application_Ids;
    foreach my $vendor_appid (split(/\s*,\s*/, $vendor_appids))
    {
	my ($vendor, $app) = split (/:/, $vendor_appid);
	$app = $Radius::DiaMsg::appname_to_code{$app} unless $app =~ /^\d+$/;
	unless ($vendor && $app)
	{
	    $module->log($main::LOG_ERR, "Could not resolve $vendor_appid to Diameter vendor and application IDs");
	    next;
	}

	push @Vendor_Application_Ids, [$vendor, $app];
    }

    return @Vendor_Application_Ids;
}

# Load the application specific dictionaries the module requires
#
sub load_dictionaries
{
    my ($module) = @_;

    # Get the appnums from the [vendornum, appnum] arrays
    my @vendor_auths = map {@{$_}[1]} @{$module->{Ids}{VendorAuthApplicationIds}};
    my @vendor_accts = map {@{$_}[1]} @{$module->{Ids}{VendorAcctApplicationIds}};
    
    foreach my $appnum (@{$module->{Ids}{AuthApplicationIds}},
			@{$module->{Ids}{AcctApplicationIds}},
			@vendor_auths,
			@vendor_accts)
    {
	next if $Radius::DiaDict::dicts{$appnum}; # Skip if already loaded

	# First load the base dictionary
	my $dict = Radius::DiaDict->new();
	$dict->activate();

	# Then add the application specific attributes
	my $app_dict = "Radius::DiaDict_$appnum";
	$module->log($main::LOG_DEBUG, "Loading Diameter dictionary $app_dict for application $appnum");
	unless (eval ("require Radius::DiaDict_$appnum"))
	{
	    $module->log($main::LOG_ERR, "Could not load Diameter dictionary $app_dict for application $appnum: $!");
	    return;
	}
	my $handle = $app_dict->get_handle();
	$dict->load_handle($handle, $app_dict);

	# Make it globally available
	$Radius::DiaDict::dicts{$appnum} = $dict;
    }

    return;
}

# Add attributes to an existing application dictionary. For example,
# 3GPP Gx interface uses IETF Diameter Credit-Control Application (RFC
# 4006) as its base and adds a number of attributes to it. This allows
# the caller to do such an expansion.
#
sub expand_dictionary
{
    my ($module, $appnum, $extra_dict) = @_;

    my $dict = $Radius::DiaDict::dicts{$appnum};
    my $class = "Radius::DiaDict_$extra_dict";
    $module->log($main::LOG_DEBUG, "Expanding Diameter dictionary $appnum with $class");
    unless (eval ("require $class"))
    {
	$module->log($main::LOG_ERR, "Could not expand Diameter dictionary $appnum with $class: $!");
	return;
    }
    my $handle = $class->get_handle();
    $dict->load_handle($handle, $class);

    return;
}

1;

