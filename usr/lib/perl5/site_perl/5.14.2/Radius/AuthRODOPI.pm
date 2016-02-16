# AuthRODOPI.pm
#
# Object for handling Authentication and accounting from Rodopi
# (http://www.rodopi.com)
# This is a subclass of SQL that can also get radius attributes
# from Rodopis special attribute tables.
#
# We only need to override the findUser function so that it 
# extracts reply items from RadConfifgs and RadATConfigs
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthRODOPI.pm,v 1.17 2007/12/18 21:23:50 mikem Exp $

package Radius::AuthRODOPI;
@ISA = qw(Radius::AuthSQL);
use Radius::AuthSQL;
use strict;

%Radius::AuthRODOPI::ConfigKeywords = 
(
 'AcctSQLStatement'     => 
 ['string', 'This optional parameter defines the SQL query that will be used to insert accounting details into the Rodopi database. ', 1],

 'CiscoVoip'            => 
 ['flag', 'This optional parameter tells AuthBy RODOPI to handle Cisco VOIP requests using the VOIP procedures specified by VoipAuthSelect and VoipAcctSQLStatement parameters. Defaults to 1, meaning that Cisco VOIP requests will be handled. If this parameter is set to 0, Cisco VOP requests will be handled using the AuthSelect and AcctSQLStatement parameters.', 0],

 'VoipAuthSelect'       => 
 ['string', 'This optional parameter specifies the SQL query which will be used to authenticate VOIP Access-Requests. May contain special characters. If CiscoVoip is enabled, then any Access-Request containing a the "cisco-h323-conf-id" attribute will be authenticated with VoipAuthSelect.', 1],

 'VoipAcctSQLStatement' => 
 ['string', 'This optional parameter defines the SQL query that will be used to insert VOIP accounting details into the Rodopi database. May contain special characters. If CiscoVoip is enabled, then any Accounting-Request containing a the "cisco-h323-conf-id" attribute will be authenticated with VoipAcctSQLStatement. ', 1],

 );

# RCS version number of this module
$Radius::AuthRODOPI::VERSION = '$Revision: 1.17 $';

# Maps Rodopi atribute names to Cisco RADIUS attribute names (as per Radiator dictionary)
%Radius::AuthRODOPI::nameToCiscoAttr =
    (
     'IVR-In-AVPair'       => 'cisco-h323-ivr-in',
     'Credit-Amount'       => 'cisco-h323-credit-amount',
     'Credit-Time'         => 'cisco-h323-credit-time',
     'Return-Code'         => 'cisco-h323-return-code',
     'Prompt-ID'           => 'cisco-h323-prompt-id',
     'Time-Of-Day'         => 'cisco-h323-time-and-day',
     'Redirect-Number'     => 'cisco-h323-redirect-number',
     'Preferred-Language'  => 'cisco-h323-preferred-lang',
     'Redirect-IP-Address' => 'cisco-h323-redirect-ip-addr',
     'Billing-Model'       => 'cisco-h323-billing-model',
     'Currency-Type'       => 'cisco-h323-currency-type',
     );

#####################################################################
# Do per-instance default initialization
# This is called by Configurabel during Configurable::new before
# the config file is parsed. Its a good place initalze 
# instance variables
# that might get overridden when the config file is parsed.
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{AuthSelect} = 'exec Interface_VircomUsers %0';
    $self->{AcctSQLStatement} = "exec Interface_VircomDetails 
%0, '%1', %2, %3, %4, %5, %6, %7, %8, %9,
%10, %11, %12, %13, %14, %15, %16, %17, %18, %19,
%20";
    $self->{CiscoVoip} = 1; # Honour Cisco VOIP by calling special Rodopi SPs
    $self->{VoipAuthSelect} = 'exec Interface_VircomUsers2 %0, %1, %2, %3, %4, %5';
    $self->{VoipAcctSQLStatement} = "exec Interface_VircomDetails2 
%0, '%1', %2, %3, %4, %5, %6, %7, %8, %9,
%10, %11, %12, %13, %14, %15, %16, %17, %18, %19,
%20, %21, %22, %23, %24, %25, %26, %27, %28, %29, %30, %31, %32";
}

#####################################################################
# Handle a request
# This function is called for each packet. $p points to a Radius::
# packet
# We just do special handling for accounting, and pass auths
# to AuthSQL
sub handle_request
{
    my ($self, $p, $dummy, $extra_checks) = @_;

    my $type = ref($self);
    return ($main::IGNORE, "Ignored due to IgnoreAuthentication")
	if $self->{IgnoreAuthentication} 
           && $p->code eq 'Access-Request';
    return ($main::IGNORE, "Ignored due to IgnoreAccounting")
	if $self->{IgnoreAccounting} 
           && $p->code eq 'Accounting-Request';

    if ($p->code eq 'Accounting-Request')
    {
	# (Re)-connect to the database if necessary,
	# No reply will be sent to the original requester if we 
	# fail to connect
	return ($main::IGNORE, 'Database failure')
	    if !$self->reconnect;

	# We are calling a stored procedure intended for Vircom
	# Get a whole bunch of additional attributes for 
	# Interface_VircomDetails. Its convenient to name them by
	# their standard Radius attribute number
	my @args = (
	     $self->quote($p->getAttrByNum
			  ($Radius::Radius::ACCT_SESSION_ID)),
	     $self->formatDate($p->get_attr('Timestamp')),
	     $self->quote($p->getAttrByNum($Radius::Radius::USER_NAME)),
	     $self->quote($p->getAttrByNum($Radius::Radius::NAS_IP_ADDRESS)),
	     $self->getIntegerAttribute($p, $Radius::Radius::NAS_PORT),
	     $self->quote($p->getAttrByNum($Radius::Radius::SERVICE_TYPE)),
	     $self->quote($p->getAttrByNum($Radius::Radius::FRAMED_PROTOCOL)),
	     $self->quote($p->getAttrByNum($Radius::Radius::FRAMED_IP_ADDRESS)),
	     $self->quote($p->getAttrByNum($Radius::Radius::CALLING_STATION_ID)),
	     $self->quote($p->getAttrByNum($Radius::Radius::NAS_IDENTIFIER)),
	     $self->quote($p->getAttrByNum($Radius::Radius::ACCT_STATUS_TYPE)),
	     $self->getIntegerAttribute($p, $Radius::Radius::ACCT_DELAY_TIME),
	     $self->getIntegerAttribute($p, $Radius::Radius::ACCT_INPUT_OCTETS),
	     $self->getIntegerAttribute($p, $Radius::Radius::ACCT_OUTPUT_OCTETS),
	     $self->getIntegerAttribute($p, $Radius::Radius::ACCT_SESSION_TIME),
	     $self->getIntegerAttribute($p, $Radius::Radius::ACCT_INPUT_PACKETS),
	     $self->getIntegerAttribute($p, $Radius::Radius::ACCT_OUTPUT_PACKETS),
	     $self->quote($p->getAttrByNum($Radius::Radius::ACCT_TERMINATE_CAUSE)),
	     $self->quote($p->getAttrByNum($Radius::Radius::NAS_PORT_TYPE)),
	     $self->quote(int $p->getAttrByNum($Radius::Radius::CONNECT_INFO)),
	     $self->quote($p->getAttrByNum($Radius::Radius::CALLED_STATION_ID)));
	
	my $statement = $self->{AcctSQLStatement};
	my $connection_id = $p->get_attr('cisco-h323-conf-id');
	if ($self->{CiscoVoip}
	    && $p->getAttrByNum($Radius::Radius::NAS_PORT_TYPE) == 0
	    && defined $connection_id)
	{
	    # VOIP, add some more accounting attrs and call a different SP
	    push (@args,
		  $self->quote($p->get_attr('cisco-h323-gw-id')), # Gateway-Name
		  $self->quote($connection_id),                            # Connection-ID
		  $self->quote($p->get_attr('cisco-h323-call-origin')),    # Call-Direction
		  $self->quote($p->get_attr('cisco-h323-call-type')),    # Call-Type
		  $self->quote($p->get_attr('cisco-h323-setup-time')),    # Setup-Time
		  $self->quote($p->get_attr('cisco-h323-connect-time')),    # Connect-Time
		  $self->quote($p->get_attr('cisco-h323-disconnect-time')),    # Disconnect-Time
		  $self->quote($p->get_attr('cisco-h323-disconnect-cause')),    # Disconnect-Cause
		  $self->quote($p->get_attr('cisco-h323-voice-quality')),    # Voice-Quality
		  $self->quote($p->get_attr('cisco-h323-remote-address')),    # Gateway-ID
		  $self->quote($p->get_attr('cisco-h323-ivr-out')),    # IVR-Out-Avpair
		  $self->quote($p->get_attr('cisco-h323-call-treatment')));    # Call-Treatment

	    $statement = $self->{VoipAcctSQLStatement};
	}
	my $q = &Radius::Util::format_special
	    ($statement,
	     $p, undef, @args);
	my $sth = $self->do($q);
	
	return ($main::ACCEPT);
    }
    else
    {
	# Everything else is handled by AuthSQL
	return $self->SUPER::handle_request($p, $p->{rp}, $extra_checks);
    }

}

#####################################################################
# Find a the named user by looking in the database, and constructing
# User object if we found the named user
# This is tailored exactly to Rodopi's user database
sub findUser
{
    my ($self, $name, $p) = @_;

    # (Re)-connect to the database if necessary, 
    return (undef, 1) unless $self->reconnect;

    # We use a stored procedure intended for use by Vircom
    # It returns all the check and reply items for this user,
    # Including the password as check item Password
    my $q;
    my $connection_id = $p->get_attr('cisco-h323-conf-id');
    if ($self->{CiscoVoip}
	&& $p->getAttrByNum($Radius::Radius::NAS_PORT_TYPE) == 0
	&& defined $connection_id)
    {
	# VOIP
	$q = &Radius::Util::format_special($self->{VoipAuthSelect}, $p, undef, 
					   $self->quote($name),
					   $self->quote($p->getAttrByNum($Radius::Radius::CALLING_STATION_ID)),
					   $self->quote($p->getAttrByNum($Radius::Radius::CALLED_STATION_ID)),
					   $self->quote($p->getAttrByNum($Radius::Radius::NAS_IP_ADDRESS)),
					   $self->quote($connection_id),
					   $self->quote($p->getAttrByNum($Radius::Radius::SERVICE_TYPE)));
    }
    else
    {
	# Ordinary dialup etc
	$q = &Radius::Util::format_special($self->{AuthSelect}, $p, undef, $self->quote($name));
    }
    my $sth = $self->prepareAndExecute($q);
    return undef unless $sth;

    my $user;
    my ($attr_name, $attr_value, $check_item);
    while (($attr_name, $attr_value, $check_item)
	   = $sth->fetchrow())
    {
	# Interface_VirocomUSers2 can return a single -1 if no match
	return undef if $attr_name == -1;

	$user = new Radius::User $name if !$user;

	# Maybe map Rodopi standard attritbue names to cisco attr names
	$attr_name = $Radius::AuthRODOPI::nameToCiscoAttr{$attr_name} 
	    if defined $connection_id && defined $Radius::AuthRODOPI::nameToCiscoAttr{$attr_name};

#	print "got $attr_name, $attr_value, $check_item\n";
	if (   $attr_name eq 'cisco-h323-credit-amount'
	    || $attr_name eq 'cisco-h323-return-code')
	{
	    # Silly behaviour from Interface_VircomUsers2 incorrectly says some 
	    # return items are check items
	    $user->get_reply->add_attr($attr_name, $attr_value);
	}
	elsif ($check_item)
	{
	    $user->get_check->add_attr($attr_name, $attr_value);
	}
	else
	{
	    $user->get_reply->add_attr($attr_name, $attr_value);
	}
    }
    $sth->finish;
    return $user;
}

#####################################################################
# Retrieve an integer attribute for SQL. This is a bit faster than
# using DBI::quote
sub getIntegerAttribute
{
    my ($self, $p, $attr) = @_;

    my $value = $p->getAttrByNum($attr);
    return defined $value ? int $value : 'NULL';
}

1;
