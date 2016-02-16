# AuthFIDELIOHOTSPOT.pm
#
# Object for handling hotspot Authentication and prepaid billing by
# Micros Fidelio Opera Hotel Property Management System (PMS)
# Based on the original fidelio-hotspot-hook.pl, which is now obsolete.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2011 Open System Consultants
# $Id: AuthFIDELIOHOTSPOT.pm,v 1.4 2014/11/11 13:38:01 hvn Exp $

package Radius::AuthFIDELIOHOTSPOT;
@ISA = qw(Radius::AuthFIDELIO Radius::SqlDb);
use Radius::AuthFIDELIO;
use Radius::SqlDb;
use strict;

%Radius::AuthFIDELIOHOTSPOT::ConfigKeywords = 
(
 'BlockDuration'     => 
 ['integer', 'Specifies a number of seconds a prepaid block of time will last for, from the time it is first purchased. Defaults to 86400 (1 day).', 1],

 'BlockPrice'     => 
 ['integer', 'Specifies a number of cents a prepaid block of time costs. Defaults to 900 cents ($9.00).', 1],

 'ServiceAttribute'     =>
 ['string', 'Specifies RADIUS attribute that is used to detect different service rates', 1],

 'ServiceAttributePrefix'     =>
 ['string', 'Specifies the prefix in ServiceAttribute. You need to specify this if there is possibility to have multiple RADIUS attributes that are defined to be ServiceAttribute', 1],

 'ConfirmUpgradeOrRenew'     =>
 ['flag', 'Use Access-Reject to ask for confirmation of the upgrade or renewal charge. Disabled by default.', 1],

  'ConfirmationMessage'     =>
 ['string', 'Specifies the message that will ask the guest to confirm the upgrade or renwal charge', 1],

);

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->Radius::AuthFIDELIO::initialize;
    $self->Radius::SqlDb::initialize;

    $self->{BlockDuration} = 86400; # One day
    $self->{BlockPrice} = 900; # Cents
    $self->{ConfirmUpgradeOrRenew} = 0;
    $self->{ConfirmationMessage} = "You are going to upgrade or renew your plan, please login again to confirm the charge";
}

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->Radius::AuthFIDELIO::activate;
    $self->Radius::SqlDb::activate;
}

#####################################################################
# Overrides handle_message in AuthFIDELIO
sub handle_message
{
    my ($self, $type, $record) = @_;

    $self->SUPER::handle_message($type, $record);

    # Special local handling for PA, record to SQL database
    if ($type eq 'PA' && $record->{AS} eq 'OK')
    {
	# Posting was accepted, log it
	my $postNumber = $record->{'P#'};
	my ($transactionNumber) = $record->{CT} =~ /Interface transaction number\/s - (\d+)/;
	$transactionNumber = 'NULL' unless defined $transactionNumber;
	my $timestamp_now = Radius::Util::strftime('%Y-%m-%d %T', time());
	my $q = "insert into postacks (roomNumber, postNumber, transactionNumber, received) values ('$record->{RN}', $postNumber, $transactionNumber, '$timestamp_now')";
	$self->do($q);
    }
}

#####################################################################
# Overrides handle_request in AuthGENERIC
# Authenticates with AuthFIDELIO then checks for prepaid block time, billing to Fidelio if a new one is required.
sub handle_request
{
    my ($self, $p, $dummy, $extra_checks) = @_;

    # First authenticate using the standard AuthFIDELIO
    my ($result, $reason) = $self->Radius::AuthFIDELIO::handle_request($p, $dummy, $extra_checks);
    return ($result, $reason)
	unless $p->code eq 'Access-Request' && $result == $main::ACCEPT;

    # Auth is complete, now look for a prepaid session
    my $room = $p->getUserName();   # Room number
    my $gn = $p->decodedPassword(); # Guest number
    if ($gn eq '')
    {
	# CHAP? Recover the correct G# from the users User-Password
	# First find the right user record
	my ($user,  $checkResult, $reason, $authenticated, $found) = $self->Radius::AuthFIDELIO::get_user($room, $p);
	if (!$user)
	{
	    $self->log($main::LOG_ERR, "Could not recover guest number for $room", $p);
	    return $main::IGNORE;
	}
	$gn = $user->{fidelio_gn}; # AuthFIDELIO::find_user caches this for us
    }

    my $mac = $p->getAttrByNum($Radius::Radius::CALLING_STATION_ID);
    my $duration = $self->{BlockDuration};
    my $cost = $self->{BlockPrice};
    my ($serviceclass, $price, $replyattrs, $expiry, $confirmation_requested);
    my $timenow = time();
    my $timestamp_now = Radius::Util::strftime('%Y-%m-%d %T', $timenow);

    if (defined $self->{ServiceAttribute})
    {
	# The user is charged by services they buy. First get the
	# service they are ordering from the RADIUS request.
    	my @serviceclass= $p->get_attr($self->{ServiceAttribute});
	unless (@serviceclass)
	{
	    $self->log($main::LOG_ERR, "Access-Request doesn't contain ServiceAttribute: $self->{ServiceAttribute}");
	    return ($main::REJECT, "Error processing request");
	}

    	foreach my $sc (@serviceclass)
    	{
        	next unless $sc =~ /^$self->{ServiceAttributePrefix}(.*)$/;
        	$serviceclass = $1;
        	last;
    	}
	unless ($serviceclass)
	{
	    $self->log($main::LOG_ERR, "Unable to find ServiceAttribute: $self->{ServiceAttribute} that begins $self->{ServiceAttributePrefix}");
	    return ($main::REJECT, "Error processing request");
	}

	# Got the service. Now fetch the service information from the DB.
    	my $q = "select price, replyattributes from services where serviceclass=?";
    	my @bind_values = ($serviceclass);
    	my $sth = $self->prepareAndExecute($q, @bind_values);
    	return $main::IGNORE unless $sth;

    	($price, $replyattrs) = $self->getOneRow($sth);
	unless (defined $price)
	{
	    $self->log($main::LOG_ERR, "Unable to find service class $serviceclass from the services table");
	    return ($main::REJECT, "Error processing request");
	}

	# Now get information about their session state and current
	# service. Then check for changes that require charging.
	$q = "select expiry,replyattributes,price,sessions.serviceclass,confirmation_requested from sessions left join services on sessions.serviceclass=services.serviceclass where roomNumber='$room' and guestNumber='$gn' and macAddress='$mac'";
    	$sth = $self->prepareAndExecute($q);
    	return $main::IGNORE unless $sth;

	my ($current_replyattrs, $current_price, $current_serviceclass);
    	($expiry, $current_replyattrs, $current_price, $current_serviceclass, $confirmation_requested) = $self->getOneRow($sth);
        $expiry = Radius::Util::parseDate($expiry) - $timenow if defined $expiry;

    	if (defined $current_serviceclass && $serviceclass ne $current_serviceclass)
    	{
		if (defined $current_price && $current_price < $price)
		{
	   		$expiry = 0;
		}
		elsif ($expiry > 0)
		{
       			$replyattrs = $current_replyattrs;
		}
    	}

	$cost = $price; # Price might be 0 too.
    }
    else
    {
	my $q = "select expiry from sessions where roomNumber='$room' and guestNumber='$gn' and macAddress='$mac'";
	my $sth = $self->prepareAndExecute($q);
	return $main::IGNORE unless $sth;

	($expiry) = $self->getOneRow($sth);
	$expiry = Radius::Util::parseDate($expiry) - $timenow if defined $expiry;
    }

    if (!defined $expiry)
    {
	# Not previously logged in, bill them and create a new session

	# Insert into sessions table
	my $expirytime = $timenow + $duration;
	my $expirytimestamp = Radius::Util::strftime('%Y-%m-%d %T', $expirytime);
	my $q = $self->{ServiceAttribute} ?
	    "insert into sessions (roomNumber, guestNumber, macAddress, serviceclass, expiry) values ('$room', '$gn', '$mac', '$serviceclass', '$expirytimestamp')" :
	    "insert into sessions (roomNumber, guestNumber, macAddress, expiry) values ('$room', '$gn', '$mac', '$expirytimestamp')";
	return $main::IGNORE unless $self->do($q);

	# Send post to Fidelio
	return $main::IGNORE unless $self->post($room, $gn, $cost, $duration, $p);

	# Insert into posts table
	$q = "insert into posts (roomNumber, guestNumber, macAddress, postNumber, posted, cost) values ('$room', '$gn', '$mac', '$self->{posting_sequence}', '$timestamp_now', $cost)";
	return $main::IGNORE unless $self->do($q);

	# Set the Session-Timeout to the available duration
	$p->{rp}->addAttrByNum($Radius::Radius::SESSION_TIMEOUT, $duration);
    }
    elsif ($expiry > 0)
    {
	# Some prepaid time left, let them use it
	# Set the Session-Timeout to the remaining time
	$p->{rp}->addAttrByNum($Radius::Radius::SESSION_TIMEOUT, $expiry);
    }
    else
    {
	# Prepaid time has been exhausted or guest wants to change the service. Buy some more

	# If prepaid services are enabled, check if the guest needs to
	# confirm the purchase first.
	if ($self->{ServiceAttribute} && $self->{ConfirmUpgradeOrRenew} && $confirmation_requested == 0 && $price != 0)
	{
	    my $q = "update sessions set confirmation_requested=1 where roomNumber='$room' and guestNumber='$gn' and macAddress='$mac'";
	    return $main::IGNORE unless $self->do($q);
	    return ($main::REJECT, $self->{ConfirmationMessage});
	}

	# Update the sessions table
	my $expirytime = $timenow + $duration;
	my $expirytimestamp = Radius::Util::strftime('%Y-%m-%d %T', $expirytime);
	my $q = $self->{ServiceAttribute} ?
	    "update sessions set expiry='$expirytimestamp',serviceclass='$serviceclass',confirmation_requested=0 where roomNumber='$room' and guestNumber='$gn' and macAddress='$mac'" :
	    "update sessions set expiry='$expirytimestamp' where roomNumber='$room' and guestNumber='$gn' and macAddress='$mac'";
	return $main::IGNORE unless $self->do($q);

	# Send post to Fidelio
	return $main::IGNORE unless $self->post($room, $gn, $cost, $duration, $p);

	# Insert into posts table
	$q = "insert into posts (roomNumber, guestNumber, macAddress, postnumber, posted, cost) values ('$room', '$gn', '$mac', '$self->{posting_sequence}', '$timestamp_now', $cost)";
	return $main::IGNORE unless $self->do($q);

	# Set the Session-Timeout to the available duration
	$p->{rp}->addAttrByNum($Radius::Radius::SESSION_TIMEOUT, $duration);
    }

    # Add the service's reply attributes
    $p->{rp}->parse($replyattrs);
    return $main::ACCEPT;
}

1;
