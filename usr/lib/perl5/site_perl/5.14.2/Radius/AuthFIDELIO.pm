# AuthFIDELIO.pm
#
# Object for handling Authentication and accounting by
# Micros Fidelio Opera Hotel Property Management System (PMS)
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthFIDELIO.pm,v 1.32 2014/09/03 19:45:36 hvn Exp $
package Radius::AuthFIDELIO;
@ISA = qw(Radius::AuthGeneric Radius::Fidelio);
use Radius::AuthGeneric;
use Radius::Fidelio;
use strict;

%Radius::AuthFIDELIO::ConfigKeywords = 
(
 'LinkRecords'        => 
 ['stringhash', 'List of Link Record specifications. These tell Opera what fields to be sent in each type of record. You should not need to change these unless you require additional guest fields for authentication', 1],

 'GuestNameField'     => 
 ['string', 'The name of the Opera guest field that will be used to match User-Name in authentication requests', 1],

 'GuestPasswordField'     => 
 ['string', 'The name of the Opera guest field that will be used to match Password in authentication requests', 1],

 'ComputeCostHook'    => 
 ['hook', 'Perl hook to compute the cost of an Accounting Stop. If this is defined, CentsPerSecond will not be used', 1],

 'UserPasswordHook'   => 
 ['hook', 'OPtional Perl hook that extract or generates the correct user password from the guest record. The default is to use the guest number (G#).', 1],

 'CentsPerSecond'     => 
 ['string', 'If ComputeCostHook is not defined, this parameter specifies to calculate the cost of an Accouning Stop by multiplying Acct-Session-Time by CentsPerSecond. CentsPerSec is a floating point number.', 1],

 'PostingRecordID'     => 
 ['string', 'Defines the type of transaction code to be used for sending Posting records to Opera. Defaults to PS but can be changed to PR. Use of PR would also require a suitable LinkRecords entry for the desired PR data.', 1],

 'PostingExtraFields'        => 
 ['stringhash', 'List of fields that are to be added to the standard fields sent to Opera in a Posting transaction. These are sent in addition to the standard ones of P#, TA, DU, PT, SO, CT and DD. Format is in the form: <fieldid>,<data>. Where <fieldid> is the 2 letter FieldID and <data> is the data to be sent in that field (special characters are permitted)', 1],

 'CheckoutGraceTime'     => 
 ['integer', 'Specifies a number of seconds after check-out to still allow a user to log in. Defaults to 0', 1],

 'KeepaliveTimeout'     => 
 ['integer', 'Specifies a number of seconds between keepalive LS messages.', 1],

 );

# RCS version number of this module
$Radius::AuthFIDELIO::VERSION = '$Revision: 1.32 $';

#####################################################################
sub activate
{
    my ($self) = @_;

    # In case this is a HUP:
    if ($self->isconnected())
    {
	$self->send_link_end();
	$self->fidelio_disconnect();
    }

    $self->Radius::AuthGeneric::activate;
    $self->Radius::Fidelio::activate;

    $self->{UseChecksums} = $self->{Protocol} eq 'serial' ? 1 : 0
	unless defined $self->{UseChecksums};
    $self->stream_connect();
}

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->Radius::AuthGeneric::initialize;
    $self->Radius::Fidelio::initialize;
    $self->{GuestNameField}     = 'RN'; # Room Number
    $self->{GuestPasswordField} = 'G#'; # Guest Number
    $self->{PostingRecordID}    = 'PS'; # Posting Simple
    %{$self->{LinkRecords}} = 
	(
	 'GI' => 'FLG#RNGNSF',
	 'GO' => 'FLG#RNSF',
	 'GC' => 'FLG#RNGN',
	 'PS' => 'FLP#RNPTTATIDUDADDSOCT',
	 'PA' => 'FLASRNP#DATICT',
	 );
    # By default, the user password is G#, the guest registration number
    $self->{'UserPasswordHook.compiled'} = sub {return $_[1]->{$self->{GuestPasswordField}}};
    $self->{AccountingStopsOnly} = 1;
    $self->{KeepaliveTimeout} = 60;
}

#####################################################################
# Handle a RADIUS request 
# This function is called for each packet. $p points to a Radius::
# packet
sub handle_request
{
    my ($self, $p, $dummy, $extra_checks) = @_;

    return ($main::IGNORE, "Ignored due to IgnoreAuthentication")
	if $self->{IgnoreAuthentication} 
           && $p->code eq 'Access-Request';
    return ($main::IGNORE, "Ignored due to IgnoreAccounting")
	if $self->{IgnoreAccounting} 
           && $p->code eq 'Accounting-Request';

    if ($p->code eq 'Accounting-Request')
    {
	my $status_type = $p->getAttrByNum($Radius::Radius::ACCT_STATUS_TYPE);
	# If we have a HandleAcctStatusTypes and this type is not mentioned
	# Acknowledge it, but dont do anything else with it
	return ($main::ACCEPT)
	    if defined $self->{HandleAcctStatusTypes}
	       && !exists $self->{HandleAcctStatusTypes}{$status_type};

	# REVISIT: remove support for AccountingStartsOnly
	# AccountingStopsOnly, and AccountingAlivesOnly in the future.
	# If AccountingStartsOnly is set, only process Starts
	# Acknowledge and drop anything else
	return ($main::ACCEPT)
	    if $self->{AccountingStartsOnly}
	       && $status_type ne 'Start';
	
	# If AccountingStopsOnly is set, only process Stops
	# Acknowledge and drop anything else
	return ($main::ACCEPT)
	    if $self->{AccountingStopsOnly}
	       && $status_type ne 'Stop';

	# If AccountingAlivesOnly is set, only process Alives
	# Acknowledge and drop anything else
	return ($main::ACCEPT)
	    if $self->{AccountingAlivesOnly}
	       && $status_type ne 'Alive';

	return $self->handle_accounting($p);

    }
    else
    {
	# Everything else is handled by AuthGeneric
	return $self->SUPER::handle_request($p, $p->{rp}, $extra_checks);
    }
}

#####################################################################
# Send the configured type of posting request to Fidelio
# $duration is raw seconds
sub post
{
    my ($self, $guestname, $reservation, $cost, $duration, $p) = @_;

    my $duration_formatted = sprintf('%02d%02d%02d',
			   $duration / 3600,
			   ($duration / 60) % 60,
			   $duration % 60);
    $self->{posting_sequence}++;
    # Advice from Michael Herzig never use a posting of 0000, wrap from 9999 to 0001
    $self->{posting_sequence} = 1 if $self->{posting_sequence} > 9999;

    my (%extra_fields, $key);
    foreach $key (keys %{$self->{PostingExtraFields}})
    {
	$extra_fields{$key} = &Radius::Util::format_special
	    (${$self->{PostingExtraFields}}{$key}, 
	     $p, $self, $guestname, $self->{posting_sequence}, $cost, $duration_formatted, $reservation);
    }
    # Ensure DD ony contains digits, else it can cause problems in Opera, apparently.
    my $dialed_digits = $p->get_attr('Called-Station-Id');
    $dialed_digits =~ s/[^\d]//g;
    return $self->send_message($self->{PostingRecordID}, 
			       $self->{GuestNameField} => $guestname,
			       'P#' => sprintf('%04d', $self->{posting_sequence}),
			       'TA' => $cost,
			       'DU' => $duration_formatted,
			       'PT' => 'C', # Posting type Direct Charge
			       'SO' => 'I', # Sales Outlet, internet
			       'CT' => 'Internet connection', # clear text
			       'DD' => $dialed_digits,
			       %extra_fields
	);
    
}

#####################################################################
sub handle_accounting
{
    my ($self, $p) = @_;

    my $duration = $p->getAttrByNum($Radius::Radius::ACCT_SESSION_TIME);
    my $class =  $p->getAttrByNum($Radius::Radius::CLASS);
    my $cost = sprintf('%03d', $self->compute_cost($duration, $p));
    my $guestname = $p->getUserName();
    my $reservation;
    if ($class =~ /FIDELIO:(\d+):(\d+)/)
    {
	$guestname = $1;
	$reservation = $2;
    }

    # Send Posting Simple message with data from the end of the connection
    # Caution: is the RN enough key? what if they have checked out?
    return ($main::IGNORE, 'Fidelio did not received ACK for Accounting Post')
	unless $self->post($guestname, $reservation, $cost, $duration, $p);

    # REVISIT: should we accept now or later when the PA comes back?
    return ($main::ACCEPT);
}

#####################################################################
# If there is a hook, use that to compute the cost, else
# work it out based on cents per second
sub compute_cost
{
    my ($self, $duration, $p) = @_;

    if (defined $self->{ComputeCostHook})
    {
	return $self->runHook('ComputeCostHook', $p, $duration, \$p);
    }
    else
    {
	return $duration * $self->{CentsPerSecond};
    }
}

#####################################################################
# Look for the user in the local copy of the Fidelio guest database
# Use the UserPasswordHook to find the correct user password
# as the password field
sub findUser
{
    my ($self, $look_for, $p, $rp, $orig_user_name, $defaultNumber) = @_;

    
    $self->log($main::LOG_DEBUG, "AuthFIDELIO looks for guest $defaultNumber in room $orig_user_name", $p);
    
    # Bomb out unless we have a valid connection to Fidelio
    return (undef, 1) unless $self->isconnected();

    # This ugliness is intended to let AuthGeneric::get_user try for multiple guests in the same room. 
    my $room = $orig_user_name;
    my @guests_in_room = keys %{$self->{guests}->{$room}};

    # Maybe remove guests with expired grace times
    if (defined $self->{CheckoutGraceTime} && $defaultNumber == 0)
    {
	foreach (keys %{$self->{guests}->{$room}})
	{
	    my $g = $self->{guests}->{$room}{$_};
	    if (defined $g->{graceValidUntil} && $g->{graceValidUntil} < time)
	    {
	        $self->log($main::LOG_DEBUG, "Guest $defaultNumber in room $room is out of grace period");
		delete $self->{guests}->{$room}{$_};
	    }
	}
    }

    my $gn = $guests_in_room[$defaultNumber];
    my $guest = $self->{guests}->{$room}{$gn};
    
    my $user;
    if ($guest)
    {
	my $graceTimeLeft;
	if (defined $self->{CheckoutGraceTime} && defined $guest->{graceValidUntil}) 
	{
	    # If the guest has checked out, verify that he is still
	    # within the grace time
	    if ($guest->{graceValidUntil} > time) 
	    {
	        # still within grace period
	        $graceTimeLeft = $guest->{graceValidUntil} - time;
	        $self->log($main::LOG_DEBUG, "Guest $defaultNumber in room $room is in grace period ($graceTimeLeft seconds left)");
	    } 
	}

	$user = new Radius::User $room;
	# Use UserPasswordHook to get the correct user name
	$user->get_check->add_attr
	    (defined $self->{EncryptedPassword} ? 
	 'Encrypted-Password' : 'User-Password', 
	     $self->runHook('UserPasswordHook', $p, $self, $guest));
	$user->get_reply->add_attr('Session-Timeout', $graceTimeLeft)
	    if $graceTimeLeft;
	$user->get_reply->add_attr('Class', "FIDELIO:$room:$gn");
	$user->{fidelio_gn} = $gn; # Callers may need this
    }
    return $user;
}

#####################################################################
# Override Radius::Fidelio::handle_message so we can get control for each message received
# from the Fidelio PMS
# $record is a pointer to a hash containing decoded data in the incoming message
sub handle_message
{
    my ($self, $type, $record) = @_;

    if ($type eq 'LS')
    {
	# Ignore closely repeated LSs, which can happen if both sides start at the same time
	my $time = time;
	if ($self->{last_ls_response} < ($time - 3))
	{
	    # Link Start, send link description, LinkRecords and Link Alive
	    $self->send_link_description();
	    foreach (keys %{$self->{LinkRecords}})
	    {
		$self->send_raw(join($self->{FieldSeparator}, 'LR', "RI$_", $self->{LinkRecords}{$_}) . $self->{FieldSeparator});
	    }
	    $self->send_link_alive();
	    $self->{need_database_update} = 1;
	    $self->{last_ls_response} = $time;
	}
    }
    elsif ($type eq 'LA')
    {
	# Link Alive reply from server
	$self->send_resync_request()
	    if $self->{need_database_update};
    }
    elsif ($type eq 'DE')
    {
	# Database resync end
	$self->{need_database_update} = 0;
	$self->log($main::LOG_WARNING, "Fidelio received no records from server during database resync. Check the server configuration")
	    if keys %{$self->{guests}} == 0;
    }
    elsif ($type eq 'LE')
    {
	# Link end disconnect
	$self->fidelio_disconnect();
    }
    elsif ($type eq 'DS')
    {
	# Database resync start, clear the existing database
	%{$self->{guests}} = ();
    }
    elsif ($type eq 'GC')
    {
	# Guest data change, save the new guest data
	$self->{guests}->{$record->{$self->{GuestNameField}}}{$record->{$self->{GuestPasswordField}}} = $record;
    }
    elsif ($type eq 'GI')
    {
	# Guest checkin, save the guest data
	$self->{guests}->{$record->{$self->{GuestNameField}}}{$record->{$self->{GuestPasswordField}}} = $record;
    }
    elsif ($type eq 'GO')
    {
	# Guest checkout
	my $rn = $record->{$self->{GuestNameField}};
	my $gn = $record->{$self->{GuestPasswordField}};
	if (defined $self->{CheckoutGraceTime} && defined $self->{guests}->{$rn}{$gn}) 
	{
	    if (!defined $self->{guests}->{$rn}{$gn}->{graceValidUntil}) 
	    {
	    	$self->{guests}->{$rn}{$gn}->{graceValidUntil} = time + $self->{CheckoutGraceTime};
	    }
	} 
	else 
	{
	    # No grace time required, so simply delete the guest
	    delete $self->{guests}->{$rn}{$gn};
	}
    }
    elsif ($type eq 'PA')
    {
	# Posting accepted. Check that it succeeded
	if ($record->{AS} ne 'OK')
	{
	    $self->log($main::LOG_WARNING, "Fidelio failed to process posting $record->{'P#'} $record->{AS} $record->{CT}");
	}
    }
}

#####################################################################
# Callback after link is started or restarted
sub link_started
{
    my ($self) = @_;

    $self->{need_database_update} = 0;

    &Radius::Select::remove_timeout($self->{keepaliveTimeoutHandle})
	if ($self->{keepaliveTimeoutHandle});

    $self->{keepaliveTimeoutHandle}= &Radius::Select::add_timeout(time + $self->{KeepaliveTimeout}, \&keepalive_timeout, $self);
}

#####################################################################
# We also send LA as a keepalive. It wont be sent unless we are actually connected
sub keepalive_timeout
{
    my ($handle, $self) = @_;

    $self->send_link_alive();
    $self->{keepaliveTimeoutHandle} = &Radius::Select::add_timeout(time + $self->{KeepaliveTimeout}, \&keepalive_timeout, $self);
}

1;

