# fidelio-hotspot-hook.pl
#
# AuthHook for handling prepaid hotspot sessions with Micros-Fidelio Opera and 
# a hotspot router such as Mikrotik
#
# By the time this hook runs, we kow:
# 1. The user wants to connect to the internet and is prepared to pay for another 24 hours 
# if they have used up the last lot
# 2. The username (room number) and password (reservation number) is correct

# The strategy here is:
# If there is no database entry for this room/guest/mac create one and charge the room
# If there is a  database entry for this room/guest/mac but it has expired, 
# extend it and charge the room
# If there is a  database entry for this room/guest/mac but it has not expired, accept, with
# a Session-Timeout of the remaining time from the record.
#
# CAUTION: requires Radiator 4.6 and latest patches as of 2010-03-29

# These variables define how much time the user gets for what cost
# Change them to suit your requirements and restart Radiator
# $cost is in cents, and $duration is in seconds
my $cost = 900;          # $9.00 in cents
my $duration = 24*60*60; # 24 hours in seconds

# Override Radius::AuthFIDELIO::handle_message to get control when a PA
# record arrives
# PA may look like this:Tue May  4 12:06:19 2010: DEBUG: Fidelio read: PA|ASOK|RN2603|P#0001|DA100504|TI120619|CTPosting successful. Interface transaction number/s - 660532|
my $original_handle_message = *Radius::AuthFIDELIO::handle_message;
*Radius::AuthFIDELIO::handle_message = *override_handle_message;
sub override_handle_message
{    
    my ($self, $type, $record) = @_;
    &$original_handle_message(@_);
    if ($type eq 'PA' && $record->{AS} eq 'OK')
    {
	# Posting was accepted, log it
	# Find the SQL clause, and use it to run queries
	my $sql = Radius::AuthGeneric::find('SQL');
	return unless $sql;

	my $postNumber = $record->{'P#'};
	my ($transactionNumber) = $record->{CT} =~ /Interface transaction number\/s - (\d+)/;
	$transactionNumber = 'NULL' unless defined $transactionNumber;
	my $q = "insert into postacks (roomNumber, postNumber, transactionNumber, received) values ('$record->{RN}', $postNumber, $transactionNumber, NOW())";
	$sql->do($q);
    }
}

sub {
    my ($p, $rp) = @_;

    # Find the SQL clause, and use it to run queries
    my $sql = Radius::AuthGeneric::find('SQL');
    return $main::IGNORE unless $sql;

    # Find the FIDELIO clause, and use it to run queries
    my $fidelio = Radius::AuthGeneric::find('Fidelio');
    return $main::IGNORE unless $fidelio;

    my $room = $p->getUserName();   # Room number
    my $gn = $p->decodedPassword(); # Guest number
    if ($gn eq '')
    {
	# CHAP? Recover the correct G# from the users User-Password
	# First find the right user record
	my ($user,  $checkResult, $reason, $authenticated, $found) = $fidelio->get_user($room, $p);
	if (!$user)
	{
	    &main::log($main::LOG_ERR, "Could not recover guest number for $room", $p);
	    return $main::IGNORE;
	}
	$gn = $user->get_check->get_attr('User-Password');
    }

    my $mac = $p->getAttrByNum($Radius::Radius::CALLING_STATION_ID);

    my $q = "select TIME_TO_SEC(TIMEDIFF(expiry, now())) from sessions where roomNumber='$room' and guestNumber='$gn' and macAddress='$mac'";
    my $sth = $sql->prepareAndExecute($q);
    return $main::IGNORE unless $sth;
    my ($expiry) = $sql->getOneRow($sth);

    if (!defined($expiry))
    {
	# Not previously logged in, bill them and create a new session
	# Insert into sessions table
	$q = "insert into sessions (roomNumber, guestNumber, macAddress, expiry) values ('$room', '$gn', '$mac', TIMESTAMP(now(), SEC_TO_TIME($duration)))";
	return $main::IGNORE unless $sql->do($q);

	# Send post to Fidelio
	return $main::IGNORE unless $fidelio->post($room, $gn, $cost, $duration, $p);

	# Insert into posts table
	$q = "insert into posts (roomNumber, guestNumber, macAddress, postNumber, posted, cost) values ('$room', '$gn', '$mac', '$fidelio->{posting_sequence}', NOW(), '$cost')";
	return $main::IGNORE unless $sql->do($q);

	# Set the Session-Timeout to the available duration
	$rp->addAttrByNum($Radius::Radius::SESSION_TIMEOUT, $duration);
    }
    elsif ($expiry > 0)
    {
	# Some prepaid time left, let them use it
	# Set the Session-Timeout to the remaining time
	$rp->addAttrByNum($Radius::Radius::SESSION_TIMEOUT, $expiry);
    }
    else
    {
	# Prepaid time has been exhausted
	# Buy some more
	# Update the sessions table
	$q = "update sessions set expiry=TIMESTAMP(now(), SEC_TO_TIME($duration)) where roomNumber='$room' and guestNumber='$gn' and macAddress='$mac'";
	return $main::IGNORE unless $sql->do($q);
	
	# Send post to Fidelio
	return $main::IGNORE unless $fidelio->post($room, $gn, $cost, $duration, $p);
	
	# Insert into posts table
	$q = "insert into posts (roomNumber, guestNumber, macAddress, posted, cost) values ('$room', '$gn', '$mac', NOW(), '$cost')";
	return $main::IGNORE unless $sql->do($q);
	
	# Set the Session-Timeout to the available duration
	$rp->addAttrByNum($Radius::Radius::SESSION_TIMEOUT, $duration);
    }

    return $main::ACCEPT;
}
