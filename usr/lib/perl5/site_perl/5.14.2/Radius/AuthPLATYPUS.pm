# AuthPLATYPUS.pm
#
# Object for handling Authentication and accounting from Platypus
# From Boardtown (http://www.boardtown.com)
# This is a subclass of SQL that can also get radius attributes
# from the platypus "customer" table, and also inserts Accounting Stops
# into the Platypus "radiusdat" table
#
# We override the findUser function so that it 
# extracts the password and some check items from "customer".
# We override the handleRequest so that onle accounting Stops are 
# inserted
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthPLATYPUS.pm,v 1.24 2007/09/25 11:31:13 mikem Exp $

package Radius::AuthPLATYPUS;
@ISA = qw(Radius::AuthSQL);
use Radius::AuthSQL;
use strict;

# RCS version number of this module
$Radius::AuthPLATYPUS::VERSION = '$Revision: 1.24 $';

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
    $self->{AccountingTable} = 'radiusdat';
    $self->{BasicSelect} = 'select password, active, timeleft, blockuser, guarantor 
             %0 from customer where username=%1';
    $self->{AuthSelect} = ' ';
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
	# Allow a way to prevent accounting logs happening at all
	return return ($main::ACCEPT)
	    if $self->{AccountingTable} eq '';

	# We insert stops only
	if ($p->getAttrByNum($Radius::Radius::ACCT_STATUS_TYPE) eq 'Stop')
	{
	    my ($username, $callstart, $callend, $sessid);

	    # (Re)-connect to the database if necessary, 
	    # No reply will be sent to the original requester if we 
	    # fail to connect
	    return $main::IGNORE
		if !$self->reconnect;

	    # Construct a query and insert it into radiusdat
	    $username = $p->getAttrByNum($Radius::Radius::USER_NAME);
	    my $timestamp = $p->get_attr('Timestamp');
	    $callend = $self->formatDate($timestamp);
	    $callstart = $self->formatDate
		($timestamp - $p->getAttrByNum($Radius::Radius::ACCT_SESSION_TIME));
	    $sessid = $p->getAttrByNum($Radius::Radius::ACCT_SESSION_ID);

	    
	    # If AcctColumnDef is set, insert additional data in
	    # our insert statement
	    my ($extracols, $extravals) = $self->getExtraCols($p);
	    if (length $extracols)
	    {
		$extracols = ", $extracols";
		$extravals = ", $extravals";
	    }

	    # Here is the insertion into the Platypus accounting table
	    my $q = "insert into $self->{AccountingTable} 
            (username, callstart, callend, sessid $extracols) 
            values ('$username', '$callstart', '$callend', 
                    '$sessid' $extravals)";
	    $self->do($q);

	    # We also need to update the "Last Radius" date, so
	    # Platypus knows where we are up to.
	    $q = "update appdata set date='$callend' 
                  where name='Last Radius'";
	    $self->do($q);

	    # Dont need to commit: AutoCommit is on
	    return ($main::ACCEPT);
	}
	else
	{
	    return ($main::ACCEPT);
	}
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
# This is tailored exactly to Platypus's user database
sub findUser
{
    my ($self, $name, $p) = @_;

    # (Re)-connect to the database if necessary, 
    return (undef, 1) unless $self->reconnect;

    my $q = &Radius::Util::format_special
	($self->{BasicSelect}, $p, undef, 
	 $self->{AuthSelect}, $self->quote($name));
	
    my $sth = $self->prepareAndExecute($q);
    return undef unless $sth;

    my $user;
    my ($password, $active, $timeleft, $blockuser, 
	$guarantor, @extras);
    if (($password, $active, $timeleft, $blockuser, 
	 $guarantor, @extras) 
	= $self->getOneRow($sth))
    {
#	print "its $password, $active, $timeleft, $blockuser, $guarantor, @extras\n";
	if ($active ne 'Y')
	{
	    $self->log($main::LOG_DEBUG, "User $name is deactivated", $p);
	    return undef;
	}
	if ($blockuser eq 'G')
	{
	    # They gave a guarantor, so get the guarantor's
	    # time left and blockuser
	    $q = "select timeleft, blockuser 
                  from customer where id=$guarantor";
	    $sth = $self->prepareAndExecute($q);
	    ($timeleft, $blockuser) = $self->getOneRow($sth);
	}
	if ($blockuser eq 'Y' && $timeleft <= 0)
	{
	    # Apply blockuser time
	    $self->log($main::LOG_DEBUG, "User $name has no time left", $p);
	    return undef;
	}
	$user = new Radius::User $name;

	# Add a *-Password check item unless the correct password
	# was NULL in the database, This means that if 
	# the password column for a user is NULL,
	# then any password is accepted for that user.
	if (defined $password)
	{
	    if (defined $self->{EncryptedPassword})
	    {
		$user->get_check->add_attr('Encrypted-Password',
					   $password);
	    }
	    else
	    {
		$user->get_check->add_attr('User-Password',
					   $password);
	    }
	}

	# If the config has defined how to handle the columns
	# in the AuthSelect statement with AuthColumnDef, use
	# that to extract check and reply items from @extras	
	$self->getAuthColumns($user, $p, @extras)
	    if defined $self->{AuthColumnDef};

	if ($timeleft > 0 && $blockuser eq 'Y')
	{
	    $user->get_reply->add_attr('Session-Timeout', $timeleft * 60);
	}
    }
    return $user;
}

1;
