# AuthPORTLIMITCHECK.pm
#
# Object for checking port limits. It can be used to impose
# use limits on groups of users. The users can be grouped in any way 
# that can be expressed by an SQL select statment. Requires
# that a <SessionDatabase SQL> be present in your Radiator config.
#
# You need to use this in conjunction with another AuthBy that 
# actually does the authentication.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1999 Open System Consultants
# $Id: AuthPORTLIMITCHECK.pm,v 1.14 2007/12/18 21:23:50 mikem Exp $

package Radius::AuthPORTLIMITCHECK;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use strict;

# Just a name for useful printing
my $class = 'AuthPORTLIMITCHECK';


%Radius::AuthPORTLIMITCHECK::ConfigKeywords = 
('CountQuery'           => 
 ['string', 'This parameter specifies an SQL query that will be used to count the users currently online according to the SQL Session Database. ', 1],

 'LimitQuery'           => 
 ['string', 'This optional parameter can be used to override the fixed session limit defined by SessionLimit. LimitQuery is an SQL query that is expected to return an integer that will be used as the limit instead of SessionLimit. If LimitQuery fails to execute, or if it does not return any rows, then SessionLimit will be used as the limit instead.', 1],

 'SessionLimit'         => 
 ['string', 'This parameter specifies the absolute upper limit to the number of current logins permitted to this group of users. Defaults to 0. For example if SessionLimit is set to 10, then up to 10 concurrent sessions are permitted. If an 11th user attempts to log in through this AuthBy, they will be rejected. If LimitQuery is defined, and if it successfully gets an integer from the database, then the result of the query will be used instead of SessionLimit. SessionLimit may contain special formatting characters.', 1],

 'ClassForSessionLimit' => 
 ['stringarray', 'This optional parameter allows you to set up different charging bands for different levels of port occupancy in this group of users. You can have one or more ClassForSessionLimit lines. If the current level of port usage is below a ClassForSessionLimit, then the class name will be applied as a Class attribute to that session. Your NAS will then tag all accounting records for that session with the Class attribute. If your billing system records and uses the Class attribute in accounting records, then you could use this to charge differently for different levels of port occupancy.', 1],

 'IgnoreErrors'         => 
 ['flag', 'This optional parameter causes AuthBy PORTLIMITCHECK to IGNORE rather than REJECT if the SQL query or SQL connection fails. It can be useful for recovering from or working around SQL server failures.', 1],

 );

# RCS version number of this module
$Radius::AuthPORTLIMITCHECK::VERSION = '$Revision: 1.14 $';

#####################################################################
# Do per-instance default initialization
# This is called by Configurable during Configurable::new before
# the config file is parsed. Its a good place initialize instance 
# variables
# that might get overridden when the config file is parsed.
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{CountQuery} = "select COUNT(*) from RADONLINE where DNIS='%{Called-Station-Id}'";
}

#####################################################################
# Handle a request
# This function is called for each packet. $p points to a Radius::
# packet
# Accounting is ignored
# Access requests are validated by checking the user password
# only. No check items are checked, no reply
# items are returned
sub handle_request
{
    my ($self, $p, $dummy, $extra_checks) = @_;

    $self->log($main::LOG_DEBUG, "Handling with PORTLIMITCHECK: $self->{Identifier}", $p);
    return ($main::IGNORE, "Ignored due to IgnoreAuthentication")
	if $self->{IgnoreAuthentication} 
           && $p->code eq 'Access-Request';
    return ($main::IGNORE, "Ignored due to IgnoreAccounting")
	if $self->{IgnoreAccounting} 
           && $p->code eq 'Accounting-Request';


    if ($p->code eq 'Access-Request')
    {
	# Run the CountQuery to count the number of current sessions
	# in this group

	# We look in our parent Handler's Session Database
	my $sessdb = Radius::SessGeneric::find
	    ($p->{Handler}->{SessionDatabase});

	# Make sure its really an SQL SessionDatabase
	if (ref($sessdb) ne 'Radius::SessSQL')
	{
	    $self->log($main::LOG_ERR, 'PORTLIMITCHECK does not have an SQL SessionDatabase to use. Ignoring', $p);
	    return ($main::IGNORE);
	}

	# Generate and run the query to count the users in this group
	my $q = &Radius::Util::format_special($self->{CountQuery}, $p);
	my $sth = $sessdb->prepareAndExecute($q);
	return ($self->{IgnoreErrors} ? $main::IGNORE : $main::REJECT, 'PORTLIMITCHECK CountQuery failed')
	    unless $sth;

	my ($count) = $sessdb->getOneRow($sth);
	$self->log($main::LOG_DEBUG, "PORTLIMITCHECK got a current session count of $count", $p);

	# Default limit is SessionLimit
	my $sesslimit = &Radius::Util::format_special
	    ($self->{SessionLimit}, $p);

	# Maybe run a query to find the limit to check
	if (defined $self->{LimitQuery})
	{
	    my $q = &Radius::Util::format_special($self->{LimitQuery}, $p);
	    my $sth = $sessdb->prepareAndExecute($q);
	    return ($self->{IgnoreErrors} ? $main::IGNORE : $main::REJECT, 'PORTLIMITCHECK LimitQuery failed')
		unless $sth;

	    my ($sqllimit) = $sessdb->getOneRow($sth);
	    $self->log($main::LOG_DEBUG, "PORTLIMITCHECK got a limit of $sqllimit", $p);

	    # If we successfully got a value from the LimitQuery
	    # then use that as the limit, else use the hardwired
	    # SessionLimit
	    $sesslimit = $sqllimit if defined $sqllimit;
	}

	# Now we have the limit, test to see whether the
	# current count is too high
	return ($main::REJECT, "SessionLimit exceeded")
	    if $count >= $sesslimit;

	# If there are any ClassForSessionLimit, use them
	# to set the Class attribute in the reply
	my $limit;
	foreach $limit (@{$self->{ClassForSessionLimit}})
	{
	    my ($limitclass, $limitcount) = split (/\s*,\s*/, $limit, 2);
	    if ($count <= $limitcount) 
	    {
		$p->{rp}->addAttrByNum($Radius::Radius::CLASS, $limitclass);
		last;
	    }
	}
	return ($main::ACCEPT);
    }
    else
    {
	# Might be an Accounting-Request, or something else
	# Send a generic reply on our behalf
	return ($main::ACCEPT);
    }
}

#####################################################################
# This function may be called during operation to 
# reinitialize this module
# it is expected to reload any state, perhaps by rereading files, 
# reconnecting to a database or something like that.
# Its not actually called yet, but it as well to be prepared 
# for the day
# when it will be.
sub reinitialize
{
    my ($self) = @_;
}

1;
