# AuthSQL.pm
#
# Object for handling Authentication and accounting by SQL
#
# Enhanced to be more general and support more features.
#
# "AuthSQL compatibility" can be configured via
# AuthColumnDef 0,User-Password,check
# AuthColumnDef 1,GENERIC,check
# AuthColumnDef 2,GENERIC,reply
#
# Author: Mike McCauley (mikem@open.com.au)
# Modified by: Lars Marowsky-Brée (lmb@teuto.net)
#
# $Id: AuthSQLExt.pm,v 1.3 2007/12/18 21:23:50 mikem Exp $

package Radius::AuthSQLExt;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use DBI;
use strict;
use vars qw($VERSION @ISA);


#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();
    &main::log($main::LOG_WARNING, 
	       "No DBSource defined for $class at '$main::config_file' line $.")
	if @{$self->{DBSource}} == 0;
}

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
    # Empty arrays for database details
    $self->{DBSource}   = [];
    $self->{DBUsername} = [];
    $self->{DBAuth}     = [];

    $self->{AccountingTable} = 'ACCOUNTING';
    $self->{AuthSelect} = 'select PASSWORD from SUBSCRIBERS where USERNAME=\'%n\'';
}

#####################################################################
# Override the keyword function in Configurable
sub keyword
{
    my ($self, $file, $keyword, $value) = @_;

    if ($keyword eq 'DBSource')
    {
	push @{$self->{DBSource}}, $value;
    }
    elsif ($keyword eq 'DBUsername')
    {
	push @{$self->{DBUsername}}, $value;
    }
    elsif ($keyword eq 'DBAuth')
    {
	push @{$self->{DBAuth}}, $value;
    }
    elsif ($keyword eq 'AccountingTable')
    {
	$self->{AccountingTable} = $value;
    }
    elsif ($keyword eq 'AuthSelect')
    {
	$self->{AuthSelect} = $value;
    }
    elsif ($keyword eq 'EncryptedPassword')
    {
	$self->{EncryptedPassword} = $value;
    }
    elsif ($keyword eq 'AuthColumnDef')
    {
	# Probably should do some error checks here.
	my ($col, $attrib, $type) = split (/,\s*/, $value);
	
	$self->{AuthColumnDef}{$col} = [$attrib, $type];
    }
    elsif ($keyword eq 'AcctColumnDef')
    {
	# Courtesy Phil Freed ptf@cybertours.com
	# Probably should do some error checks here.
	my ($col, $attrib, $type) = split (/,\s*/, $value);
	$self->{AcctColumnDef}{$col} = [$attrib, $type];
    }
    else
    {
	return $self->SUPER::keyword($file, $keyword, $value);
    }
    return 1;
}

#####################################################################
# Handle a request
# This function is called for each packet. $p points to a Radius::
# packet
# REVISIT:should we fork before handling. There might be long timeouts?
sub handle_request
{
    my ($self, $p, $rp, $extra_checks) = @_;

    my $type = ref($self);
    # (Re)-connect to the database if necessary, 
    # No reply will be sent to the original requester if we 
    # fail to connect
    return $main::IGNORE
	if !$self->reconnect;

    my $user_name = $p->getUserName;
    if ($p->code eq 'Access-Request')
    {
	# Short circuit for no authentication
	return $main::IGNORE if $self->{AuthSelect} eq '';

	# The default behaviour in AuthGeneric is fine for this
	return $self->SUPER::handle_request($p, $rp, $extra_checks);
    }
    elsif ($p->code eq 'Accounting-Request')
    {
	# Short circuits for no accounting
	return $main::IGNORE if 
	    !defined $self->{AcctColumnDef} 
	|| $self->{AccountingTable} eq '';

	$p->add_attr('Timestamp', $p->{RecvTime} + int $p->get_attr('Acct-Delay-Time'));

	# Add each column defined by AcctColumnDef
	# Courtesy Phil Freed ptf@cybertours.com
	my ($cols, $vals, $columndefs, $col, $ref);
	while (($col, $ref) = each %{$self->{AcctColumnDef}})
	{
	    my ($attr, $type) = @$ref;
	    my $value = $p->get_attr($attr);
	    if (defined $cols)
	    {
		# Add separators
		$cols .= ", ";
		$vals .= ", ";
	    }
	    $cols .= $col;
	    if ($type eq 'integer')
	    {
		$vals .= defined $value ? "$value" : 'NULL';
	    }
	    # Could define other data types here?
	    else
	    {
		$vals .= defined $value ? "'$value'" : 'NULL';
	    }
	}
 

	my $q = "insert into $self->{AccountingTable} 
		($cols) 
		values 
		($vals)";
	# Perhaps could tack on some extra stuff to the query?

	&main::log($main::LOG_DEBUG, "Query is: $q\n");

	my $rc = $self->{dbh}->do($q)
	    || &main::log($main::LOG_ERR, 
			  "$type do failed for '$q': $DBI::errstr");
	
	# Dont need to commit: AutoCommit is on

	return $main::ACCEPT; # Send a generic reply on our behalf: ACK
    }
    else
    {
	return $main::ACCEPT; # Send a generic reply on our behalf
    }
}

#####################################################################
# This function may be called during operation to reinitialize 
# this module
# it is expected to reload any state, perhaps by rereading files, 
# reconnecting to a database or something like that.
# Its not actually called yet, but it as well to be 
# prepared for the day
# when it will be.
sub reinitialize
{
    my ($self) = @_;
}

#####################################################################
# reconnect
# Connect or reconnect to the database, and extract 
# any necessary table information
# Returns true if there is a viable database connection available
sub reconnect
{
    my ($self) = @_;

    if (!defined $self->{dbh} || !$self->{dbh}->ping)
    {
	$self->{dbh} = undef;

	# A new connection is required, try all the 
	# ones in the $self->{DBSource} in order til we 
	# find a good one
	my $i;
	for ($i = 0; $i < @{$self->{DBSource}}; $i++)
	{
	    $self->{dbh} = DBI->connect($self->{DBSource}[$i],
					$self->{DBUsername}[$i],
					$self->{DBAuth}[$i]);
	    
	    if (defined $self->{dbh})
	    {
		$self->{dbh}->{AutoCommit} = 1;
		return 1; # Database is available
	    }
	    &main::log($main::LOG_ERR, "Could not connect to SQL database with DBI->connect $self->{DBSource}[$i], $self->{DBUsername}[$i], $self->{DBAuth}[$i]: $DBI::errstr");
	}
	&main::log($main::LOG_ERR, "Could not connect to any SQL database. Request is ignored.");
	return 0;  # Database is not available
    }
    else
    {
	return 1; # Database is still up
    }
}

#####################################################################
# Find a the named user by looking in the database, and constructing
# User object if we found the named user
# $name is the user name we want
# $p is the current request we are handling
sub findUser
{
    my ($self, $name, $p) = @_;

    # (Re)-connect to the database if necessary, 
    return undef
	if !$self->reconnect;

    # We have to change User-Name in the request so we can 
    # use %n etc in AuthSelect
    my $original_user_name = $p->getUserName;
    $p->change_attr('User-Name', $name);

    my $q = &main::format_special($self->{AuthSelect}, $p);
    &main::log($main::LOG_DEBUG, "Query is: $q\n");
	
    my $sth = $self->{dbh}->prepare($q);
    if (!$sth)
    {
	&main::log($main::LOG_ERR, 
		   "Prepare failed for '$q': $DBI::errstr");
	$p->change_attr('User-Name', $original_user_name);
	return undef;
    }
    my $rc = $sth->execute;
    if (!$rc)
    {
	&main::log($main::LOG_ERR, 
		   "Execute failed for '$q': $DBI::errstr");
	$self->{dbh}->disconnect;
	$self->{dbh} = undef;
	$p->change_attr('User-Name', $original_user_name);
	return undef;
    }
    
    my $user;
    my @row;
    if (@row = $sth->fetchrow)
    {
	$sth->finish;
	
	$user = new Radius::User $name;

    my ($colnr);
    foreach $colnr (keys %{$self->{AuthColumnDef}}) {
	        my ($attrib,$type) = @{$self->{AuthColumnDef}{$colnr}};
			
			# A "NULL" entry in the database will never be added to the check items,
			# ie for an entry which is NULL, every attribute will match.
			# A "NULL" entry will also not be added to the reply items list.
			
			next unless defined($row[$colnr]);
			
			if ($attrib eq "GENERIC") {
			   if ($type eq "check") {
			     $user->get_check->parse($row[$colnr]);
			   } elsif ($type eq "reply") {
			     $user->get_reply->parse($row[$colnr]);
			   }
			} else {
			  if ($type eq "check") {
			     $user->get_check->add_attr($attrib,$row[$colnr]);
			  } elsif ($type eq "reply") {
			     $user->get_reply->add_attr($attrib,$row[$colnr]);
			  }
			}
	}
	
    }
    $p->change_attr('User-Name', $original_user_name);
    return $user;
}

1;

