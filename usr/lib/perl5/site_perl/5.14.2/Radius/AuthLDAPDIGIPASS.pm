# AuthLDAPDIGIPASS.pm
#
# Object for handling Authentication of DIGIPASS tokens (www.vasco.com)
# from an LDAP database
#
# Requires Authen-Digipass 1.6 or better from Open System Consultants.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001-2006 Open System Consultants
# $Id: AuthLDAPDIGIPASS.pm,v 1.8 2013/08/13 20:58:45 hvn Exp $

package Radius::AuthLDAPDIGIPASS;
@ISA = qw(Radius::AuthDIGIPASSGeneric Radius::Ldap);
use Radius::AuthDIGIPASSGeneric;
use Radius::Ldap;
use strict;

%Radius::AuthLDAPDIGIPASS::ConfigKeywords = 
('UsernameAttr'  => 
 ['string', 'This optional parameter gives the name of the LDAP attribute that contains the username of the user assigned to that token. It is used as %0 in the SearchFilter. Defaults to oscDigipassTokenAssignedTo.', 1],

 'TokenDataAttr' => 
 ['string', 'This parameter specifies the name of the LDAP attribute that contains the Digipass token data, which is used to authenticate Digipass token logins. Defaults to oscDigipassTokenData.', 1],

 'MaxRecords'    => 
 ['integer', 'This optional parameter specifies the maximum number of Digipass tokens returned by the SearchFilter that will be examined. Defaults to 1.', 1],

 );

# RCS version number of this module
$Radius::AuthLDAPDIGIPASS::VERSION = '$Revision: 1.8 $';

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    $self->Radius::AuthDIGIPASSGeneric::check_config();
    $self->Radius::Ldap::check_config();
    return;
}

#####################################################################
sub activate
{
    my ($self) = @_;

    # Multiple inheritance:
    $self->Radius::AuthDIGIPASSGeneric::activate();
    $self->Radius::Ldap::activate();
}

#####################################################################
# Do per-instance default initialization
# This is called by Configurable during Configurable::new before
# the config file is parsed. Its a good place initialize instance 
# variables
# that might get overridden when the config file is parsed.
# Do per-instance default initialization. This is called after
# construction is complete
sub initialize
{
    my ($self) = @_;

    # Multiple inheritance:
    $self->Radius::AuthDIGIPASSGeneric::initialize();
    $self->Radius::Ldap::initialize();

    $self->{SearchFilter}  = '(%0=%1)';
    $self->{UsernameAttr} = 'oscDigipassTokenAssignedTo';
    $self->{TokenDataAttr} = 'oscDigipassTokenData';
    $self->{MaxRecords} = 1;
}


#####################################################################
# Return ($data, $digipass, $error)
# $data is the raw digipass data block
# $digipass is a key that identifies the record where the data is stored,
# it is not used by the caller except to pass back to UpdateDigipassData
# for this module it is the DN of the token record
sub GetDigipassData
{
    my ($self, $user, $p) = @_;

    # (Re)-connect to the database if necessary, 
    # No reply will be sent to the original requester if we 
    # fail to connect
    return (undef, undef, 'Could not connect to LDAP server') 
	unless $self->reconnect;

    my $authdn = &Radius::Util::format_special($self->{AuthDN}, $p);
    my $authpassword = &Radius::Util::format_special($self->{AuthPassword}, $p);
    return (undef undef, 'Could not bind to LDAP server') 
	unless $self->bind($authdn, $authpassword);
    
    my $ename = $self->escapeLdapLiteral($user);
    my $filter = &Radius::Util::format_special
	($self->{SearchFilter}, 
	 $p, undef,
	 $self->{UsernameAttr},
	 $ename);
    my $basedn = &Radius::Util::format_special
	($self->{BaseDN}, 
	 $p, undef,
	 $self->{UsernameAttr},
	 $ename);
    # These are the parameters we will look for
    my @attrs = ($self->{TokenDataAttr});

    # We evaluate the search
    # with an alarm for the timeout period
    # pending. If the alarm goes off, the eval will die
    my $result;
    &Radius::Util::exec_timeout($self->{Timeout},
       sub {
	   $result = $self->{ld}->search
	       (base => $basedn,
		scope => $self->{Scope},
		filter => $filter,
		attrs => \@attrs,
		deref => lc $self->{Deref});
	   
       });

    # $result is an object of type Net::LDAP::Search
    if (!$result || $result->code())
    {
	my $code = $result ? $result->code() : -1;
	my $errname = Net::LDAP::Util::ldap_error_name($code);
	$errname = 'LDAP Timeout' if $@ && $@ =~ /timeout/;
	$self->log($main::LOG_ERR, "ldap search failed with error $errname.", $p);
	if ($errname eq  'LDAP_NO_SUCH_OBJECT')
	{
	    # They are not there
	    return (undef, undef, 'No token found');
	}
	elsif ($errname eq  'LDAP_PARAM_ERROR')
	{
	    # Something unpleasant in the username?
	    $self->log($main::LOG_ERR, "LDAP_PARAM_ERROR", $p);
	    return (undef, undef, 'LDAP error');
	}
	else
	{
	    # Any other error probably indicates we lost the connection to 
	    # the database. Make sure we try to reconnect again later.
	    $self->log($main::LOG_ERR, "Disconnecting from LDAP server (server $self->{Host}:$self->{Port}).", $p);
	    $self->close_connection();
	    return (undef, undef, 'Disconnected from LDAP server');
	}
    }
	
    # We only use the first MaxRecords records
    my ($index, $entry, $firstdn);

    for ($index = 0; $index < $self->{MaxRecords} && ($entry = $result->entry($index)); $index++)
    {
	my $dn = $entry->dn;
	$self->log($main::LOG_DEBUG, "LDAP got result for $dn", $p);
	
	$firstdn = $dn # The DN of the first entry we see
	    if $index == 0;

	my ($attr);
	foreach $attr ($entry->attributes())
	{
	    my $vals = $entry->get($attr);

	    # Some LDAP servers (MS) leave trailing NULs
	    map s/\0$//, @$vals;

	    $self->log($main::LOG_DEBUG, "LDAP got $attr: @$vals", $p);
	    # The attributes are not returned in the order we asked 
	    # for them. Bummer. Also the case of the returned 
	    # attribute names does not necessarily match either.
	    # OK so we have to look at each one and see if its one
	    # we expect and need to use
	    if (lc $attr eq lc $self->{TokenDataAttr})
	    {
		#This is the one we want

		# Else can get die in Authen-Digipass later:
		my $data = $$vals[0];

		return (undef, undef, "Bad Digipass token data for user $user $user")
		    unless length $data == 248;

		return ($data, $dn);
	    }
	}
    }

    # Not found
    return (undef, undef, "No token found for user $user in Digipass database");
}

#####################################################################
# $digipass is the key identifying the record where the data is to be stored,
# must be the same as was returned by GetDigipassData. IN this module
# it is the DN of the token record
sub UpdateDigipassData
{
    my ($self, $data, $digipass, $p) = @_;

    # We evaluate the search
    # with an alarm for the timeout period
    # pending. If the alarm goes off, the eval will die
    my $result;
    &Radius::Util::exec_timeout($self->{Timeout},
       sub {
	   $result = $self->{ld}->modify
	       ($digipass, 
		replace => {$self->{TokenDataAttr}, $data});
       });

    # $result is an object of type Net::LDAP::Search
    if (!$result || $result->code())
    {
	my $code = $result ? $result->code() : -1;
	my $errname = Net::LDAP::Util::ldap_error_name($code);
	$errname = 'LDAP Timeout' if $@ && $@ =~ /timeout/;
	$self->log($main::LOG_ERR, "ldap modify failed with error $errname.", $p);
	if ($errname eq  'LDAP_NO_SUCH_OBJECT')
	{
	    # They are not there. Thats odd: it was there before
	    return;
	}
	else
	{
	    # Any other error probably indicates we lost the connection to 
	    # the database. Make sure we try to reconnect again later.
	    $self->log($main::LOG_ERR, "Disconnecting from LDAP server (server $self->{Host}:$self->{Port}).", $p);
	    $self->close_connection();
	    return;
	}
    }
    # Success

    # GUECM: Altijd connectie sluiten
    # Force disconnection from database. Some LDAP servers
    # dont expect us to try to bind several times on the same
    # TCP connection. Some dont even like us to search several times!
    $self->close_connection() unless $self->{HoldServerConnection};

    return 1;
}

1;
