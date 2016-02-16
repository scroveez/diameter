# AuthNISPLUS.pm
#
# Object for handling Authentication via NIS+.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1998 Open System Consultants
# $Id: AuthNISPLUS.pm,v 1.16 2007/12/18 21:23:50 mikem Exp $

package Radius::AuthNISPLUS;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Net::NISPlus::Table;
use strict;

# Make sure we get reinitialized on sighup
push(@main::reinitFns, \&reinitialize);

%Radius::AuthNISPLUS::ConfigKeywords = 
('Table'                  => 
 ['string', 'This optional parameter defines the name of the NIS+ table to search in. It defaults to passwd.org_dir which is the name of the standard password table in NIS+. You would not normally need to change this. You could define your own NIS+ table with your own table structure to authenticate from, and define the name of the table with the Table parameter. ', 1],

 'Query'                  => 
 ['string', 'This optional parameter specifies how users are to be located in the NIS+ table. It is a list of field=value pairs. You can use any of the special macros described in Section 5.2 on page 16. In addition, you can use %0 for the user name. The default is [name=%0], which will find the user name in a standard NIS+ passwd table. You would only need to define this if you define your own NIS+ table to authenticate from.', 1],

 'EncryptedPasswordField' => 
 ['string', 'This optional parameter specifies the name of the field in the NIS+ table that contains the encrypted password for the user. It defaults to passwd, which is the name of the password field in the standard NIS+ passwd table. Radiator will use this field as the source of the encrypted password with which to check authentication requests.', 1],

 'AuthFieldDef'           => 
 ['stringhash', 'This optional parameter allows you to specify precisely how the fields in the NIS+ table are to be interpreted. If any AuthFieldDef parameters are specified, EncryptedPasswordField will be completely ignored, and you will have to define every check and reply item (including the encrypted password) with an AuthFieldDef entry.<p>You can specify any number of AuthFieldDef parameters, one for each interesting field in the NIS+ table. The general format is:
<p><pre><code>fieldname,attributename,type</code></pre>', 1],

 );

# RCS version number of this module
$Radius::AuthNISPLUS::VERSION = '$Revision: 1.16 $';

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{Table} = 'passwd.org_dir';
    $self->{Query} = '[name=%0]';
    $self->{EncryptedPasswordField} = 'passwd';
}

#####################################################################
# This function may be called during operation to reinitialize 
# this module
# it is expected to reload any state, perhaps by rereading files, 
# reconnecting to a database or something like that.
# Its not actually called yet, but it as well to be prepared 
# for the day
# when it will be.
sub reinitialize
{
    my ($self) = @_;

    $self->{table} = undef;
}

#####################################################################
# Find a the named user by looking in NIS+, and constructing
# User object if we found the named user
# $name is the user name we want
# $p is the current request we are handling
sub findUser
{
    my ($self, $name, $p) = @_;

    # (Re)-connect to the database if necessary, 
    return (undef, 1) unless $self->reconnect;

    # We have to change User-Name in the request so we can 
    # use %n etc in AuthSelect
    # REVISIT: delete this one day
    my $original_user_name = $p->getUserName;
    $p->changeUserName($name);

    my $user;

    my $query = &Radius::Util::format_special($self->{Query}, $p, undef, 
					      $name);
    $self->log($main::LOG_DEBUG, "NIS+ query is $query", $p);
    my @results = $self->{table}->lookup($query);

    # BUG ALERT: we dont seem to be able to tell the difference
    # between "no match" and a more serious problem like
    # "NIS+ servers unreachable"
    if (@results)
    {
	$user = new Radius::User $name;

	# We only use the first entry found in the result set.
	if (defined $self->{AuthFieldDef})
	{
	    # Decode the fields returned from NIS+ using
	    # the column definitions in AuthFieldDef
	    my $fname;
	    foreach $fname (keys %{$self->{AuthFieldDef}}) 
	    {
	        my ($attrib, $type) = split (/,\s*/, $self->{AuthFieldDef}{$fname});
			
		$type = lc($type); # lower-casify
		# An empty entry in the database will never be 
		# added to the check items,
		# ie for an entry which is empty, every attribute 
		# will match.
			
		next unless defined($results[0]->{$fname});
			
		if ($attrib eq "GENERIC") 
		{
		    # Column is a list of attr=value pairs
		    if ($type eq "check") 
		    {
			$user->get_check->parse($results[0]->{$fname});
		    } 
		    elsif ($type eq "reply") 
		    {
			$user->get_reply->parse($results[0]->{$fname});
		    }
		} 
		else 
		{
		    # $attrib is an attribute name, and the 
		    # value is the string to match
		    if ($type eq "check") 
		    {
			$user->get_check->add_attr($attrib,
					  $results[0]->{$fname});
		    } 
		    elsif ($type eq "reply") 
		    {
			$user->get_reply->add_attr($attrib,
					  $results[0]->{$fname});
		    }
		}
	    }
	}
	else
	{
	    # No special definition of fields, so just
	    # get the encrypted passwd from the field named 
	    # EncryptedPasswordField
	    $user->get_check->add_attr('Encrypted-Password',
		  $results[0]->{$self->{EncryptedPasswordField}});
	}
    }
    $p->changeUserName($original_user_name);
    return $user;
}

#####################################################################
# Connect or reconnect to the NIS+ table of interest
sub reconnect
{
    my ($self) = @_;

    # Connect to the table if possible
    if (!$self->{table})
    {
	$self->{table} = Net::NISPlus::Table->new($self->{Table});
	if (!$self->{table})
	{
	    $self->log($main::LOG_ERR, 
		       "Could not access table $self->{Table}");
	    return 0;
	}
    }
    return 1; # Database is available
}
1;
