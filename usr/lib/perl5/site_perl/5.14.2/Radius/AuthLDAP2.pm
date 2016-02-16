# AuthLDAP2.pm
#
# Object for handling Authentication via LDAP, using the new
# perl-ldap module Net::LDAP. It replaces AuthLDAP.pm, which
# should not be used for new installations
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthLDAP2.pm,v 1.78 2014/03/31 20:52:21 hvn Exp $

package Radius::AuthLDAP2;
@ISA = qw(Radius::Ldap Radius::AuthGeneric);
use Radius::AuthGeneric;
use Radius::Ldap;
use strict;

%Radius::AuthLDAP2::ConfigKeywords = 
('UsernameAttr'            => 
 ['string', 
  'The name of the LDAP attribute that is required to match the username in the authentication request (possibly after username rewriting by RewriteUsername). ', 
  1],

 'PasswordAttr'            => 
 ['string', 
  'The name of the LDAP attribute that contains the correct password for the user. If you specify EncryptedPasswordAttr, it will be used instead of PasswordAttr, and PasswordAttr will not be fetched.', 
  1],

 'EncryptedPasswordAttr'   => 
 ['string', 
  'Name of the LDAP attribute that contains a Unix crypt(3) encrypted password for the user. If you specify EncryptedPasswordAttr, it will be used instead of PasswordAttr, and PasswordAttr will not be fetched. You must specify either PasswordAttr or EncryptedPasswordAttr. ', 
  1],

 'CheckAttr'               => 
 ['string', 
  'Name of an LDAP attribute that contains the Radius check items for the user. During authentication, all the check items in this LDAP attribute (if specified) will be matched against the Radius attributes in the authentication request ', 
  1],

 'ReplyAttr'               => 
 ['string', 
  'Name of an LDAP attribute that contains the Radius reply items for the user. If the user authenticates successfully, all the Radius attributes named in this LDAP attribute will be returned to the user in the Access-Accept message. ', 
  1],

 'ServerChecksPassword'    => 
 ['flag', 
  'Normally, Radiator fetches the user\'s password attribute from the LDAP server (using the PasswordAttr parameter), and checks the password internally. This optional parameter causes the LDAP server to check the password instead. This is useful with LDAP servers that implement proprietary encryption algorithms in their passwords (notably Open Directory from Platinum) can be used.', 
  1],

 'UnbindAfterServerChecksPassword'    => 
 ['flag', 
  'Normally, when ServerChecksPassword is set, after Radiator checks a users password the LDAP connection is not unbound. This can cause problems with some LDAP servers (notably Oracle ID), where they unexpectedly cause the following LDAP query to fail with LDAP_INAPPROPRIATE_AUTH. Setting this flag causes an unbind after each ServerChecksPassword bind.', 
  1],

 'AuthCheckDN'             => 
 ['string', 
  'Allows you to specify an alternative DN to use
   to check a user\'s password, instead of the one returned by the search result. Special characters may be used. %0 is replaced by the first matching DN returned by the search', 
  1],

 'LDAPRejectEmptyPassword' => 
 ['flag', 
  'Forces any Access-Request with an empty password to be rejected. ', 
  1],

 'AuthAttrDef'             => 
 ['stringarray', 
  'Allows you to specify LDAP attributes to use as general check and reply items during authentication. AuthAttrDef is more general and useful than CheckAttr and ReplyAttr, and should be used in preference to them. The general format is:
<p><pre><code>AuthAttrDef ldapattributename, radiusattributename, type[, formatted]</code></pre>', 
  1],

 'AttrsWithBaseScope'     =>
 ['flag', 
  'Tells Radiator to search first for the user DN then do a search with scope base to fetch the attributes. Required for example, to get access to Windows AD constructed attributes, such as tokenGroups, which are only returned when the search scope is set to base. Defaults to off.', 
  1],

 'MaxRecords'              => 
 ['integer', 
  'Specifies the maximum number of matching LDAP records to use for check and reply items.', 
  1],

 'GetNovellUP'             => 
 ['flag', 'used with the Novell eDirectory LDAP server to fetch the user\'s Universal Password and use it to authenticate the user. The eDirectory Universal Password is a single password for each user that can be used to authenticate a range of Unix and Windows services. Normally it is not possible to fetch the users passwrod from eDirectory, but GetNovellUP uses a special Novell API to fetch the users plaintext password.', 
  1],

 'PostSearchHook'          => 
 ['hook', 
  'Perl function that will be run during the authentication process. The hook will be called after the LDAP search results have been received, and after Radiator has processed the attributes it is interested in. Hook authors can use the appropriate LDAP library routines to extract other attributes and process them in any way.', 
  1],

 'GroupSearchFilter'          => 
 ['string', 
  'For advanced applications, you can specify a search filter that Radiator will use to find which user groups a user belongs to by using the optional GroupSearchFilter parameter. It allows you to use arbitrarily complicated LDAP search filters to find the names of user groups the user belongs to. Special formatting characters are permitted, and %0 is replaced by UsernameAttr and %1 by the user name. ', 2],

 'GroupNameCN'          => 
 ['string', 
  'When GroupSearchFilter is specified and Radiator looks for the user groups the user is a member of, this parameter specifies the name of the Group name attribute in the LDAP records. Defaults to "cn". ', 2],


 'GroupBaseDN'          => 
 ['string', 
  'When GroupSearchFilter is specified and Radiator looks for the user groups the user is a member of, this parameter specifies an alternate LDAP base DN for the group search. Defaults  to the value of BaseDN.', 2],


 'UseNovellNMASSequence'             => 
 ['string', 'Use the Novell NMAS login sequence named. Valid only with Novell eDirectory. This parametre names the NMAS login sequence to be used to authenticate the user password. This might be for example "NDS" or "Digipass"', 
  1],

 );

# RCS version number of this module
$Radius::AuthLDAP2::VERSION = '$Revision: 1.78 $';

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    $self->log($main::LOG_WARNING, "No UsernameAttr defined for AuthLDAP2 in '$main::config_file'")
	unless defined $self->{UsernameAttr};
    $self->log($main::LOG_WARNING, "No PasswordAttr or EncryptedPasswordAttr defined for AuthLDAP2 in '$main::config_file'")
	if !defined $self->{PasswordAttr}
           && !defined $self->{EncryptedPasswordAttr}
           && !defined $self->{ServerChecksPassword}
           && !defined $self->{NoCheckPassword}
           && !$self->{GetNovellUP}
           && !$self->{UseNovellNMASSequence}
    ;

    $self->Radius::AuthGeneric::check_config();
    $self->Radius::Ldap::check_config();
    return;
}

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->Radius::AuthGeneric::activate;
    $self->Radius::Ldap::activate;
}

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->Radius::AuthGeneric::initialize;
    $self->Radius::Ldap::initialize;

    $self->{SearchFilter} = '(%0=%1)';
    $self->{UsernameAttr} = 'uid';
    $self->{LDAPRejectEmptyPassword} = 1;
    $self->{MaxRecords} = 1;
    $self->{GroupNameCN} = 'cn';
}

#####################################################################
# This subclassable function is intended to do all the work 
# of checking a user check items, (if any)
# We override this so we can get control for NMAS authentication, which may need
# to challenge. 
sub checkUserAttributes
{
    my ($self, $user, $p, $user_name) = @_;

    if (defined $self->{UseNovellNMASSequence})
    {
	my $stateattr = $p->getAttrByNum($Radius::Radius::STATE);
	my ($challenge) = ($stateattr =~ /NMAS_STATE=(.*)/);

	# Find out what NMAS Login sequence to use. It might come from eDirectory sasDefaultLoginSequence,
	# or from the per-user check items, or it could be specified directly by UseNovellNMASSequence
	my $sequence = $user->get_check->get_attr('eDir-Auth-Option');
	$sequence = $self->{UseNovellNMASSequence}
	    if $sequence eq '';
	$sequence = 'NDS'
	    if $sequence eq '';

	# ldap_user_dn was cached by findUser below
	my ($result, $s) = $self->nmasldap_authenticate($p->{ldap_user_dn}, $sequence, $p->decodedPassword(), $challenge);
	if ($result == $Radius::Ldap::RADAUTH_AUTHSTATE_CHALLENGED)
	{
	    # This hasnt really been tested on NMAS yet:
	    $p->{rp}->addAttrByNum($Radius::Radius::STATE, "NMAS_STATE=$s");
	    $p->{rp}->addAttrByNum($Radius::Radius::REPLY_MESSAGE, $s);
	    return ($main::CHALLENGE, "NMAS Challenge");
	}
	elsif ($result == $Radius::Ldap::RADAUTH_AUTHSTATE_REJECTED)
	{
	    return ($main::REJECT, $s);
	}
	# else accept, fall through to rest of attr checking
    }
    # Continue with normal attr checking
    return $self->SUPER::checkUserAttributes($user, $p, $user_name);
}

#####################################################################
# Check a password for a DN, by attempting to bind with a 
# supplied password. Careful: an empty password will always appear 
# to match, so we reject that case
sub checkPassword
{
    my ($self, $dn, $password) = @_;

    my $result;
    return if $self->{LDAPRejectEmptyPassword} && $password eq '';
    &Radius::Util::exec_timeout($self->{Timeout},
				sub {$result = $self->{ld}->bind(dn => $dn, password => $password);});
    if (!$result || 
	($result->code() 
	 && $result->code() != Net::LDAP::Constant->LDAP_INAPPROPRIATE_AUTH
	 && $result->code() != Net::LDAP::Constant->LDAP_INVALID_CREDENTIALS))
    {
	my $code = $result ? $result->code() : -1;

	my $errname = Net::LDAP::Util::ldap_error_name($code);
	$errname = 'LDAP Timeout' if $@ && $@ =~ /timeout/;
	$self->log($main::LOG_ERR, "ldap bind for $dn failed with error $errname.");
	$self->log($main::LOG_ERR, "Disconnecting from LDAP server (server $self->{connectedHost}).");
	$self->close_connection();
    }

    my $ret = $result && !$result->code();
    # Caution: a bind failure can cause the server to unexpectedly disconnect
    # Unbind provokes disconnections from  some servers
    $self->{ld}->unbind 
	if $self->{ld} && $self->{UnbindAfterServerChecksPassword};
    return $ret;
}

# $password is the new password string
# $dn can be a string or a Net::LDAP::Entry object.
sub changePassword
{
    my ($self, $dn, $password, $p) = @_;

    # (Re)-connect to the database if necessary, 
    # No reply will be sent to the original requester if we 
    # fail to connect
    return (undef, 1) unless $self->reconnect;
    my $authdn = &Radius::Util::format_special($self->{AuthDN}, $p);
    my $authpassword = &Radius::Util::format_special($self->{AuthPassword}, $p);
    return (undef, 1) unless $self->bind($authdn, $authpassword);

    my $result;
    &Radius::Util::exec_timeout($self->{Timeout},
       sub {
	   $result = $self->{ld}->modify(
	       $dn, replace => { $self->{PasswordAttr} => $password});
       });

    # $result is an object of type Net::LDAP::Search
    if (!$result || $result->code())
    {
	my $code = $result ? $result->code() : -1;
	my $errname = Net::LDAP::Util::ldap_error_name($code);
	$errname = 'LDAP Timeout' if $@ && $@ =~ /timeout/;
	$self->log($main::LOG_ERR, "ldap modify '$dn' failed with error $errname.", $p);
    }

    my $ret = $result && !$result->code();
    return $ret;
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
    # No reply will be sent to the original requester if we 
    # fail to connect
    return (undef, 1) unless $self->reconnect;

    my $authdn = &Radius::Util::format_special($self->{AuthDN}, $p);
    my $authpassword = &Radius::Util::format_special($self->{AuthPassword}, $p);
    return (undef, 1) unless $self->bind($authdn, $authpassword);
    
    my ($user, @attrs, $got_password);
    # Add password to LDAP request, unless the server will check
    # it later
    if (!$self->{ServerChecksPassword})
    {
	if (defined $self->{EncryptedPasswordAttr})
	{
	    push(@attrs, $self->{EncryptedPasswordAttr});
	}
	elsif ($self->{PasswordAttr})
	{
	    push(@attrs, $self->{PasswordAttr});
	}
    }

    # Continue building LDAP request
    push(@attrs, $self->{CheckAttr}) if defined $self->{CheckAttr};
    push(@attrs, $self->{ReplyAttr}) if defined $self->{ReplyAttr};
	
    # look for all of the new AuthAttr attributes (basically push more
    # attributes onto @attrs
    # my $ldapname;
    my ($ldapname, $attrib, $type, $formatting, $authattrdef_set);
    foreach $authattrdef_set (@{$self->{AuthAttrDef}}) 
    {
	# my ($attrib, $type) = @{$self->{AuthAttrDef}{$ldapname}};
	($ldapname,$attrib,$type) = split (/,\s*/, $authattrdef_set);
	push(@attrs, $ldapname);
    }

    my $ename = $self->escapeLdapLiteral($name);
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

    # Now locate the user DN if so requested. If the user is found,
    # the user's DN becomes the new base DN and we fetch the
    # attributes with search scope of base - direct lookup.
    my $scope = $self->{Scope};
    if ($self->{AttrsWithBaseScope})
    {
	my $error;
	($basedn, $error) = $self->findUserDn($p, $basedn, $scope, $filter);
	return (undef, $error) unless $basedn; # User not found, maybe got an error too
	$scope = 'base'; # Switch scope to base
    }

    # We evaluate the search
    # with an alarm for the timeout period
    # pending. If the alarm goes off, the eval will die
    my $result;
    &Radius::Util::exec_timeout($self->{Timeout},
       sub {
	   $result = $self->{ld}->search
	       (base => $basedn,
		scope => $scope,
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
	$self->log($main::LOG_ERR, "ldap search for $filter failed with error $errname.", $p);
	if ($errname eq  'LDAP_NO_SUCH_OBJECT')
	{
	    # They are not there
	    return undef;
	}
	elsif (   $errname eq  'LDAP_PARAM_ERROR'
	       || $errname eq  'LDAP_INVALID_DN_SYNTAX')
	{
	    # Something unpleasant in the username?
	    $self->log($main::LOG_ERR, $errname, $p);
	    return undef;
	}
	else
	{
	    # Any other error probably indicates we lost the connection to 
	    # the database. Make sure we try to reconnect again later.
	    $self->log($main::LOG_ERR, "Disconnecting from LDAP server (server $self->{connectedHost}).", $p);
	    $self->close_connection();
	    return (undef, 1);
	}
    }
	
    # We might not be interested in pw check
    $got_password=1
	if (   !$self->{ServerChecksPassword}
	    && !$self->{GetNovellUP}
	    && !$self->{UseNovellNMASSequence}
	    && !$self->{EncryptedPasswordAttr}
	    && !$self->{PasswordAttr});
    
    # We only use the first MaxRecords records
    my ($index, $entry, $firstdn);
    for ($index = 0; $index < $self->{MaxRecords} && ($entry = $result->entry($index)); $index++)
    {
	# Get a new User object to return
	$user = new Radius::User unless $user;

	my $dn = $entry->dn;
	$self->log($main::LOG_DEBUG, "LDAP got result for $dn", $p);
	
	$firstdn = $dn # The DN of the first entry we see
	    if $index == 0;

	my ($attr);
	foreach $attr ($entry->attributes())
	{
	    # This should work for ldap-perl before and after 0.20
	    # vals is now a reference to an array
	    my $vals = $entry->get_value($attr, asref => 1);
	    my @vals = @$vals;

	    # Some LDAP servers (MS) leave trailing NULs
	    map s/\0$//, @vals;

	    $self->log($main::LOG_DEBUG, "LDAP got $attr: @vals", $p);

	    # The attributes are not returned in the order we asked 
	    # for them. Bummer. Also the case of the returned 
	    # attribute names does not necessarily match either.
	    # OK so we have to look at each one and see if its one
	    # we expect and need to use
	    $attr = lc $attr;
	    if (defined $self->{EncryptedPasswordAttr} 
		&& $attr eq lc $self->{EncryptedPasswordAttr})
	    {
		$got_password = 1;
		$user->get_check->add_attr('Encrypted-Password',
					   $vals[0]);
	    }
	    elsif (defined $self->{PasswordAttr} 
		   && $attr eq lc $self->{PasswordAttr})
	    {
		$got_password = 1;
		$user->get_check->add_attr('User-Password',
					   $vals[0]);
	    }
	    elsif (defined $self->{CheckAttr} 
		   && $attr eq lc $self->{CheckAttr})
	    {
		# This is the attribute with check items in it
		$user->get_check->parse(join ',', @vals);
	    }
	    elsif (defined $self->{ReplyAttr} 
		   && $attr eq lc $self->{ReplyAttr})
	    {
		# This is the attribute with reply items in it
		$user->get_reply->parse(join ',', @vals);
	    }
	    else
            {
		# Perhaps its one of the attributes from AuthAttrDef
		# Based on code contributed by Steven E Ames.
		my ($ldapname,$attrib,$type, $authattrdef_set);

	        foreach $authattrdef_set (@{$self->{AuthAttrDef}})
	        {
		    ($ldapname, $attrib, $type, $formatting) = split (/,\s*/, $authattrdef_set);
		    $type = lc($type); # lower-casify
		    $formatting = lc($formatting); # lower-casify

		    # Maybe do special char processing on the value from the database
		    @vals = map {&Radius::Util::format_special($_, $p)} @vals
			if ($formatting eq 'formatted');

		    if ($attr eq lc $ldapname)
		    {
			if ($type eq 'check') 
			{
			    if ($attrib eq 'GENERIC')
			    {
				$user->get_check->parse(join ',', @vals);
			    }
			    else 
			    {
				# Permit alternation from multivalued attrs
				$user->get_check->add_attr($attrib, join('|', @vals));
			    }
			}
			elsif ($type eq 'reply')
			{
			    if ($attrib eq 'GENERIC')
                            {
				$user->get_reply->parse(join ',', @vals);
                            }
			    else
			    {
				map {$user->get_reply->add_attr($attrib, $_)}  (@vals);
			    }
			}
			elsif ($type eq 'request')
			{
			    if ($attrib eq 'GENERIC')
			    {
				$p->parse(join ',', @vals);
			    }
			    else
			    {
				map {$p->add_attr($attrib, $_)}  (@vals);
			    }
			}
		    }
		}
	    }
	}


	# Perhaps run a hook to do other things with the LDAP data
        $self->runHook('PostSearchHook', $p, $self, $name, $p, $user, $entry, $p->{rp});
    }
    $self->log($main::LOG_DEBUG, "No entries for $name found in LDAP database", $p)
	unless $user;


    # Have to check for Novell Universal Password here and servercheckspassword here, 
    # becuase we cant do it in the middle
    # of a set of replies from search.
    if (!$got_password && defined $firstdn)
    {
	my $auth_check_dn = $firstdn;
	$auth_check_dn = &Radius::Util::format_special
	    ($self->{AuthCheckDN}, $p, undef, $firstdn)
	    if $self->{AuthCheckDN};
	if ($self->{ServerChecksPassword})
	{
	    # Now we have the DN, we can get the server to 
	    # check the username if necessary, and only for the
	    # first matching record
	    $got_password = 1;
	    if (!$self->checkPassword($auth_check_dn, $p->decodedPassword()))
	    {
		# LDAP server did not like the password
		# Make a 13 octet crypt password that will never succeed
		# And will therefore provoke password failure later
		$user->get_check->add_attr('Encrypted-Password', '**nevermatch-');
	    }
	}
	elsif (defined $self->{UseNovellNMASSequence})
	{
	    # Password will be checked later in checkUserAttributes
	    $p->{ldap_user_dn} = $auth_check_dn;
	    $got_password = 1;
	}
	elsif ($self->{GetNovellUP})
	{
	    # Fetch the Novell Universal password if possible
	    my $password = $self->nmasldap_get_password($auth_check_dn);
	    $got_password = 1;
	    $self->log($main::LOG_EXTRA_DEBUG, "Got Novell Universal Password: $password", $p);
	    if (defined $password)
	    {
		$user->get_check->add_attr('User-Password', $password);
	    }
	    else
	    {
		# Couldnt get the plaintext password
		# Make a 13 octet crypt password that will never succeed
		# And will therefore provoke password failure later
		$user->get_check->add_attr('Encrypted-Password', '**nevermatch-');
	    }
	}
    }

    # Force disconnection from database. Some LDAP servers
    # dont expect us to try to bind several times on the sameq
    # TCP connection. Some dont even like us to search several times!
    $self->close_connection() unless $self->{HoldServerConnection};

    if ($user && !$got_password && !defined $self->{NoCheckPassword})
    {
	$self->log($main::LOG_ERR, "There was no password attribute found for $name. Check your LDAP database.", $p);
	# Force a rejection
	$user->get_check->add_attr('Encrypted-Password', '**nevermatch-');
    }
    return $user;
}

# Search for the user's DN and return it. Some attributes may only be
# available when the search is done with scope base.
sub findUserDn
{
    my ($self, $p, $basedn, $scope, $filter) = @_;

    # We evaluate the search
    # with an alarm for the timeout period
    # pending. If the alarm goes off, the eval will die
    my $result;
    Radius::Util::exec_timeout($self->{Timeout},
       sub {
	   $result = $self->{ld}->search
	       (base => $basedn,
		scope => $scope,
		filter => $filter,
		attrs => ['1.1'],  # Request no attributes
		deref => lc $self->{Deref});
       });

    # $result is an object of type Net::LDAP::Search
    if (!$result || $result->code())
    {
	my $code = $result ? $result->code() : -1;
	my $errname = Net::LDAP::Util::ldap_error_name($code);
	$errname = 'LDAP Timeout' if $@ && $@ =~ /timeout/;
	$self->log($main::LOG_ERR, "LDAP use DN search for $filter failed with error $errname.", $p);
	if ($errname eq  'LDAP_NO_SUCH_OBJECT')
	{
	    # They are not there
	    return undef;
	}
	elsif (   $errname eq  'LDAP_PARAM_ERROR'
	       || $errname eq  'LDAP_INVALID_DN_SYNTAX')
	{
	    # Something unpleasant in the username?
	    $self->log($main::LOG_ERR, $errname, $p);
	    return (undef, 1);
	}
	else
	{
	    # Any other error probably indicates we lost the connection to 
	    # the database. Make sure we try to reconnect again later.
	    $self->log($main::LOG_ERR, "User DN search failed, disconnecting from LDAP server (server $self->{connectedHost}).", $p);
	    $self->close_connection();
	    return (undef, 1);
	}
    }

    my $entry = $result->entry();
    unless ($entry)
    {
	$self->log($main::LOG_DEBUG, "User DN search found no entry in LDAP database", $p);
	return undef;
    }

    my $dn = $entry->dn();
    $self->log($main::LOG_DEBUG, "LDAP user DN search found $dn", $p);

    return $dn;
}

#####################################################################
# Find which Groups $user is a member of.
# Return the list, or undef if failure.
# This will be called to check Group check items by AuthGeneric::userIsInGroup
sub getUserGroups
{
    my ($self, $user, $p) = @_;

    if (!defined $self->{GroupSearchFilter})
    {
	$self->log($main::LOG_WARNING, "AuthLDAP2 cant getUserGroups because GroupSearchFilter is not defined.", $p);
	return;
    }

    # (Re)-connect to the database if necessary, 
    return unless $self->reconnect;

    my $authdn = &Radius::Util::format_special($self->{AuthDN}, $p);
    my $authpassword = &Radius::Util::format_special($self->{AuthPassword}, $p);
    return unless $self->bind($authdn, $authpassword);

    # Get the cn of all groups of which this user is a member
    my $ename = $self->escapeLdapLiteral($user);
    my $filter = &Radius::Util::format_special
	($self->{GroupSearchFilter}, 
	 $p, undef,
	 $self->{UsernameAttr},
	 $ename);
    my $basedn = &Radius::Util::format_special
	($self->{GroupBaseDN} || $self->{BaseDN}, 
	 $p, undef,
	 $self->{UsernameAttr},
	 $ename);
    $self->log($main::LOG_DEBUG, "AuthLDAP2 getUserGroups searches for $filter in $basedn", $p);

    my $result;
    &Radius::Util::exec_timeout($self->{Timeout},
       sub {
	   $result = $self->{ld}->search
	       (base => $basedn,
		scope => $self->{Scope},
		filter => $filter,
		attrs => [$self->{GroupNameCN}],
		deref => lc $self->{Deref});
	   
       });

    # $result is an object of type Net::LDAP::Search
    if (!$result || $result->code())
    {
	my $code = $result ? $result->code() : -1;
	my $errname = Net::LDAP::Util::ldap_error_name($code);
	$errname = 'LDAP Timeout' if $@ && $@ =~ /timeout/;
	$self->log($main::LOG_ERR, "AuthLDAP2 getUserGroups ldap search for $filter failed with error $errname.", $p);
	return;
    }
    
    my @groups;
    # So far so good, look at all the groups we got
    my ($entry, $index);
    while ($entry = $result->entry($index++))
    {
	my $dn = $entry->dn;
	$self->log($main::LOG_DEBUG, "AuthLDAP2 getUserGroups ldap search got group $dn", $p);
	# The cn is the group name
	my $vals = $entry->get_value($self->{GroupNameCN}, asref => 1);
	push(@groups, @$vals);
    }

    # Success, return the groups this user is a member of
    return @groups;
}
1;




