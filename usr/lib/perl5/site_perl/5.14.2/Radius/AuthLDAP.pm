# AuthLDAP.pm
#
# Object for handling Authentication vi LDAP.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthLDAP.pm,v 1.34 2007/12/18 21:23:50 mikem Exp $

package Radius::AuthLDAP;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Net::LDAPapi;
use strict;

%Radius::AuthLDAP::ConfigKeywords = 
(
'BaseDN'                => 
 ['string', 
  'This is the base DN where searches will be made. For each authentication request, Radiator does a SUBTREE search starting at BaseDN, looking for a UsernameAttr that exactly matches the user name in the radius request (possibly after username rewriting).', 
  0],

 'Host'                  => 
 ['string', 
  'Name of the LDAP host to connect to. Special formatting characters are permitted.', 
  0],

 'Port'                  => 
 ['string', 
  'The port to connect to on the LDAP host. Defaults to 389, the standard port for unencrypted LDAP. If UseSSL is specified, it defaults to 636, the standard port for encrypted LDAP. Can be a numeric port number or a symbolic service name from /etc/services or its equivalent on your system. ', 
  1],

 'UseSSL'                => 
 ['flag', 
  'Specifies to use SSL to connect to the LDAP server. UseSSL is supported with LDAP and LDAP2. The syntax is slightly different for the two versions. See the alternative UseTLS parameter for TLS support.', 1],


 'AuthDN'                => 
 ['string', 
  'Name to use to authenticate this Radiator server to the LDAP server. You only need to specify this if the LDAP server requires authentication from its clients.', 
  0],

 'AuthPassword'          => 
 ['string', 
  'Password to use to authenticate this Radiator server to the LDAP server. You only need to specify this if the LDAP server requires authentication from its clients, and you specify AuthDN.', 
  0],
'UsernameAttr'            => 
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

 'SearchFilter'          => 
 ['string', 
  'For advanced applications, you can completely alter the search filter that Radiator will use by using the optional SearchFilter parameter. It allows you to use arbitrarily complicated LDAP search filters to select or exclude users based on attributes other than their user name. Special formatting characters are permitted, and %0 is replaced by UsernameAttr and %1 by the user name. ', 1],

 'HoldServerConnection'  => 
 ['flag', 
  'Forces this module to hold the connection to the LDAP server up for as long as possible. Only some LDAP servers support this behaviour (notably University of Michigan, Netscape, Open Directory and Novell eDirectory), but for those servers it can significantly improve performance, especially where UseTLS or UseSSL is enabled. If you enable this parameter and you start to get odd behaviour from your AuthBy LDAP, you are probably using an unsupported LDAP server, and you should not use this parameter on it.', 
  1],

 'Scope'                 => 
 ['string', 
  'Controls the search scope used during LDAP searches.', 
  1],

 'PostSearchHook'          => 
 ['hook', 
  'Perl function that will be run during the authentication process. The hook will be called after the LDAP search results have been received, and after Radiator has processed the attributes it is interested in. Hook authors can use the appropriate LDAP library routines to extract other attributes and process them in any way.', 
  1],

 'AuthAttrDef'             => 
 ['stringarray', 
  'Allows you to specify LDAP attributes to use as general check and reply items during authentication. AuthAttrDef is more general and useful than CheckAttr and ReplyAttr, and should be used in preference to them.', 
  1],

 'Timeout'               => 
 ['integer', 
  'Sets the TCP conection timeout period in seconds for the connection to the LDAP server. ', 
  1],

 'FailureBackoffTime'    => 
 ['integer', 
  'Sets the period of time that AuthBy LDAP and LDAP2 will stop trying to connect to its LDAP server after a connection failure. Defaults to 600 seconds (10 minutes). This is intended to give the LDAP server time to recover after a failure. During the failure backoff interval, all authentication requests will be IGNOREd.', 
  1],

 );

# RCS version number of this module
$Radius::AuthLDAP::VERSION = '$Revision: 1.34 $';

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();
    my $class = ref($self);
    $self->log($main::LOG_WARNING, 
	       "No BaseDN defined for $class at '$main::config_file' line $.")
	unless defined $self->{BaseDN};
    $self->log($main::LOG_WARNING, 
	       "No UsernameAttr defined for $class at '$main::config_file' line $.")
	unless defined $self->{UsernameAttr};
    $self->log($main::LOG_WARNING, 
	       "No PasswordAttr or EncryptedPasswordAttr defined for $class at '$main::config_file' line $.")
	if !defined $self->{PasswordAttr}
           && !defined $self->{EncryptedPasswordAttr};
}

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{Host} = 'localhost';
    $self->{UsernameAttr} = 'uid';
    $self->{Port} = LDAP_PORT;
    $self->{Scope} = 'subtree'; # Not supported yet
    $self->{SearchFilter} = '(%0=%1)';
    $self->{Timeout} = 10;
    $self->{FailureBackoffTime} = 600; # Seconds
}

#####################################################################
# reconnect
# Connect or reconnect to the LDAP
# Returns true if there is a viable LDAP connection available
sub reconnect
{
    my ($self) = @_;

    return 1 if $self->{ld}; # We are already up
    return 0 if time < $self->{backoff_until};

    my $result;
    my $host = &Radius::Util::format_special($self->{Host});
    $self->log($main::LOG_DEBUG, "Connecting to $host, port $self->{Port}");
    if (($self->{ld} = ldap_open($host, 
		 Radius::Util::get_port($self->{Port}))) == 0)
    {
	$self->{backoff_until} = time + $self->{FailureBackoffTime};
	$self->log($main::LOG_ERR, 
		   "Could not open LDAP connection to $host, port $self->{Port}, backing off for $self->{FailureBackoffTime} seconds.");
	return 0;
    }

    ldap_set_option($self->{ld}, 
		  Net::LDAPapi::LDAP_OPT_TIMELIMIT, $self->{Timeout});

    # Maybe we need to do SSL
    # This is only possible with Netscape SDK. With Umich LDAP
    # perl will die with something like 
    # Can't locate auto/Net/LDAPapi/ldapssl_cli.al in @INC
    if (defined $self->{UseSSL})
    {
	# Get the name of the certificate database. certdbhandle
	# is not used by SDK yet.
	my ($certdbpath, $certdbhandle) = split(/\s+/, $self->{UseSSL});
	my $certdbfilename = &Radius::Util::format_special($certdbpath);
	if (($result = ldapssl_client_init($certdbfilename, $certdbhandle))
	    != LDAP_SUCCESS)
	{
	    my $msg = ldap_err2string(ldap_result2error($self->{ld}, $result, 0));
	    $self->log($main::LOG_ERR, 
		       "Could not initialize SSL with $certdbpath, $certdbhandle: $msg. Disconnecting");
	    # Patch by: Johnathan Ingram <johnathani@bigfoot.com> 
	    # 10 July 2000
	    # Must unbind the LDAP handle in order to terminate the socket
	    # connection and release the socket handle. 
	    # Otherwise will run out of file handles
	    # and authentication will fail and not able to bind to 
	    # LDAP server.
	    ldap_unbind($self->{ld});
	    $self->{ld} = undef;
	    return 0;
	}
	if (($result = ldapssl_install_routines($self->{ld}))
	    != LDAP_SUCCESS)
	{
	    my $msg = ldap_err2string(ldap_result2error($self->{ld}, $result, 0));
	    $self->log($main::LOG_ERR, 
		       "Could not install SSL routines: $msg. Disconnecting");
	    ldap_unbind($self->{ld});
	    $self->{ld} = undef;
	    return 0;
	}
    }

    my $authdn = &Radius::Util::format_special($self->{AuthDN});
    my $authpassword = &Radius::Util::format_special($self->{AuthPassword});
    if ((ldap_simple_bind_s($self->{ld}, 
			    $authdn, 
			    $authpassword)) != LDAP_SUCCESS)
    {
	$self->log($main::LOG_ERR, 
		   "Could not bind connection with $self->{AuthDN}. Disconnecting");
	ldap_unbind($self->{ld});
	$self->{ld} = undef;
	return 0;
    }
    # REVISIT: may want to set some options here

    return 1;  # LDAP is available
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

    my $user;

    # Construct an LDAP request
    my @attrs;
    if (defined $self->{EncryptedPasswordAttr})
    {
	push(@attrs, $self->{EncryptedPasswordAttr});
    }
    else
    {
	push(@attrs, $self->{PasswordAttr});
    }
    push(@attrs, $self->{CheckAttr}) if defined $self->{CheckAttr};
    push(@attrs, $self->{ReplyAttr}) if defined $self->{ReplyAttr};

    # look for all of the new AuthAttr attributes (basically push more
    # attributes onto @attrs
    my $ldapname;
    foreach $ldapname (keys %{$self->{AuthAttrDef}})
    {
	push(@attrs, $ldapname);
    }
    
    my $filter = &Radius::Util::format_special($self->{SearchFilter}, 
					       $p, undef,
					       $self->{UsernameAttr},
					       $name);
    my $result;
    if (ldap_search_s($self->{ld},
		      $self->{BaseDN},
		      LDAP_SCOPE_SUBTREE,
		      $filter,
		      \@attrs, 
		      0,
		      $result) != LDAP_SUCCESS)
    {
	my $msg = ldap_err2string(ldap_result2error($self->{ld}, $result, 0));
	$self->log($main::LOG_ERR, "ldap_search_s failed: $msg. Disconnecting from LDAP server.", $p);
	# Any error probably indicates we lost the connection to 
	# the database. Make sure we try to reconnect again later.
	ldap_unbind($self->{ld});
	$self->{ld} = undef;
	return (undef, 1);
    }

    # We only use the first returned record
    my $got_password;
    my $entry = ldap_first_entry($self->{ld}, $result);
    if ($entry)
    {
	# Get a new User object to return
	$user = new Radius::User $name;

	my $dn = &ldap_get_dn($self->{ld}, $entry);
	$self->log($main::LOG_DEBUG, "LDAP got result for $dn", $p);
	
	my ($attr, $ber);
	# We might not be interested in pw check
	$got_password = 1
	    if ((!$self->{EncryptedPasswordAttr}) 
		&& (!$self->{PasswordAttr}));

	for ($attr = ldap_first_attribute($self->{ld}, $entry, $ber);
	     defined $attr;
	     $attr = ldap_next_attribute($self->{ld}, $entry, $ber))
	{
	    my @vals = ldap_get_values($self->{ld}, $entry, $attr);
	    $self->log($main::LOG_DEBUG, "LDAP got $attr: @vals", $p);

	    # The attributes are not returned in the order we asked 
	    # for them. Bummer. Also the case of the returned 
	    # attribute names does not necessarily match either.
	    # OK so we have to look at each one and see if its one
	    # we expect and need to use
	    $attr = lc $attr;
	    if ($attr eq lc $self->{EncryptedPasswordAttr})
	    {
		$got_password = 1;
		$user->get_check->add_attr('Encrypted-Password',
					   $vals[0]);
	    }
	    elsif ($attr eq lc $self->{PasswordAttr})
	    {
		$got_password = 1;
		$user->get_check->add_attr('User-Password',
					   $vals[0]);
	    }
	    elsif ($attr eq lc $self->{CheckAttr})
	    {
		# This is the attribute with check items in it
		$user->get_check->parse(join ',', @vals);
	    }
	    elsif ($attr eq lc $self->{ReplyAttr})
	    {
		# This is the attribute with reply items in it
		$user->get_reply->parse(join ',', @vals);
	    }
	    else
            {
		# Perhaps its one of the attributes from AuthAttrDef
		# Based on code contributed by Steven E Ames.
		my $ldapname;

	        foreach $ldapname (keys %{$self->{AuthAttrDef}})
	        {
		    if ($attr eq lc $ldapname)
		    {
			my ($attrib, $type) = split(/,\s*/, $self->{AuthAttrDef}{$ldapname});
			$type = lc($type); # lower-casify
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
    else
    {
	$self->log($main::LOG_DEBUG, "No entries for $name found in LDAP database", $p);
    }
    # Force disconnection from database. Some LDAP servers
    # dont expect us to try to bind several times on the same
    # TCP connection. Some dont even like us to search several times!
    if (!$self->{HoldServerConnection})
    {
	ldap_unbind($self->{ld});
	$self->{ld} = undef;
    }

    if ($user && !$got_password)
    {
	$self->log($main::LOG_ERR, "There was no password attribute found for $name. Check your LDAP database.", $p);
	# Force a rejection
	$user->get_check->add_attr('Encrypted-Password', 'no password attribute in LDAP database');
    }
    return $user;
}
1;
