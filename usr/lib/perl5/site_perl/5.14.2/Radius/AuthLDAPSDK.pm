# AuthLDAPSDK.pm
#
# Object for handling Authentication via Netscape's LDAP SDK
# and their PerLDAP interface.
# This is a work in progress. At the time of writing, the
# Netscape LDAP SDK and the PerLDAP interface still had some rough
# edges. Nevertheless it works on ActiveState Perl on NT.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthLDAPSDK.pm,v 1.27 2013/08/13 20:58:45 hvn Exp $

package Radius::AuthLDAPSDK;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Mozilla::LDAP::Conn;
use strict;

%Radius::AuthLDAPSDK::ConfigKeywords = 
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
 );

# RCS version number of this module
$Radius::AuthLDAPSDK::VERSION = '$Revision: 1.27 $';

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    my $class = ref($self);
    $self->log($main::LOG_WARNING, 
	       "No BaseDN defined for $class in '$main::config_file'")
	unless defined $self->{BaseDN};
    $self->log($main::LOG_WARNING, 
	       "No UsernameAttr defined for $class in '$main::config_file'")
	unless defined $self->{UsernameAttr};
    $self->log($main::LOG_WARNING, 
	       "No PasswordAttr or EncryptedPasswordAttr defined for $class in '$main::config_file'")
	if !defined $self->{PasswordAttr}
           && !defined $self->{EncryptedPasswordAttr};

    $self->SUPER::check_config();
    return;
}

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();
}

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{Host} = 'localhost';
    $self->{UsernameAttr} = 'uid';
    $self->{Scope} = 'subtree';
    $self->{SearchFilter} = '(%0=%1)';
}

#####################################################################
# reconnect
# Connect or reconnect to the LDAP
# Returns true if there is a viable LDAP connection available
# BUG ALERT: acfcording to the SDK docs, if the LDAP server
# disappears, PerLDAP will not (yet) reconnect
sub reconnect
{
    my ($self) = @_;

    return 1 if $self->{ld}; # We are already up

    my ($result, $certdbfilename, $port);

    # Maybe we need to do SSL
    # This is only possible with Netscape SDK.
    $port = 389;
    if (defined $self->{UseSSL})
    {
	# Get the name of the certificate database. certdbhandle
	my ($certdbpath, $certdbhandle) = split(/\s+/, $self->{UseSSL});
	$certdbfilename = &Radius::Util::format_special($certdbpath);
	$port = Mozilla::LDAP::API::LDAPS_PORT;
    }
    $port = $self->{Port} if defined  $self->{Port};

    my $host = &Radius::Util::format_special($self->{Host});
    $self->log($main::LOG_DEBUG, "Connecting to $host, port $port");
    my $authdn = &Radius::Util::format_special($self->{AuthDN});
    my $authpassword = &Radius::Util::format_special($self->{AuthPassword});
    if (!($self->{ld} = new Mozilla::LDAP::Conn
	 ($host, 
	  &Radius::Util::get_port($port),
	  $authdn, 
	  $authpassword,
	  $certdbfilename)))
    {
	$self->log($main::LOG_ERR, 
		   "Could not open LDAP connection to $host, port $port");
	return 0;
    }
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

    my $filter = &Radius::Util::format_special($self->{SearchFilter}, 
					       $p, undef,
					       $self->{UsernameAttr},
					       $name);
#    $filter = eval qq/"$filter"/; # Interpolate perl vars

    my $entry = $self->{ld}->search($self->{BaseDN},
				    $self->{Scope},
				    $filter);

    # We only use the first returned record
    my $got_password;
    my $user;

    if ($entry)
    {
	if ($main::config->{Trace} >= 4)
	{
	    # This will print all the attributes we got on stdout
	    $entry->printLDIF();
	}

	# Get a new User object to return
	$user = new Radius::User $name;

	# We might not be interested in pw check
	$got_password = 1
	    if ((!$self->{EncryptedPasswordAttr}) 
		&& (!$self->{PasswordAttr}));

	# All the attributes are now in $entry as 
	# $entry->{attributename}[n] The attribute names are all lowercase
	# Multiple instances of the same atribute are in consecutove entries
	# in the array
	if (defined $self->{EncryptedPasswordAttr})
	{
	    $user->get_check->add_attr('Encrypted-Password',
			    $entry->{lc $self->{EncryptedPasswordAttr}}[0]);
	    $got_password = 1;
	}
	elsif (defined $self->{PasswordAttr})
	{
	    $user->get_check->add_attr('User-Password',
			    $entry->{lc $self->{PasswordAttr}}[0]);
	    $got_password = 1;
	}
	if (defined $self->{CheckAttr}
	    && defined $entry->{lc $self->{CheckAttr}})
	{
	    # Join all the attributes together into a long set of
	    # comma separated check items
	    $user->get_check->parse(join ',', 
				    @{$entry->{lc $self->{CheckAttr}}});
	}
	if (defined $self->{ReplyAttr}
	    &&  defined $entry->{lc $self->{ReplyAttr}})
	{
	    # Join all the attributes together into a long set of
	    # comma separated reply items
	    $user->get_reply->parse(join ',', 
				    @{$entry->{lc $self->{ReplyAttr}}});
	}
	# Get any additional auth attributes from AuthAttrDef
	# Based on code contributed by Steven E Ames.
	my $ldapname;
	foreach $ldapname (keys %{$self->{AuthAttrDef}})
	{
	    if (defined $entry->{lc $ldapname})
	    {
		my @vals = @{$entry->{lc $ldapname}};
		# Some LDAP servers (MS) leave trailing NULs
		map s/\0$//, @vals;
		my ($attrib, $type) = split (/,\s*/, $self->{AuthAttrDef}{$ldapname});
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
    if (!$self->{HoldServerConnection} && $self->{ld})
    {
     	$self->{ld}->close;
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

