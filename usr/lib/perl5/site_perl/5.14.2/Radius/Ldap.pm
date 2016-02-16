# Ldap.pm
#
# Base class for classes that require LDAP server access
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997-2004 Open System Consultants
# $Id: Ldap.pm,v 1.40 2014/04/15 14:53:13 hvn Exp $

package Radius::Ldap;
@ISA = qw(Radius::Configurable);
use Radius::Configurable;
use Net::LDAP;
use Net::LDAP::Util;
use strict;

%Radius::Ldap::ConfigKeywords = 
('BaseDN'                => 
 ['string', 
  'This is the base DN where searches will be made. For each authentication request, Radiator does a SUBTREE search starting at BaseDN, looking for a UsernameAttr that exactly matches the user name in the radius request (possibly after username rewriting).
Special formatting characters are permitted, and %0 is replaced by UsernameAttr and %1 by the user name. ', 
  0],

 'Host'                  => 
 ['string', 
  'Name or address of the LDAP host to connect to. Special formatting characters are permitted. If Host begins with "ipv6:" the subsequent host name(s) will be interpreted as IPV6 addresses where possible, and Net::LDAP will use INET6 to connect to the LDAP server (requires IO::Socket::INET6).', 
  0],

 'Port'                  => 
 ['string', 
  'The port to connect to on the LDAP host. Defaults to 389, the standard port for unencrypted LDAP. If UseSSL is specified, it defaults to 636, the standard port for encrypted LDAP. Can be a numeric port number or a symbolic service name from /etc/services or its equivalent on your system. ', 
  1],

 'UseSSL'                => 
 ['flag', 
  'Specifies to use SSL to connect to the LDAP server. UseSSL is supported with LDAP and LDAP2. The syntax is slightly different for the two versions. See the alternative UseTLS parameter for TLS support.', 1],

 'UseTLS'                => 
 ['flag', 
  'Forces the LDAP connection to use TLS authentication and encryption.', 
  1],

 'AuthDN'                => 
 ['string', 
  'Name to use to authenticate this Radiator server to the LDAP server. You only need to specify this if the LDAP server requires authentication from its clients.', 
  0],

 'AuthPassword'          => 
 ['string', 
  'Password to use to authenticate this Radiator server to the LDAP server. You only need to specify this if the LDAP server requires authentication from its clients, and you specify AuthDN.', 
  0],

 'Debug'                 => 
 ['integer', 
  'Enable LDAP library debug messages to be printed to STDOUT', 
  1],

 'Timeout'               => 
 ['integer', 
  'Sets the TCP conection timeout period in seconds for the connection to the LDAP server. ', 
  1],

 'FailureBackoffTime'    => 
 ['integer', 
  'Sets the period of time that AuthBy LDAP and LDAP2 will stop trying to connect to its LDAP server after a connection failure. Defaults to 600 seconds (10 minutes). This is intended to give the LDAP server time to recover after a failure. During the failure backoff interval, all authentication requests will be IGNOREd.', 
  1],

 'HoldServerConnection'  => 
 ['flag', 
  'Forces this module to hold the connection to the LDAP server up for as long as possible. Only some LDAP servers support this behaviour (notably University of Michigan, Netscape, Open Directory and Novell eDirectory), but for those servers it can significantly improve performance, especially where UseTLS or UseSSL is enabled. If you enable this parameter and you start to get odd behaviour from your AuthBy LDAP, you are probably using an unsupported LDAP server, and you should not use this parameter on it.', 
  1],

 'NoBindBeforeOp'	     => 
 ['flag', 'Prevents AuthBy LDAP2 from binding with the AuthDN and password prior to a search operation.', 
  2],

 'Scope'                 => 
 ['string', 
  'Controls the search scope used during LDAP searches.', 
  1],

 'SSLVerify'             => 
 ['string', 
  'May be used with the UseSSL or UseTLS parameters to control how the LDAP server\'s certificate will be verified.', 
  1],

 'SSLCiphers'            => 
 ['string', 
  'Specify which subset of cipher suites are permissible for this connection, using the standard OpenSSL string format. The default value is \'ALL\', which permits all ciphers, even those that don\'t encrypt.', 
  1],

 'SSLCAPath'             => 
 ['string', 'When verifying the LDAP server\'s certificate, set this to the pathname of the directory containing CA certificates. These certificates must all be in PEM format. The directory in must contain certificates named using the hash value of the certificates\' subject names. ', 
  1],

 'SSLCAFile'             => 
 ['string', 
  'When verifying the LDAP server\'s certificate, set this to the filename containing the certificate of the CA who signed the server\'s certificate. The certificate must all be in PEM format.', 
  1],

 'SSLCAClientCert'       => 
 ['string', 
  'When UseSSL or UseTLS are enabled, specifies the path to the client certificate to use to authenticate the connection to the LDAP server', 
  1],

 'SSLCAClientKey'        => 
 ['string', 
  'When UseSSL or UseTLS are enabled, specifies the path to the PEM file containing the client\'s unencrypted private key', 
  1],

 'Version'               => 
 ['integer', 
  'Sets the LDAP version number to use. Cuurently supported values are 2 and 3. Defaults to 2. Setting Version to 3 may be useful for connecting to Microsoft Active Directory. Available in AuthBy LDAP2 only. OpenLDAP 2 requires Version 3 unless you have \`allow bind_v2\' in your slapd.conf', 
  1],

 'Deref'                 => 
 ['string', 
  'By default aliases are dereferenced to locate the base object for the search, but not when searching subordinates of the base object. This may be changed by specifying the Deref parameter', 1],

 'SearchFilter'          => 
 ['string', 
  'For advanced applications, you can completely alter the search filter that Radiator will use by using the optional SearchFilter parameter. It allows you to use arbitrarily complicated LDAP search filters to select or exclude users based on attributes other than their user name. Special formatting characters are permitted, and %0 is replaced by UsernameAttr and %1 by the user name. ', 1],

 'UseSASL'               => 
 ['flag', 
  'Tells Radiator to request SASL authentication of the connection to the LDAP server instead of the default simple authentication. AuthDN and AuthPassword will be used as the SASL credentials: AuthDN is the SASL user name and AuthPassword is the SASL users password.', 
  1],

 'SASLUser'              => 
 ['string', 
  'Username to use during SASL authentication of the connection to the LDAP server.', 
  1],

 'SASLPassword'          => 
 ['string', 
  'Password to use during SASL authentication of the connection to the LDAP server.', 
  1],

 'SASLMechanism'         => 
 ['string', 
  'UseSASL is enabled, this optional parameter specifies what SASL mechanism(s) are to be used to authenticate the connection to the LDAP server. SASLMechanism is a space separated list of mechanism names supported by Authen::SASL. See your SASL sytem documentation for details on what mechanisms are supported.', 
  1],
 'BindAddress'         => 
 ['string', 
  'Local address to use to bind the client side of the LDAP connection, in the form hostname[:port]. Default is 0.0.0.0.', 
  1],
 'MultiHomed'         => 
 ['flag', 
  'Controls whether the multihomed flag is used in Net::LDAP. If this is set then Net::LDAP will try all addresses for a multihomed LDAP host until one is successful. Default is true (set).', 
  1],
 );

# RCS version number of this module
$Radius::Ldap::VERSION = '$Revision: 1.40 $';

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    my $type = ref($self);
    $self->log($main::LOG_WARNING, "No BaseDN defined for $type in '$main::config_file'")
	unless defined $self->{BaseDN};

    # Only one of UseSSL or UseTLS should be specified.  UseSSL will take priority.
    $self->log($main::LOG_WARNING, "Both UseSSL and UseTLS defined in '$main::config_file'")
	if defined($self->{UseSSL}) && defined($self->{UseTLS});

    $self->SUPER::check_config();
    return;
}

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();
    $self->{ld} = undef;
    $self->{backoff_until} = 0;

    $self->{Port} = 636 if ($self->{UseSSL} && $self->{Port} == 389);

    # TLS requires LDAPv3
    $self->{Version} = 3 if ($self->{UseTLS});
}

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{Host} = 'localhost';
    $self->{Port} = 389;
    $self->{Scope} = 'sub';
    $self->{SSLVerify} = 'require';    
    $self->{SSLCiphers} = 'ALL';
    $self->{Timeout} = 10;
    $self->{FailureBackoffTime} = 600; # Seconds
    $self->{Version} = 2; # LDAP version
    $self->{Deref} = 'find';
    $self->{SSLCAFile} = ''; # else SSLVerify none causes a crash in Socket/SSL.pm
    $self->{SASLMechanism} = 'DIGEST-MD5';
    $self->{MultiHomed} = 1;
#    $self->{BindAddress} = '0.0.0.0'; # Interferes with ipv6: and INET6
}

#####################################################################
# reconnect
# Connect or reconnect to the LDAP
# Returns true if there is a viable LDAP connection available
sub reconnect
{
    my ($self) = @_;

    # Some LDAP servers (notably imail) disconnect us after an unbind
    # so we see if we are still connected now
    $self->close_connection() 
	if ($self->{ld} && $self->{ld}->{net_ldap_socket} && !getpeername($self->{ld}->{net_ldap_socket}));

    # In case we have a persistent server connection there are events that
    # can drop this connection. Possible causes could be a firewall timeout
    # sending a RST or ICMP Message or an LDAP Server 'Idletimeout' with or
    # without an unsolicited notification 'Notice of Disconnection'.
    # Unfortunately Net::LDAP does not have any sane way to handle all but
    # the 'Notice of Disconnection' before any operation like search().
    # All you get is an LDAP_OPERATIONS_ERROR afterwards.
    # Work aroudn this if we have a 'valid' persistent server connection.
    if ($self->{HoldServerConnection} && $self->{ld} && $self->{ld}->socket()) 
    {
	# See if there is any pending input
	# (which should not be the case with sync operation).
	my $rin = '';
	vec($rin, fileno($self->{ld}->socket()), 1) = 1;
	my $nfound = select($rin, undef, undef, 0);
	# There is something to read but we did not expect anything. EOL?
	if ($nfound) 
	{
	    # Let Net::LDAP read the incoming data (message).
	    # _recvresp is an alias for process, which is only available
	    # in  perl-ldap >= 0.35. Thanks to Ernst Oudhof.
	    my $code = $self->{ld}->_recvresp();
	    if ($code == Net::LDAP::Constant->LDAP_OPERATIONS_ERROR && $@ eq 'Unexpected EOF') 
	    {
		$self->log($main::LOG_INFO, "Server side disconnect (server $self->{connectedHost}).");
		# Cleanly shutdown the socket using Net::LDAP function.
		$self->{ld}->_drop_conn($self->{ld}, Net::LDAP::Constant->LDAP_SERVER_DOWN, "Server side disconnect");
		# Also clear our LDAP handle.
		$self->close_connection();
	    }
	}
    }

    return 1 if $self->{ld}; # We are already connected
    return 0 if time < $self->{backoff_until};

    my $host = &Radius::Util::format_special($self->{Host});
    my $useInet6 = 0;
    if ($host =~ /^ipv6:(.*)/)
    {
	$host = $1;
	$useInet6 = 1;
    }
    my $port = &Radius::Util::get_port(&Radius::Util::format_special($self->{Port}));

    # Permit multiple space separated host names so Net::LDAP will connect to the first available host
    # Patch from Raphael Luta
    my @host = ();
    foreach(split(/ /,$host))
    {
	# If we are using GSSAPI, then the host we are connecting to has to match an RDNS entry.
	if ($self->{UseSASL} && $self->{SASLMechanism} eq 'GSSAPI')
	{
		my $resolved_host = &Radius::Util::gethostbyaddr(&Radius::Util::inet_pton($_));

		# It's quite possible that the forward or reverse DNS fails.
		unless ($resolved_host)
		{
		    $self->log($main::LOG_INFO, "Forward or reverse resolution of $_ failed.");
		    next;
		}

		unless ($_ eq $resolved_host)
		{
		    $self->log($main::LOG_INFO, "$_ resolves to $resolved_host and will be used for GSSAPI.");
		    $_ = $resolved_host;
		}
	}

	push @host, "$_:$port" if $_;
    }

    # It's pretty bad if we end up with an empty list of servers.
    unless (@host)
    {
	$self->log($main::LOG_ERR, "None of the entries in $host could be resolved.");
	return 0;
    }

    $host = \@host;

    $self->log($main::LOG_INFO, "Connecting to " . join(' ', @host) );
    $self->{bound} = undef;
    if ($self->{UseSSL})
    {
	require Net::LDAPS;
	my %args;
	$args{clientcert} = &Radius::Util::format_special($self->{SSLCAClientCert}) if defined $self->{SSLCAClientCert};
	$args{clientkey} = &Radius::Util::format_special($self->{SSLCAClientKey}) if defined $self->{SSLCAClientKey};
	$args{cafile} = &Radius::Util::format_special($self->{SSLCAFile}) if defined $self->{SSLCAFile};
	$args{capath} = &Radius::Util::format_special($self->{SSLCAPath}) if defined $self->{SSLCAPath};
	$self->{ld} = new Net::LDAPS
	    ($host,
	     inet6 => $useInet6,
	     port => $port,
	     timeout => $self->{Timeout},
	     verify => $self->{SSLVerify},
	     ciphers => $self->{SSLCiphers},
	     version => $self->{Version},
	     localaddr => $self->{BindAddress},
	     multihomed => $self->{MultiHomed} ? 1 : 0,
	     %args);
    }
    else
    {
	$self->{ld} = new Net::LDAP
	    ($host,
	     inet6 => $useInet6,
	     port => $port,
	     timeout => $self->{Timeout},
	     version => $self->{Version},
	     localaddr => $self->{BindAddress},
	     multihomed => $self->{MultiHomed} ? 1 : 0,
	    );
	
	if ($self->{ld} && $self->{UseTLS}) 
	{
	    $self->log($main::LOG_DEBUG, 'Starting TLS');
	    $IO::Socket::SSL::SSL_Context_obj = undef; # Else get a crash in SSL.pm 2nd time
	    my %args;
	    $args{clientcert} = &Radius::Util::format_special($self->{SSLCAClientCert}) if defined $self->{SSLCAClientCert};
	    $args{clientkey} = &Radius::Util::format_special($self->{SSLCAClientKey}) if defined $self->{SSLCAClientKey};
	    $args{cafile} = &Radius::Util::format_special($self->{SSLCAFile}) if defined $self->{SSLCAFile};
	    $args{capath} = &Radius::Util::format_special($self->{SSLCAPath}) if defined $self->{SSLCAPath};
	    my $result = $self->{ld}->start_tls
		(verify => $self->{SSLVerify},
		 ciphers => $self->{SSLCiphers},
		 %args);
	    if ($result->code) 
	    {
		undef $self->{ld};
		$self->log($main::LOG_ERR, 'StartTLS failed: ' . $result->error);
	    } 
	    else 
	    {
		$self->log($main::LOG_INFO, 'StartTLS negotiated with cipher mode ' . $self->{ld}->cipher);
#		$Radius::AuthLDAP2::tls_started++;
	    }
	}
    }

    if (!$self->{ld})
    {
	$self->{backoff_until} = time + $self->{FailureBackoffTime};
	$self->log($main::LOG_ERR, 
		   "Could not open LDAP connection to " . join(' ', @host) .". Backing off for $self->{FailureBackoffTime} seconds.");
	return 0;
    }

    # If Host is configured with multiple hosts, see which one we just
    # connected to. Needs recent enough Net::LDAP
    $self->{connectedHost} = ($Net::LDAP::VERSION > 0.33) ? sprintf("%s:%s", $self->{ld}->host(), $self->{ld}->port()) : $self->{Host};
    $self->log($main::LOG_INFO, "Connected to $self->{connectedHost}");

    $self->{ld}->debug($self->{Debug}) if $self->{Debug};

    return 1;  # LDAP is available
}

sub bind
{
    my ($self, $name, $password) = @_;

    return 1 if (   $self->{bound}
		 || $self->{NoBindBeforeOp}); 

    return 0 if time < $self->{backoff_until};

    my $sasl;
    if ($self->{UseSASL})
    {
	eval {require Authen::SASL;};
	if ($@)
	{
	    $self->log($main::LOG_ERR, "Could not UseSASL: $@");
	}
	else
	{
	    # SASL credentials default to the credentials passed in, but can be overridden
	    my $mech  = $self->{SASLMechanism};
	    $name     = $self->{SASLUser}     unless defined $name;
	    $password = $self->{SASLPassword} unless defined $password;
	    $sasl     = Authen::SASL->new(mechanism => "$mech",
				      callback => { user => $name,
						    pass => $password});

	    # GSSAPI requires hostname to request a service ticket. By default, Authen::SASL will add
	    # the IP, so we need to override that behavior.  
	    if ($mech eq 'GSSAPI') 
	    {
		# By now, connectedHost contains the port, so let's strip that.
		my ($plain_host) = split ':', $self->{connectedHost};
	        $sasl = $sasl->client_new('ldap',$plain_host);
	    }
	}
	$self->log($main::LOG_WARNING, "Could not create SASL object to perform UseSASL during bind. Defaulting to ldap server authentication") 
	    unless $sasl;
    }

    my $result;
    my @bindargs;
    if (defined $sasl)
    {
	# SASL authentication
	@bindargs = (sasl => $sasl);
    }
    else
    {
	# LDAP server authentication. Allow for anonymous binding
	@bindargs = (dn => $name, password => $password) if length $name;
    }
    &Radius::Util::exec_timeout($self->{Timeout},
       sub {
	$self->log($main::LOG_INFO, "Attempting to bind to LDAP server $self->{connectedHost}");
	$result = $self->{ld}->bind(@bindargs);
    });

    if (!$result || $result->code())
    {
	my $code = $result ? $result->code() : -1;
	my $errname = Net::LDAP::Util::ldap_error_name($code);
	$errname = 'LDAP Timeout' if $@ && $@ =~ /timeout/;

	# Log SASL errors.
	my $saslerror = defined $sasl ? " SASL error: " . $sasl->error : "";

	$self->log($main::LOG_ERR, 
		   "Could not bind connection with $name, $password, error: $errname (server $self->{connectedHost})." . $saslerror);

	$self->{backoff_until} = time + $self->{FailureBackoffTime};
	$self->log($main::LOG_ERR, "Backing off from $self->{connectedHost} for $self->{FailureBackoffTime} seconds.");
	$self->close_connection();
	return 0;
    }

    return $self->{bound} = 1; # Success
}

#####################################################################
sub unbind
{
    my ($self) = @_;

    $self->{ld}->unbind() if $self->{ld};
    $self->{ld} = undef;
    $self->{bound} = undef;
    return 1;
}

#####################################################################
# Force closure of the LDAP server connection.
# This is a bit ugly in order to deal with the various diffferent ways
# perl-ldap has dealt with sockets over earlier versions
sub close_connection
{
    my ($self) = @_;

    close($self->{ld}->{net_ldap_socket}) 
	if $self->{ld} && $self->{ld}->{net_ldap_socket};
    $self->{ld} = undef;
}

#####################################################################
# Support for Novell eDirectory Universal Password.
# Novell eDirectory permits fetching of the plaintext password
# provided 'Universal Password' is enabled, The Password Policy covering 
# the user has the "Allow password retrieval by admin", and the user has
# had their Universal Password set
my $passwordReq;
my $passwordRes;
my $authReq;
my $authRes;
my $NOVELL_SUCCESS = 0;
my %errorcodes =
(
 # these codes from https://summersoft.fay.ar.us/repos/ethereal/branches/redhat-9/ethereal-0.10.3-1/ethereal-0.10.3/packet-ncp-nmas.c
 -1631 => '(-1631) Fragment failure',
 -1632 => '(-1632) Bad request syntax',
 -1633 => '(-1633) Buffer overflow',
 -1634 => '(-1634) System resources',
 -1635 => '(-1635) Insufficient memory',
 -1636 => '(-1636) Not supported',
 -1637 => '(-1637) Buffer underflow',
 -1638 => '(-1638) Not found',
 -1639 => '(-1639) Invalid operation',
 -1640 => '(-1640) ASN1 decode',
 -1641 => '(-1641) ASN1 encode',
 -1642 => '(-1642) Login failed',
 -1643 => '(-1643) Invalid parameter',
 -1644 => '(-1644) Timed out recoverable',
 -1645 => '(-1645) Timed out not recoverable',
 -1646 => '(-1646) Timed out unknown',
 -1647 => '(-1647) Authorization failure',
 -1648 => '(-1648) Invalid distingushed name',
 -1649 => '(-1649) Cannot resolve distinguished name',
 -1650 => '(-1650) Cannot resolve connection',
 -1651 => '(-1651) No cryptography',
 -1652 => '(-1652) Invalid version',
 -1653 => '(-1653) Sync needed',
 -1654 => '(-1654) Protocol state',
 -1655 => '(-1655) Invalid handle',
 -1656 => '(-1656) Invalid method',
 -1657 => '(-1657) Development version',
 -1658 => '(-1658) Missing key',
 -1659 => '(-1659) Access not allowed',
 -1660 => '(-1660) Sequence not found',
 -1661 => '(-1661) Clearance not found',
 -1662 => '(-1662) Login server method not found',
 -1663 => '(-1663) Login client method not found',
 -1664 => '(-1664) Server not found',
 -1665 => '(-1665) Login attribute not found',
 -1666 => '(-1666) Legacy invalid password',
 -1667 => '(-1667) Account disabled',
 -1668 => '(-1668) Account locked',
 -1669 => '(-1669) Address restriction',
 -1670 => '(-1670) Connection cleared',
 -1671 => '(-1671) Time restriction',
 -1672 => '(-1672) Short term secret',
 -1673 => '(-1673) No nmas on tree',
 -1674 => '(-1674) No nmas on server',
 -1675 => '(-1675) Request challenged',
 -1676 => '(-1676) Login canceled',
 -1677 => '(-1677) Local credential store',
 -1678 => '(-1678) Remote credential store',
 -1679 => '(-1679) Smc nicm',
 -1680 => '(-1680) Sequence not authorized',
 -1681 => '(-1681) Transport',
 -1682 => '(-1682) Crypto failed init',
 -1683 => '(-1683) Doublebyte failed init',
 -1684 => '(-1684) Codepage failed init',
 -1685 => '(-1685) Unicode failed init',
 -1686 => '(-1686) Dll failed loading',
 -1687 => '(-1687) Evaluation version warning',
 -1688 => '(-1688) Concurrent login',
 -1689 => '(-1689) Thread create',
 -1690 => '(-1690) Secure channel required',
 -1691 => '(-1691) No default user sequence',
 -1692 => '(-1692) No treename',
 -1693 => '(-1693) Mechanism not found',
 -1694 => '(-1694) Account not activated',
 -1695 => '(-1695) Incompatible login data',
 -1696 => '(-1696) Password history full',
 -1697 => '(-1697) Invalid SPM request',
 -1698 => '(-1698) Password Mismatch',
 -1699 => '(-1699) Obsolete method',

 # these deduced from behaviour
 -601  => '(-601) No such entry',
 -603  => '(-603) No such attribute. Universal password not set?',
 -1659 => '(-1659) Access not allowed. Allow password retrieval by admin not enabled?',
 -1697 => '(-1697) Invalid spm request. Universal password not enabled on container?',
 -4998 => '(-4998) ConnectionXS not authenticated',
 );
my $NMAS_LDAP_EXT_VERSION          = 1;
my $NMASLDAP_GET_PASSWORD_REQUEST  = '2.16.840.1.113719.1.39.42.100.13';
my $NMASLDAP_GET_PASSWORD_RESPONSE = '2.16.840.1.113719.1.39.42.100.14';
my $RADAUTH_LDAP_EXT_VERSION       = 1;
my $RADAUTH_OID_NMAS_AUTH_REQUEST  = '2.16.840.1.113719.1.510.100.1';
my $RADAUTH_OID_NMAS_AUTH_REPLY    = '2.16.840.1.113719.1.510.100.2';

$Radius::Ldap::RADAUTH_AUTHSTATE_ACCEPTED   = 0;
$Radius::Ldap::RADAUTH_AUTHSTATE_CHALLENGED = 1;
$Radius::Ldap::RADAUTH_AUTHSTATE_REJECTED   = 2;

# Convert a Novell error code into a printable string.
sub get_error_code
{
    my ($code) = @_;

    return $errorcodes{$code} || "($code) UNKNOWN NOVELL ERROR CODE";
}

# Fetch the Universal Password for the DN given.
# Returns the password or undef;
sub nmasldap_get_password
{
    my ($self, $dn) = @_;

    # Prepare ASN decoders if not already done
    if (!$passwordReq)
    {
	$passwordReq = Convert::ASN1->new;
	$passwordReq->prepare(q<SEQUENCE {
	    extversion  INTEGER,
	    objectdn    OCTET STRING
	    }>);
    }
    if (!$passwordRes)
    {
	$passwordRes = Convert::ASN1->new;
	$passwordRes->prepare(q<SEQUENCE {
	    serverversion    INTEGER,
	    errorcode        INTEGER,
	    password         OCTET STRING OPTIONAL
	    }>);
    }

    my $result;
    &Radius::Util::exec_timeout($self->{Timeout},
       sub {
    $result = $self->{ld}->extension
	(name => $NMASLDAP_GET_PASSWORD_REQUEST,
	 value => $passwordReq->encode
	 (extversion => $NMAS_LDAP_EXT_VERSION,
	  objectdn => $dn));
       });

    if (!$result || $result->code())
    {
	my $code = $result ? $result->code() : -1;
	my $errname = Net::LDAP::Util::ldap_error_name($code);
	$errname = 'LDAP Timeout' if $@ && $@ =~ /timeout/;
	my $errorstring =  $result ? $result->error() : '';
	$self->log($main::LOG_ERR, "nmasldap_get_password for $dn could not do LDAP extension: $errname: $errorstring");
	return;
    }

    my $out = $passwordRes->decode($result->response());
    if (!$out)
    {
	my $error = $passwordRes->error();
	$self->log($main::LOG_ERR, "nmasldap_get_password for $dn could not decode response: $error");
	return;
    }

    my $resultoid = $result->response_name();
    if ($resultoid ne $NMASLDAP_GET_PASSWORD_RESPONSE)
    {
	$self->log($main::LOG_ERR, "nmasldap_get_password for $dn got incorrect response: $resultoid ");
	return;
    }

    if ($out->{serverversion} != $NMAS_LDAP_EXT_VERSION)
    {
	$self->log($main::LOG_ERR, "nmasldap_get_password for $dn got incorrect server version: $out->{serverversion}");
	return;
    }

    if ($out->{errorcode} != $NOVELL_SUCCESS)
    {
	my $error = get_error_code($out->{errorcode});
	$self->log($main::LOG_ERR, "nmasldap_get_password for $dn error code: $error");
	return;
    }
    
    # Finally, everything is OK:
    return $out->{password};
}

#####################################################################
# Do NMAS authentication
# Experimental and incomplete
sub nmasldap_authenticate
{
    use Radius::ASN1;
    my ($self, $dn, $sequence, $password, $challenge) = @_;

    # Prepare ASN encoders if not already done
    if (!$authReq)
    {
	$authReq = Convert::ASN1->new;
	$authReq->prepare(q<SEQUENCE {
	    extversion   INTEGER,
	    objectdn     OCTET STRING,
            password     OCTET STRING,
            sequence     OCTET STRING,
            nasip        OCTET STRING,
            statepresent INTEGER,
            state        OCTET STRING
	    }>);
    }

    my $result;
    &Radius::Util::exec_timeout($self->{Timeout},
       sub {
    $result = $self->{ld}->extension
	(name => $RADAUTH_OID_NMAS_AUTH_REQUEST,
	 value => $authReq->encode
	 (extversion => $RADAUTH_LDAP_EXT_VERSION,
	  objectdn => $dn,
	  password => $password,
          sequence => $sequence,
	  nasip => '1.2.3.4',
          statepresent => 0,
	  state => defined $challenge ? $challenge : ''
	 )
	);
       });

    if (!$result || $result->code())
    {
	# This usually indicates bad password or token :-(
	# And usually there is a 3 second delay imposed by the server if the password is wrong :-(
	# So we will only log this at INFO level
	my $code = $result ? $result->code() : -1;
	my $errname = Net::LDAP::Util::ldap_error_name($code);
	$errname = 'LDAP Timeout' if $@ && $@ =~ /timeout/;
	my $errorstring =  $result ? $result->error() : '';
	$self->log($main::LOG_INFO, "nmasldap_authenticate for $dn could not do LDAP extension: $errname: $errorstring");
	return ($Radius::Ldap::RADAUTH_AUTHSTATE_REJECTED, 'Rejected by NMAS');
    }

    # Sigh: there is a big problem with the LDAP response from NMAS:
    # It contains a sequence with the error code, auth_state and maybe challenge, but 
    # NMAS makes it 1024 octets long and fills the rest with rubbish which confuses 
    # Convert::ASN1 decoder
    # Can make it work a bit by patching Convert/ASN1/_decode.pm
    # But better: we have our own primitive BER decoder with just enough sense to decode 
    # the simple responses from NMAS
    my $response = Radius::ASN1::decode($result->response());
    if (!$response || @{$response} != 1)
    {
	$self->log($main::LOG_ERR, "nmasldap_authenticate for $dn could not decode response");
	return ($Radius::Ldap::RADAUTH_AUTHSTATE_REJECTED, "nmasldap_authenticate for $dn could not decode response");
    }

    # Expect [ [int, int]] or [ [int, int, string]]
    # Expect 2 integers: errCode, auth_state, and maybe a string, the challenge
    my $errorcode = $$response[0][0];
    my $authstate = $$response[0][1];
    my $newchallenge = $$response[0][2];
    if ($errorcode != $NOVELL_SUCCESS)
    {
	my $error = get_error_code($errorcode);
	$self->log($main::LOG_ERR, "NMAS Auth Request for $dn error code: $error");
	return ($Radius::Ldap::RADAUTH_AUTHSTATE_REJECTED, "NMAS Auth Request for $dn error code: $error");
    }

    if ($authstate == $Radius::Ldap::RADAUTH_AUTHSTATE_ACCEPTED)
    {
	return ($Radius::Ldap::RADAUTH_AUTHSTATE_ACCEPTED);
    }
    elsif  ($authstate == $Radius::Ldap::RADAUTH_AUTHSTATE_CHALLENGED)
    {	
	return ($Radius::Ldap::RADAUTH_AUTHSTATE_CHALLENGED, $newchallenge);
    }
    elsif  ($authstate == $Radius::Ldap::RADAUTH_AUTHSTATE_REJECTED)
    {
	return ($Radius::Ldap::RADAUTH_AUTHSTATE_REJECTED, 'Rejected by NMAS authstate');
    }
    else
    {
	$self->log($main::LOG_ERR, "NMAS Auth Request unknown authstate: $authstate");
	return ($Radius::Ldap::RADAUTH_AUTHSTATE_REJECTED, "NMAS Auth Request unknown authstate: $authstate");
    }
    return 1;
}

#####################################################################
# Escape LDAP special characters in an LDAP literal value as per
# http://msdn.microsoft.com/library/default.asp?url=/library/en-us/adsi/adsi/search_filter_syntax.asp
sub escapeLdapLiteral
{
    my ($self, $s) = @_;

    # convert * ( ) \ and / to \xx
    $s =~ s/(\*|\(|\)|\\|\/| )/sprintf('\\%02x', ord($1))/eg;
    return $s;
}

1;





