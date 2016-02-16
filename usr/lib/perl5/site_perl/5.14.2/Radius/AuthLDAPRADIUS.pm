# AuthLDAPRADIUS.pm
#
# Object for handling Authentication with remote radius servers.
# Looks up the target radius server from an LDAP database
# based on the realm.
#
# A sample LDAP schema and example data can be found in goodies/radiator-ldap.schema 
# and goodies/radiator-ldap.ldif
# An example config file can be found in goodies/ldapradius.cfg.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001-2004 Open System Consultants
# $Id: AuthLDAPRADIUS.pm,v 1.8 2013/08/13 20:58:45 hvn Exp $
package Radius::AuthLDAPRADIUS;
@ISA = qw(Radius::AuthRADIUS Radius::Ldap);
use Radius::Ldap;
use Radius::AuthRADIUS;
use strict;

%Radius::AuthLDAPRADIUS::ConfigKeywords = 
('NumHosts'      => 
 ['integer', 'This parameter defines the maximum number of times that SearchFilter will be called for as given request. If NumHosts is exceeded for a given request, the proxying of the request fails. Defaults to 1. The current count is available as %0 in SearchFilter and HostAttrDef.', 1],

 'Host'                  => 
 ['string', 
  'Name of the LDAP host to connect to. Special formatting characters are permitted.', 
  0],

 'StartHost'     => 
 ['integer', 'The initial value for the host counter', 1],

 'HostAttrDef'   => 
 ['stringhash', 'This optional parameter specifies which parameters to get from an LDAP record and how they are to be used to set the parameters of the Radiator Host clause for proxying. Format is 
<p><code><pre>ldapattrname,hostparamname</pre></code><p>
where ldapattrname is the name of the LDAP attribute to fetch and hostparamname is the name of the Radiator Host clause parameter it will be used to set. ', 1],

 );

# RCS version number of this module
$Radius::AuthLDAPRADIUS::VERSION = '$Revision: 1.8 $';

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    # Multiple inheritance:
    $self->Radius::AuthRADIUS::check_config();
    $self->Radius::Ldap::check_config();
    return;
}

#####################################################################
sub activate
{
    my ($self) = @_;

    # Multiple inheritance:
    # Dont activate with Radius::AuthRADIUS as it thinks Host is an array
    # and causes a crash later
    $self->Radius::Ldap::activate();
}

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    # Multiple inheritance:
    $self->Radius::AuthRADIUS::initialize();
    $self->Radius::Ldap::initialize();

    $self->{SearchFilter} = '(oscRadiusTarget=%R)';
    $self->{NumHosts} = 1; # Max number of LDAP searches per request
    $self->{StartHost} = 1; # First host number
}

#####################################################################
# Override the object function in Configurable
sub object
{
    my ($self, @args) = @_;
    $self->Radius::AuthRADIUS::object(@args);
}
#####################################################################
# chooseHost selects which host to use to send a packet to
# Choose the next host to send to. Default implementation chooses
# the next HOSTn column in the SQL table until hostCounter
# reaches NumHosts.
# Returns a ref to a Radius::Host object.
sub chooseHost
{
    my ($self, $fp, $p) = @_;

    # (Re)-connect to the database if necessary, 
    # No reply will be sent to the original requester if we 
    # fail to connect
    return unless $self->reconnect;

    my $authdn = &Radius::Util::format_special($self->{AuthDN}, $p);
    my $authpassword = &Radius::Util::format_special($self->{AuthPassword}, $p);
    return unless $self->bind($authdn, $authpassword);
    
    # initialize or increment hostCounter 
    $fp->{hostCounter} = defined($fp->{hostCounter}) ? $fp->{hostCounter} + 1 : $self->{StartHost};

    # If they have already tried to send this too many times, and there
    # are no more hosts to send to take the policy from the database
    # This standard table has space for 2 hosts. Adjust this if necessary
    return if $fp->{hostCounter} >= ($self->{NumHosts} + $self->{StartHost});

    # Default HostAttrDef are compatible with the default behaviour
    # of AuthBy LDAPRADIUS and the example LDAP schema
    %{$self->{HostAttrDef}}  = (oscRadiusHost                       => 'Host',
				oscRadiusSecret                     => 'Secret',
				oscRadiusAuthPort                   => 'AuthPort',
				oscRadiusAcctPort                   => 'AcctPort',
				oscRadiusRetries                    => 'Retries',
				oscRadiusRetryTimeout               => 'RetryTimeout',
				oscRadiusUseOldAscendPasswords      => 'UseOldAscendPasswords',
				oscRadiusServerHasBrokenPortNumbers => 'ServerHasBrokenPortNumbers',
				oscRadiusServerHasBrokenAddresses   => 'ServerHasBrokenAddresses',
				oscRadiusIgnoreReplySignature       => 'IgnoreReplySignature',
				oscRadiusFailurePolicy              => 'failurePolicy') 
	unless defined  $self->{HostAttrDef};

    # HostAttrDef is subject to special character conversion, mainly so that
    # hostCounter can be used to select differnt LDAP attributes on the first, second etc searches
    # in order to find primary and secondary hosts and secrets
    my %defs;
    foreach (keys %{$self->{HostAttrDef}})
    {
	$defs{&Radius::Util::format_special($_, $p, undef, $fp->{hostCounter})} = ${$self->{HostAttrDef}}{$_};
    }

    # The keys of HostAttrDef are the (now translated) names of the LDAP attributes to fetch
    my @attrs = (keys %defs);

    my $filter = &Radius::Util::format_special
	($self->{SearchFilter}, 
	 $p, undef, 
	 $fp->{hostCounter});
    my $basedn = &Radius::Util::format_special
	($self->{BaseDN}, 
	 $p, undef, 
	 $fp->{hostCounter});
    $self->log($main::LOG_DEBUG, "LDAPRADIUS SearchFilter: $filter, BaseDN: $basedn, attrs: @attrs", $p);
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
		attrs => \@attrs);
	   
       });

    # $result is an object of type Net::LDAP::Search
    if (!$result || $result->code() != Net::LDAP::LDAP_SUCCESS)
    {
	my $code = $result ? $result->code() : -1;
	my $errname = Net::LDAP::Util::ldap_error_name($code);
	$errname = 'LDAP Timeout' if $@ && $@ =~ /timeout/;
	$self->log($main::LOG_ERR, "LDAPRADIUS search failed with error $errname.", $p);
	if ($errname eq  'LDAP_NO_SUCH_OBJECT')
	{
	    # No record there, cant proxy
	    return;
	}
	elsif ($errname eq  'LDAP_PARAM_ERROR')
	{
	    # Something unpleasant in the realm?
	    $self->log($main::LOG_ERR, "LDAP_PARAM_ERROR", $p);
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
	
    # We only use the first returned record
    my $entry = $result->entry(0);
    if ($entry)
    {
	my $dn = $entry->dn;
	$self->log($main::LOG_DEBUG, "LDAP got result for $dn", $p);
	
	my ($attr, $host, %args);
	foreach $attr ($entry->attributes())
	{
	    # This should work for ldap-perl before and after 0.20
	    # vals is now a reference to an array
	    my $vals = $entry->get($attr);

	    # Some LDAP servers (MS) leave trailing NULs
	    map s/\0$//, @$vals;

	    $self->log($main::LOG_DEBUG, "LDAP got $attr: @$vals", $p);

	    my $attrib = $defs{$attr}; # The config parameter for the Host object
	    if ($attrib eq 'Host') 
	    {
		$host = $$vals[0];
	    }
	    elsif ($attrib eq 'failurePolicy')
	    {
		$fp->{failurePolicy} = $$vals[0];
	    }
	    elsif ($attrib eq 'RewriteUsername')
	    {
		# Has to be an array.
		push(@{$args{$attrib}}, @$vals);
	    }
	    else
	    {
		$args{$attrib} = $$vals[0];
	    }
	}
	return if $host eq ''; # No LDAP parameter mapped to Host name
	my $h = Radius::Host->new(undef, $host, %args);
	$h->activate();
	return $h;
    }
    else
    {
	# Call the superclass to fall back to any hardwired
	# hosts.
	return $self->SUPER::chooseHost($fp, $p, $p->{rp});
    }
}

#####################################################################
# Override so that we can rewrite the username if the SQL database
# contained a rewrite field.
sub sendHost
{
    my ($self, $host, $fp, $p) = @_;

    $fp->rewriteUsername($host->{RewriteUsername})
	if defined $host->{RewriteUsername};

    # Add and strip attributes before forwarding.
    map {$fp->delete_attr($_)} (split(/\s*,\s*/, $host->{StripFromRequest}))
	if defined $host->{StripFromRequest};

    $fp->delete_attr_fn
        (sub {!grep($_[0] eq $_, 
                    split(/\s*,\s*/, $host->{AllowInRequest}))})
            if defined $host->{AllowInRequest};

    if (defined $host->{AddToRequest})
    {
        my $s = &Radius::Util::format_special($host->{AddToRequest}, $p);
        $fp->parse($s);
    }

    return $self->SUPER::sendHost($host, $fp, $p, $p->{rp});
}

#####################################################################
# Called when no reply is received fromn any of the attempted
# hosts. 
# Look at the failure policy we recorded from the database
# and maybe implement it
sub noreply
{
    my ($self, $fp, $p) = @_;

    # Call the NoReply hook if there is one, you could adjust the pending reply here
    $self->SUPER::noreply($fp, $p, $p->{rp});

    if (defined $fp->{failurePolicy})
    {
	# The database told us how to deal with failure
	$self->adjustReply($p);
	
	$p->{Handler}->handlerResult($p, $fp->{failurePolicy}, 'LDAPRADIUS Proxy failed');
    }
    return;
}

1;
