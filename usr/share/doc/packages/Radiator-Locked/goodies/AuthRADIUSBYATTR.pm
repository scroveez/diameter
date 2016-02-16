# AuthRADIUSBYATTR.pm
#
# Object for handling Authentication with remote radius servers.
# Looks up Radius information based on Attributes defined in the 
# Radius packet.
#

package Radius::AuthRADIUSBYATTR;
@ISA = qw(Radius::AuthRADIUS);
use Radius::AuthRADIUS;
use strict;

%Radius::AuthRADIUSBYATTR::ConfigKeywords = 
    (
      'StartHost'           => 'integer',
      'HostsInfoAttribute'  => 'string',
      'HostAttrDef'         => 'stringhash',
    );

#####################################################################
# Do per-instance default initialization
sub initialize {
  my ($self) = @_;

  $self->SUPER::initialize;
  $self->{StartHost} = 0;
  $self->{HostsInfoAttribute} = 'RadiusHosts'; # Formatted Attribute containing multiple hosts; overrides Host, Secret, AuthPort & AcctPort definitions
}

#####################################################################
# chooseHost selects which host to use to send a packet to.
# Choose the next host to send to. 
# Returns a ref to a Radius::Host object.
sub chooseHost 
{
    my ($self, $fp, $p) = @_;

    # initialize or increment hostCounter 
    $fp->{hostCounter} = defined($fp->{hostCounter}) ? $fp->{hostCounter} + 1 : $self->{StartHost};
    
    # initialize hosts list from Radius Attribute
    my $hostsinfo = $p->get_attr($self->{HostsInfoAttribute});
    
    my ($hostval,$secret,$authport,$acctport);
    # check HostsInfoAttribute data else use HostAttrDef
    if ($hostsinfo ne '') {
	my @hostarry = split(/\|/, $hostsinfo);
	my $hostcnt = scalar(@hostarry);
	
	# if hostCounter > number of hosts then return, indicating
	# no more available hosts to send to
	return if $fp->{hostCounter} >= $hostcnt;
	
	# parse hostinfo and return next target host
	($hostval,$authport,$acctport,$secret) = split(/\:/,@hostarry[$fp->{hostCounter}]);
    }
    
    # parse HostAttrDef
    my ($keywd, %args);
    if (defined $self->{HostAttrDef}) {
	foreach $keywd (keys %{$self->{HostAttrDef}}) {
	    my $attrib = $self->{HostAttrDef}{$keywd};
	    
	    # assign Host,Secret,AuthPort & AcctPort if not defined by HostsInfoAttribute
	    if (($attrib eq 'Host') && ($hostval eq '')) {
		my @hostarry = split(/\,/, $p->get_attr($attrib));
		my $hostcnt = scalar(@hostarry);
		
		# if hostCounter > number of hosts then return, indicating
		# no more available hosts to send to
		return if $fp->{hostCounter} >= $hostcnt;
		
		$hostval = @hostarry[$fp->{hostCounter}];
	    } elsif (($attrib eq 'Secret') && ($secret eq '')) {
		$secret = $p->get_attr($attrib);
	    } elsif (($attrib eq 'AuthPort') && ($authport eq '')) {
		$authport = $p->get_attr($attrib);
	    } elsif (($attrib eq 'AcctPort') && ($acctport eq '')) {
		$acctport = $p->get_attr($attrib);
	    } 
	    # assign Additional Host Attributes
	    else {
		$args{$keywd} = $p->get_attr($attrib);
	    }
	}
    }
    
    # set identifier for current host
    if ($hostval ne '') { $args{Identifier} = $hostval.'_'.$authport.'_'.$acctport; }
    
    # return if NoForwardAccounting Set
    return ($main::ACCEPT) if $args{'NoForwardAccounting'};
    
    # return if no host information found
    return if ($hostval eq '');
    
    my $host = Radius::Host->new
	(undef,  $hostval,
	 'Secret'                     => $secret,
	 'AuthPort'                   => $authport,
	 'AcctPort'                   => $acctport,
	 %args
	 );
    
    return $host;
}

#####################################################################
# Override so that we can rewrite the username and handle request
# attribute changes
sub sendHost 
{
    my ($self, $host, $fp, $p) = @_;

    # rewrite username using RewriteFunction if possible
    if (defined $host->{RewriteUsername}) {
	my $un = $p->getUserName;
	my $rw = eval $host->{RewriteUsername};
	$un =~ /$rw/;
	my $name = $1;
	$p->changeUserName($name);
	&main::log($main::LOG_DEBUG, "$host->{RewriteUsername}");
	&main::log($main::LOG_DEBUG, "Username $un changed to $name");
    }
    
    # Add and strip attributes before forwarding.
    map {$fp->delete_attr($_)} (split(/\s*,\s*/, $host->{StripFromRequest}))
	if defined $host->{StripFromRequest};
    
    if (defined $host->{AddToRequest}) {
	my $s = &Radius::Util::format_special($host->{AddToRequest}, $p);
	$fp->parse($s);
    }
    
    if (defined $host->{AddToRequestIfNotExist}) {
	my $s = &Radius::Util::format_special($host->{AddToRequestIfNotExist}, $p);
	$fp->parse($s);
    }
    
    return $self->SUPER::sendHost($host, $fp, $p, $p->{rp});
}

1;
