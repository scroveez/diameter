# AuthSQLRADIUS.pm
#
# Object for handling Authentication with remote radius servers.
# Looks up the target radius server from an SQL database
# based on the realm.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2001 Open System Consultants
# $Id: AuthSQLRADIUS.pm,v 1.24 2013/08/13 20:58:45 hvn Exp $
package Radius::AuthSQLRADIUS;
@ISA = qw(Radius::AuthRADIUS Radius::SqlDb);
use Radius::SqlDb;
use Radius::AuthRADIUS;
use strict;

%Radius::AuthSQLRADIUS::ConfigKeywords = 
('HostSelect'      => 
 ['string', 'This parameter defines the SQL statement that will be run to determine the details of the target RADIUS server. It is run for each request that is handled by the AuthBy. If no reply is received by the target RADIUS server for a given request, it will be rerun to find a secondary server, and so on until either HostSelect returns no more rows, or the number of times exceeds NumHosts.', 0],

 'HostSelectParam' => 
 ['stringarray', 'This optional parameter enables the use of bound variables (where supported by the SQL server) and query caching. If you specify one or more HostSelectParam parameters, they will be used in order to replace parameters named with a question mark ("?") in HostSelect, and the query will be cached for future reuse by the SQL server. Only the first QueryCacheSize queries will be cached.', 1],

 'NumHosts'        => 
 ['integer', 'This parameter defines the maximum number of times that HostSelect will be called for as given request. If NumHosts is exceeded for a given request, the proxying of the request fails. Defaults to 2. The current count is available as %0 in HostSelect.', 1],

 'StartHost'       => 
 ['integer', 'The initial host number', 1],

 'HostColumnDef'   => 
 ['stringhash', 'This optional parameter allows you to specify an alternate mapping between the fields returned by HostSelect and the parameters used to define the Host. If HostColumnDef is not specified, the mapping is the default as described in HostSelect in the Radiator reference manual', 1],

 );

# RCS version number of this module
$Radius::AuthSQLRADIUS::VERSION = '$Revision: 1.24 $';

# Cached host failure numbers for determining backoff etc:
%Radius::AuthSQLRADIUS::cached_stats = ();
my @cached_stats = ('failedRequests', 'start_failure_grace_time', 'backoff_until');

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    $self->Radius::AuthRADIUS::check_config();
    $self->Radius::SqlDb::check_config();
    return;
}

#####################################################################
sub activate
{
    my ($self) = @_;

    # Multiple inheritance:
    $self->Radius::AuthRADIUS::activate();
    $self->Radius::SqlDb::activate();
}

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    # Multiple inheritance:
    $self->Radius::AuthRADIUS::initialize();
    $self->Radius::SqlDb::initialize();
    $self->{HostSelect} = 'select HOST%0, SECRET, AUTHPORT, ACCTPORT,
RETRIES, RETRYTIMEOUT, USEOLDASCENDPASSWORDS, SERVERHASBROKENPORTNUMBERS,
SERVERHASBROKENADDRESSES, IGNOREREPLYSIGNATURE, FAILUREPOLICY from RADSQLRADIUS
where TARGETNAME=\'%R\'';
    $self->{NumHosts} = 2; # Number of hosts (primary and secodary) per realm
    $self->{StartHost} = 1; # First host number
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

    # initialize or increment hostCounter 
    $fp->{hostCounter} = defined($fp->{hostCounter}) ? $fp->{hostCounter} + 1 : $self->{StartHost};

    my $host;

    while ($fp->{hostCounter} < ($self->{NumHosts} + $self->{StartHost}))
    {
	my $sth;

	# If they have already tried to send this too many times, and there
	# are no more hosts to send to take the policy from the database
	# This standard table has space for 2 hosts. Adjust this if necessary
        my $q = Radius::Util::format_special($self->{HostSelect}, $p, $self, $fp->{hostCounter});
        if (!$self->{HostSelectParam})
        {
	    $sth = $self->prepareAndExecute($q);
	}
	else
	{
	    my @bind_values = ();

	    map (push(@bind_values, &Radius::Util::format_special($_, $p, $self, $fp->{hostCounter})),
	         @{$self->{HostSelectParam}});

	    $sth = $self->prepareAndExecute($q, @bind_values);
	}

	return unless $sth;

	my @row;
	if (@row = $self->getOneRow($sth))
	{
	    # If there is no host (maybe no secondary?) return
	    return if $row[0] eq '';
	    
	    if (defined $self->{HostColumnDef})
	    {
		$host = $self->getHostColumns($fp, @row);
	    }
	    else
	    {
		# If certain columns are present, use them to 
		# initialise the Radius::Host object that tells
		# AuthRADIUS where to proxy to.
		$fp->{failurePolicy} = $row[10] if defined $row[10];
		
		$host = Radius::Host->new
		    (undef,  $row[0],
		     defined $row[1]  ? (Secret                     => $row[1])  : (),
		     defined $row[2]  ? (AuthPort                   => $row[2])  : (),
		     defined $row[3]  ? (AcctPort                   => $row[3])  : (),
		     defined $row[4]  ? (Retries                    => $row[4])  : (),
		     defined $row[5]  ? (RetryTimeout               => $row[5])  : (),
		     defined $row[6]  ? (UseOldAscendPasswords      => $row[6])  : (),
		     defined $row[7]  ? (ServerHasBrokenPortNumbers => $row[7])  : (),
		     defined $row[8]  ? (ServerHasBrokenAddresses   => $row[8])  : (),
		     defined $row[9]  ? (IgnoreReplySignature       => $row[9])  : (),
		     #  $row[10] handled above
		     defined $row[11] ? (FailureBackoffTime         => $row[11]) : (),
		     defined $row[12] ? (MaxFailedRequests          => $row[12]) : (),
		     defined $row[13] ? (MaxFailedGraceTime         => $row[13]) : (),
		     );
		
	    }
	    # recover cached failure stats
	    my $key = "$host->{Name}:$host->{AuthPort}:$host->{AcctPort}";
	    if (exists $Radius::AuthSQLRADIUS::cached_stats{$key})
	    {
		foreach (@cached_stats)
		{
		    $host->{$_} = $Radius::AuthSQLRADIUS::cached_stats{$key}{$_};
		}
	    }
	    $host->activate();
	    return $host unless time < $host->{backoff_until};
	}
	else
	{
	    # Call the superclass to fall back to any hardwired
	    # hosts.
	    return $self->SUPER::chooseHost($fp, $p, $p->{rp});
	}
	$fp->{hostCounter} += 1;
    }
    return;
}

#####################################################################
# Work out the extra attributes returned by using HostColumnDef
# @cols is an array of field values, that should correspond to
# HostColumnDef definitions
sub getHostColumns
{
    my ($self, $fp, @cols) = @_;

    # Decode the cols returned by HostSelect using
    # the column definitions in HostColumnDef
    # Based on the code contributed by Lars Marowsky-Brée (lmb@teuto.net)
    my ($colnr, %args);
    my $host = '';
    foreach $colnr (keys %{$self->{HostColumnDef}}) 
    {
	my $attrib = $self->{HostColumnDef}{$colnr};

        # A "NULL" entry in the database will never be
        # added to the check items,
        # ie for an entry which is NULL, every attribute
        # will match.
        # A "NULL" entry will also not be added to the
        # reply items list.
        # Also protect against empty and all NULLs that can be got from
        # a NULL nvarchar on MS-SQL via ODBC
        next if !defined($cols[$colnr])
            || $cols[$colnr] eq ''
            || $cols[$colnr] =~ /^\000+$/;
	
	if ($attrib eq 'Host') 
	{
	    $host = $cols[$colnr];
	}
	elsif ($attrib eq 'failurePolicy')
	{
	    $fp->{failurePolicy} = $cols[$colnr];
	}
	elsif ($attrib eq 'RewriteUsername')
	{
	    # Has to be an array.
	    push(@{$args{$attrib}}, $cols[$colnr]);
	}
	else
	{
	    $args{$attrib} = $cols[$colnr];
	}
    }
    return if ($host eq '');
    my $h = Radius::Host->new(undef, $host,
			     LocalAddress => $self->{LocalAddress},
			     OutPort      => $self->{OutPort},
			     %args);
    $h->activate();
    return $h;
}

#####################################################################
# Override so that we can be sure to update OK statistics
sub handleReply
{
    my ($self, $host, $p, $op, $sp) = @_;

    #
    # This is the original AuthRADIUS method which, if the reply is OK,
    # updates the failedRequest and start_failure_grace_time stats in the $host object.
    #
    $self->SUPER::handleReply($host, $p, $op, $sp);

    #
    # Let's update the AuthSQLRADIUS cached statistics
    #
    my $key = "$host->{Name}:$host->{AuthPort}:$host->{AcctPort}";

    if (exists $Radius::AuthSQLRADIUS::cached_stats{$key})
    {
	foreach (@cached_stats)
	{
	    $Radius::AuthSQLRADIUS::cached_stats{$key}{$_} = $host->{$_};
	}
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
        my $s = &Radius::Util::format_special($host->{AddToRequest}, $p, $self);
        $fp->parse($s);
    }

    return $self->SUPER::sendHost($host, $fp, $p, $p->{rp});
}

#####################################################################
# Called after Retries transmissions to a host without
# a response. Override base class so we can capture the failure counts etc.
sub failed
{
    my ($self, $host, $fp, $p) = @_;

    # This may set failedRequests, start_failure_grace_time and backoff_until
    my $ret = $self->SUPER::failed($host, $fp, $p);

    # Save those values for later
    my $key = "$host->{Name}:$host->{AuthPort}:$host->{AcctPort}";
    foreach (@cached_stats)
    {
	$Radius::AuthSQLRADIUS::cached_stats{$key}{$_} = $host->{$_};
    }
    return $ret;
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
	
	$p->{Handler}->handlerResult
	    ($p, $fp->{failurePolicy}, 'SQLRADIUS Proxy failed');
    }
    return;
}

1;
