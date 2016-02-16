# AuthSQLAUTHBY.pm
#
# Object for creating AuthBy clauses for each realm automatically from SQL
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthSQLAUTHBY.pm,v 1.5 2013/08/13 20:58:45 hvn Exp $

package Radius::AuthSQLAUTHBY;
@ISA = qw(Radius::AuthGeneric Radius::SqlDb);
use Radius::SqlDb;
use Radius::AuthGeneric;
use strict;

%Radius::AuthSQLAUTHBY::ConfigKeywords = 
('AuthBySelect'      => 
 ['string', 'This parameter defines the SQL statement that will be run to determine the details of the target AuthBy. It is run for each request that is handled by this AuthBy. Only the first row returned (if any) is used.', 0],

 'Class' => ['string', 'This parameter defines the type of AuthBy clause that will be created. The paramters to control the AuthBy will be based on the columns received from SQL. It can be any Radiator AuthBy class name. Examples might include \'LDAP\', \'SQL\' etc. Default is LDAP', 0],

 'DefaultParam' =>
 ['stringarray', 'Default values for clause configuration parameters, and whioch may be overridden by values from the AuthBySelect', 0],

 'AuthBySelectParam' => 
 ['stringarray', 'This optional parameter enables the use of bound variables (where supported by the SQL server) and query caching. If you specify one or more AuthBySelectParam parameters, they will be used in order to replace parameters named with a question mark ("?") in AuthBySelect, and the query will be cached for future reuse by the SQL server. Only the first QueryCacheSize queries will be cached.', 1],

 'ParamColumnDef'   => 
 ['stringhash', 'This parameter allows you to specify the mapping between the fields returned by AuthBySelect and the parameters used to define the AuthBy.', 1],

 );

# RCS version number of this module
$Radius::AuthSQLAUTHBY::VERSION = '$Revision: 1.5 $';

# Cached host failure numbers for determining backoff etc:
%Radius::AuthSQLAUTHBY::cached_stats = ();
my @cached_stats = ('failedRequests', 'start_failure_grace_time', 'backoff_until');

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    $self->Radius::AuthGeneric::check_config();
    $self->Radius::SqlDb::check_config();
    return;
}

#####################################################################
sub activate
{
    my ($self) = @_;

    # Multiple inheritance:
    $self->Radius::AuthGeneric::activate();
    $self->Radius::SqlDb::activate();
}

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    # Multiple inheritance:
    $self->Radius::AuthGeneric::initialize();
    $self->Radius::SqlDb::initialize();
    $self->{AuthBySelect} = 'select HOST, PORT, AUTHDN, AUTHPASSWORD, BASEDN, USERNAMEATTR, PASSWORDATTR, HOLDSERVERCONNECTION from RADSQLAUTHBY where TARGETNAME=\'%R\'';
}

#####################################################################
# Handle a request
# This function is called for each packet. 
# Look up the appropriate AuthBy clause details in sql and create a new one if necessary
# dispatch the request to the clause
sub handle_request
{
    my ($self, $p, $dummy, $extra_checks) = @_;

    my $type = ref($self);
    $self->log($main::LOG_DEBUG, "Handling with $type: $self->{Identifier}", $p);
    return ($main::IGNORE, "Ignored due to IgnoreAuthentication")
	if $self->{IgnoreAuthentication} 
           && $p->code eq 'Access-Request';
    return ($main::IGNORE, "Ignored due to IgnoreAccounting")
	if $self->{IgnoreAccounting} 
           && $p->code eq 'Accounting-Request';

    my $sth;
    if (!$self->{AuthBySelectParam})
    {
	my $q = &Radius::Util::format_special($self->{AuthBySelect}, $p, $self);
	$sth = $self->prepareAndExecute($q);
    }
    else
    {
	my @bind_values = ();

	map (push(@bind_values, &Radius::Util::format_special($_, $p, $self)),
	     @{$self->{AuthBySelectParam}});
	
	$sth = $self->prepareAndExecute($self->{AuthBySelect}, @bind_values);
    }
    return ($main::IGNORE, 'SQL prepareAndExecute failed')
	unless $sth;

    my @row = $self->getOneRow($sth);
    return ($main::IGNORE, 'No clause parameters found for target realm')
	unless @row;

    # Make a key based on all the details in the row to identify a unique target clauase
    my $key = join(':', @row);

    # If there is already a target clause created for this key, reuse it, else create a new one
    if (!exists($self->{targetClauses}{$key}))
    {
	# Need to instantiate a new clause to send requests for this target to
	my ($colnr, %args);

	# Get the default values for some params
	foreach (@{$self->{DefaultParam}})
	{
	    if (/(\S*)\s*(.*)/)
	    {
		# keyword value
		my ($keyword, $value) = ($1, $2);
		$args{$keyword} = $value;
	    }
	    else
	    {
		$self->log($main::LOG_ERR, "Bad format DefaultParam: $_");
	    }
	}

	# Now maybe override them with columns from the database
	foreach $colnr (keys %{$self->{ParamColumnDef}}) 
	{
	    my $attrib = $self->{ParamColumnDef}{$colnr};
	    
	    # A "NULL" entry in the database will never be
	    # added to the parameter items,
	    # Also protect against empty and all NULLs that can be got from
	    # a NULL nvarchar on MS-SQL via ODBC
	    next if !defined($row[$colnr])
		|| $row[$colnr] eq ''
		|| $row[$colnr] =~ /^\000+$/;
	    
	    $args{$attrib} = $row[$colnr];
	}

	# Have all the clause parameters, now create an instance of the new class
	$self->log($main::LOG_DEBUG, "Creating new AuthBy $self->{Class}", $p);
	my $class = "Radius::Auth$self->{Class}";
	my $clause;
	if (eval ("require $class") && ($clause = $class->new()))
	{
	    foreach (keys %args) 
	    {
		$clause->set($_, $args{$_});
	    }
	    $clause->activate();
	    $self->{targetClauses}{$key} = $clause;
	}
	else
	{
	    $self->log($main::LOG_ERR, "Could not 'require $class'");
	}
    }
    return ($main::IGNORE, 'No clause found for target realm')
	unless  exists($self->{targetClauses}{$key});

    my $clause = $self->{targetClauses}{$key};
    $p->rewriteUsername($clause->{RewriteUsername})
	if defined $clause->{RewriteUsername};

    return $clause->handle_request($p, $dummy, $extra_checks);
}

1;


