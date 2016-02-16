# AuthPLSQL.pm
#
# Object for handling Authentication and Accounting 
# by Oracle PL/SQL
#
# Author: Pavel Crasotin (pavel@ctk.ru)
#
# $Id: AuthPLSQL.pm,v 1.7 2009/11/11 21:44:37 mikem Exp $

package Radius::AuthPLSQL;
@ISA = qw(Radius::AuthSQL);
use Radius::AuthSQL;
use DBI;
use strict;

%Radius::AuthPLSQL::ConfigKeywords =
(
 'AuthBlock'	=>
 ['string',
  'PL/SQL statement that will be used to find and fetch the password and possibly check items and reply items for the user who is attempting to log in.',
  1],

 'AcctBlock'	=>
 ['string',
  'This parameter executes PL/SQL code each time an accounting request is received.',
  1],

 'AuthParamDef'	=>
 ['splitstringhash',
  'This parameter enables the use of bound INOUT variables for AuthBlock. If you specify one or more AuthParamDef parameters, they will be used in order to replace parameters named with a label in AuthBock, and the query will be cached for future reuse by the SQL server. Only the first QueryCacheSize queries will be cached. The general form is
<p><pre><code>label,attributename,type[,initial_value]</code></pre>',
  1],

 'AcctParamDef'	=>
 ['stringhash',
  'This parameter enables the use of bound INOUT variables for AcctBlock. If you specify one or more AcctParamDef parameters, they will be used in order to replace parameters named with a label in AuthBock, and the query will be cached for future reuse by the SQL server. Only the first QueryCacheSize queries will be cached. The general form is
<p><pre><code>label,initial_value</code></pre>',
  1],

 'MaxOUTParamLen' =>
 ['integer',
  'The maximum length of the buffer for OUT parameter',
  1]
 );

# RCS version number of this module
$Radius::AuthPLSQL::VERSION = '$Revision: 1.7 $';

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate;
}
	    
#####################################################################
# Do per-instance default initialization
# This is called by Configurabel during Configurable::new before
# the config file is parsed. Its a good place initalze 
# instance variables
# that might get overridden when the config file is parsed.
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;

    $self->{AuthBlock}		= 'BEGIN null; END;';
    $self->{AcctBlock}		= undef;
    $self->{AuthParamDef}	= undef;
    $self->{AcctParamDef}	= undef;
    $self->{MaxOUTParamLen}	= 2000;

    # Placeholders
    $self->{AuthPlaceHolder}	= undef;
    $self->{AcctPlaceHolder}	= undef;

    # Ugly trick to force AuthSQL execute our handle_accounting
    @{$self->{AcctSQLStatement}} = ('BEGIN null; END;');
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
    return (undef, 1) unless $self->reconnect;

    # We have to change User-Name in the request so we can 
    # use %n etc in AuthBlock.
    # Make sure all odd characers are escaped. We use the native SQL quote
    # function, but then strip the leading and trailing quotes
    $name = $Radius::SqlDb::handles{$self->{dbname}}->quote($name);
    $name =~ s/^'//;
    $name =~ s/'$//;

    my $original_user_name = $p->getUserName;
    $p->changeUserName($name);

    my $q = &Radius::Util::format_special($self->{AuthBlock}, $p, $self, $name);

    # Put formatted initial value into placeholder 
    # for OUT/INOUT variables
    # Reference
    #   $self->{AuthParamDef}->{$label}[0] - Attribute
    #   $self->{AuthParamDef}->{$label}[1] - Type
    #   $self->{AuthParamDef}->{$label}[2] - Unformatted IN value if any
    map {
	$self->{AuthPlaceHolder}->{$_} = &Radius::Util::format_special
	    ($self->{AuthParamDef}->{$_}[2], $p, $self, $name);
    } keys %{$self->{AuthParamDef}};

    my $sth = $self->prepareAndExecute($q, \$self->{AuthPlaceHolder});
    if (!$sth)
    {
        # Change the name back to what it was
	$p->changeUserName($original_user_name);
	return undef;
    }
    
    my $user = new Radius::User $name;

    # If the config has defined how to handle the returned 
    # values in the AuthBlock statement with AuthParamDef,
    # use that to extract check and reply items from
    if (defined $self->{AuthParamDef})
    {
	$self->getAuthParams($user,$p);
    }

    $p->changeUserName($original_user_name);
    return $user;
}

#####################################################################
# Handle an accounting request
sub handle_accounting
{
    my ($self, $p) = @_;
    my $acct_failed;

    return $self->SUPER::handle_accounting($p)
	if !defined $self->{AcctBlock};

    my $q = &Radius::Util::format_special($self->{AcctBlock}, $p, $self);

    # Put formatted initial value into placeholder 
    # for IN variables.
    # REVISIT: Do we need INOUT/OUT variables for accounting??
    # Reference
    #   $self->{AcctParamDef}->{$label} - Unformatted IN value if any
    #
    map {
	$self->{AcctPlaceHolder}->{$_} = &Radius::Util::format_special
	    ($self->{AcctParamDef}->{$_}, $p, $self);
    } keys %{$self->{AcctParamDef}};

    my $sth = $self->prepareAndExecute($q, \%$self->{AcctPlaceHolder});

    if (!$sth)
    {
	if (!$self->connected())
	{
	    # Connection failed, serious error
	    &Radius::Util::logAccounting
		($p, undef, 
		 $self->{AcctFailedLogFileName}, 
		 $self->{AcctLogFileFormat})
		if $self->{AcctFailedLogFileName};
	    return ($main::IGNORE, 'Database failure');
	}
	$acct_failed += 1;
    }

    &Radius::Util::logAccounting
	($p, undef, 
	 $self->{AcctFailedLogFileName}, 
	 $self->{AcctLogFileFormat})
	if $self->{AcctFailedLogFileName} && $acct_failed;
    
    # Dont need to commit: AutoCommit is on
    # Send a generic reply on our behalf: ACK
    return ($main::ACCEPT); 
}

#####################################################################
# Convenience function to prepare and execute a query.
# If it fails to execute, complain, and try to reconnect and reexecute.
# If it still fails to execute, return undef, else a statement handle
sub prepareAndExecute
{
    my ($self, $q, $ph_ref) = @_;
    my ($attempts, $cached_sth, $sth, $rc);
    my @ph_keys = keys %{$$ph_ref};

    $self->log($main::LOG_DEBUG, "Query is: '$q': " . join(' ', map { "$_=`$$ph_ref->{$_}`" } @ph_keys));

    # Try to execute the query. If we fail due to database failure
    # try to reconnect and try again. If that also fails, give up
    while (!$sth && $attempts++ < 2)
    {
	if ($self->reconnect())
	{
	    $cached_sth = $sth = $Radius::SqlDb::statements{$self->{dbname}}{$q}
		if @ph_keys > 0;

	    # We evaluate the execution
	    # with an alarm for the timeout period
	    # pending. If the alarm goes off, the eval will die
	    &Radius::Util::exec_timeout($self->{Timeout},
		sub {
		    if (!$sth)
		    {
			# Prepare new statement
			$sth = $Radius::SqlDb::handles{$self->{dbname}}->prepare($q);
			# Bind placeholders
			map {
			    $sth->bind_param_inout($_, \$$ph_ref->{$_}, $self->{MaxOUTParamLen});
			    $self->log($main::LOG_DEBUG, "Binding $_ = `$$ph_ref->{$_}`");
			} @ph_keys;
		    }
		    $rc = $sth->execute if $sth;
		}
	    );

	    # Preparing a statement is a relatively expensive operation.
	    # Keep the statement around for future use.
	    #
	    if ((@ph_keys > 0) && $sth && ($sth ne $cached_sth))
	    {
		my @tmp = keys %{$Radius::SqlDb::statements{$self->{dbname}}};

		# Cache the prepared statement only as long as we still have room
		$Radius::SqlDb::statements{$self->{dbname}}{$q} = $sth
		    if @tmp <= $Radius::SqlDb::MAX_CACHED_PREPARED_STATEMENTS;
	    }

	    # Some DBD drivers dont undef rc on DB failure
	    return $sth if $sth && $rc && !$DBI::err;
	    
	    # If we got here, something went wrong
	    my $reason = $DBI::errstr;
	    $reason = "SQL Timeout" if $@ && $@ =~ /timeout/;
	    $self->log($main::LOG_ERR, "Execute failed for '$q': $reason");
	    $self->log($main::LOG_ERR, "Bind parameters: " . join(' ', map { "$_=`$$ph_ref->{$_}`" } @ph_keys))
		if @ph_keys > 0;
	}
	# Hmm, failed prob due to database failure, try to reconnect
	# to an alternate
	$self->disconnect();
	$sth = undef;
    }
    return undef;
}

#####################################################################
# Work out the check and reply items returned
# from using AuthParamDef
sub getAuthParams
{
    my ($self, $user, $p) = @_;

    my $key;
    foreach $key (keys %{$self->{AuthParamDef}}) 
    {
	my ($attrib, $type, @dummy) =  @{$self->{AuthParamDef}->{$key}};

	next if $type eq 'skip';

	my $value = $self->{AuthPlaceHolder}->{$key};

	# A "NULL" entry in the database will never be 
	# added to the check items,
	# ie for an entry which is NULL, every attribute 
	# will match.
	# A "NULL" entry will also not be added to the 
	# reply items list.

	next unless defined($value);

	if ($attrib eq "GENERIC") 
	{
	    # Value is a list of attr=value pairs
	    if ($type eq "check") 
	    {
		$user->get_check->parse($value);
	    } 
	    elsif ($type eq "reply") 
	    {
		$user->get_reply->parse($value);
	    }
            elsif ($type eq "request")
	    {
		$p->parse(join ',', $value);
	    }
	    # Other types here?
	} 
	else 
	{
	    # $attrib is an attribute name, and the 
	    # value is the string to match
	    if ($type eq "check") 
	    {
		$user->get_check->add_attr($attrib,
					   $value);
	    } 
	    elsif ($type eq "reply") 
	    {
		$user->get_reply->add_attr($attrib,
					   $value);
	    }
            elsif ($type eq "request")
            {
                $p->add_attr($attrib, $value);
            }
	}
    }
}

1;
