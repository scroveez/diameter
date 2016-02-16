# AuthSQL.pm
#
# Object for handling Authentication and accounting by SQL
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthSQL.pm,v 1.81 2014/09/29 19:39:11 hvn Exp $

package Radius::AuthSQL;
@ISA = qw(Radius::AuthGeneric Radius::SqlDb);
use Radius::AuthGeneric;
use Radius::SqlDb;
use DBI;
use strict;

%Radius::AuthSQL::ConfigKeywords = 
('AccountingTable'        => 
 ['string', 'name of the table that will be used to store accounting records. Defaults to "ACCOUNTING". If AccountingTable is defined to be an empty string, all accounting requests will be accepted and acknowledged, but no accounting data will be stored. You must also define at least one AcctColumnDef before accounting data will be stored.', 1],
 'AuthSelect'             => 
 ['string', 'SQL select statement that will be used to find and fetch the password and possibly check items and reply items for the user who is attempting to log in. You can use the special formatting characters. %0 is replaced with the quoted and escaped user name. The first column returned is expected to be the password; the second is the check items (if any) and the third is the reply items (if any) (you can change this expectation with the AuthColumnDef parameter). ', 1],
 'AuthSelectParam'        => 
 ['stringarray', 'This optional parameter enables the use of bound variables (where supported by the SQL server) and query caching. If you specify one or more AuthSelectParam parameters, they will be used in order to replace parameters named with a question mark (\`?\') in AuthSelect, and the query will be cached for future reuse by the SQL server. Only the first QueryCacheSize queries will be cached.', 1],
 'PostAuthSelectHook'     => 
 ['hook', 'Perl function that will be run during the authentication process. The hook will be called after the AuthSelect results have been received, and before Radiator has processed the attributes it is interested in.', 2],
 'EncryptedPassword'      => 
 ['flag', 'This parameter should be set if and only if your AuthSelect statement will return a bare Unix encrypted password, and you are not using AuthColumnDef. Encrypted passwords cannot be used with CHAP or MSCHAP authentication. If the encrypted password column for a user is NULL in the database, then any password will be accepted for that user.', 1],
 'AcctSQLStatement'       => 
 ['stringarray', 'This parameter allows you to execute arbitrary SQL statements each time an accounting request is received. You might want to do it to handle processing in addition to the normal inserts defined by AcctColumnDef, or you might want to construct a much more complicated SQL statement than AcctColumnDef can handle. You only need this if the accounting definitions provided by AcctColumnDef are not powerful enough.', 1],
 'AuthSQLStatement'       => 
 ['stringarray', 'This parameter allows you to execute arbitrary SQL statements each time an authentication request is received, but before authentication is done.', 1],
 'AuthColumnDef'          => 
 ['stringhash', 'This optional parameter allows you to change the way Radiator interprets the result of the AuthSelect statement. If you don\'t specify any AuthColumnDef parameters, Radiator will assume that the first column returned is the password; the second is the check items (if any) and the third is the reply items (if any). If you specify any AuthColumnDef parameters, Radiator will use the column definitions you provide.<p>
You can specify any number of AuthColumnDef parameters, one for each interesting field returned by AuthSelect. The general format is:
<p><pre><code>AuthColumnDef n, attributename, type[, formatted]</code></pre>', 1],
 'AcctColumnDef'          => 
 ['stringarray', 'AcctColumnDef is used to define which attributes in accounting requests are to be inserted into AccountingTable, and it also specifies which column they are to be inserted into, and optionally the data type of that column. The general form is 
<p><pre><code>Column,Attribute[,Type][,Format]</code></pre>', 1],
 'AcctInsertQuery'        => 
 ['string', 'This optional parameter allows you to customise the exact form of the insert query used to insert accounting data.', 1],
 'NullPasswordMatchesAny' => 
 ['flag', 'Normally, a NULL password in the SQL table will match any submitted password. By disabling this option, NULL passwords will not match any submitted password, causing every authentication request for that user to be REJECTed.', 1],
 'GroupMembershipQuery'   => 
 ['string', 'This optional parameter defines an SQL query which will be used to determine which user group a user is a member of, in order to implement the Group check item. Special characters are supported. ', 1],
 'GroupMembershipQueryParam'        => 
 ['stringarray', 'This optional parameter enables the use of bound variables (where supported by the SQL server) and query caching in the GroupMembershipQuery. If you specify one or more GroupMembershipQueryParam parameters, they will be used in order to replace parameters named with a question mark (\`?\') in GroupMembershipQuery, and the query will be cached for future reuse by the SQL server. Only the first QueryCacheSize queries will be cached.', 1],
 'AcctTotalSinceQuery'    => 
 ['string', 'This optional parameter defines an SQL query which will be used to determine the total of session times from a certain time until now for a given user. Special characters are supported. ', 1],
 'AcctTotalQuery'         => 
 ['string', 'This optional parameter defines an SQL query which will be used to determine the total of session times from a certain time until now for a given user. Special characters are supported. %0 is replaced by the user name being checked. %1 is replaced by the Unix epoch time in seconds in the start time of the query. It is expected to return a single field containing the total session time in seconds', 1],
 'AcctTotalOctetsSinceQuery' =>
 ['string', 'This optional parameter defines an SQL query which will be used to determine the total of octets from a certain time until now for a given user. Special characters are supported. %0 is replaced by the user name being checked. %1 is replaced by the Unix epoch time in seconds of the start time of the query. It is expected to return a single field containing the total octets.', 1],
 'AcctTotalOctetsQuery' =>
 ['string', 'This optional parameter defines an SQL query which will be used to determine the total of octets for a given user. Special characters are supported. %0 is replaced by the user name being checked. It is expected to return a single field containing the total octets.', 1],
 'AcctTotalGigawordsSinceQuery' =>
 ['string', 'This optional parameter defines an SQL query which will be used to determine the total of gigawords from a certain time until now for a given user. Special characters are supported. %0 is replaced by the user name being checked. %1 is replaced by the Unix epoch time in seconds of the start time of the query. It is expected to return a single field containing the total gigawords.', 1],
 'AcctTotalGigawordsQuery' =>
 ['string', 'This optional parameter defines an SQL query which will be used to determine the total of gigawords for a given user. Special characters are supported. %0 is replaced by the user name being checked. It is expected to return a single field containing the total gigawords.', 1],

 'CreateEAPFastPACQuery'         => 
 ['string', 'This optional parameter defines an SQL query which will be used to create and save an EAP-FAST PAC to the database', 1],
 'GetEAPFastPACQuery'         => 
 ['string', 'This optional parameter defines an SQL query which will be used to retrieve an EAP-FAST PAC from the database', 1],
 );

# RCS version number of this module
$Radius::AuthSQL::VERSION = '$Revision: 1.81 $';

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

    $self->Radius::AuthGeneric::activate;
    $self->Radius::SqlDb::activate;
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

    $self->Radius::AuthGeneric::initialize;
    $self->Radius::SqlDb::initialize;

    $self->{AccountingTable} = 'ACCOUNTING';
    $self->{AuthSelect} = 'select PASSWORD from SUBSCRIBERS where USERNAME=%0';
    $self->{AcctInsertQuery} = 'insert into %0 (%1) values (%2)';
    $self->{NullPasswordMatchesAny} = 1;
}

#####################################################################
# Handle a request
# This function is called for each packet. $p points to a Radius::
# packet
# REVISIT:should we fork before handling. There might be long timeouts?
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

    my $user_name = $p->getUserName;
    if ($p->code eq 'Access-Request' || $self->{AuthenticateAccounting})
    {
	# If AuthSQLStatement is set, parse the strings and execute them
	map {$self->do(&Radius::Util::format_special($_, $p, $self))}
	         @{$self->{AuthSQLStatement}}
	    if defined $self->{AuthSQLStatement};
	
	# Short circuit for no authentication
	return ($main::REJECT, 'Authentication disabled')
	    if $self->{AuthSelect} eq '';

	# The default behaviour in AuthGeneric is fine for this
	return $self->SUPER::handle_request($p, $p->{rp}, $extra_checks);
    }
    elsif ($p->code eq 'Accounting-Request')
    {
	$self->log($main::LOG_DEBUG, "Handling accounting with $type", $p);

	# Short circuits for no accounting
	return ($main::ACCEPT) 
	    if (!defined $self->{AcctColumnDef} 
		|| $self->{AccountingTable} eq '')
		&& !defined $self->{AcctSQLStatement};

	my $status_type = $p->getAttrByNum($Radius::Radius::ACCT_STATUS_TYPE);
	# If we have a HandleAcctStatusTypes and this type is not mentioned
	# Acknowledge it, but dont do anything else with it
	return ($main::ACCEPT)
	    if defined $self->{HandleAcctStatusTypes}
	       && !exists $self->{HandleAcctStatusTypes}{$status_type};

	# REVISIT: remove support for AccountingStartsOnly
	# AccountingStopsOnly, and AccountingAlivesOnly in the future.
	# If AccountingStartsOnly is set, only process Starts
	# Acknowledge and drop anything else
	return ($main::ACCEPT)
	    if $self->{AccountingStartsOnly}
	       && $status_type ne 'Start';
	
	# If AccountingStopsOnly is set, only process Stops
	# Acknowledge and drop anything else
	return ($main::ACCEPT)
	    if $self->{AccountingStopsOnly}
	       && $status_type ne 'Stop';

	# If AccountingAlivesOnly is set, only process Alives
	# Acknowledge and drop anything else
	return ($main::ACCEPT)
	    if $self->{AccountingAlivesOnly}
	       && $status_type ne 'Alive';

	return $self->handle_accounting($p);
    }
    else
    {
	# Send a generic reply on our behalf
	return ($main::ACCEPT); 
    }
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

    my ($original_user_name, $sth);

    if (!$self->{AuthSelectParam})
    {
        # We have to change User-Name in the request so we can 
        # use %n etc in AuthSelect.
        # Make sure all odd characers are escaped. We use the native SQL quote
        # function, but then strip the leading and trailing quotes
        # One day soon, %n will not get this special handling any more
        my $qname = $self->quote($name);
        my $qsname = $qname;
        $qsname =~ s/^'//;
        $qsname =~ s/'$//;

        $original_user_name = $p->getUserName;
        $p->changeUserName($qsname);

        my $q = &Radius::Util::format_special
	    ($self->{AuthSelect}, $p, $self, $qname);
	
        # BUG ALERT: Should we strip placeholders before prepare?
        $sth = $self->prepareAndExecute($q);
        if (!$sth)
        {
            # Change the name back to what it was
	    $p->changeUserName($original_user_name);
	    return undef;
        }
    }
    else
    {
        my @bind_values = ();

        #
        # Bind variables can handle all odd characters so there is no need to
        # escape any characters
        #
        map (push(@bind_values, &Radius::Util::format_special($_, $p, $self, $name)),
             @{$self->{AuthSelectParam}});

        $sth = $self->prepareAndExecute($self->{AuthSelect}, @bind_values);

        if (!$sth)
        {
	    return undef;
        }
    }
    
    my ($user, @row);

    if (@row = $self->getOneRow($sth))
    {
	$user = new Radius::User $name;

	# Perhaps run a hook to do other things with the SELECT data
	$self->runHook('PostAuthSelectHook', $p, $self, $name, $p, $user, \@row);

	# If the config has defined how to handle the columns
	# in the AuthSelect statement with AuthColumnDef, use
	# that to extract check and reply items from
	if (defined $self->{AuthColumnDef})
	{
	    $self->getAuthColumns($user, $p, @row)
	}
	else
	{
	    # Use the default assumption about returned cols:
	    # first is password, second is check items, third
	    # is reply items
	    my $password = shift @row;
	
	    # Add a *-Password check item unless the correct password
	    # was NULL in the database, This means that if 
	    # the password column for a user is NULL,
	    # then any password is accepted for that user.
	    $user->get_check->add_attr
		(defined $self->{EncryptedPassword} ? 
		 'Encrypted-Password' : 'User-Password', $password)
		unless (!defined $password && $self->{NullPasswordMatchesAny});
	    
	    $user->get_check->parse(shift @row);
	    $user->get_reply->parse(shift @row);
	}
    }

    if (!$self->{AuthSelectParam})
    {
        $p->changeUserName($original_user_name);
    }

    return $user;
}

#####################################################################
# Handle an accounting request
sub handle_accounting
{
    my ($self, $p) = @_;

    # If AcctSQLStatement is set, parse the strings and execute them
    # Contributed by Nicholas Barrington <nbarrington@smart.net.au>
    my $acct_failed;
    map {$acct_failed += 1 unless $self->do(&Radius::Util::format_special($_, $p, $self))}
    @{$self->{AcctSQLStatement}}
    if defined $self->{AcctSQLStatement};
    
    # If AcctColumnDef is set, build an insert statment
    if (defined $self->{AcctColumnDef})
    {
	# Add each column defined by AcctColumnDef
	# Courtesy Phil Freed ptf@cybertours.com
	my ($cols, $vals) = $self->getExtraCols($p);
	
	my $table = &Radius::Util::format_special
	    ($self->{AccountingTable}, $p, $self);
	my $q = &Radius::Util::format_special
	    ($self->{AcctInsertQuery}, $p, $self, $table, $cols, $vals);
	
	# Execute the insert, and if it fails, log the accounting
	# record to a file
	if (!$self->do($q))
	{
	    if (!$self->connected())
	    {
		# Connection failed, serious error
		if ($self->{AcctFailedLogFileName})
		{
		    # Anonymous subroutine hides the details from logAccounting
		    my $format_hook;
		    $format_hook = sub { $self->runHook('AcctLogFileFormatHook', $p, $p); }
		        if $self->{AcctLogFileFormatHook};

		    &Radius::Util::logAccounting
			($p, undef, 
			 $self->{AcctFailedLogFileName}, 
			 $self->{AcctLogFileFormat},
			 $format_hook);
		}
		return ($main::IGNORE, 'Database failure');
	    }
	    $acct_failed += 1;
	}
    }
    if ($self->{AcctFailedLogFileName} && $acct_failed)
    {
	# Anonymous subroutine hides the details from logAccounting
	my $format_hook;
	$format_hook = sub { $self->runHook('AcctLogFileFormatHook', $p, $p); }
	    if $self->{AcctLogFileFormatHook};

	&Radius::Util::logAccounting
	    ($p, undef, 
	     $self->{AcctFailedLogFileName}, 
	     $self->{AcctLogFileFormat},
	     $format_hook);
    }
    
    # Heres a way to automatically keep your "time left" column up
    # to date, even in a database without triggers.
    # You will probably need to change the names of the table and
    # columns to suit your database. One day this will be 
    # easily configurable. IN the meantime, you have to uncomment
    # and configure the code yourself.
    # This is probably redundant given the new AcctSQLStatement
#	if ($p->getAttrByNum($Radius::Radius::ACCT_STATUS_TYPE) eq 'Stop')
#	{
#	    my $session_time = $p->getAttrByNum($Radius::Radius::ACCT_SESSION_TIME) + 0;
#	    my $user_name = $p->getUserName;
#	    $q = "update SUBSCRIBERS set TIME_LEFT = (TIME_LEFT - $session_time) where USERNAME = '$user_name'";
#	    $self->log($main::LOG_DEBUG, "Query is: $q\n", $p);
    
#	    $self->do($q);
#	}
    
    # Dont need to commit: AutoCommit is on
    # Send a generic reply on our behalf: ACK
    return ($main::ACCEPT); 
}

#####################################################################
# Work out the extra cols and values to be inserted, according to
# AcctColumnDef
# Add each column defined by AcctColumnDef
# Idea courtesy Phil Freed ptf@cybertours.com
# Column definitions with the same column and multiple (non-null) 
# values will be only inserted once
# The _last_ column definition with a non-null value will win
sub getExtraCols
{
    my ($self, $p) = @_;

    my ($ref, $value, %cols);
    foreach $ref (@{$self->{AcctColumnDef}})
    {
	my ($col, $attr, $type, $format) = split(/\s*,\s*/, $ref, 4);
	
	if ($type eq 'formatted' || $type eq 'literal')
	{
	    # Use the second field as a format_special string
	    $value = &Radius::Util::format_special($attr, $p, $self);
	    next unless $value ne '';
	}
	else
	{
	    $value = $p->get_attr($attr);
	    next unless defined $value; # Dont insert non-existent attrs
	}

	# See what type of attribute it is
	if ($type eq 'integer')
	{
	    $value = $p->{Dict}->valNameToNum($attr, $value);
	}
	elsif ($type eq 'integer-date')
	{
	    # Convert a unix epoch date into an SQL date
	    # Format with the format string, else with with the default SQL 
	    # datetime format

	    $format = $self->{DateFormat} unless defined $format;
	    $value = &Radius::Util::strftime($format, $value);
	    $value = $self->quote($value);
	    $format = undef; # dont do sprintf formatting too
	}
	elsif ($type eq 'formatted-date')
	{
	    # Use Date::Format to format an SQL date
	    # Deprecated
	    if (!eval{require Date::Format})
	    {
		$self->log($main::LOG_ERR, "Could not load Date::Format for formatted-date: $@");
		next;
	    }

	    # Convert a unix epoch date into an SQL date
	    $value = &Date::Format::time2str($format, $value);
	    $format = undef; # dont do sprintf formatting too
	}
	elsif ($type eq 'literal')
	{
	    # Formatting has already been done above. This is just to
	    # avoid quotes
	}
	elsif ($type eq 'inet_aton')
	{
	    # Patch by Benoit Grange <b.grange@libertysurf.fr>
	    # and Jerome Fleury <jerome.fleury@freesbee.net>
	    # Convert an IPv4 address to an unsigned integer (32 bits)
	    # Can be used with MySQL 3.23 INET_ATON() and INET_NTOA() functions
	    my $ip = 0;
	    map ($ip = $ip*256+$_, split('\.', $value));
	    $value = sprintf ("%u", $ip);
	    $format = undef; # dont do sprintf formatting too
	}
	# Could define other data types here
	else
	{
	    # Its a simple string
	    # Tidy up any embedded quotes, maybe use NULL
	    $value = $self->quote($value);
	}
	# Maybe there is some special formatting?
	$value = sprintf($format, $value) if defined $format;

	# This implicitly removes duplicate column names
	$cols{$col} = $value;
    }
    my @ks = sort keys %cols;
    return (join(',', @ks), join(',', @cols{@ks}));
}

#####################################################################
# Work out the check and reply items returned
# from using AuthColumnDef
# @cols is an array of field values, that should correspond to
# AuthColumnDef definitions
sub getAuthColumns
{
    my ($self, $user, $p, @cols) = @_;

    # Decode the cols returned by AuthSelect using
    # the column definitions in AuthColumnDef
    # Contributed by Lars Marowsky-Brée (lmb@teuto.net)
    my $colnr;
    foreach $colnr (sort {$a <=> $b} keys %{$self->{AuthColumnDef}}) 
    {
	my ($attrib, $type, $formatting) = split (/,\s*/, $self->{AuthColumnDef}{$colnr});
	$type = lc($type); # lower-casify
	$formatting = lc($formatting); # lower-casify
#	print "trying $colnr, 	$attrib, $type, '$formatting'\n";
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

	# Maybe do special char processing on the value from the database
	$cols[$colnr] = &Radius::Util::format_special($cols[$colnr], $p)
	    if ($formatting eq 'formatted');

	if ($attrib eq "GENERIC") 
	{
	    # Column is a list of attr=value pairs
	    if ($type eq 'check') 
	    {
		$user->get_check->parse($cols[$colnr]);
	    } 
	    elsif ($type eq 'reply') 
	    {
		$user->get_reply->parse($cols[$colnr]);
	    }
	    elsif ($type eq 'request') 
	    {
		$p->parse(join ',', $cols[$colnr]);
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
					   $cols[$colnr]);
	    } 
	    elsif ($type eq "reply") 
	    {
		$user->get_reply->add_attr($attrib,
					   $cols[$colnr]);
	    }
	    elsif ($type eq "request") 
	    {
		$p->add_attr($attrib, $cols[$colnr]);
	    }
	}
    }
}

# Converts check item name to SQL query name for getLimitValue.
my %querynames =
    (
     'Max-All-Session'       => 'AcctTotalQuery',
     'Max-Hourly-Session'    => 'AcctTotalSinceQuery',
     'Max-Daily-Session'     => 'AcctTotalSinceQuery',
     'Max-Monthly-Session'   => 'AcctTotalSinceQuery',
     'Max-All-Octets'        => 'AcctTotalOctetsQuery',
     'Max-All-Gigawords'     => 'AcctTotalGigawordsQuery',
     'Max-Hourly-Octets'     => 'AcctTotalOctetsSinceQuery',
     'Max-Hourly-Gigawords'  => 'AcctTotalGigawordsSinceQuery',
     'Max-Daily-Octets'      => 'AcctTotalOctetsSinceQuery',
     'Max-Daily-Gigawords'   => 'AcctTotalGigawordsSinceQuery',
     'Max-Monthly-Octets'    => 'AcctTotalOctetsSinceQuery',
     'Max-Monthly-Gigawords' => 'AcctTotalGigawordsSinceQuery',
    );

#####################################################################
# Override AuthGeneric getLimitValue so we can handle prepaid
# limits etc
sub getLimitValue
{
    my ($self, $username, $check_name, $p) = @_;

    my $qusername = $self->quote($username);
    my ($queryname, $resettime);
    my @resettime = localtime(time);
    if (   $check_name eq 'Max-All-Session'
	|| $check_name eq 'Max-All-Octets'
	|| $check_name eq 'Max-All-Gigawords')
    {
	# These are not time limited, do nothing here
    }
    elsif (   $check_name eq 'Max-Hourly-Session'
	   || $check_name eq 'Max-Hourly-Octets'
	   || $check_name eq 'Max-Hourly-Gigawords')
    {
	$resettime[0] = $resettime[1] = 0; # sec, min
    }
    elsif (   $check_name eq 'Max-Daily-Session'
	   || $check_name eq 'Max-Daily-Octets'
	   || $check_name eq 'Max-Daily-Gigawords')
    {
	$resettime[0] = $resettime[1] = $resettime[2] = 0; # sec, min, hour
    }
    elsif (   $check_name eq 'Max-Monthly-Session'
	   || $check_name eq 'Max-Monthly-Octets'
	   || $check_name eq 'Max-Monthly-Gigawords')
    {
	$resettime[0] = $resettime[1] = $resettime[2] = 0; # sec, min, hour
	$resettime[3] = 1; #day
    }
    else
    {
	return; # Tell the caller we dont understand this one
    }

    # Map the check name to the correct query
    $queryname = $querynames{$check_name};

    # Dont know how to get the query
    return unless defined $self->{$queryname};

    $resettime = Time::Local::timelocal(@resettime);
    my $q = &Radius::Util::format_special
	($self->{$queryname}, $p, $self, $qusername, $resettime);
    my $sth = $self->prepareAndExecute($q);
    return unless $sth;
    my @row = $self->getOneRow($sth);
    $self->log($main::LOG_DEBUG, "$queryname result $row[0]", $p);
    return $row[0] + 0;
}

#####################################################################
# Determine if user is in a given group
# Overrides AuthGeneric 
sub userIsInGroup
{
    my ($self, $user, $group, $p) = @_;

    return unless defined $self->{GroupMembershipQuery};
    my $qusername = $self->quote($user);
    my $qgroupname = $self->quote($group);
    my $q = &Radius::Util::format_special($self->{GroupMembershipQuery}, $p, 
					  $self, $qusername, $qgroupname);
    my @bind_values;
    map (push(@bind_values, &Radius::Util::format_special($_, $p, $self, $user, $group)),
	 @{$self->{GroupMembershipQueryParam}});

    my $sth = $self->prepareAndExecute($q, @bind_values);
    return unless $sth;

    my @row = $sth->fetchrow();
    $sth->finish();
    return unless @row;
    return $row[0] eq $group;
}

#####################################################################
# Create a new EAP-FAST PAC and return its OPAQUE
# The structure will autodelete after the lifetime expires.
# lifetime is the lifetime of the PAC in seconds
# This may be overridden by subclasses
# This default implementation creates and caches PACs in memory
# Return a hash of the PAC data
sub create_eapfast_pac
{
    my ($self, $p) = @_;

    return unless $self->reconnect;
    return $self->SUPER::create_eapfast_pac()
	unless defined($self->{CreateEAPFastPACQuery});
    my $pac_opaque = &Radius::Util::random_string(32);
    my $hex_pac_opaque = unpack('H*', $pac_opaque);
    my $pac_lifetime = time() + $self->{EAPFAST_PAC_Lifetime};
    my $pac_key = &Radius::Util::random_string(32);
    my $hex_pac_key = unpack('H*', $pac_key);
    my $q = &Radius::Util::format_special($self->{CreateEAPFastPACQuery}, $p, 
					  $self, $hex_pac_opaque, $pac_lifetime, $hex_pac_key);
    my $sth = $self->prepareAndExecute($q);
    return unless $sth;

    return {pac_opaque   => $pac_opaque,
	    pac_lifetime => $pac_lifetime,
	    pac_key      => $pac_key};
}

#####################################################################
# Find a previously created EAP-FAST PAC given its OPAQUE.
# The returned hash contains the pac_lifetime and the pac_key, if available
# This may be overridden by subclasses
sub get_eapfast_pac
{
    my ($self, $pac_opaque, $p) = @_;

    return unless $self->reconnect;
    return $self->SUPER::create_eapfast_pac()
	unless defined($self->{GetEAPFastPACQuery});

    my $hex_pac_opaque = unpack('H*', $pac_opaque);
    my $q = &Radius::Util::format_special($self->{GetEAPFastPACQuery}, undef, $self, $hex_pac_opaque, time());
    my $sth = $self->prepareAndExecute($q);

    my @row = $sth->fetchrow();
    $sth->finish();
    return unless @row;
    return {pac_opaque   => $pac_opaque,
	    pac_lifetime => $row[0],
	    pac_key      => pack('H*', $row[1])};
}


1;
