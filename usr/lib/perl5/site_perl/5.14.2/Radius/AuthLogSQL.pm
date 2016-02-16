# AuthLogSQL.pm
#
# Specific class for logging authentication to SQL
#
# Author: contributed by Dave Lloyd <david@freemm.org>
# Copyright (C) Open System Consultants
# $Id: AuthLogSQL.pm,v 1.20 2014/03/05 22:11:27 hvn Exp $

package Radius::AuthLogSQL;
@ISA = qw(Radius::AuthLogGeneric Radius::SqlDb);
use Radius::AuthLogGeneric;
use Radius::SqlDb;
use strict;

%Radius::AuthLogSQL::ConfigKeywords = 
 ('Table'        => 
  ['string', 'This optional parameter specifies the name of the SQL table where the logging messages are to be inserted. Defaults to RADAUTHLOG.', 1],

  'SuccessQuery' => 
  ['string', 'This optional parameter specifies the SQL query that will be used to log authentication successes if LogSuccess is enabled (LogSuccess is not enabled by default). There is no default. If SuccessQuery is not defined (which is the default), no logging of authentication successes will occur. In the query, special formatting characters are permitted, %0 is replaced with the message severity level. %1 is replaced with the quoted reason message (which is usually empty for successes). %2 is replaced with the SQL quoted User-Name. %3 is replaced with the SQL quoted decoded plaintext password (if any). %4 is replaced with the SQL quoted original user name from the incoming request (before any RewriteUsername rules were applied)', 1],

 'SuccessQueryParam' =>
 ['stringarray', 'This optional parameter enables the use of bound variables (where supported by the SQL server) and query caching. If you specify one or more SuccessQueryParam parameters, they will be used in order to replace parameters named with a question mark (\`?\') in SuccessQuery, and the query will be cached for future reuse by the SQL server. Only the first QueryCacheSize queries will be cached.', 1],

  'FailureQuery' => 
  ['string', 'This optional parameter specifies the SQL query that will be used to log authentication failures if LogFailure is enabled (LogFailure is enabled by default). There is no default. If FailureQuery is not defined (which is the default), no logging of authentication failures will occur. In the query, special formatting characters are permitted, %0 is replaced with the message severity level. %1 is replaced with the quoted reason message. %2 is replaced with the SQL quoted User-Name. %3 is replaced with the SQL quoted decoded plaintext password (if any). %4 is replaced with the SQL quoted original user name from the incoming request (before any RewriteUsername rules were applied)', 1],

 'FailureQueryParam' =>
 ['stringarray', 'This optional parameter enables the use of bound variables (where supported by the SQL server) and query caching. If you specify one or more FailureQueryParam parameters, they will be used in order to replace parameters named with a question mark (\`?\') in FailureQuery, and the query will be cached for future reuse by the SQL server. Only the first QueryCacheSize queries will be cached.', 1],

  );

# RCS version number of this module
$Radius::AuthLogSQL::VERSION = '$Revision: 1.20 $';

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    # Multiple inheritance:
    $self->Radius::AuthLogGeneric::check_config();
    $self->Radius::SqlDb::check_config();
    return;
}

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->Radius::AuthLogGeneric::activate;
    $self->Radius::SqlDb::activate;
}

#####################################################################
# Do per-instance default initialization
# This is called by Configurable during Configurable::new before
# the config file is parsed. Its a good place initialize instance 
# variables
# that might get overridden when the config file is parsed.
# Do per-instance default initialization. This is called after
# construction is complete
sub initialize
{
    my ($self) = @_;

    $self->Radius::AuthLogGeneric::initialize;
    $self->Radius::SqlDb::initialize;
    $self->{Table} = 'RADAUTHLOG';
}

#####################################################################
# Log a message 
sub authlog
{
    my ($self, $s, $reason, $p) = @_;

    my @bind_values = ();

    if (defined($self->{SuccessQuery}) 
	&& $self->{LogSuccess} 
	&& $s == $main::ACCEPT) 
    {
	return unless $self->reconnect();
	if (!$self->{SuccessQueryParam})
	{
	    $self->do(&Radius::Util::format_special
		      ($self->{SuccessQuery}, $p, $self,
		       $s,
		       $self->quote($reason),
		       $self->quote($p->getUserName()),
		       $self->quote($p->decodedPassword()),
		       $self->quote($p->{OriginalUserName}),
		      ));
	}
	else
	{
	    map (push(@bind_values, Radius::Util::format_special(
			  $_, $p, $self,
			  $s, $reason, $p->getUserName(), $p->decodedPassword(), $p->{OriginalUserName})),
		 @{$self->{SuccessQueryParam}});

	    $self->prepareAndExecute($self->{SuccessQuery}, @bind_values);
	}
    }
    elsif (defined($self->{FailureQuery}) 
	   && $self->{LogFailure} 
	   && $s == $main::REJECT) 
    {
	return unless $self->reconnect();
	if (!$self->{FailureQueryParam})
	{
	    $self->do(&Radius::Util::format_special
		      ($self->{FailureQuery}, $p, $self,
		       $s,
		       $self->quote($reason),
		       $self->quote($p->getUserName()),
		       $self->quote($p->decodedPassword()),
		       $self->quote($p->{OriginalUserName}),
		      ));
	}
	else
	{
	    map (push(@bind_values, Radius::Util::format_special(
			  $_, $p, $self,
			  $s, $reason, $p->getUserName(), $p->decodedPassword(), $p->{OriginalUserName})),
	     @{$self->{FailureQueryParam}});

	    $self->prepareAndExecute($self->{FailureQuery}, @bind_values);
	}
    }
}

1;
