# AuthRADMIN.pm
#
# Object for handling Authentication and accounting from Radmin
# (http://www.open.com.au/radmin)
# This is a subclass of SQL that can also get radius attributes
# from Radmin's special attribute tables.
#
# We only need to override the findUser function so that it 
# extracts reply items from RadConfifgs and RadATConfigs
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthRADMIN.pm,v 1.39 2013/01/22 09:47:00 mikem Exp $

package Radius::AuthRADMIN;
@ISA = qw(Radius::AuthSQL);
use Radius::AuthSQL;
use strict;

# Gag, this module variable holds the last username we fetched from
# the database, so we can tell who to update badlogins for
my $lastUsername;

%Radius::AuthRADMIN::ConfigKeywords = 
('LogQuery'                => 
 ['string', 'This optional parameter allows you to control the SQL query that is used to insert log messages into the database. Message strings are truncated to MaxMessageLength characters.', 1],

 'UserAttrQuery'           => 
 ['string', 'This optional parameter allows you to control the query used to get user-specific RADIUS check and reply items. %0 is replaced by the (possibly rewritten) User-Name. Other special formatting characters may be used.', 1],

 'ServiceAttrQuery'        => 
 ['string', 'This optional parameter allows you to control the query used to get service-specific RADIUS check and reply items. %0 is replaced by the Service Profile name from the SERVICENAME column in the user\'s database record. Other special formatting characters may be used. ServiceAttrQuery will be run after UserAttrQuery if ServiceAttrQuery is non-empty, and if a non-empty servicename was found in the 5th field returned from AuthSelect.', 1],

 'AttrQueryParam'        => 
 ['stringarray', 'This optional parameter  enables the use of bound variables (where supported by the SQL server) and query caching in the UserAttrQuery and ServiceAttrQuery strings. If you specify one or more AttrQueryParam parameters, they will be used in order to replace parameters named with a question mark (\`?\') in the UserAttrQuery and ServiceAttrQuery queries, and the query will be cached for future reuse by the SQL server. Only the first QueryCacheSize queries will be cached. %0 is replaced by the apropriate user name or service name.', 1],

 'MaxBadLogins'            => 
 ['integer', 'AuthBy RADMIN compares the bad login count in the RAdmin database with MaxBadLogins. If it is exceeded, it is assumed that password guessing has been attempted and the user will be disabled until their bad login count is reset. Defaults to 5. If set to 0, the bad login count is ignored.', 1],

 'IncrementBadloginsQuery' => 
 ['string', 'This optional parameter specifies the SQL query to issue if AuthBy RADMIN detects a bad password. It is intended to increment a count of the number of bad logins, which can then be checked during authentication. %0 is replaced with the name of the user being authenticated. Other special formatting characters may be used. Disabled if an empty string is specified.', 1],

 'ClearBadloginsQuery'     => 
 ['string', 'This optional parameter specifies the SQL query to issue if AuthBy RADMIN detects a good password. It is intended to clear a count of the number of bad logins, which can then be checked during authentication. %0 is replaced with the name of the user being authenticated. Other special formatting characters may be used. Disabled if an empty string is specified.', 1],

 'MaxMessageLength' => 
 ['integer', 
  'Sets the maximum length of log messages as stored in the database by LogQuery. All messages longer than MaxMessageLength characters wil be truncated to MaxMessageLength. Set this to the width of the column that will store the messages. Defaults to 200', 
  1],
 );

# RCS version number of this module
$Radius::AuthRADMIN::VERSION = '$Revision: 1.39 $';

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
    $self->{AuthSelect} = "select PASS_WORD, STATICADDRESS, TIMELEFT, MAXLOGINS, SERVICENAME, BADLOGINS, VALIDFROM, VALIDTO from RADUSERS where USERNAME=%0";
    $self->{LogQuery} = 'insert into RADMESSAGES (TIME_STAMP, TYPE, MESSAGE) values (%t, %0, %1)';
    # Get per-user radius attributes
    $self->{UserAttrQuery} = 'select ATTR_ID, VENDOR_ID, IVALUE, SVALUE, ITEM_TYPE from RADCONFIG where NAME=%0 order by ITEM_TYPE';
    # Get per-service radius attributes
    $self->{ServiceAttrQuery} = 'select ATTR_ID, VENDOR_ID, IVALUE, SVALUE, ITEM_TYPE from RADSTCONFIG where NAME=%0 order by ITEM_TYPE';
    $self->{MaxBadLogins} = 5;
    $self->{IncrementBadloginsQuery} = 'update RADUSERS set BADLOGINS=BADLOGINS+1 where USERNAME=%0';
    $self->{ClearBadloginsQuery} = 'update RADUSERS set BADLOGINS=0 where USERNAME=%0';
    $self->{NullPasswordMatchesAny} = 0;
    $self->{MaxMessageLength} = 200;
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
    # use %n etc in AuthSelect.
    # Make sure all odd characers are escaped. We use the native SQL quote
    # function, but then strip the leading and trailing quotes
    # One day soon, %n will not get this special handling any more
    my $qname = $self->quote($name);
    my $qsname = $qname;
    $qsname =~ s/^'//;
    $qsname =~ s/'$//;

    $lastUsername = $p->getUserName;
    $p->changeUserName($qsname);

    my $q = &Radius::Util::format_special
	($self->{AuthSelect}, $p, undef, $qname);
	
    # BUG ALERT: Should we strip placeholders before prepare?
    my @bind_values;
    map (push(@bind_values, &Radius::Util::format_special($_, $p, $self, $name)),
	 @{$self->{AuthSelectParam}});
    my $sth = $self->prepareAndExecute($q, @bind_values);
    if (!$sth)
    {
        # Change the name back to what it was
	$p->changeUserName($lastUsername);
	return undef;
    }

    my ($user, $password, $staticaddress, $timeleft, $maxlogins, $servicetype, $badlogins, $validfrom, $validto, @extras);
    if (($password, $staticaddress, $timeleft, $maxlogins, $servicetype, $badlogins, $validfrom, $validto, @extras)
	= $self->getOneRow($sth))
    {
	$user = new Radius::User $name;

	# Perhaps run a hook to do other things with the SELECT data
	$self->runHook('PostAuthSelectHook', $p, $self, $name, $p, $user, $password, $staticaddress, $timeleft, $maxlogins, $servicetype, $badlogins, $validfrom, $validto, @extras);


	$user->get_check->add_attr
	    (defined $self->{EncryptedPassword} ? 
	     'Encrypted-Password' : 'User-Password', $password)
	    unless (!defined $password && $self->{NullPasswordMatchesAny});
	if (defined $timeleft)
	{
	    if ($timeleft <= 0)
	    {
		$self->log($main::LOG_DEBUG, "User $name has no time left", $p);
                $p->changeUserName($lastUsername);
		return undef;
	    }
	    else
	    {
		$user->get_reply->add_attr('Session-Timeout', $timeleft);
	    }
	}
	$user->get_reply->add_attr('Framed-IP-Address', $staticaddress)
	    if $staticaddress ne '';
	$user->get_check->add_attr('Simultaneous-Use', $maxlogins)
	    if defined $maxlogins;
	$user->get_check->add_attr('ValidFrom', $validfrom)
	    if defined $validfrom;
	$user->get_check->add_attr('ValidTo', $validto)
	    if defined $validto;

	if (defined $badlogins && $self->{MaxBadLogins} && $badlogins >= $self->{MaxBadLogins})
	{
	    $self->log($main::LOG_INFO, "User $name Bad Login count exceeded");
	    $p->changeUserName($lastUsername);
	    return undef;
	}

	# If the config has defined how to handle any extra columns
	# in the AuthSelect statement with AuthColumnDef, use
	# that to extract extra check and reply items from @extras	
	$self->getAuthColumns($user, $p, @extras)
	    if defined $self->{AuthColumnDef};
    }
    $p->changeUserName($lastUsername);

    # Cant go any further if there is no user
    return unless $user;

    # Maybe get any per-service radius attribtues
    $self->getAttrs($self->{ServiceAttrQuery}, $p, $user, $servicetype)
	if ($servicetype ne ''
	    && $self->{ServiceAttrQuery} ne '');

    # Maybe Get any per-user radius attribtues
    $self->getAttrs($self->{UserAttrQuery}, $p, $user, $name)
	if ($self->{UserAttrQuery} ne '');
    
    return $user;
}

#####################################################################
# Given a SQL query fetch the attribtues and add them to the $users
# check and reply items
# $q is the query
# $p is the current packet
# $name is a variable name that might be used in the query as %0
sub getAttrs
{
    my ($self, $q, $p, $user, $name) = @_;

    my $qname = $self->quote($name);
    my $qq = &Radius::Util::format_special($q, $p, undef, $qname);
    my @bind_values;
    map (push(@bind_values, &Radius::Util::format_special($_, $p, $self, $name)),
	 @{$self->{AttrQueryParam}});
    my $sth = $self->prepareAndExecute($qq, @bind_values);
    if ($sth)
    {
	my ($attr_id, $vendor_id, $ivalue, $svalue, $item_type, @attrDetails, $attr_list);
	while (($attr_id, $vendor_id, $ivalue, $svalue, $item_type) 
	       = $sth->fetchrow())
	{
	    # Dictionaries may not agree, so we use the 
	    # attribute number to find the name
	    # Some DBs return attr_id as a float!
	    $attr_id = int $attr_id;
	    @attrDetails = $main::dictionary->attrByNum
		($attr_id, $vendor_id ? $vendor_id : undef);
	    
	    $attr_list = $item_type < 10000
		? $user->get_check(): $user->get_reply();
	    # Session-Timeout can be a string
	    $attrDetails[2] = 'string'
		if $attrDetails[0] eq 'Session-Timeout' && $svalue ne '';

	    if ($attrDetails[2] eq 'integer')
	    {
		# Maybe translate an integer value into a string suitable
		# for checking an unpacked Radius packet
                $svalue=$main::dictionary->valNumToName($attrDetails[0], $ivalue);
		$attr_list->add_attr($attrDetails[0], defined($svalue) ? $svalue : $ivalue);
	    }
	    else
	    {
		$attr_list->add_attr($attrDetails[0], $svalue);
	    }
	}
    }
}

#####################################################################
# Log a message to the logging table, and deduce how to update
# the badlogin count using a heuristic based on the content of the
# messages. (There really should be a better way)
my $in_log;
sub log
{
    my ($self, $priority, $s, $p) = @_;

    return if $in_log++; # Prevent recursion

    # We also insert into our database
    # (Re)-connect to the database if necessary, 
    if (!$self->reconnect)
    {
	$in_log = 0;
	return undef;
    }

    my $truncated = substr($s, 0, $self->{MaxMessageLength}) if $self->{MaxMessageLength};
    # Only log according to the global trace level
    if ($self->{LogQuery} 
	&& ($priority <= $main::config->{Trace} || ($p && $p->{PacketTrace})))
    {
	$self->do(&Radius::Util::format_special
		  ($self->{LogQuery}, undef, undef, 
		   $priority, $self->quote($truncated)));
    }
    $in_log = 0;

    if ($priority == $main::LOG_DEBUG
	&& $s =~ /REJECT: Bad .*assword/)
    {
	# If its a bad login message, increment the bad login 
	# count for this user
	$self->do(&Radius::Util::format_special
	    ($self->{IncrementBadloginsQuery}, undef, undef, 
	     $self->quote($lastUsername)))
	    if length $self->{IncrementBadloginsQuery};
    }
    elsif ($priority == $main::LOG_DEBUG
	&& $s =~ /ACCEPT:/)
    {
	# Its a good login, so set the badlogin count to 0 for this user
	$self->do(&Radius::Util::format_special
	    ($self->{ClearBadloginsQuery}, undef, undef, 
	     $self->quote($lastUsername)))
	    if length $self->{ClearBadloginsQuery};
    }

    $self->SUPER::log($priority, $s, $p);
}

1;
