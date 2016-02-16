# Handler.pm
#
# Object for handling requests based on almost any 
# attribute in a packet
# We maintain a list of handlers in the same order they 
# appear in the config file
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: Handler.pm,v 1.74 2014/10/31 19:18:54 hvn Exp $

package Radius::Handler;
@ISA = qw(Radius::Configurable);
use Radius::AuthGeneric;
use Radius::AuthLogGeneric;
use Radius::SessGeneric;
use File::Basename;
use Socket;
use strict;

%Radius::Handler::ConfigKeywords = 
('AcctLogFileName'                => 
 ['stringarray', 
  'Names of the files used to log Accounting-Request messages in the standard radius accounting log format. All Accounting-Request messages will be logged to the files, regardless of their Acct-Status-Type. ', 
  1],

 'RewriteUsername'                => 
 ['stringarray', 
  'Perl expressions to alter the user name in authentication and accounting requests when they are handled by this Realm or Handler. Perl substitution and translation expressions are supported, such as s/^([^@]+).*/$1/ and tr/A-Z/a-z/', 
  1],

 'AcctLogFileFormatHook'              =>
 ['hook',
  'Specifies an optional Perl hook that will be run for each Accounting-Request message when defined. The value returned by the hook is printed to the accounting log file. By default no Hook is defined. A newline will be automatically appended.',
  1],

 'AcctLogFileFormat'              => 
 ['string', 
  'Alters the format of the accounting log file from the standard radius format. AcctLogFileFormat is a string containing special formatting characters. It specifies the format for each line to be printed to the accounting log file. A newline will be automatically appended. ', 
  1],

 'WtmpFileName'                   => 
 ['string', 
  'Unix SVR4 wtmp format file to log Accounting-Request messages. All Accounting-Request messages will be logged. If WtmpFileName is not defined, no messages will be logged in this format. Unix only', 
  1],

 'PasswordLogFileName'            => 
 ['string', 
  'File to log all authentication attempts to. The default is no logging. The file name can include special formatting characters, which means that using the %C, %c and %R specifiers, you can maintain separate password log files for each Realm or Client or a combination.', 
  1],

 'MaxSessions'                    => 
 ['integer', 
  'Apply a simple limit to the number of simultaneous sessions a user in this Realm is permitted to have. ', 
  1],

 'AccountingHandled'              => 
 ['flag', 
  'Forces Radiator to acknowledge Accounting requests, even if the AuthBy modules for the Realm would have normally ignored the request. This is useful if you don\'t really want to record Accounting requests, but your NAS keeps retransmitting unless it gets an acknowledgment.', 
  1],

 'AuthByPolicy'                   => 
 ['string', 
  'Specifies whether and how to continue authenticating after each AuthBy', 
  0],

 'RejectHasReason'                => 
 ['flag', 
  'Normally, when Radiator rejects an Access-Request, it sets the reply message to "Request Denied". This optional parameter forces Radiator to put an additional Reply-Message into Access-Reject indicating why the rejection occurred. This may be useful for debugging in some cases, since some  NASs will display the Reply-Message during an interactive login.', 
  1],

 'ExcludeRegexFromPasswordLog'    => 
 ['string', 'For security reasons, you can exclude certain users from the passwords logged to PasswordLogFileName. The value is a Perl regular expression.', 
  1],

 'SessionDatabase'                => 
 ['string', 
  'Specifies a particular Session Database to use for the enclosing Realm or Handler. The value of the parameter must be the Identifier of a SessionDatabase clause. The default behaviour is to use the last global SessionDatabase specified in the configuration file. If no SessionDatabases are specified in the configuration file, then the default INTERNAL session database will be used.', 
  1],

 'UsernameCharset'                => 
 ['string', 
  'List of characters permitted in User-Name. Request with User-Name containing characters not in this set are rejected. Perl character set formats are permitted, such as "a-zA-Z0-9" which permits all alphanumeric characters', 
  1],

 'AddToRequest'                   => 
 ['string', 
  'Adds attributes to the request before passing it to any authentication modules. Value is a list of comma separated attribute value pairs', 
  1],

 'AddToRequestIfNotExist'         => 
 ['string', 
  'Adds attributes to the request before passing it to any authentication modules. Unlike AddToRequest, an attribute will only be added if it does not already exist in the request. Value is a list of comma separated attribute value pairs ', 
  1],

 'StripFromRequest'               => 
 ['string', 
  'Strips the named attributes from the request before passing it to any authentication modules. The value is a comma separated list of attribute names. StripFromRequest removes attributes from the request before AddToRequest adds any to the request. ', 
  1],

 'HandleAscendAccessEventRequest' => 
 ['flag', 
  'Causes Radiator to respond to Ascend-Access-Event-Request messages. These messages are sent by some types of specially configured Ascend NASs. They contain a count of the number of sessions the NAS thinks it currently has in each Class.', 
  2],

 'PreProcessingHook'              => 
 ['hook', 
  'Perl function that will be called during packet processing. PreProcessingHook is called for each request before per-Realm username rewriting, before accounting log files are written, and before any PreAuthHooks. ', 
  2],

 'PostProcessingHook'             => 
 ['hook', 
  'Perl function that will be called during packet processing. PostProcessingHook is called for each request after all authentiation methods have been called and just before a reply is sent back to the requesting NAS. If the processing results in no reply (for example if the request is proxied) then PostProcessingHook is not called.', 
  2],

 'PreAuthHook'                    => 
 ['hook', 'Perl function that will be called during packet processing. PreAuthHook is called for each request after per-Realm username rewriting and before it is passed to any AuthBy clauses. ', 
  2],

 'PostAuthHook'                   => 
 ['hook', 
  'Perl function that will be called during packet processing. PostAuthHook is called for each request after it has been passed to all the AuthBy clauses. ', 
  2],

 'RewriteFunction'                => 
 ['hook', 
  'Perl function to rewrite user names. You can define an arbitrarily complex Perl function that might call external programs, search in databases or whatever. The username is changed to whatever is returned by this function.', 
  2],

 'PacketTrace'                    => 
 ['flag', 
  'Forces all packets that pass through this module to be logged at trace level 4. This is useful for logging packets that pass through this clause in more detail than other clauses during testing or debugging. The packet tracing  will stay in effect until it passes through another clause with PacketTrace set to off or 0.', 
  1],

 'LogRejectLevel'            => 
 ['integer',
  'Log level for rejected authentication attempts. Defaults to global LogRejectLevel value.',
  2],

 'ExcludeFromPasswordLog'         => 
 ['splitstringarray', 
  'For security reasons, you can exclude certain users from the passwords logged to PasswordLogFileName. The value is a white space separated list of user names.', 
  1],

 'AuthBy'                         => 
 ['objectlist', 
  'List of AuthBy clauses to be used to authenticate requests processed by the Realm or Handler. Requests are processed by each AuthBy in order until AuthByPolicy is satisifed. ', 
  0],

 'AuthLog'                        => 
 ['objectlist', 
  'A list of AuthLog clauses that will be used to log authentication results', 
  1],

 'DefaultReply'                   => 
 ['string', 
  'Adds attributes to an Access-Accept only if there would otherwise be no reply attributes. StripFromReply will never remove any attributes added by DefaultReply. Value is a list of comma separated attribute value pairs ', 
  1],

 'FramedGroup'                    => 
 ['integer', 
  'If FramedGroup is set and a matching FramedGroupBaseAddress is set in the Client from where the request came, then a Framed-IP-Address reply item is automatically calculated by adding the NAS-Port in the request to the FramedGroupBaseAddress specified by FramedGroup. ', 
  1],

 'StripFromReply'                 => 
 ['string', 
  'Strips the named attributes from Access-Accepts before replying to the originating client. The value is a comma separated list of Radius attribute names. StripFromReply removes attributes from the reply before AddToReply adds any to the reply.', 
  1],

 'AllowInReply'                   => 
 ['string', 
  'Specifies the only attributes that are permitted in an Access-Accept. It is most useful to limit the attributes that will be passed back to the NAS from a proxy server. That way, you can prevent downstream customer Radius servers from sending back illegal or troublesome attributes to your NAS.', 
  1],

 'AddToReply'                     => 
 ['string', 
  'Adds attributes reply packets. Value is a list of comma separated attribute value pairs all on one line, exactly as for any reply item. StripFromReply removes attributes from the reply before AddToReply adds any to the reply. ', 
  1],

 'AddToReplyIfNotExist'           => 
 ['string', 
  'Similar to AddToReply, but only adds an attribute to a reply if and only if it is not already present in the reply. Therefore it can be used to add, but not override a reply attribute.', 
  1],

 'DynamicReply'                   => 
 ['stringarray', 
  'Specifies reply items that will be eligible for run-time variable   substitution. That means that you can use any of the % substitutions in that reply item.', 
  1],

 'SessionDatabaseUseRewrittenName'=> 
 ['flag', 
  'Controls the username used to update and access the session database for this Handler. If SessionDatabaseUseRewrittenName is true, the rewritten username (as rewritten by RewriteUsername etc) is used. Otherwise the original User-Name attribute from the request is used.', 
  2],
 );

# RCS version number of this module
$Radius::Handler::VERSION = '$Revision: 1.74 $';

# Tell Client.pm how to get to our find function
push(@Radius::Client::handlerFindFn, \&find);

# These allow us to call various AuthGeneric functions as if they were our own
# required by checkAttributes
*Radius::Handler::check_plain_password     =  *Radius::AuthGeneric::check_plain_password;
*Radius::Handler::check_chap               =  *Radius::AuthGeneric::check_chap;
*Radius::Handler::check_mschap             =  *Radius::AuthGeneric::check_mschap;
*Radius::Handler::check_mschapv2           =  *Radius::AuthGeneric::check_mschapv2;
*Radius::Handler::check_mschapv2_plaintext =  *Radius::AuthGeneric::check_mschapv2_plaintext;
*Radius::Handler::check_plaintext          =  *Radius::AuthGeneric::check_plaintext;



#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();
    
    # Parse the handler selection expression into
    # an AttrVal for later evaluation
    $self->{Check} = Radius::AttrVal->new($self->{Name});
}

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{LogRejectLevel} = $main::config->{LogRejectLevel};
    $self->{AuthByPolicy} = 'ContinueWhileIgnore';
    $self->{ObjType} = 'Handler'; # Maintain a name-based directory
}

#####################################################################
# Find a Handler that can handle this packet, by looking in all the
# handlers inside the config file (ie in ServerConfig->{Handler})
# This is a linear search, and might be slow
# If you need to speed it up, consider a custom subclass of Handler,
# similar to Realm
sub find
{
    my ($p, $username, $realm) = @_;
    my ($h, $result, $reason);
    foreach $h (@{$main::config->{Handler}})
    {
	# See if the selection expression for the handler is true
#	&main::log($main::LOG_DEBUG, "Check if Handler $h->{Name} should be used to handle this request", $p);
	# Note, $h passed as $self in order to get the Handlers logger if present
	($result, $reason) = Radius::AuthGeneric::checkAttributes($h, $h->{Check}, $p);
	
	return $h if $result == $main::ACCEPT;
    }
    return;
}

#####################################################################
# Handle a request for a Handler
sub handle_request
{
    my ($self, $p, $no_reply) = @_;

    no warnings "uninitialized";
    # Remember which Handler processed the packet
    $p->{Handler} = $self;

    $p->{PacketTrace} = $self->{PacketTrace} 
        if defined  $self->{PacketTrace}; # Optional extra tracing

    $self->log($main::LOG_DEBUG, "Handling request with Handler '$self->{Name}', Identifier '$self->{Identifier}'", $p);

    # Prepare a reply packet, available everywhere $p is
    # If the request was redespatched by eg AuthBy HANDLER, dont overwrite it
    $p->{rp} = new Radius::Radius $main::dictionary 
        unless $p->{rp};

    $p->{rp}->set_identifier($p->identifier);
    $p->{rp}->set_authenticator($p->authenticator);

    # Call the PreProcessingHook, if there is one
    $self->runHook('PreProcessingHook', $p, \$p, \$p->{rp});

    # Rewrite the user name if required
    my $name = $p->getUserName;
    if (length $self->{RewriteFunction})
    {
	# Contributed by shawni@teleport.com, but undocumented.
	# RewriteFunction is a perl sub declaration. The sub
	# will be called to rewrite the username
	# Usage example:
	# RewriteFunction sub { my($a) = shift; $a =~ s/[\000]//g; $a =~ s/^([^@]+).*/$1/; $a =~ tr/[A-Z]/[a-z]/; $a =~ s/'//g; $a; }
	($name) = $self->runHook('RewriteFunction', $p, $name);
	$p->changeUserName($name);
 
	$self->log($main::LOG_DEBUG, "RewriteFunction rewrote user name to $name", $p);
    } 
    elsif (length $self->{RewriteUsername})
    {
	$name = $p->rewriteUsername($self->{RewriteUsername});
    }

    # Maybe check that the user name is valid
    return $self->handlerResult($p, $main::REJECT, 'Invalid character in User-Name')
	if (defined $main::config->{UsernameCharset}
	    && $name =~ /[^$main::config->{UsernameCharset}]/);
    return $self->handlerResult($p, $main::REJECT, 'Invalid character in User-Name')
	if (defined $self->{UsernameCharset}
	    && $name =~ /[^$self->{UsernameCharset}]/);

    # Add and strip attributes before forwarding. 
    map {$p->delete_attr($_)} (split(/\s*,\s*/, $self->{StripFromRequest}))
	if defined $self->{StripFromRequest};

    $p->parse(&Radius::Util::format_special($self->{AddToRequest}, $p))
	if defined $self->{AddToRequest};

    $p->parse_ifnotexist(&Radius::Util::format_special
			 ($self->{AddToRequestIfNotExist}, $p))
	if defined $self->{AddToRequestIfNotExist};
     
    # We keep some interesting attributes from the request
    # that will probably be needed
    my $nas_id = $p->getNasId();
    my $nas_port = $p->getAttrByNum($Radius::Radius::NAS_PORT);
    # 3com HiPerArc does not send NAS-Identifier EVER, and doesn't
    # send NAS-IP-Address w/Accounting-ON.  This is going to be
    # a problem if they start sending NAS-Identifier's with
    # Accounting-Starts and not Accounting-ON's.
    if (!defined $nas_id)
    {
	my ($port, $addr)
	    = Socket::unpack_sockaddr_in($p->{RecvFrom});
	$nas_id = Radius::Util::inet_ntop($addr);
    }

    ## Adjust the session database
    # Get the username before any rewriting. Need this to 
    # match users in the session database
    my $sess_username = $self->{SessionDatabaseUseRewrittenName}
                        ? $name : $p->{OriginalUserName}; 

    my $session_id = $p->getAttrByNum($Radius::Radius::ACCT_SESSION_ID);
    my $framed_ip_address = $p->getAttrByNum($Radius::Radius::FRAMED_IP_ADDRESS);
    my $sessdb = Radius::SessGeneric::find($self->{SessionDatabase});
    # See if the user will exceed the max number of sessions
    if ($p->code eq 'Access-Request')
    {
	# If we lost a Stop for this port, clean up the session database
	$sessdb->delete($sess_username, $nas_id, $nas_port, $p, 
			$session_id, $framed_ip_address);

	# Issue a denial and bomb out
	return $self->handlerResult($p, $main::REJECT, 'MaxSessions exceeded')
	    if (defined $self->{MaxSessions}
		&& $sessdb->exceeded($self->{MaxSessions}, $sess_username, $p));
    }
    elsif ($p->code eq 'Accounting-Request')
    {
	# Add a pseudo attribute for the Timestamp 
	# (adjusted by Delay-Time)
	# Some modules (AuthSQL) and logfile scripts rely on it
	$p->change_attr('Timestamp', 
		     $p->{RecvTime} 
		     - int $p->getAttrByNum($Radius::Radius::ACCT_DELAY_TIME));

	# Log the packet
	my $status_type = $p->getAttrByNum
	    ($Radius::Radius::ACCT_STATUS_TYPE);
	 
	# Handle multiple accounting log files
	if ($self->{AcctLogFileName})
	{
	    # Anonymous subroutine hides the details from logAccounting
	    my $format_hook;
	    $format_hook = sub { $self->runHook('AcctLogFileFormatHook', $p, $p); }
	        if $self->{AcctLogFileFormatHook};

	    foreach my $acctFileName (@{$self->{AcctLogFileName}})
	    {
		&Radius::Util::logAccounting
		    ($p, undef,
		     $acctFileName,
		     $self->{AcctLogFileFormat},
		     $format_hook);
	    }
	}
	
	if ($self->{WtmpFileName} ne '')
	{
	    my $filename = &Radius::Util::format_special
		($self->{WtmpFileName}, $p);
	    # Make sure the files directory exists. mkpath can die
	    eval {mkpath(dirname($filename), 0, 0755)}
		unless -d dirname($filename);

	    open(LOG, ">>$filename")
		|| $self->log($main::LOG_ERR, "Could not open wtmp file '$filename': $!", $p);
	    
	    # This is where the packet is formatted into the wtmp file.
	    # If you want a different wtmp file format, you can
	    # change this bit
	    # Write to a wtmp compatible file
	    # If its a Start, make a USER_PROCESS (7) entry else a
	    # DEAD_PROCESS (8) entry
	    if ($^O eq 'linux')
	    {
		print LOG pack 's x x i a12 a2 x xL a8 a16 l',
		$status_type eq 'Start' ? 7 : 8, $$, 
		$nas_port, '?',
		$p->{RecvTime}, $name, 'RADIUS', 
		$p->getAttrByNum($Radius::Radius::FRAMED_IP_ADDRESS);
	    }		
	    elsif ($^O eq 'freebsd')
	    {
		print LOG pack 'a8 a16 a16 L',
		$nas_port,
		# FreeBSD uses NULL username as a DEAD_PROCESS
		# hope this is ok. Jason - 'godsey@fidalgo.net'
		$status_type eq 'Start' ? $name : '',
		$p->getAttrByNum($Radius::Radius::FRAMED_IP_ADDRESS),
		$p->{RecvTime};
	    }
	    else
	    {
		print LOG pack 'a8 a4 a12 s s s s L',
		$name, '?', $nas_port, $$, 
		$status_type eq 'Start' ? 7 : 8, 0, 0, $p->{RecvTime};
	    }
	    close(LOG);
	}
	
	# Adjust the session details if we are in the parent
	# For each user, we keep a hash of session details
	# with a key of $nas_id:$nas_port
	# BUG ALERT: should we really do this every time. What
	# if its IGNOREd. What if the handler forked etc.
	if ($status_type eq 'Start')
	{
	    # Some Ciscos dont send accounting-on, so we will
	    # detect a reboot with the first session (ID 00000001)
	    $sessdb->clearNas($nas_id, $p)
		if    $session_id eq '00000000'
		   || (   $session_id eq '00000001' 
		       && $p->{Client}->{NasType} =~ /^Cisco/);
	    
	    $sessdb->add($sess_username, $nas_id, $nas_port, $p);
	}
	elsif ($status_type eq 'Alive' || $status_type eq 'Interim-Update')
	{
	    # When Cisco sends an Alive, we are going to do an update,
	    # not an insert.
	    $sessdb->update($sess_username, $nas_id, $nas_port, $p);
	}
	elsif ($status_type eq 'Stop')
	{
	    $sessdb->delete($sess_username, $nas_id, $nas_port, $p,
			    $session_id, $framed_ip_address);
	}
	elsif ($status_type eq 'Accounting-On' 
	    || $status_type eq 'Accounting-Off')
	{
	    # Detect the various kinds of NAS reboots
	    # Remove all session entries for a given NAS.
	    $sessdb->clearNas($nas_id, $p);
	}
    }
    elsif ($self->{HandleAscendAccessEventRequest}
	   && $p->code eq 'Ascend-Access-Event-Request')
    {
	# Ascend-Access-Event-Request has a count of the number
	# of sessions the NAS thinks it has in each Class. We can use
	# this to check whether out local session database is correct
	# provided its an SQL session database.
	# Sum the total number of sessions that this NAS thinks it has
	# and compare it to how many in the SessionDatabase.
	# If there is a discrepancy delete any 
	# dead sessions from SessionDatabase. Note that we never
	# add sessions to the session database, so this strategy
	# only corrects for lost Stops, not lost Starts.

	# Add up all the sessions for all classes
	my ($nascount, $detail);
	foreach $detail ($p->get_attr('Ascend-Number-Sessions'))
	{
	    # counts are in the format: 
	    # Ascend-Number-Sessions = "<0><0><0><1>classname"
	    my ($count, $class) = unpack('La*', $detail);
	    $nascount += $count;
	}
	$self->log($main::LOG_DEBUG, "Got a current session count of $nascount for NAS $nas_id", $p);

	# Make sure its really an SQL SessionDatabase
	if (ref($sessdb) eq 'Radius::SessSQL')
	{
	    # Now find out how many sessions the SessionDatabase 
	    # thinks we have for this NAS
	    my ($result, @sessions) = $sessdb->sessionsOnNAS($nas_id, $p);
	    $self->log($main::LOG_DEBUG, "sessionsOnNAS reports $result, @sessions for NAS $nas_id", $p);
	    
	    if ($result && @sessions > $nascount)
	    {
		# The counts dont agree, so poll the NAS for its list 
		# of current sessions, and remove dead ones from the 
		# session database
		$self->log($main::LOG_WARNING, "PORTLIMITCHECK SessionDatabase count does not agree with NAS", $p);
		
		my ($sessresult, @nassessions) = 
		  Radius::Nas::activeSessions
		      ($p->{Client}->{NasType}, $nas_id, $p->{Client});

		if ($sessresult)
		{
		    # Now find sessions in our session database that are
		    # not in the NAS's list, and delete them
		    my ($session, %nassessionhash);
		    # Make a hash for easy lookup of the existence of 
		    # a session
		    map { $nassessionhash{$_}++ } @nassessions;
		    foreach $session (@sessions)
		    {
			if (!exists $nassessionhash{$session})
			{
			    # The session is in our session database
			    # but not in the NAS
			    $sessdb->clearNasSession($nas_id, 
						     $session, $p);
			}
		    }
		}
	    }
	}
	else
	{
	    $self->log($main::LOG_ERR, 'No SQL SessionDatabase to use. Ignoring', $p);
	}

	# Send a reply, no matter what happened
	$p->{rp}->set_code('Accounting-Response');
	$p->{Client}->replyTo($p);
	return $main::ACCEPT;
    }

    # $result can be IGNORE, ACCEPT or REJECT
    my $result = $main::REJECT; # If there is no handlers
    my $reason = 'No AuthBy found';
    $result = $main::IGNORE if ($p->code eq 'Accounting-Request');

    # Call the PreAuthHook, if there is one
    $self->runHook('PreAuthHook', $p, \$p, \$p->{rp});

    # Try all the AuthBy handlers in sequence until the AuthByPolicy
    # is satisfied
    # CAUTION: The AuthBy handler might fork
    my $auth;

    foreach $auth (@{$self->{AuthBy}})
    {
	# Make sure the authby is updated with stats
	push(@{$p->{StatsTrail}}, \%{$auth->{Statistics}});

	# Remember which AuthBy was last to process the packet
	$p->{AuthBy} = $auth;

	($result, $reason) = $auth->handle_request($p, $p->{rp});
	$self->log($main::LOG_DEBUG, "AuthBy $auth->{Name} result: $Radius::AuthGeneric::reasons[$result], $reason", $p);

	# Evaluate the AuthByPolicy
	last unless $self->evaluatePolicy($self->{AuthByPolicy},$result);
    }

    # Call the PostAuthHook, if there is one
    $self->runHook('PostAuthHook', $p, \$p, \$p->{rp}, \$result, \$reason);

    # AuthBy HANDLER needs this to prevent inner requests being lost
    return ($result, $reason) if $no_reply;

    # And send the right type of reply back
    return $self->handlerResult($p, $result, $reason);
}

#####################################################################
# Process the results of authenticating the request by sending back
# the appropriate type of reply
# This might be a useful function in a noReplyHook, with something like:
# $p->{Handler}->handlerResult($p, Radius::AuthGeneric::find('identifier')->handle_request($p, $p->{rp}))
# Caution, this API changed post 2.19
sub handlerResult
{
    my ($self, $p, $result, $reason) = @_;

    my $doReply;
    my $code = $p->code;

    if ($code eq 'Access-Request')
    {
	my $name = $p->getUserName;
	if ($result == $main::ACCEPT)
	{
	    $self->log($main::LOG_DEBUG, "Access accepted for $name", $p);
	    $self->authlog($main::ACCEPT, $reason, $p);
	    $p->{rp}->set_code('Access-Accept');
	    $doReply++;
	}
	elsif (   $result == $main::REJECT
	       || $result == $main::REJECT_IMMEDIATE)
	{
	    $self->log($self->{LogRejectLevel}, "Access rejected for $name: $reason", $p);
	    $self->authlog($main::REJECT, $reason, $p);
	    $p->{rp}->set_code('Access-Reject');

	    if ($p->{rp}->getAttrByNum($Radius::Radius::REPLY_MESSAGE)) 
	    {
		$p->{rp}->changeAttrByNum($Radius::Radius::REPLY_MESSAGE,'Request Denied')
		    if !$self->{RejectHasReason};
	    }
	    else
	    {
		$p->{rp}->addAttrByNum($Radius::Radius::REPLY_MESSAGE,
				       $self->{RejectHasReason} ?
				       $reason : 'Request Denied');
	    }

	    $doReply++;
	}
	elsif ($result == $main::CHALLENGE)
	{
	    $self->log($main::LOG_DEBUG, "Access challenged for $name: $reason", $p);
	    $p->{rp}->set_code('Access-Challenge');
	    $doReply++;
	}
	elsif (!$p->{proxied})
	{
	    # IGNORE means no reply
	    $p->statsIncrement('droppedRequests', 'droppedAccessRequests');
	}
    }
    elsif ($code eq 'Accounting-Request')
    {
 	#
 	# AccountingHandled Patch <shawni@teleport.com>
 	#
 	# Sometimes we want to lie to the terminal server and tell
 	# it the accounting-request was handled, regardless of
 	# what the AuthBy handlers said.
 	#
	$result = $main::ACCEPT
	    if $self->{AccountingHandled};

	if ($result == $main::ACCEPT)
	{
	    $self->log($main::LOG_DEBUG, "Accounting accepted", $p);
	    $p->{rp}->set_code('Accounting-Response');
	    $doReply++;
	}
	elsif ($result == $main::REJECT)
	{
	    $self->log($main::LOG_DEBUG, "Accounting rejected: $reason", $p);
	    $p->statsIncrement('droppedRequests', 'droppedAccountingRequests');
	}
	elsif ($result == $main::IGNORE && !$p->{proxied})
	{
	    # IGNORE means no reply
	    $p->statsIncrement('droppedRequests', 'droppedAccountingRequests');
	}
    }
    elsif ($code eq 'Disconnect-Request')
    {
	if ($result == $main::ACCEPT)
	{
	    $self->log($main::LOG_DEBUG, "Disconnect-Request accepted", $p);
	    $p->{rp}->set_code('Disconnect-Request-ACKed');
	    $doReply++;
	}
	elsif ($result == $main::REJECT
	       || $result == $main::REJECT_IMMEDIATE)
	{
	    $self->log($main::LOG_INFO, "Disconnect-Request rejected: $reason", $p);
	    $p->{rp}->set_code('Disconnect-Request-NAKed');
	    $doReply++;
	}
    }
    elsif ($code eq 'Change-Filter-Request')
    {
	if ($result == $main::ACCEPT)
	{
	    $self->log($main::LOG_DEBUG, "Change-Filter-Request accepted", $p);
	    $p->{rp}->set_code('Change-Filter-Request-ACKed');
	    $doReply++;
	}
	elsif ($result == $main::REJECT
	       || $result == $main::REJECT_IMMEDIATE)
	{
	    $self->log($main::LOG_INFO, "Change-Filter-Request rejected: $reason", $p);
	    $p->{rp}->set_code('Change-Filter-Request-NAKed');
	    $doReply++;
	}
    }
    elsif ($code eq 'Ascend-Access-Event-Request')
    {
	if ($result == $main::ACCEPT)
	{
	    $self->log($main::LOG_DEBUG, "Ascend-Access-Event-Request accepted", $p);
	    $p->{rp}->set_code('Ascend-Access-Event-Response');
	    $doReply++;
	}
	# Dont know how to reject them, just ignore
    }

    # If the request was proxied, adjust the count
    $p->statsIncrement('proxiedRequests')
	if $p->{proxied} && $result == $main::IGNORE;

    if ($doReply)
    {
	# Make sure we always copy the Proxy-State
	# There may be more than one Proxy-State attribute
	# in a request, so copy all of them to the reply
	$p->{rp}->delete_attr('Proxy-State'); # Remove bogus or cached state
	map {$p->{rp}->addAttrByNum($Radius::Radius::PROXY_STATE, $_)} $p->get_attr('Proxy-State');

	# Also copy Proxy-Action, in case its merit asking us
	my $pa = $p->getAttrByNum($Radius::Radius::PROXY_ACTION);
	$p->{rp}->changeAttrByNum($Radius::Radius::PROXY_ACTION, $pa)
	    if defined $pa;

	# Honour DefaultReply etc
	$self->adjustReply($p);

	# Call the PostProcessingHook, if there is one
	$self->runHook('PostProcessingHook', $p, \$p, \$p->{rp});

	# Run the original receivers reply func
	my @replyFn = @{$p->{replyFn}};
	my $replyFn = shift @replyFn;
	&{$replyFn}($p, @replyFn, \$result); 
    }
    # Ignore anything else
    return $result;
}

#####################################################################
# Maybe log success or fail of password checking
sub logPassword
{
    my ($self, $user, $submitted_pw, $correct_pw, $result, $p) = @_;


    if (defined $self->{PasswordLogFileName})
    {
	# Dont log for any of the names in ExcludeFromPasswordLog
	return 
	    if defined $self->{ExcludeFromPasswordLog}
	       && grep {$_ eq $user} @{$self->{ExcludeFromPasswordLog}};

  	# Dont log for any of the names that match ExcludeRegex FromPasswordLog
  	return 
  	    if defined $self->{ExcludeRegexFromPasswordLog}
 		&& $user =~ /$self->{ExcludeRegexFromPasswordLog}/;
  
	my $filename = &Radius::Util::format_special($self->{PasswordLogFileName}, $p);
	my $time = time;
	my $ctime = localtime($time);
	my $r = $result ? 'PASS' : 'FAIL';
	&Radius::Util::append
	    ($filename, 
	     "$ctime:$time:$user:$submitted_pw:$correct_pw:$r\n")
		|| $self->log($main::LOG_ERR, "Could not append password log file '$filename': $!", $p);
    }
}

#####################################################################
# Log auth success/failure to all AuthLog modules
# Args are $s, $r, $p
# $s is the result code
# $r is the reason message
# $p is the current packet
sub authlog
{
    my ($self, @args) = @_;

    map {$_->authlog(@args)} @{$self->{AuthLog}}; 
}

1;

