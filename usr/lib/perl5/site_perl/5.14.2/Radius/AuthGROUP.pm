# AuthGROUP.pm
#
# Object for handling Authentication and accounting groups
# Most of this is pinched from Handler.pm, which will eventually inherit 
# this behaviour from this module.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthGROUP.pm,v 1.17 2010/11/17 21:03:08 mikem Exp $

package Radius::AuthGROUP;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use strict;

%Radius::AuthGROUP::ConfigKeywords = 
(
 'AuthByPolicy'                   => 
 ['string', 
  'Specifies whether and how to continue authenticating after each AuthBy', 
  0],

 'RewriteUsername'                => 
 ['stringarray', 
  'Perl expressions to alter the user name in authentication and accounting requests when they are handled by this GROUP. Perl substitution and translation expressions are supported, such as s/^([^@]+).*/$1/ and tr/A-Z/a-z/', 
  1],

 'AuthBy'                         => 
 ['objectlist', 
  'List of AuthBy clauses to be used to authenticate requests processed by the GROUP. Requests are processed by each AuthBy in order until AuthByPolicy is satisifed. ', 
  0],

 'StripFromRequest'               => 
 ['string', 
  'Strips the named attributes from the request before passing it to any authentication modules. The value is a comma separated list of attribute names. StripFromRequest removes attributes from the request before AddToRequest adds any to the request. ', 
  1],

 'AddToRequest'                   => 
 ['string', 
  'Adds attributes to the request before passing it to any authentication modules. Value is a list of comma separated attribute value pairs', 
  1],

 'AddToRequestIfNotExist'         => 
 ['string', 
  'Adds attributes to the request before passing it to any authentication modules. Unlike AddToRequest, an attribute will only be added if it does not already exist in the request. Value is a list of comma separated attribute value pairs ', 
  1],
 );

# RCS version number of this module
$Radius::AuthGROUP::VERSION = '$Revision: 1.17 $';

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
    $self->{AuthByPolicy} = 'ContinueWhileIgnore';
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

    # Trivial handling follows
    if ($p->code eq 'Access-Request')
    {
	return ($main::IGNORE, "Ignored due to IgnoreAuthentication")
	    if $self->{IgnoreAuthentication} ;
    }
    elsif ($p->code eq 'Accounting-Request')
    {
	return ($main::IGNORE, "Ignored due to IgnoreAccounting")
	    if $self->{IgnoreAccounting};

	my $status_type = $p->getAttrByNum($Radius::Radius::ACCT_STATUS_TYPE);
	# If we have a HandleAcctStatusTypes and this type is not mentioned
	# Acknowledge it, but dont do anything else with it
	return ($main::ACCEPT)
	    if defined $self->{HandleAcctStatusTypes}
	       && !exists $self->{HandleAcctStatusTypes}{$status_type};

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
    }

    # Now we might fork before processing the request
    # Should only do this for "slow" authentication methods
    return ($main::IGNORE, 'Forked')
	if $self->{Fork} && !$self->handlerFork();

    # $handled can be IGNORE, ACCEPT or REJECT
    my $handled = $main::REJECT; # No handler

    $p->rewriteUsername($self->{RewriteUsername})
	if (defined $self->{RewriteUsername});

    # Add and strip attributes before handling. 
    map {$p->delete_attr($_)} (split(/\s*,\s*/, $self->{StripFromRequest}))
	if defined $self->{StripFromRequest};

    $p->parse(&Radius::Util::format_special($self->{AddToRequest}, $p))
	if defined $self->{AddToRequest};

    $p->parse_ifnotexist(&Radius::Util::format_special
			 ($self->{AddToRequestIfNotExist}, $p))
	if defined $self->{AddToRequestIfNotExist};
     
    # Try all the authenticators in sequence until the AuthByPolicy
    # is satisfied
    # CAUTION: The handler might fork
    my ($handler, $reason);
    foreach $handler (@{$self->{AuthBy}})
    {
	# Make sure the authby is updated with stats
	push(@{$p->{StatsTrail}}, \%{$handler->{Statistics}});

	($handled, $reason) = $handler->handle_request($p, $p->{rp}, $extra_checks);
	# Evaluate the AuthByPolicy
	$self->log($main::LOG_DEBUG, "$type:$self->{Identifier} $handler->{Identifier} result: $Radius::AuthGeneric::reasons[$handled], $reason", $p);
	last unless $self->evaluatePolicy($self->{AuthByPolicy},$handled);
    }

    # Check the DefaultSimultaneousUse
    if (defined $self->{DefaultSimultaneousUse}
	&& $p->code eq 'Access-Request'
	&& Radius::SessGeneric::find($p->{Handler}->{SessionDatabase})
	->exceeded($self->{DefaultSimultaneousUse}, $p->getUserName(), $p))
    {
	return ($main::REJECT,
		"DefaultSimultaneousUse of $self->{DefaultSimultaneousUse}  exceeded");
    }

    $self->adjustReply($p)
	if ($handled == $main::ACCEPT);
	
    return ($handled, $reason);
}

#####################################################################
# This function may be called during operation to reinitialize 
# this module
# it is expected to reload any state, perhaps by rereading files, 
# reconnecting to a database or something like that.
# Its not actually called yet, but it as well to be 
# prepared for the day
# when it will be.
sub reinitialize
{
    my ($self) = @_;
}

1;
