# AuthINTERNAL.pm
#
# Object for handling requests in fixed, parameterised ways
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthINTERNAL.pm,v 1.10 2007/12/18 21:23:50 mikem Exp $

package Radius::AuthINTERNAL;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use strict;

# Just a name for useful printing
my $class = 'AuthINTERNAL';

%Radius::AuthINTERNAL::ConfigKeywords = 
('DefaultResult'              => 
 ['string', 'Result to use if no other more specific result code is specified', 0],

 'AuthResult'                 => 
 ['string', 'Result to use for Authentication requests', 1],

 'AcctResult'                 => 
 ['string', 'Result to use for Accounting requests if no other more specific result code is specified', 1],

 'AcctStartResult'            => 
 ['string', 'Result to use for Accounting Start requests', 1],

 'AcctStopResult'             => 
 ['string', 'Result to use for Accounting Stop requests', 1],

 'AcctAliveResult'            => 
 ['string', 'Result to use for Accounting Alive requests', 1],

 'AcctOtherResult'            => 
 ['string', 'Result to use for other Accounting requests', 1],

 'RequestHook'                => 
 ['hook', 'Perl hook that returns a result code. Called for all requests unless there is a more specific hook', 1],

 'AuthHook'                   => 
 ['hook', 'Perl hook that returns a result code. Called for all Authentication requests', 1],

 'AcctHook'                   => 
 ['hook', 'Perl hook that returns a result code. Called for all Accounting requests unless there is a more specific hook', 1],

 'AcctStartHook'              => 
 ['hook', 'Perl hook that returns a result code. Called for all Accounting Start requests', 1],

 'AcctStopHook'               => 
 ['hook', 'Perl hook that returns a result code. Called for all Accounting Stop requests', 1],

 'AcctAliveHook'              => 
 ['hook', 'Perl hook that returns a result code. Called for all Accounting Alive requests', 1],

 'AcctOtherHook'              => 
 ['hook', 'Perl hook that returns a result code. Called for all other Accounting requests', 1],

 'OtherHook'                  => 
 ['hook', 'Perl hook that returns a result code. Called for all other requests', 1],

 'RejectReason'               => 
 ['string', 'Specifies an alternate string to return as the Reply-Message of the request is rejected (the enclosing Realm or Handler must also have RejectHasReason enabled for this to work).', 1],

 );

# RCS version number of this module
$Radius::AuthINTERNAL::VERSION = '$Revision: 1.10 $';

#####################################################################
# Do per-instance default initialization
# This is called by Configurable during Configurable::new before
# the config file is parsed. Its a good place initialize instance 
# variables
# that might get overridden when the config file is parsed.
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    
    $self->{DefaultResult} = 'ignore';
}

#####################################################################
# Handle a request
# Return according to the type of request and config parameters 
sub handle_request
{
    my ($self, $p, $dummy, $extras) = @_;

    $self->log($main::LOG_DEBUG, "Handling with $class: $self->{Identifier}", $p);

    # Call the RequestHook, if there is one
    return $self->hookResult('RequestHook', $p, $p, $p->{rp}, $extras)
	if defined $self->{RequestHook};


    if ($p->code eq 'Access-Request')
    {
	# Call the AuthHook, if there is one
	return $self->hookResult('AuthHook', $p, $p, $p->{rp}, $extras)
	    if defined $self->{AuthHook};

	return ($main::IGNORE, "Ignored due to IgnoreAuthentication")
	    if $self->{IgnoreAuthentication}; 
	return $self->handleResult('AuthResult', $p)
	    if defined $self->{AuthResult};
    }
    elsif ($p->code eq 'Accounting-Request')
    {
	return ($main::IGNORE, "Ignored due to IgnoreAccounting")
	    if $self->{IgnoreAccounting};

	# Call the AcctHook, if there is one
	return $self->hookResult('AcctHook', $p, $p, $p->{rp}, $extras)
	    if defined $self->{AcctHook};

	# Handle any of the specialised accounting types
	my $type = $p->getAttrByNum($Radius::Radius::ACCT_STATUS_TYPE);

	return $self->hookResult("Acct${type}Hook", $p, $p, $p->{rp}, $extras)
	    if defined $self->{"Acct${type}Hook"};

	return $self->handleResult("Acct${type}Result", $p)
	    if defined $self->{"Acct${type}Result"}
	       && $p->getAttrByNum($Radius::Radius::ACCT_STATUS_TYPE) eq $type;

	# Call the AcctOtherHook, if there is one
	return $self->hookResult('AcctOtherHook', $p, $p, $p->{rp}, $extras)
	    if defined $self->{AcctOtherHook};

	return $self->handleResult('AcctResult', $p)
	    if defined $self->{AcctResult};
    }
    else
    {
	# Call the OtherHook, if there is one
	return $self->hookResult('OtherHook', $p, $p, $p->{rp}, $extras)
	    if defined $self->{OtherHook};
    }
    return $self->handleResult('DefaultResult', $p);
}

#####################################################################
# Convert a string of the type permitted by the config
# parameters to a return code.
sub stringToResult
{
    my ($self, $s) = @_;

    if ($s =~ /accept/i)
    {
	return $main::ACCEPT;
    }
    elsif ($s =~ /reject/i)
    {
	return $main::REJECT;
    }
    elsif ($s =~ /ignore/i)
    {
	return $main::IGNORE;
    }
    elsif ($s =~ /challenge/i)
    {
	return $main::CHALLENGE;
    }
    else
    {
	$self->log($main::LOG_WARNING, "Unknown result code string $s. Using IGNORE");
	return $main::IGNORE;
    }
}

#####################################################################
# Works out the reply depending ont he result code.
# Adjusts the reply message according at AddToReply etc 
# if necessary
sub handleResult
{
    my ($self, $resultparam, $p) = @_;

    my $reason =  "Fixed by $resultparam";
    my $result = $self->stringToResult($self->{$resultparam});
    $self->adjustReply($p)
	if $result == $main::ACCEPT;
    $reason = $self->{RejectReason} 
        if $result == $main::REJECT && defined $self->{RejectReason};
    return ($result, $reason);
}

#####################################################################
# Run a hook to get the result code. If the result is undefined, set it to IGNORE
sub hookResult
{
    my ($self, @rest) = @_;

    my ($result, $reason) = $self->runHook(@rest);
    ($result, $reason) = ($main::IGNORE, 'Hook error') unless defined $result;
    return ($result, $reason);
}


1;
