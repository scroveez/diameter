# AuthRATELIMIT.pm
#
# Object for limiting RADIUS request rates.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2012 Open System Consultants
# $Id: AuthRATELIMIT.pm,v 1.2 2013/10/14 12:13:37 hvn Exp $

package Radius::AuthRATELIMIT;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use strict;

# RCS version number of this module
$Radius::AuthRATELIMIT::VERSION = '$Revision: 1.2 $';

%Radius::AuthRATELIMIT::ConfigKeywords =
(
 'MaxRate'      => 
 ['integer',
  'Maximum number of requests per second that wil be ACCEPTed. If more than this number of requests are received by this AuthBy in a given second, they will be IGNOREd by default. The result can be changed with MaxRateResult option. A value of 0 means no limit.',
  2],

 'MaxRateResult' =>
 ['string',
  'Result to use for when MaxRate is exceeded. Defaults to IGNORE.',
  2],
);

#####################################################################
# Do per-instance default initialization.
# This is called by Configurable during Configurable::new before the
# config file is parsed. Its a good place initialize instance
# variables that might get overridden when the config file is parsed.
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{MaxRateResult} = 'IGNORE';

    return;
}

sub handle_request
{
    my ($self, $p, $dummy, $extra_checks) = @_;

    $p->{PacketTrace} = $self->{PacketTrace} 
        if defined  $self->{PacketTrace}; # Optional extra tracing

    my $type = ref($self);
    $self->log($main::LOG_DEBUG, "Handling with $type: $self->{Identifier}", $p);

    my $time = time();
    if (!$self->{last_time} || $time != $self->{last_time})
    {
	$self->{requests_this_second} = 1;
	$self->{last_time} = $time;
    }
    else
    {
	$self->{requests_this_second}++;
    }
    if ($self->{MaxRate} && $self->{requests_this_second} > $self->{MaxRate})
    {
	my $result = $self->stringToResult($self->{MaxRateResult});
	return ($result, 'MaxRate exceeded');
    }
    else
    {
	return ($main::ACCEPT);
    }
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

1;
