# AuthHANDLER.pm
#
# Object for handling Authentication by redirecting requests to 
# a Handler that is seleced based on the Handlers's Identifier and the 
# HandlerId parameter. 
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) Open System Consultants
# 
# $Id: AuthHANDLER.pm,v 1.5 2012/12/13 20:19:47 mikem Exp $


package Radius::AuthHANDLER;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use strict;

%Radius::AuthHANDLER::ConfigKeywords = 
('HandlerId'        => 
 ['string', 'Specifies how to derive the Identifier of the Handler to handle a request. When a request is received by AuthBy HANDLER, this string will be used to derive a Handler Identifier. If a Handler with that identifier is found, the request will be redispatched to that Handler. Special characters are supported. Defaults to \'handler%{Request:Called-Station-Id}\'', 0],
 );

# RCS version number of this module
$Radius::AuthHANDLER::VERSION = '$Revision: 1.5 $';

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{HandlerId} = 'handler%{Request:Called-Station-Id}';
}

#####################################################################
sub handle_request
{
    my ($self, $p, $dummy, $extra_checks) = @_;

    $p->{PacketTrace} = $self->{PacketTrace} 
        if defined  $self->{PacketTrace}; # Optional extra tracing

    my $type = ref($self);
    $self->log($main::LOG_DEBUG, "Handling with $type: $self->{Identifier}", $p);

    # Now we might fork before processing the request
    # Should only do this for "slow" authentication methods
    return ($main::IGNORE, 'forked')
	if $self->{Fork} && !$self->handlerFork();

    # Assemble the Identifier name of the Handler we want based on the
    # pattern in HandlerId
    my $id = &Radius::Util::format_special($self->{HandlerId}, $p);
    my $handler = &Radius::Configurable::find('Handler', $id);
    if ($handler)
    {
	$self->log($main::LOG_DEBUG, "AuthBy HANDLER is redirecting to Handler '$id'", $p);
	return $handler->handle_request($p, 1);
    };

    # No handler with that Identifier found, so complain
    $self->log($main::LOG_WARNING, "AuthBy HANDLER could not find a Handler with Identifier '$id'. Ignoring", $p);
    return ($main::IGNORE, 'No Handler found');
}

1;

