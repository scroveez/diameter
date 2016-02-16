# ServerRADSEC.pm
#
# Object for receiving RadSec requests and satisfying them
# As per RFC 6614
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2003-2012 Open System Consultants
# $Id: ServerRADSEC.pm,v 1.42 2014/03/24 20:47:00 hvn Exp $

package Radius::ServerRADSEC;
@ISA = qw(Radius::Configurable Radius::StreamServer);
use Radius::Configurable;
use Radius::StreamServer;
use Radius::Radius;
use Radius::RadSec;
use strict;

# RCS version number of this module
$Radius::ServerRADSEC::VERSION = '$Revision: 1.42 $';

#####################################################################
# This hash describes all the standards types of keywords understood by this
# class. If a keyword is not present in ConfigKeywords for this
# class, or any of its superclasses, Configurable will call sub keyword
# to parse the keyword
# See Configurable.pm for the list of permitted keywordtype
%Radius::ServerRADSEC::ConfigKeywords = 
(
 'Secret'                     => 
 ['string',  'This parameter specifies the shared secret that will be used between this ServerRADSEC and the AuthBy RADSEC clients that will connect to it. The shared secret is used in the same was as Secret parameter in the Client clause: to encrypt passwords and generate message authenticators. The shared secret must be configured identically into ServerRADSEC and all the AuthBy RADSEC clients that will connect to it (regardless of whether TLS is enabled). Failure to do this will result in authentication errors.', 0],

 'StripFromRequest'               => 
 ['string', 'This optional parameter strips the named RADIUS attributes from the RADIUS requests received by ServerRADSEC before passing them to any authentication modules. The value is a comma separated list of attribute names. StripFromRequest removes attributes from the request before AddToRequest adds any to the request.', 1],

 'AddToRequest'               => 
 ['string', 'This optional parameter adds any number of RADIUS attributes to the RADIUS requests received by ServerRADSEC. It can be used to tag requests arriving from RadSec for special handling within Radiator or in remote RADIUS servers.', 1],

 'DefaultRealm'               => 
 ['string', 'This optional parameter can be used to specify a default realm to use for received RadSec requests that have a username that does not include a realm. If the incoming user name does not have a realm (i.e. there is no @something following the user name) and if DefaultRealm is specified, the User-Name in the resulting RADIUS request will have @defaultrealm appended to it. The realm can then be used to trigger a specific <Realm> or <Handler> clause. This is useful if you operate a number of RadSec clients for different customer groups and where some or all of your customers log in without specifying a realm.', 1],

 'PreHandlerHook'             => 
 ['hook', 'This optional parameter allows you to define a Perl function that will be called during packet processing. PreHandlerHook is called for each request received by this ServerRADSEC before it is passed to a Realm or Handler clause. A reference to the current request is passed as the only argument.', 1],

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

 'PacketTrace'                 => 
 ['flag', 
  'Forces all packets that pass through this module to be logged at trace level 4. This is useful for logging packets that pass through this clause in more detail than other clauses during testing or debugging. The packet tracing  will stay in effect until it passes through another clause with PacketTrace set to off or 0.', 
  1],

 );

#####################################################################
# Constructs a new handler
sub activate
{
    my ($self) = @_;

    $self->Radius::Configurable::activate();
    $self->Radius::StreamServer::activate();
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

    $self->Radius::Configurable::initialize();
    $self->Radius::StreamServer::initialize();
    $self->{Port} = 2083; # IANA official for RadSec
    $self->{Secret} = 'radsec';
    $self->{UseTLS} = 1;
    $self->{TLS_RequireClientCert} = 1;
}

#####################################################################
# This is called by StreamServer when a new connetion has been made
sub handle_new_connection
{
    my ($self, $newsocket) = @_;

    Radius::RadSecConnection->new
	($self, $newsocket,
	 MaxBufferSize             => $self->{MaxBufferSize},
	 Secret                    => $self->{Secret},
	 StripFromRequest          => $self->{StripFromRequest},
	 AddToRequest              => $self->{AddToRequest},
	 Identifier                => $self->{Identifier},
	 UseTLS                    => $self->{UseTLS},
	 TLS_ExpectedPeerName      => $self->{TLS_ExpectedPeerName},
	 TLS_SubjectAltNameURI     => $self->{TLS_SubjectAltNameURI},
	 TLS_CertificateFingerprint=> $self->{TLS_CertificateFingerprint},
	 TLS_PrivateKeyPassword    => $self->{TLS_PrivateKeyPassword},
	 TLS_CertificateType       => $self->{TLS_CertificateType},
	 TLS_CertificateFile       => $self->{TLS_CertificateFile},
	 TLS_CertificateChainFile  => $self->{TLS_CertificateChainFile},
	 TLS_PrivateKeyFile        => $self->{TLS_PrivateKeyFile},
	 TLS_RequireClientCert     => $self->{TLS_RequireClientCert},
	 );
}

#####################################################################
sub destroy
{
    my ($self) = @_;

    $self->Radius::StreamServer::destroy();
}

#####################################################################
#####################################################################
#####################################################################
package Radius::RadSecConnection;
use vars qw(@ISA);
@ISA = qw(Radius::StreamServer::Connection Radius::RadSec);


#####################################################################
# Called when a complete request has been received
# Parse and process it
# Version has been checked
sub recv
{
    my ($self, $rec) = @_;

    my $tp = Radius::Radius->new($main::dictionary, $rec, $self->{peer});
    $tp->{RecvSockname} = getsockname($self->{socket});
    ($tp->{RecvTime}, $tp->{RecvTimeMicros}) = &Radius::Util::getTimeHires;
    $tp->{OriginalUserName} = $tp->getAttrByNum($Radius::Radius::USER_NAME);
    $tp->{PacketTrace} = $self->{PacketTrace}
        if defined $self->{PacketTrace}; # Optional extra tracing

    $tp->decode_attrs($self->{Secret}, $tp);
    $tp->recv_debug_dump($self) if (main::willLog($main::LOG_DEBUG, $tp));
    $tp->{Client} = $self; # So you can use Client-Identifier check items

    # Add and strip attributes before passing to the modules.
    map {$tp->delete_attr($_)} (split(/\s*,\s*/, $self->{StripFromRequest}))
	if defined $self->{StripFromRequest};
    $tp->parse(&Radius::Util::format_special($self->{AddToRequest}))
	if (defined $self->{AddToRequest});

    # Arrange to call our reply function when we get a reply
    $tp->{replyFn} = [\&Radius::RadSecConnection::replyFn, $self];

    $main::statistics{total_packets}++;
    $main::statistics{packets_this_sec}++;

    if ($tp->code() eq  'Status-Server')
    {
	&Radius::Client::handle_status_server($self, $tp);
    }
    else
    {
	$self->dispatch_radius_request($tp);
    }
}

#####################################################################
# Dispatch a fake Radius request to the appropriate Handler
sub dispatch_radius_request
{
    my ($self, $tp) = @_;

    $self->log($main::LOG_WARNING, "Bad authenticator in request from RadSec $self->{Host}:$self->{Port} ", $tp)
	unless $tp->check_authenticator($self->{Secret});

    # Make sure top level config is updated with stats
    push(@{$tp->{StatsTrail}}, \%{$main::config->{Statistics}});

    $tp->{PacketTrace} = $self->{parent}->{PacketTrace} 
        if defined $self->{parent}->{PacketTrace}; # Optional extra tracing

    # Now arrange for this fake radius request to be handled and find out the result
    my ($userName, $realmName) = split(/@/, $tp->get_attr('User-Name'));
    # Maybe set a default realm
    if (defined $userName
	&& $realmName eq '' 
	&& defined $self->{'DefaultRealm'})
    {
	$realmName = $self->{'DefaultRealm'};
	$tp->changeUserName("$userName\@$realmName");
    }

    my ($handler, $finder, $handled);
    # Call the PreHandlerHook, if there is one
    $self->{parent}->runHook('PreHandlerHook', $tp, \$tp);
    foreach $finder (@Radius::Client::handlerFindFn)
    {
	if ($handler = &$finder($tp, $userName, $realmName))
	{
	    # Make sure the handler is updated with stats
	    push(@{$tp->{StatsTrail}}, \%{$handler->{Statistics}});
	    
	    # replyFn will be called from inside the handler when the
	    # reply is available
	    $handled = $handler->handle_request($tp);
	    last;
	}
    }
    $self->{parent}->log($main::LOG_WARNING, "RadSecConnection could not find a Handler")
	if !$handler;

    # Adjust statistics
    my $code = $tp->code();
    $tp->statsIncrement('requests');
    $tp->statsIncrement('accessRequests') 
	if $code eq 'Access-Request';
    $tp->statsIncrement('accountingRequests') 
	if $code eq 'Accounting-Request';
    
}


#####################################################################
# This function is called automatically when an authentication request
# has been serviced. $p->{rp} will have been set to the reply message
sub replyTo
{
    my ($self, $p) = @_;

    # Honour DefaultReply etc
    $self->{parent}->adjustReply($p);

    my $code = $p->{rp}->code;
    $p->statsIncrement('accessAccepts')
	if $code eq 'Access-Accept';
    $p->statsIncrement('accessRejects')
	if $code eq 'Access-Reject';
    $p->statsIncrement('accessChallenges')
	if $code eq 'Access-Challenge';
    $p->statsIncrement('accountingResponses')
	if $code eq 'Accounting-Response';
    my $response_time = &Radius::Util::timeInterval($p->{RecvTime}, $p->{RecvTimeMicros}, &Radius::Util::getTimeHires);
    $p->statsAverage($response_time, 'responseTime');

    # Format dumps only when they are really logged
    if (main::willLog($main::LOG_DEBUG, $p->{rp}))
    {
	my $text = "Packet dump:\n*** Sending reply to RadSec $self->{Host}:$self->{Port} ....\n" .
	    $p->{rp}->dump;
	$self->{parent}->log($main::LOG_DEBUG, $text, $p->{rp});
    }

    my $msg = $p->{rp}->assemble_packet
	($self->{Secret}, $p, 
	 ClearTextTunnelPassword => $self->{ClearTextTunnelPassword});
    $self->write($msg);
}

#####################################################################
# This fn is called by Handler when the reply to the request is ready to go back
# This works even for delayed or asynch replies.
sub replyFn
{
    my ($p, $self) = @_;
    $self->replyTo($p);
}

#####################################################################
# Push log messages from RadSec up to the parent
sub log
{
    my ($self, @args) = @_;
    $self->{parent}->log(@args);
}

1;

