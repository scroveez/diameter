# AuthTEST.pm
#
# Object for handling Authentication.
# This test version shows how to construct a new type 
# of packet handler.
#
# This file will be 'require'd only one time when the first Realm 
# with an AuthType of TEST is found in the config file
#
# In this example, Authentication requests always succeed
# and accounting packets ar ignored.
# All packets are dumped to stdout
#
# You can use $self->log to log messages to the logfile, and any 
# other modules you see fit.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthTEST.pm,v 1.25 2013/08/13 20:58:45 hvn Exp $

package Radius::AuthTEST;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use strict;

#####################################################################
# This hash describes all the standards types of keywords understood by this
# class. If a keyword is not present in ConfigKeywords for this
# class, or any of its superclasses, Configurable will call sub keyword
# to parse the keyword
# See Configurable.pm for the list of permitted keywordtypes
%Radius::AuthTEST::ConfigKeywords = 
(
 'MyKeyword1' => 
 ['string', 'Documentation for MyKeyword1', 1],

 'MyKeyword2' => 
 ['string', 'Documentation for MyKeyword2', 1],

 );

# RCS version number of this module
$Radius::AuthTEST::VERSION = '$Revision: 1.25 $';

# Just a name for useful printing
my $class = 'AuthTEST';

# Can make sure we get reinitialized on sighup
#push(@main::reinitFns, \&reinitialize);

&main::log($main::LOG_DEBUG, "$class loaded");

#####################################################################
# Constructs a new handler
# This will be called one for each <Realm ...> that specifies
# <AuthTEST ...>
# $file is the file we are currently parsing, it should be
# passed to the superclass Configurable, which will call
# the keyword and object routines here whenever it sees 
# those things in the config file.
# You should set up any permanent state here, such as a cached 
# user name file, or open a database etc
#
# If your 'new' constructor does not do anything other than calling
# the superclass, you can omit it.
#
# This instance will be destroyed when the server is reinitialised
sub new
{
    my ($class, @args) = @_;

    my $self = $class->SUPER::new(@args);

    $self->log($main::LOG_DEBUG, "New $class constructed");
    return $self;
}


#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate.
sub check_config
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "Configuration check for $class succeeded");

    $self->SUPER::check_config();
    return;
}

#####################################################################
# Do per-instance state (re)creation.
# This wil be called after the instance is created and after parameters have
# been changed during online reconfiguration.
# If it doesnt do anything, you can omit it.
sub activate
{
    my ($self) = @_;
    $self->SUPER::activate();
}

#####################################################################
# Do per-instance default initialization
# This is called by Configurable during Configurable::new before
# the config file is parsed. Its a good place initialize instance 
# variables
# that might get overridden when the config file is parsed.
# If it doesnt do anything, you can omit it.
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{MyKeyword1} = 1234;
}

#####################################################################
# Handle a request
# This function is called for each packet. $p points to a Radius::
# packet containing the original request. $p->{rp} is a reply packet
# you can use to reply, or else fill with attributes and get
# the caller to reply for you.
# $extra_checks is an AttrVal containing check items that 
# we must check for, regardless what other check items we might 
# find for the user. This is most often used for cascading 
# authentication wuth Auth-Type .
# In this test module, Accounting is ignored
# It is expected to (eventually) reply to Access-Request packets
# with either Access-Accept or Access-Reject
# Accounting-Request will automatically be replied to by the 
# Realm object
# so there is no need to reply to them, although they might be forwarded
# logged in a site-specific fashion, or something else.
#
# The return value significant:
# If false, a generic reply will be constructed by Realm, else no reply will
# be sent to the requesting client. In general, you should always
# handle at least Access-Request and return 0
# Also returns an optional reason message for rejects
sub handle_request
{
    my ($self, $p, $dummy, $extra_checks) = @_;

    return ($main::IGNORE, "Ignored due to IgnoreAuthentication")
	if $self->{IgnoreAuthentication} 
           && $p->code eq 'Access-Request';
    return ($main::IGNORE, "Ignored due to IgnoreAccounting")
	if $self->{IgnoreAccounting} 
           && $p->code eq 'Accounting-Request';

    my $client_port = $p->{RecvFromPort};
    my $client_addr = $p->{RecvFromAddress};
    my $client_name = Radius::Util::inet_ntop($client_addr);

    $self->log($main::LOG_INFO, 
	       "$class handle_request: Received from $client_name port $client_port", $p);
    print $p->dump
	if ($main::config->{Trace} >= 4);

    if ($p->code eq 'Access-Request')
    {
	# You could put your own attributes in the reply
	# by calling $p->{rp}->add_attr('attr-name', 'attr-value') here

	# Add and strip attributes before replying
	$self->adjustReply($p);

	return ($main::ACCEPT);
    }
    elsif ($p->code eq 'Accounting-Request')
    {
	# Handler will construct a generic reply for us
	return ($main::ACCEPT);
    }
    else
    {
	# Handler will construct a generic reply for us
	return ($main::ACCEPT);
    }
}

#####################################################################
# This function will be called during SIGHUP
# Its class-specific, not object-specific
# Override it to do any module specific reinitialization
# it could reload any state, perhaps by rereading files, 
# reconnecting to a database or something like that.
# You usually dont need to do anything here, and can remove this function
#sub reinitialize
#{
#}

#####################################################################
# Optionally handle object destruction
# You usually dont need to do anything here, and can remove this function
#sub DESTROY
#{
#}

#####################################################################
# Find the named user, return a User object if found for this
# authentication type else undef.
# If there is a database access error (as opposed to the user
# was not found, return (undef, 1)
# In many cases, this is the only serious function you would need to
# implement
sub findUser
{
    my ($self, $name, $p) = @_;

    $self->log($main::LOG_DEBUG, "$class findUser", $p);
    return;
}

1;

