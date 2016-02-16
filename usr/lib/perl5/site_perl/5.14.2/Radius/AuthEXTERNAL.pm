# AuthEXTERNAL.pm
#
# Object for handling requests with an external program
# The command line given with the Command parameter will be run
# for each request. The attributes in the request will 
# be passed to stdin, and each line output to stdout will
# be replied in Reply-Message attributes.
# The type of reply will depend on the exit status of the external
# command:
#  0 Accept
#  1 Reject
#  2 Ignore (done send any reply
#  3 Issue an Access-Challenge
# If you use the ResultInOutput switch, then the type of the reply
# is given on the first line of the stdout output of the external
# program.
# 
# SPECIAL NOTE: only the  ResultInOutput is working on Win98, 
# OK on NT and UNix
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthEXTERNAL.pm,v 1.26 2013/08/13 20:58:45 hvn Exp $

package Radius::AuthEXTERNAL;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use IPC::Open2;
use strict;

%Radius::AuthEXTERNAL::ConfigKeywords = 
('Command' => 
 ['string', 'Specifies the command to run. The command can include special formatting characters. There is no default, and a Command must be specified. See the refernece manual for details of how stdin, stdout and exit status are interpreted.', 0],

 'DecryptPassword' => 
 ['flag', 'This optional parameter makes AuthBy EXTERNAL decrypt the User-Password attribute before passing it to the external program. If you don\'t specify this, User-Password will be passed exactly as received in the request (i.e. encrypted by MD5 according to the Radius standard).', 1],

 'ResultInOutput' => 
 ['flag', 'If this optional parameter is set, AuthBy EXTERNAL will determine the type of the reply from the first line of the stdout output of the external program, rather than the exit code of the external program.', 1],
 );

# RCS version number of this module
$Radius::AuthEXTERNAL::VERSION = '$Revision: 1.26 $';

# Hash for converting result names to result codes for the case
# where ResultInOutput is in use.
my %resultToCode = (
		    'ACCEPT', $main::ACCEPT,
		    'REJECT', $main::REJECT,
		    'IGNORE', $main::IGNORE,
		    'CHALLENGE', $main::CHALLENGE,
		    'REJECT_IMMEDIATE', $main::REJECT_IMMEDIATE,
		    );

#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate
sub check_config
{
    my ($self) = @_;

    $self->log($main::LOG_WARNING, "No Command defined for AuthEXTERNAL in '$main::config_file'")
	unless defined $self->{Command};

    $self->SUPER::check_config();
    return;
}

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();
}

#####################################################################
# Handle a request
# This function is called for each packet. $p points to a Radius::
# packet
sub handle_request
{
    my ($self, $p, $dummy, $extra_checks) = @_;


    return ($main::IGNORE, "Ignored due to IgnoreAuthentication")
	if $self->{IgnoreAuthentication} 
           && $p->code eq 'Access-Request';
    return ($main::IGNORE, "Ignored due to IgnoreAccounting")
	if $self->{IgnoreAccounting} 
           && $p->code eq 'Accounting-Request';

    # Maybe we will fork?
    return ($main::IGNORE, 'Forked')
	if $self->{Fork} && !$self->handlerFork();

    my ($result, $reason, $firstline);
    my $command = &Radius::Util::format_special($self->{Command}, $p);

    $self->log($main::LOG_DEBUG, "Running command: $command", $p);
    local (*READER, *WRITER);
    my $pid = open2(\*READER, \*WRITER, $command);
    
    # Put the request atributes on stdin
    # and convert the password if we need to
    my $r;
    foreach $r (@{$p->{Attributes}})
    {
	my $value = $r->[1];
	my @attr = $p->{Dict}->attrByName($r->[0]);
	if ($attr[1] == $Radius::Radius::USER_PASSWORD
	    && $attr[3] == 0
	    && $self->{DecryptPassword})
	{
	    $value = $p->decodedPassword();
	}
        print WRITER "\t$r->[0] = \"" . Radius::AttrVal::pclean($value) . "\"\n";
    }

    # The pipe does not close in Win95 unless we do this:
    # ^Z closes the pipe
    print WRITER "\032" if $^O eq 'MSWin32'; 
    close WRITER;

    # For each line received from the external program, try
    # to parse it as a set of attribute=vaue pairs. If that doesnt
    # work, just use the line as a Reply-Message (for backwards
    # compatibility
    while (<READER>)
    {
	chomp;        
	# Get the the result from the first line of stdout
	if ($self->{ResultInOutput} && $. == 1)
	{
	    $firstline = $_;
	    next;
	}
	if (!$p->{rp}->parse($_))
	{
	    $p->{rp}->addAttrByNum($Radius::Radius::REPLY_MESSAGE, $_);
	}
    }
    my $exit = $?;
    # This usually sets $?
    close READER; 
    # Sometimes need to do this too.
    $exit = $? if waitpid($pid, 0);
    $self->log($main::LOG_DEBUG, "External command exited with status $exit", $p);
	    
    if ($self->{ResultInOutput})
    {
	$result = $resultToCode{$firstline};
	if (!defined $result)
	{
	    $self->log($main::LOG_ERR, 
		       "ResultInOutput is enabled, but the first line of from the EXTRNAL command is an unknown result code", $p);
	    $result = -1;
	}
	    
    }
    elsif ($exit & 0xff)
    {
	# Some sort of error or signal
	$result = $main::REJECT;
	$reason = "Error $exit running EXTERNAL command: $!";
    }
    else
    {
	# No error, result code is what we want
	$result = $exit >> 8;
    }

    # Add and strip attributes before replying
    $self->adjustReply($p)
	if $result == $main::ACCEPT;

    return ($result, $reason); 
    
}

#####################################################################
# This function may be called during operation to 
# reinitialize this module
# it is expected to reload any state, perhaps by rereading files, 
# reconnecting to a database or something like that.
# Its not actually called yet, but it as well to be 
# prepared for the day
# when it will be.
sub reinitialize
{
#    my ($self) = @_;
}

1;
