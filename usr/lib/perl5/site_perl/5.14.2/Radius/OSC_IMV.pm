# OSC_IMV.pm
#
# Acts as an IMV for OSC-IMC clients, implementing a configurable policy that conforms
# to the grammar specified in $Radius::OSC_IMV::grammartext
# Implement a grammar for assessing OSC-IMC
# Copyright (C) Open System Consultants
# Author: mikem@open.com.au

package Radius::OSC_IMV;
use Radius::Log;
use Radius::TNC;
use Parse::RecDescent;
use strict;

# RCS version number of this module
$Radius::OSC_IMV::VERSION = '$Revision: 1.6 $';

# This is the grammar that describes the language for evaluating OSC_IMC clients
# It automatically generates a parse tree, which we later use to execute in the context
# of an IMC-IMV connection
$Radius::OSC_IMV::grammartext = <<'EOF';
# this is the grammar
 <autotree>
 policy: statement(s)
    | <error>
 statement: comment | if | recommend | log | usermessage
    | <error>
 comment : /#.*$/m
 if: 'if' '(' disjunction ')' '{' statement(s) '}'
    | <error>
 disjunction:    <leftop: conjunction 'or' conjunction>
    | <error>
 conjunction:    <leftop: predicate 'and' predicate>
    | <error>
 predicate: function op string
    | <error>
 function:  /[\w]+/ '.' /[\w]+/ '(' string(?) ')'
    | <error>
 op: '==' | 'contains' | 'like' | '>' | '<' | 'eq'
    | <error>
 string: "'" /[^']*/ "'"
    | <error>
 recommend: 'recommend' recommendation
    | <error>
 recommendation: 'ALLOW' | 'NO_ACCESS' | 'ISOLATE' | 'NO_RECOMMENDATION'
    | <error>
 log: 'log' loglevel string
    | <error>
 loglevel: 'ERR' | 'WARNING' | 'NOTICE' | 'INFO' | 'DEBUG'
    | <error>
 usermessage: 'usermessage' string
    | <error>
EOF

# This is the parsed grammar
$Radius::OSC_IMV::grammar = new Parse::RecDescent($Radius::OSC_IMV::grammartext) 
    or die "Bad OSC_IMV grammar\n";

# This is the parse tree that results from parsing an OSC_IMV policy script
$Radius::OSC_IMV::policy = undef;

# Load the default policy file if possible
# Allow the ability to override and predifine it at startup time
$Radius::OSC_IMV::policyFile = ($^O eq 'MSWin32') ? 'C:\osc_imv_policy.cfg' 
 : '/etc/osc_imv_policy.cfg' unless defined $Radius::OSC_IMV::policyFile;

#####################################################################
# Override the RecDescent error reporter
no warnings qw(redefine);
sub Parse::RecDescent::_error($;$)
{
    &main::log($main::LOG_ERR, "OSC_IMV policy error: @_");
}

#####################################################################
# Load a policy from a file
sub setPolicyFile
{
    my ($filename) = @_;

    local *IMV;
    if (open(IMV, $filename))
    {
	my $oldrs = $/;
	undef $/; 
	my $policy = <IMV>; # Slurp the whole file
	$/ = $oldrs;
	setPolicy($policy);
	close(IMV);
    }
    else
    {
	&main::log($main::LOG_ERR, "Could not open OSC IMV Policy file '$filename': $!. Access will not be allowed");
	return;
    }
}

#####################################################################
# $config is the text of a policy script
# it is parsed into a parse tree for later use
sub setPolicy
{
    my ($policy) = @_;

    $Radius::OSC_IMV::policy = $Radius::OSC_IMV::grammar->policy($policy)
}

#####################################################################
# Evalute the policy in the context of
# a specific IMC-IMV connection
# $context is Radius::TNC which holds the TNC details of a specific IMC-IMV connection.
sub evaluate
{
    my ($context) = @_;

    &setPolicyFile($Radius::OSC_IMV::policyFile) unless $Radius::OSC_IMV::policy;
    return $Radius::OSC_IMV::policy && $Radius::OSC_IMV::policy->execute($context);
}

#####################################################################
#####################################################################
#####################################################################
# Here are the classes that are auto-instantiated by <autotree> in the 
# grammar. These functions are executed when the 
# policy is executed in the context of a specific IMC-IMV connection, 
# passed as $context to each function

# policy is the top level grammar object
package policy;
sub execute
{
    my ($self, $context) = @_;

    foreach (@{$self->{'statement(s)'}})
    {
	$_->execute($context);
    }
    return 1;
}

# if, log or recommend
package statement;
sub execute
{
    my ($self, $context) = @_;

    $self->{log} && return $self->{log}->execute($context);
    $self->{recommend} && return $self->{recommend}->execute($context);
    $self->{usermessage} && return $self->{usermessage}->execute($context);
    $self->{if} && return $self->{if}->execute($context);
}

# if (predicate [and|or predicate]...) { statement [statement]... }
package if;
sub execute
{
    my ($self, $context) = @_;

    if ($self->{disjunction}->evaluate($context))
    {
	foreach (@{$self->{'statement(s)'}})
	{
	    $_->execute($context);
	}
	return 1;
    }
    return;
}

# function('string') op 'string'
package predicate;
sub evaluate
{
    my ($self, $context) = @_;

    my ($result, $op, $string);
    my $function = $self->{function}->evaluate($context);
    return unless defined $function; # Need to get the value
    if (defined $function)
    {
	my $op = $self->{op}->{__VALUE__};
	my $string = $self->{string}->evaluate($context);
#	print "comparing $function $op $string\n";
	if ($op eq '==')
	{
	    return $function == $string;
	}
	elsif ($op eq 'contains')
	{
	    return index($function, $string) >= 0;
	}
	elsif ($op eq 'like')
	{
	    return $function =~ /$string/;
	}
	elsif ($op eq '>')
	{
	    return $function > $string;
	}
	elsif ($op eq '<')
	{
	    return $function < $string;
	}
	elsif ($op eq 'eq')
	{
	    return $function eq $string;
	}
    }
    return;
}

# predicate or predicate
package disjunction;
sub evaluate
{
    my ($self, $context) = @_;

    my $result;
    # We dont shortcut, so we can collect all the possible IMV values we may
    # need to evaluate it correctly next time around
    foreach (@{$self->{__DIRECTIVE1__}})
    {
	my $thisresult = $_->evaluate($context);
	$result = $result || $thisresult;
    }
    return $result;
}

# predicate and predicate
package conjunction;
sub evaluate
{
    my ($self, $context) = @_;

    my $result = 1;
    # We dont shortcut, so we can collect all the possible IMV values we may
    # need to evaluate it correctly next time around
    foreach (@{$self->{__DIRECTIVE1__}})
    {
	my $thisresult = $_->evaluate($context);
	$result = $result && $thisresult;
    }
    return $result;
}

# sysname.subsysname('string')
package function;
sub evaluate
{
    my ($self, $context) = @_;

    my $sysname = $self->{__PATTERN1__};
    my $subsysname =  $self->{__PATTERN2__};
    my $string = '';
    $string = $self->{'string(?)'}[0]->evaluate() 
	if exists $self->{'string(?)'}[0];
    if (exists $context->{clientval}{$sysname}{$string}{$subsysname})
    {
	return $context->{clientval}{$sysname}{$string}{$subsysname};
    }
    
    if (!$context->{askfor}{$sysname}{$string})
    {
	$context->{askfor}{$sysname}{$string}++;
	if ($sysname eq 'Registry')
	{
	    $context->{requests} .= $context->make_registry_request($string);
	}
	elsif ($sysname eq 'Package')
	{
	    $context->{requests} .= $context->make_package_request($string);
	}
	elsif ($sysname eq 'File')
	{
	    $context->{requests} .= $context->make_file_request($string);
	}
	elsif ($sysname eq 'Extcommand')
	{
	    $context->{requests} .= $context->make_extcommand_request($string);
	}
    }
    return;
}

# recommend ALLOW|NO_ACCESS|ISOLATE|NO_RECOMMENDATION
package recommend;
sub execute
{
    my ($self, $context) = @_;
    $context->{recommendation} = $self->{recommendation}->evaluate($context);
}

package recommendation;
# Convert strings to recommendations
sub evaluate
{
    my ($self, $context) = @_;

    my %recommendations = 
	('ALLOW'             => $Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_ALLOW,
	 'NO_ACCESS'         => $Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_NO_ACCESS,
	 'ISOLATE'           => $Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_ISOLATE,
	 'NO_RECOMMENDATION' => $Radius::TNC::TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION);
    return $recommendations{$self->{__VALUE__}};
}

# log ERR|WARNING|NOTICE|DEBUG|EXTRA_DEBUG 'string'
package log;
sub execute
{
    my ($self, $context) = @_;

    &main::log($self->{loglevel}->evaluate($context), 'OSC_IMC log: ' . $self->{string}->evaluate());
}

package loglevel;
my %priorities = 
    (
     'ERR'         => $main::LOG_ERR,
     'WARNING'     => $main::LOG_WARNING,
     'NOTICE'      => $main::LOG_NOTICE,
     'INFO'        => $main::LOG_INFO,
     'DEBUG'       => $main::LOG_DEBUG,
     'EXTRA_DEBUG' => $main::LOG_EXTRA_DEBUG,
     );
sub evaluate
{
    my ($self, $context) = @_;
    return $priorities{$self->{__VALUE__}};
}

# usermessage 'string'
package usermessage;
sub execute
{
    my ($self, $context) = @_;

    $context->{requests} .= $context->make_user_message($self->{string}->evaluate());
}

# 'string'
package string;
sub evaluate
{
    my ($self, $context) = @_;
    return $self->{__PATTERN1__};
}

1;
