# AuthLogFile.pm
#
# Specific class for logging authentication to a file
#
# Author: contributed by Dave Lloyd <david@freemm.org>
# Copyright (C) Open System Consultants
# $Id: AuthLogFILE.pm,v 1.15 2014/09/19 19:56:39 hvn Exp $

package Radius::AuthLogFILE;
@ISA = qw(Radius::AuthLogGeneric);
use Radius::AuthLogGeneric;
use Radius::Configurable;
use File::Path;
use File::Basename;
use strict;

%Radius::AuthLogFILE::ConfigKeywords = 
('SuccessFormat' => 
 ['string', 'This optional parameter specifies the format that is to be used to log authentication successes in Filename. You can use any of the special characters. Also %0 is replaced by the message severity level, and %1 by the reason string (usually an empty string for success). Defaults to %l:%U:%P:OK', 1],

 'FailureFormat' => 
 ['string', 'This optional parameter specifies the format that is to be used to log authentication failures in Filename. You can use any of the special characters. Also %0 is replaced by the message severity level, and %1 by the reason string Defaults to %l:%U:%P:FAIL', 1],

 'Filename'      => 
 ['string', 'This optional parameter specifies the name of the file where authentication log messages are to be written. You can use any of the special characters defined in Section 5.2 on page 16. Defaults to %L/password.log. ', 0],

 );

# RCS version number of this module
$Radius::AuthLogFILE::VERSION = '$Revision: 1.15 $';

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

    $self->SUPER::initialize;
    $self->{SuccessFormat} = '%l:%U:%P:OK';
    $self->{FailureFormat} = '%l:%U:%P:FAIL';
    $self->{Filename} = '%L/password.log';
}

#####################################################################
# Log a message 
# $s is $main::REJECT, or $main::ACCEPT
# $reason is the reason, $p is the request packet
sub authlog
{
    my ($self, $s, $reason, $p) = @_;

    # Leave now if this type of result should not be logged
    return unless
      ($s == $main::ACCEPT && $self->{LogSuccess} ||
       $s == $main::REJECT && $self->{LogFailure});

    my $message;
    if (defined $self->{LogFormatHook})
    {
	($message) = $self->runHook('LogFormatHook', $p, $s, $reason, $p);
    }
    elsif (defined($self->{SuccessFormat}) 
	&& $s == $main::ACCEPT) 
    {
    	$message = &Radius::Util::format_special
	    ($self->{SuccessFormat}, $p, undef, $s, $reason);
    } 
    elsif (defined($self->{FailureFormat}) 
	   && $s == $main::REJECT)
    {
    	$message = &Radius::Util::format_special
	    ($self->{FailureFormat}, $p, undef, $s, $reason);
    } 
    else 
    {
    	return;
    }

    my $filename = &Radius::Util::format_special
	($self->{Filename}, $p, undef, $s, $reason);
    &Radius::Util::append($filename, $message . "\n")
	|| warn "AuthLogFILE could not append '$message' to log file '$filename': $!";
}

1;
