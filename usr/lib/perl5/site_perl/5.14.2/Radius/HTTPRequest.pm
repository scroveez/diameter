# HTTPRequest.pm
#
# Simple class for holding HTTP request
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2007 Open System Consultants
# $Id: HTTPRequest.pm,v 1.3 2012/12/13 20:19:47 mikem Exp $
package Radius::HTTPRequest;
use Config;
use strict;

# RCS version number of this module
$Radius::HTTPRequest::VERSION = '$Revision: 1.3 $';

my $os = $Config::Config{'osname'};
my $ebcdic=  "\t" ne "\011";
$Radius::HTTPRequest::CRLF = "\015\012";
if ($os eq 'VMS') 
{
  $Radius::HTTPRequest::CRLF = "\n";
} 
elsif ($ebcdic) 
{
  $Radius::HTTPRequest::CRLF= "\r\n";
}

#####################################################################
sub new
{
    my ($class, %args) = @_;

    $args{'proto'} ||= 'HTTP/0.9';
    return bless {%args}, $class;
}

#####################################################################
sub param
{
    my ($self, $name) = (@_);

    return @{$self->{parameters}->{$name}} if wantarray;
    return $self->{parameters}->{$name}[0];
}

#####################################################################
sub params
{
    my ($self) = (@_);

    return keys %{$self->{parameters}};
}

#####################################################################
sub header
{
    my ($self, $name) = (@_);

    $name = lc $name;
    return @{$self->{headers}->{$name}} if wantarray;
    return $self->{headers}->{$name}[0];
}

#####################################################################
# Parse header lines out of $$buf (destrctively) and return
# a has of all the headers found
# Headers are all stored with lower cased keys
sub parse_header
{
    my ($buf) = @_;

    my %headers;
    my($key, $val);
    while ($$buf =~ s/^([^\012]*)\012//) 
    {
	$_ = $1;
	s/\015$//;
	if (/^([^:\s]+)\s*:\s*(.*)/) 
	{
	    push(@{$headers{lc $key}}, $val) if $key;
	    ($key, $val) = ($1, $2);
	}
	elsif (/^\s+(.*)/) 
	{
	    $val .= " $1";
	}
	else 
	{
	    last;
	}
    }
    push(@{$headers{lc $key}}, $val) if $key;

    return %headers;
}

#####################################################################
sub parse_params
{
    my ($self) = @_;

    # See if we need to handle a multipart form
    my $ct = $self->header('Content-Type');
    if ($ct =~ /multipart\/form-data/)
    {
	my ($boundary) = $ct =~ /boundary=\"?([^\";,]+)\"?/;
	my ($content) = $self->{content} =~ /$boundary$Radius::HTTPRequest::CRLF(.*)$boundary/s;
	my %formheaders = parse_header(\$content);
	my $cd = $formheaders{'content-disposition'}[0];
	my ($param) = $cd =~ / name="([^;]*)"/;
	my ($filename) = $cd =~ / filename="([^;]*)"/;
	push (@{$self->{parameters}->{$param}}, $content);
    }
    else
    {
	my $tosplit = $self->{content};
	my (@pairs) = split(/[&;]/, $tosplit);
	my ($param, $value);
	foreach (@pairs) 
	{
	    ($param,$value) = split('=',$_,2);
	    next unless defined $param;
	    $value = '' unless defined $value;
	    $param = CGI::Util::unescape($param);
	    $value = CGI::Util::unescape($value);
	    push (@{$self->{parameters}->{$param}},$value);
	}
	
    }
}

#####################################################################
# Extract and parse keywords from the URI
sub parse_keywords
{
    my ($self) = @_;

    $self->{path} = $self->{uri};
    return unless $self->{uri} =~ /(.*)\?(.*)/;
    $self->{path} = $1;
    $self->{keywords} = $2;
    my $tosplit = $2;
    my (@pairs) = split(/[&;]/, $tosplit);
    my ($param, $value);
    foreach (@pairs) 
    {
	($param,$value) = split('=',$_,2);
	next unless defined $param;
	$value = '' unless defined $value;
	$param = CGI::Util::unescape($param);
	$value = CGI::Util::unescape($value);
	push (@{$self->{parameters}->{$param}}, $value);
    }
}


1;
