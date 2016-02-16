# SIP2.pm
#
# Routines for communicating with 3M Standard Interchange Protocol 2
# as used in 3Ms Automated Circulation Systems (ACS) for book libraries
# 
# vdxipedia.oclc.org/uploads/e/ec/Sip2_developers_guide.pdf
# http://mws9.3m.com/mws/mediawebserver.dyn?6666660Zjcf6lVs6EVs66S0LeCOrrrrQ-
#
# Tested against atz-SIPServer-c8e2ac5
# https://github.com/atz/SIPServer
#
# Not to be confused with SIP Session Initiation Protocol for VOIP.
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2012 Open System Consultants
# $Id: SIP2.pm,v 1.5 2014/08/01 21:16:42 hvn Exp $

package Radius::SIP2;
@ISA = qw(Radius::Configurable);
use Radius::Configurable;
use IO::Socket::INET;
use Radius::Log;
use POSIX;
use strict;

%Radius::SIP2::ConfigKeywords = 
(
 'Port'              => 
 ['string', 'Port specifies the TCP-IP port name or number of the ACS server. Defaults to 6001.', 1],

 'Host'              => 
 ['string', 'Specifies the name or address of the ACS server. Defaults to localhost.', 0],

 'Timeout'            =>
 ['integer',
  'Specifies a timeout interval in seconds that Radiator will wait for when trying to contact the SIP2 server. Defaults to 3.', 1],

 'Delimiter'              => 
 ['string', 'The field delimiter ACS server. Defaults to "|".', 2],

 'LoginUserID'              => 
 ['string', 'User ID that Radiator will use to log into the ACS server. Defaults to "scclient". If this is defined as the empty string, no login will be performed (Caution: this must match what the server is expecting from the client. Many servers do not require a login phase.). ', 0],

 'LoginPassword'              => 
 ['string', 'Password that Radiator will use to log into the ACS server. Defaults to "clientpwd"', 0],

 'LocationCode'              => 
 ['string', 'Location code that Radiator will use to log into the ACS server. Defaults to "Radiator".', 0],

 'TerminalPassword'              => 
 ['string', 'Terminal Password that Radiator will use to log into the ACS server. Not all installations require this.', 0],

 'SendChecksum'              => 
 ['flag', 'Tells Radiator to send checksums in every request sent to ACS. This must agree with the configuraiton of the ACS.', 0],

 'VerifyChecksum'              => 
 ['flag', 'Tells Radiator to verify checksums sent by ACS are present and correct. This must agree with the configuration of the ACS.', 0],

 'UsePatronInformationRequest'              =>
 ['flag', 'Tells Radiator to use Patron Information Request instead of Patron Status Request. Defaults to off.', 0],

 'SIP2Hook'      =>
 ['hook', 'Perl hook that is run for each request handled by SIP2', 2],

);

my $language = '000';

#####################################################################
# Do per-instance default initialization
# This is called by Configurable during Configurable::new before
# the config file is parsed. Its a good place initialize
# instance variables
# that might get overridden when the config file is parsed.
sub initialize
{
    my ($self) = @_;

    $self->Radius::Configurable::initialize;
    $self->{Port} = 6001;
    $self->{Host} = 'localhost';
    $self->{Timeout} = 3;
    $self->{Delimiter} = '|';
    $self->{LoginUserID} = 'scclient'; # Works with atz-SIPServer
    $self->{LoginPassword} = 'clientpwd'; # Works with atz-SIPServer
    $self->{LocationCode} = 'Radiator';
    $self->{TerminalPassword} = 'terminal password';

    $self->{next_sequence_number} = 0;
    $self->{retries} = 3;
}

# 4 spaces means localtime
sub sip_datetime
{
    my ($self, $time) = @_;

    # Format an ACS local time
    return POSIX::strftime('%Y%m%d    %H%M%S', localtime($time));
}

sub sip_datetime_now
{
    my ($self) = @_;

    return $self->sip_datetime(time);
}

# SIP does not like NUL or delimiter in fields
sub sip_sanitize
{
    my ($self, $s) = @_;

    # Remove any NULs, CRs NLs
    $s =~ s/\0//g;
    $s =~ s/\r//g;
    $s =~ s/\n//g;
    # Replace any occurences of the delimiter with empty string
    my $d = quotemeta($self->{Delimiter});
    $s =~ s/$d//g;

    return $s;
}

sub sip_message_identifier
{
    my ($self, $s) = @_;

    return substr($s, 0, 2);
}

sub sip_format_field
{
    my ($self, $code, $value) = @_;

    return $code . $self->sip_sanitize($value) . $self->{Delimiter};
}

# Find and return the value of the field with the given code
# If not present returns undef
sub sip_decode_field
{
    my ($self, $code, $s) = @_;

    my $d = quotemeta($self->{Delimiter});
    my ($ret) = ($s =~ /$code(.*?)$d/);
    return $ret;
}

# return the next sequence number field
sub sip_sequence
{
    my ($self) = @_;

    my $ret = 'AY' . $self->{next_sequence_number};
    $self->{next_sequence_number} = ($self->{next_sequence_number} + 1) % 10;
    return $ret;
}

# Compute 4 hex digit checksum
sub sip_checksum
{
    my ($self, $s) = @_;

    my $u = unpack('%16C*', $s);
    $u = -$u & 0xFFFF;
    return sprintf('%04.4X', $u);
}

# Append sequence and checksum and return it
sub sip_append_checksum
{
    my ($self, $s) = @_;
    
    $s .= $self->sip_sequence() . 'AZ';
    $s .= $self->sip_checksum($s);
    return $s;
}

# Extracts the trailing checksum digits from the message and confirms they are correct
sub sip_verify_checksum
{
    my ($self, $s) = @_;

    return $self->sip_checksum(substr($s, 0, -4)) eq substr($s, -4);
}

# Check if the patron exists and their plaintext password is correct.
# SIP2Hook can do further or all checks.
sub acs_check_password
{
    my ($self, $patron, $password, $p) = @_;

    # 23 is Patron Status Request. 63 is Patron Information Request
    my $msg = $self->{UsePatronInformationRequest} ? 63 : 23;

    # Patron Status Request does not have the 10 octet Summary field.
    my $message = pack('a2 a3 a18', $msg, $language, $self->sip_datetime_now());
    $message .= pack('a10', '          ') if $self->{UsePatronInformationRequest}; # Summary
    $message .=
	  $self->sip_format_field('AO', $self->{institution}) 
	. $self->sip_format_field('AA', $patron)
	. $self->sip_format_field('AC', $self->{TerminalPassword})
	. $self->sip_format_field('AD', $password);
    my $response = $self->acs_connect_send_receive($message);

    # If SIP2Hook is defined, it can do some or all of authn and authz checks
    if (defined $self->{SIP2Hook})
    {
	my ($result, $reason) = $self->runHook('SIP2Hook', undef, $self, $response, $p);
	return ($main::IGNORE, 'SIP2Hook error') unless defined $result;
	return ($result, $reason) unless $result == $main::ACCEPT;
    }

    # This lets the hook to do all the work
    return ($main::ACCEPT) if $self->{NoCheckPassword};

    # Expect a 24 or 64 message, depending on request type, with CQY| in it
    unless (   $self->sip_message_identifier($response) == ($msg + 1)
	    && $self->sip_decode_field('CQ', $response) eq 'Y')
    {
	return ($main::REJECT, 'Bad password');
    }

    return $main::ACCEPT;
}

# Do login and SC Status handshake
# Need to do this once after a (re)connection
sub acs_login()
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "SIP2 logging in");
    my $message = pack('a2 a a', '93', '0', '0') 
	. $self->sip_format_field('CN', $self->{LoginUserID}) 
	. $self->sip_format_field('CO', $self->{LoginPassword}) 
	. $self->sip_format_field('CP', $self->{LocationCode});
    my $result = $self->acs_send_receive($message); 
    # check return 941 is OK, 940 or anything else is failed long
    if ($result !~ /^941/)
    {
	print STDERR "login failed\n";
	return;
    }

    # Logged in, now Send SC status, get ACS status
    # We ignore the contents of the ACS status
    # SC status is 99, OK, 30 char print width, version 2.00
    $self->log($main::LOG_DEBUG, "SIP2 SC Status");
    $message = pack('a2 a a3 a4', '99', '0', '030', '2.00');
    $result = $self->acs_send_receive($message);
    my @fixed_fields = unpack('a2 a a a a a a a3 a3 a18 a4', $result);
    if ($fixed_fields[0] eq '98')
    {
	# Get some interesting fields from ACS Status
	$self->{retries} = $fixed_fields[8];
	$self->{timeout} = $fixed_fields[7] / 10;
	$self->{institution} = $self->sip_decode_field('AO', $result);
    }
    else
    {
	$self->log($main::LOG_ERR, "SIP2 SC Status failed");
	return;
    }

    return 1; # Success
}

sub acs_disconnect
{
    my ($self) = @_;

    $self->log($main::LOG_DEBUG, "SIP2 acs_disconnect");
    $self->{socket}->close() if $self->{socket};
    $self->{socket} = undef;
}

sub acs_connected
{
    my ($self) = @_;

    return $self->{socket} && !$self->{socket}->error();
}

sub acs_connect
{
    my ($self) = @_;

    if (!$self->acs_connected())
    {
	$self->log($main::LOG_DEBUG, "SIP2 ACS connecting to $self->{Host} $self->{Port}");
	$self->{socket} = IO::Socket::INET->new
	    (PeerHost => $self->{Host},
	     PeerPort => $self->{Port},
	    );

	if (!$self->{socket})
	{
	    $self->log($main::LOG_ERR, "SIP2 could not open connection to $self->{Host} $self->{Port}: $!");
	    return;
	}
    }
    $self->log($main::LOG_DEBUG, "SIP2 ACS connected to $self->{Host} $self->{Port}");
    return $self->{socket};
}

# Send a message and recive a reply with retries
sub acs_send_receive
{
    my ($self, $s) = @_;

    $s = $self->sip_append_checksum($s) if $self->{SendChecksum};
    local $/ = "\r";

    my $retry_count;
    for ($retry_count = 0; $retry_count < $self->{retries}; $retry_count++)
    {
	$self->log($main::LOG_DEBUG, "SIP2 send '$s'");
	if (!$self->{socket}->print($s . "\r"))
	{
	    $self->log($main::LOG_ERR, "SIP2 send failed: $!");
	    $self->acs_disconnect();
	    return;
	}

	my $response;
	eval 
	{
	    local $SIG{ALRM} = sub {die "timeout"};
	    alarm($self->{Timeout});
	    $response = $self->{socket}->getline(); # Read to EOL
	};

	if ($@ && $@ =~ /timeout/)
	{
	    $self->log($main::LOG_ERR, "SIP2 timeout");
	    next;
	}

	if (!defined $response)
	{
	    $self->log($main::LOG_ERR, "SIP2 read failed: $!");
	    $self->acs_disconnect();
	    return;
	}

	# Strip leading and trailing whitepace, newlines etc
	$response =~ s/^\s+//;
	$response =~ s/\s+$//;

	$self->log($main::LOG_DEBUG, "SIP2 read '$response'");

	# REQUEST_SC_RESEND?
	if ( $response =~ /^96/)
	{
	    $self->log($main::LOG_INFO, "SIP2 received REQUEST_SC_RESEND");
	    next;
	}
	# Check the checksum
	if ($self->{VerifyChecksum} && !$self->sip_verify_checksum($response))
	{
	    $self->log($main::LOG_INFO, "SIP2 received bad checksum");
	    if (!$self->{socket}->print('97AZFEF5' . "\r")) # REQUEST_ACS_RESEND
	    {
		$self->log($main::LOG_ERR, "SIP2 write of REQUEST_ACS_RESEND failed: $!");
		$self->acs_disconnect();
		return;
	    }
	    next;
	}
	return $response;
    }
    $self->log($main::LOG_ERR, "SIP2 retries exhausted");
    $self->acs_disconnect();
    return; # Retries exhausted
}

# The main goal of this is to catch unexpected disconnections
# and to reconnect and retry the request
# As long as the connection stays up, reconnection and login are not needed
# and just the request $s is sent
# If successful, returns the response
sub acs_connect_send_receive
{
    my ($self, $s) = @_;

    my $i;
    for ($i = 0; $i < 2; $i++)
    {
	if (!$self->acs_connected())
	{
	    return unless $self->acs_connect(); # Fail
	    # Optional login
	    next if $self->{LoginUserID} ne '' && !$self->acs_login();
	}
	my $response = $self->acs_send_receive($s);
	next unless defined $response;
	return $response;
    }
    return;
}


1;
