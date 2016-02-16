# Tacacsplus.pm
#
# Routines for handling TACACS+ protocol
# Based on draft-grant-tacacs-02.txt 
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2004 Open System Consultants
# $Id: Tacacsplus.pm,v 1.8 2010/11/18 04:01:16 mikem Exp $

package Radius::Tacacsplus;
use Digest::MD5;
use strict;

# RCS version number of this module
$Radius::Tacacsplus::VERSION = '$Revision: 1.8 $';

# Version numbers
$Radius::Tacacsplus::TAC_PLUS_MAJOR_VERSION         = 0xc;
$Radius::Tacacsplus::TAC_PLUS_MINOR_VERSION_DEFAULT = 0;
$Radius::Tacacsplus::TAC_PLUS_MINOR_VERSION_ONE     = 1;
$Radius::Tacacsplus::TAC_PLUS_VERSION_DEFAULT       = 0xc0;
$Radius::Tacacsplus::TAC_PLUS_VERSION_ONE           = 0xc1;

# Request types
$Radius::Tacacsplus::TAC_PLUS_AUTHEN                = 1;
$Radius::Tacacsplus::TAC_PLUS_AUTHOR                = 2;
$Radius::Tacacsplus::TAC_PLUS_ACCT                  = 3;

# Flags
$Radius::Tacacsplus::TAC_PLUS_UNENCRYPTED_FLAG      = 0x01;
$Radius::Tacacsplus::TAC_PLUS_SINGLE_CONNECT_FLAG   = 0x04;

# Authentication Start actions
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_LOGIN          = 1;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_CHPASS         = 2;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_SENDPASS       = 3;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_SENDAUTH       = 4;

# Authentication Start privelege levels
$Radius::Tacacsplus::TAC_PLUS_PRIV_LVL_MAX          = 0x0f;
$Radius::Tacacsplus::TAC_PLUS_PRIV_LVL_ROOT         = 0x0f;
$Radius::Tacacsplus::TAC_PLUS_PRIV_LVL_USER         = 0x01;
$Radius::Tacacsplus::TAC_PLUS_PRIV_LVL_MIN          = 0x00;

# Authentication Start authentication types
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_TYPE_ASCII     = 1;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_TYPE_PAP       = 2;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_TYPE_CHAP      = 3;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_TYPE_ARAP      = 4;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_TYPE_MSCHAP    = 5;

# Authentication Start service types
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_SVC_NONE       = 0;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_SVC_LOGIN      = 1;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_SVC_ENABLE     = 2;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_SVC_PPP        = 3;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_SVC_ARAP       = 4;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_SVC_PT         = 5;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_SVC_RCMD       = 6;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_SVC_X25        = 7;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_SVC_NASI       = 8;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_SVC_FWPROXY    =  9;

# Authentication Start status types
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_STATUS_PASS    = 1;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_STATUS_FAIL    = 2;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_STATUS_GETDATA = 3;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_STATUS_GETUSER = 4;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_STATUS_GETPASS = 5;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_STATUS_RESTART = 6;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_STATUS_ERROR   = 7;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_STATUS_FOLLOW  = 0x21;

# Authentication Start flags
$Radius::Tacacsplus::TAC_PLUS_REPLY_FLAG_NOECHO     = 1;

# Above value is correct but code uses this one
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_FLAG_NOECHO    = 1;

# Authentication Continue flags
$Radius::Tacacsplus::TAC_PLUS_CONTINUE_FLAG_ABORT     = 0x01;

# Authorization authen_method values
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_METH_NOT_SET     = 0x00;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_METH_NONE        = 0x01;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_METH_KRB5        = 0x02;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_METH_LINE        = 0x03;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_METH_ENABLE      = 0x04;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_METH_LOCAL       = 0x05;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_METH_TACACSPLUS  = 0x06;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_METH_GUEST       = 0x08;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_METH_RADIUS      = 0x10;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_METH_KRB4        = 0x11;
$Radius::Tacacsplus::TAC_PLUS_AUTHEN_METH_RCMD        = 0x20;

# Authorization RESPONSE status types
$Radius::Tacacsplus::TAC_PLUS_AUTHOR_STATUS_PASS_ADD   = 0x01;
$Radius::Tacacsplus::TAC_PLUS_AUTHOR_STATUS_PASS_REPL  = 0x02;
$Radius::Tacacsplus::TAC_PLUS_AUTHOR_STATUS_FAIL       = 0x10;
$Radius::Tacacsplus::TAC_PLUS_AUTHOR_STATUS_ERROR      = 0x11;
$Radius::Tacacsplus::TAC_PLUS_AUTHOR_STATUS_FOLLOW     = 0x21;

# Accounting flags
$Radius::Tacacsplus::TAC_PLUS_ACCT_MORE                = 0x01;
$Radius::Tacacsplus::TAC_PLUS_ACCT_START               = 0x02;
$Radius::Tacacsplus::TAC_PLUS_ACCT_STOP                = 0x04;
$Radius::Tacacsplus::TAC_PLUS_ACCT_WATCHDOG            = 0x08;

# Accounting reply status
$Radius::Tacacsplus::TAC_PLUS_ACCT_STATUS_SUCCESS      = 0x01;
$Radius::Tacacsplus::TAC_PLUS_ACCT_STATUS_ERROR        = 0x02;
$Radius::Tacacsplus::TAC_PLUS_ACCT_STATUS_FOLLOW       = 0x21;

$Radius::Tacacsplus::TAC_PLUS_PORT                     = 49;


#####################################################################
# Reversible TACACS+ encryption
sub crypt
{
    my ($session_id, $key, $version, $seq_no, $body) = @_;

    my $res;
    my $i = 0;
    my $pad = '';
    while ($i < length $body)
    {
	$pad = Digest::MD5::md5(pack('Na*CCa*', $session_id, $key, $version, $seq_no, $pad));
	$res .= substr($body, $i, 16) ^ $pad;
	$i += 16;
    }

    # Spec calls for encrypted data to be truncated to the length of
    # the cleartext message.
    return substr($res, 0, length($body));
}

#####################################################################
sub pack_authentication_start
{
    my ($seq_no, $tflags, $session_id, $action, $priv_lvl, $authen_type, $service, $user, $port, $rem_addr, $key, $data) = @_;

    my $body = pack('CCCCCCCCa*', 
		    $action, $priv_lvl, $authen_type, $service, 
		    length($user), length($port), length($rem_addr), length($data),
		    $user . $port . $rem_addr . $data);
		    
    return pack_request($Radius::Tacacsplus::TAC_PLUS_VERSION_ONE,
			$Radius::Tacacsplus::TAC_PLUS_AUTHEN,
			$seq_no,
			$tflags,
			$session_id,
			$body,
			$key);
}

#####################################################################
sub pack_authentication_continue
{
    my ($seq_no, $tflags, $session_id, $user_msg, $aflags, $key, $data) = @_;

    my $body = pack('nnCa*', 
		    length($user_msg), length($data), $aflags,
		    $user_msg . $data);
		    
    return pack_request($Radius::Tacacsplus::TAC_PLUS_VERSION_ONE,
			$Radius::Tacacsplus::TAC_PLUS_AUTHEN,
			$seq_no,
			$tflags,
			$session_id,
			$body,
			$key);
}

#####################################################################
sub pack_authorization_request
{

    my ($seq_no, $tflags, $session_id, $authen_method, $priv_lvl, $authen_type, $authen_service, $user, $port, $rem_addr, $key, @args) = @_;

    my $body = pack('CCCCCCCCa*',
		    $authen_method, $priv_lvl, $authen_type, $authen_service, 
		    length($user), length($port), length($rem_addr), scalar @args,
		    pack('C*', map {length($_)} @args) . $user . $port . $rem_addr . join('', @args));

    return pack_request($Radius::Tacacsplus::TAC_PLUS_VERSION_DEFAULT,
			$Radius::Tacacsplus::TAC_PLUS_AUTHOR,
			$seq_no,
			$tflags,
			$session_id,
			$body,
			$key);
}

#####################################################################
sub pack_accounting_request
{

    my ($seq_no, $tflags, $aflags, $session_id, $authen_method, $priv_lvl, $authen_type, $authen_service, $user, $port, $rem_addr, $key, @args) = @_;

    my $body = pack('CCCCCCCCCa*',
		    $aflags, $authen_method, $priv_lvl, $authen_type, $authen_service, 
		    length($user), length($port), length($rem_addr), scalar @args,
		    pack('C*', map {length($_)} @args) . $user . $port . $rem_addr . join('', @args));

    return pack_request($Radius::Tacacsplus::TAC_PLUS_VERSION_DEFAULT,
			$Radius::Tacacsplus::TAC_PLUS_ACCT,
			$seq_no,
			$tflags,
			$session_id,
			$body,
			$key);
}

#####################################################################
sub pack_request
{
    my ($version, $type, $seq_no, $tflags, $session_id, $body, $key) = @_;

    $body = &crypt($session_id, $key, $version, $seq_no, $body) if defined $key;
    $tflags |= $Radius::Tacacsplus::TAC_PLUS_UNENCRYPTED_FLAG unless defined $key;
    return pack('CCCCNNa*', 
		$version, $type, $seq_no, $tflags, $session_id, length($body), $body);
}

#####################################################################
sub unpack_authentication_response
{
    my ($msg) = @_;

    my ($status, $aflags, $server_msg_length, $data_length, $body) 
	= unpack('CCnna*', $msg);

    # Check length consistency in case of bad key
    return if $server_msg_length > length($body);

    my $server_msg = substr($body, 0, $server_msg_length);
    my $data = substr($body, $server_msg_length);
    return ($status, $aflags, $server_msg, $data);
}

#####################################################################
sub unpack_authorization_response
{
    my ($msg) = @_;

    my ($status, $arg_cnt, $server_msg_length, $data_length, $body) 
	= unpack('CCnna*', $msg);
    # Check length consistency in case of bad key
    return if $arg_cnt + $server_msg_length + $data_length > length($body);

    my @arg_lens = unpack('C*', substr($body, 0, $arg_cnt));
    my $server_msg = substr($body, $arg_cnt, $server_msg_length);
    my $data = substr($body, $arg_cnt + $server_msg_length, $data_length);
    my $args = substr($body, $arg_cnt + $server_msg_length + $data_length);
    my @args;
    my $offset = 0;
    foreach (@arg_lens)
    {
	push(@args, substr($args, $offset, $_));
	$offset += $_;
    }
    return ($status, $server_msg, $data, @args);
}

#####################################################################
sub unpack_accounting_response
{
    my ($msg) = @_;

    my ($server_msg_length, $data_length, $status, $body) = unpack('nnCa*', $msg);

    # Check length consistency in case of bad key
    return if $server_msg_length > length($body);

    my $server_msg = substr($body, 0, $server_msg_length);
    my $data = substr($body, $server_msg_length);
    return ($status, $server_msg, $data);
}

#####################################################################
# Blocks
sub recv_response
{
    my ($socket, $key) = @_;

    my $inbuffer = '';
    while (sysread($socket, $inbuffer, 16384, length($inbuffer)))
    {
	if (length($inbuffer) >= 12)
	{
	    # Have the header at least
	    my ($version, $type, $seq_no, $tflags, $session_id, $length, $body) = unpack('CCCCNNa*', $inbuffer);
	    
	    # Make some trivial checks on the request
	    if (   $version != $Radius::Tacacsplus::TAC_PLUS_VERSION_DEFAULT 
		&& $version != $Radius::Tacacsplus::TAC_PLUS_VERSION_ONE)
	    {
		die "Received invalid Tacacs version number: $version\n";
	    }
	    if ($length > 100000)
	    {
		die "Received ridiculous length in response: $length\n";
	    }
	    if (length($inbuffer) >= $length + 12)
	    {
		# Have the entire request
		$body = &crypt($session_id, $key, $version, $seq_no, $body) 
		    if defined $key && !($tflags & $Radius::Tacacsplus::TAC_PLUS_UNENCRYPTED_FLAG);
		return ($version, $type, $seq_no, $tflags, $session_id, $body);
	    }
	}
    }
    return;
}

1;
