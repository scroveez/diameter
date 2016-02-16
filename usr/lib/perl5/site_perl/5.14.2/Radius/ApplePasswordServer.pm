# ApplePasswordServer.pm
#
# Module for connecting to a Mac OS-X Apple Passsword Server and authenticating users
# Copyright (C) 1997 Open System Consultants
# Author: mikem@open.com.au

package Radius::ApplePasswordServer;
@ISA = qw(Radius::Logger);
use Radius::Logger;
use Crypt::OpenSSL::Random;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Bignum;
use MIME::Base64;
use Digest::MD5;
use Digest::HMAC_MD5;
use strict;

# RCS version number of this module
$Radius::ApplePasswordServer::VERSION = '$Revision: 1.9 $';

# Hash of current connections to different password servers, indexed by thier host
my %connections = ();

#####################################################################
# Find an existing connection or create a new connection to a PS
# $address is the address of the server, in one of the forms:
#  203.63.154.59
#  dns/yoke.open.com.au
#  ipv4/203.63.154.59
#  ipv6/2001:720:1500:1::a100
# $rootuser is the name and host of the 
# Implements caching and reuse of connection, based on $address
sub connect
{
    my ($self, $address, $certificate) = @_;

    my $c = $connections{$address};
    if ($c)
    {
	return unless $c->connect();
	return $c;
    }
    else
    {
	# need to create a new connection to PS and verify it
	$c = Radius::ApplePasswordServer::Connection->new
	    (Parent => $self,
	     Host => $address,
	     Port => 3659,
	     Protocol => 'tcp',
	     Certificate => $certificate);
	$connections{$address} = $c;
	return unless $c;
	return unless $c->connect();
	return $c;
    }
}

#####################################################################
#####################################################################
#####################################################################
package Radius::ApplePasswordServer::Connection;

#####################################################################
sub new
{
    my ($class, %args) = @_;

    my $self = {%args};
    bless $self, $class;

    return $self;
}

#####################################################################
# Connect to a PS and validate the connection
sub connect
{
    my ($self) = @_;

    $self->{Parent}->log($main::LOG_DEBUG, "ApplePasswordServer connect $self->{Host} $self->{Port}");
    return 1 if $self->{connected} && getpeername($self->{socket});

    # Need to reconnect
    my $port = Radius::Util::get_port($self->{Port});
    my $host = $self->{Host};
    my ($paddr, $pfamily);
    if ($host =~ /ipv6\/(\S+)/)
    {
	($paddr, $pfamily) = &Radius::Util::pack_sockaddr_pton($port, 'ipv6:' . $host);
    }
    elsif ($host =~ /dns\/(\S+)/
	   || $host =~ /ipv4\/(\S+)/
	   || $host =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)
    {
	($paddr, $pfamily) = &Radius::Util::pack_sockaddr_pton($port, $host);
    }
    else
    {
	$self->{Parent}->log($main::LOG_ERR, "ApplePasswordServer: bad address format: $host");
	return;
    }
    my $protocol = getprotobyname($self->{Protocol});
    if (!defined $protocol)
    {
	$self->{Parent}->log($main::LOG_ERR,  "ApplePasswordServer: Unknown Protocol type: $self->{Protocol}");
	return;
    }
    if (socket($self->{socket}, $pfamily, &Socket::SOCK_STREAM(), $protocol))
    {
	$self->{Parent}->log($main::LOG_DEBUG, "ApplePasswordServer attempting $self->{Protocol} connection to $self->{Host}:$self->{Port}");

	# Blocking
	if (connect($self->{socket}, $paddr))
	{
	    # Got an immediate connection, dont need to wait for
	    # connenction with select()
	    select((select($self->{socket}), $| = 1)[0]); # Autoflush
	    return $self->connected();
	}
    }
}

#####################################################################
# Have a basic TCP connection to the server
# Return true if connected to the right server and validated
sub connected
{
    my ($self) = @_;

    $self->{Parent}->log($main::LOG_DEBUG, "ApplePasswordServer: connected to $self->{Host}:$self->{Port}");
    $self->{connected}++;
    return $self->validate();
}

#####################################################################
sub disconnected
{
    my ($self) = @_;

    $self->{Parent}->log($main::LOG_WARNING, "ApplePasswordServer: disconnected from $self->{Host}:$self->{Port}");
    $self->{connected} = undef;
    shutdown($self->{socket}, 2);
    close($self->{socket});
}

#####################################################################
# Have a basic TCP connection to the server, now validate the connection
sub validate
{
    my ($self) = @_;

    my $in = $self->readServer();
    # Should get something like
    # +OK ApplePasswordServer 10.4.5.0 password server at 0.0.0.0 ready.
    if ($in =~ /^\+OK (\S+) (\S+)/)
    {
	$self->{Parent}->log($main::LOG_DEBUG, "ApplePasswordServer connected to server $1 $2");
	$self->{servertype} = $1;
	$self->{serverversion} = $2;
    }
    else
    {
	$self->{Parent}->log($main::LOG_ERR, 'ApplePasswordServer: bad initial string from server');
	return;
    }

    # Ask for SASL methods and RSA public key
    $self->sendServer('LIST RSAPUBLIC');

    # Get the response to the LIST command
    $in = $self->readServer();
    if ($in =~ /^\+OK \(SASL (.*)\)/)
    {
	@{$self->{methods}} = map {/\"(.*)\"/} split(/ /, $1);
    }
    else
    {
	$self->{Parent}->log($main::LOG_ERR, "ApplePasswordServer: bad response to LIST RSAPUBLIC");
	return;
    }
    
    # Now get the RSAPUBLIC response. It consists of 
    # a public key (number of bits, exponent, modulus, name)
    $in = $self->readServer();
    if ($in =~ /^\+OK ((\d+) (\d+) (\d+) (\S+))/)
    {
	# Check here that the public key is the one we expected?
	if ($1 ne $self->{Certificate})
	{
	    $self->{Parent}->log($main::LOG_ERR, "ApplePasswordServer: Incorrect public certificate received from $self->{Host}");
	return;
	}

	my $exponent = Crypt::OpenSSL::Bignum->new_from_decimal($3);
	my $modulus  = Crypt::OpenSSL::Bignum->new_from_decimal($4);
	$self->{rsa_pub}  = Crypt::OpenSSL::RSA->new_key_from_parameters($modulus, $exponent);
	$self->{rsa_pub}->use_pkcs1_padding();
    }
    else
    {
	$self->{Parent}->log($main::LOG_ERR, "ApplePasswordServer: Bad response to RSAPUBLIC");
	return;
    }

    # OK, now have the servers public key. Check that the server has the corresponding 
    # private key.
    # We generate a random nonce. Encrypt it wit hthe servers public key. 
    # The server then sends back either the decrypted nonce or its hash. 
    # If that matches our original nonce, then we can be sure that the server has the 
    # correct private key correspoionding to the public key.
    # IF that is all OK, then we can also use the nonce as a CAST encryption key 
    # for traffic to the server (not implemented here yet)
    my $nonce = &Radius::Util::random_string(32);
    my $plaintext = $nonce;

    # If the nonce ends in 'hash' then the server will send back a 16 octet MD5 hash 
    # of the decrypted nonce, else the decrypted nonce itself. This improves the 
    # security of the verification algorithm, and allows us to encrypt the conversation
#    $plaintext .= "hash";

    my $ciphertext = $self->{rsa_pub}->encrypt($plaintext);
    $self->sendServer('RSAVALIDATE ' .  binToB64($ciphertext));

    # Now get back our nonce decrypted by the server using the servers private key.
    # if it matches the nonce before we encrypted it, 
    # this proves the server is the one we expect to talk to
    $in = $self->readServer();
    if ($in =~ /^\+OK (\S+)/)
    {
	my $decoded = B64ToBin($1);

	# If the nonce ends in 'hash' the server _should_ send back MD5 hash 
	# of the decrypted nonce
	if (length($decoded) == 16 
	    && $decoded eq Digest::MD5::md5($nonce))
	{
	    # REVISIT: Need to do CAST encryption of the conversation with the server
	    $self->{Parent}->log($main::LOG_DEBUG, 'ApplePasswordServer: good hashed nonce from server');
	}
	# otherwise the server sends back the decrypted nonce (padded)
	elsif (length($decoded) == 128
	       && substr($decoded, 0, length($nonce)) eq $nonce)
	{
	    $self->{Parent}->log($main::LOG_DEBUG, 'ApplePasswordServer: good unhashed nonce from server');
	}
	else
	{
	    $self->{Parent}->log($main::LOG_ERR, 'ApplePasswordServer: bad nonce from server');
	    return;
	}
    }
    else
    {
	$self->{Parent}->log($main::LOG_ERR, 'ApplePasswordServer: bad response from RSAVALIDATE');
	return;
    }
    return 1; # Success
}

#####################################################################
# Returns true if the server supports a particular method
sub supports_method
{
    my ($self, $method) = @_;

    return grep {$_ eq $method} @{$self->{methods}};
}

#####################################################################
sub auth_plaintext
{
    my ($self, $userid, $pw) = @_;

    # See if we can do CRAM-MD5
    if ($self->supports_method('CRAM-MD5'))
    {
	# Use CRAM-MD5 to authenticate a plaintext password as per RFC 2195
	# We generate the challenge
#	my $challenge = Radius::Util::random_string(32);
	# Sigh, at 10.4, if the challenge has a NUL in it, the server
	# fails to authenticate!!!! Use a pseudo-random:
	my $challenge = 'uadsbdfiulzDfashdflgjkhsdlf-oauf';
	my $response = Digest::HMAC_MD5::hmac_md5($challenge, $pw);
#	my $response = Radius::Util::hmac_md5($pw, $challenge); # old alternative
	return $self->auth_cram_md5($userid, $challenge, $response);
    }
    else
    {
	$self->{Parent}->log($main::LOG_DEBUG, "ApplePasswordServer: no suitable method found for plaintext authentication");
	return;
	
    }
}

#####################################################################
# $userid is the Apple Password Server user id eg 0x45de6abc3dce3ee80000000400000004
# $challenge is a 32 octet binary challenge
# $response is the 32 octet response calculated from 
#  Digest::HMAC_MD5::hmac_md5($challenge, $pw);
sub auth_cram_md5
{
    my ($self, $userid, $challenge, $response) = @_;

    # Its possible to lose the connection to the server at unexpected times
    # be prepared to try again
    my $retries = 0;
    while ($retries++ < 2)
    {
	next unless $self->connect();

	# Now tell the server the username we want to do CRAM-MD5
	# If its not uppercase HEX encoded, get wierd responses back
	$self->sendServer("USER $userid AUTH CRAM-MD5 " . uc(unpack('H*', $challenge)));
	my $in = $self->readServer();
	next unless $self->{connected};
	# Expect 64 hex characters of challenge
	# Sigh, at 10.4, if teh challenge has a NUL in it, we dont get the 
	# whole thing back from the server here.
	if ($in =~ /^\+AUTHOK ([0-9a-fA-F]{64})/)
	{
	    my $retchallenge = pack('H*', $1);
	    if ($retchallenge ne $challenge)
	    {
		$self->{Parent}->log($main::LOG_ERR, "ApplePasswordServer, bad challenge received back from server");
		return;
	    }
	}
	else
	{
	    $self->{Parent}->log($main::LOG_ERR, 'ApplePasswordServer, bad response from AUTH CRAM-MD5 command');
	    return;
	}
	
	# Now send the username and the HMAC MD5 of the password and challenge hex encoded
	my $auth = $userid . ' ' . unpack('H*', $response);
	my $auth_hex = unpack('H*', $auth);
	$self->sendServer("AUTH2 $auth_hex");
	$in = $self->readServer();
	next unless $self->{connected};
	if ($in =~ /^\+OK/)
	{
	    return 1;
	}
	else
	{
	    $self->{Parent}->log($main::LOG_ERR, "ApplePasswordServer, bad response from AUTH command: $in");
	    return;
	}
    }
    $self->{Parent}->log($main::LOG_ERR, "ApplePasswordServer, too many retries");
    return;
}

#####################################################################
# $userid is the Apple Password Server user id eg 0x45de6abc3dce3ee80000000400000004
# $challenge 16 octet random challenge gemerated by the authentication server
# $peerchallenge is t he 16 octet random challenge generated by the peer
# $response is the 24 octet MSCHAPV2 response from the peer
# $clientusername is the username used by the peer to generate the response 
# (usually the username  entereed bythe user at the clinet
# $authenticator_responsedest is a refernce to the returned authenticator response
# $mppekeys_dest is a reference to the returned MPPE keys (total 16 octets)
sub auth_mschapv2
{
    my ($self, $userid, $challenge, $peerchallenge, $response, $clientusername, $mppekeys_dest, $authenticator_responsedest) = @_;

    # Its possible to lose the connection to the server at unexpected times
    # be prepared to try again
    my $retries = 0;
    while ($retries++ < 2)
    {
	next unless $self->connect();

	# Now tell the server we want to do MSCHAPV2
	# The string sent is in a special format and MUST be upppercase hex encoded
	$self->sendServer("USER $userid AUTH MS-CHAPv2 " . 
			  uc(unpack('H*', 
				    pack('a* x a* x a16 a16 x8 a24 x a*', 
					 $userid, $userid, $challenge, $peerchallenge, 
					 $response, $clientusername))));
	
	my $in = $self->readServer();
	next unless $self->{connected};
	my $authenticator_response;
	if ($in =~ /^\+AUTHOK ([0-9a-fA-F]{80})/)
	{
	    # This is the hex encoded authenticator_response (which is itelf hex encoded)
	    # Prefix with S= to make the authenticator repsonse string
	    $$authenticator_responsedest = 'S=' . pack('H*', $1)
		if defined $authenticator_responsedest;
	}
	else
	{
	    $self->{Parent}->log($main::LOG_ERR, "ApplePasswordServer, bad response from AUTH MS-CHAPv2 command: $in");
	    return;
	}
	
	my $keylength = 16;
	# Now get the user session key
	$self->sendServer("GETPPTPKEYS $userid " . uc(unpack('H*', $response)) . " $keylength");
	$in = $self->readServer();
	next unless $self->{connected};
	if ($in =~ /^\+OK (\{\d+}\S+)/)
        {
	    # This is the B64 encoded MPPE keys
	    my $k = B64ToBin($1);
	    # This result is bytecount(1) sendkey(16) recvkey(16) padding
	    # (all strung together) eg:
	    # 10 09743cafc46ef097 6efaff0881bbb676cf225b67f91bcafa63a2cabcf831bd2f 00000000000000
	    my $keys = unpack('x a32', $k);
	    if (length($keys) != $keylength * 2)
	    {
		$self->{Parent}->log($main::LOG_ERR, "ApplePasswordServer, bad MPPE Master key length from GETPPTPKEYS");
		return;
	    }
	    # $keys is the send and receive keys concatenated, 
	    # as would be returned by Radius::MSCHAP::mppeGetKeys. 
	    # Each key is $keylength/2 octets

	    $$mppekeys_dest = $keys if defined $mppekeys_dest;
	    return 1; # Success
	}
        else
	{
	    $self->{Parent}->log($main::LOG_ERR, "ApplePasswordServer, bad response from GETPPTPKEYS command: $in");
	    return;
	}
    }
    $self->{Parent}->log($main::LOG_ERR, "ApplePasswordServer, too many retries");
    return;
}

#####################################################################
# WARNING: incomplete
sub auth_digest_md5
{
    my ($self, $userid, $realm, $nonce, $cnonce, $nc, $qop, $method, $digest_uri, $response) = @_;

    # Its possible to lose the connection to the server at unexpected times
    # be prepared to try again
    my $retries = 0;
    while ($retries++ < 2)
    {
	next unless $self->connect();

	# Now tell the server we want to do DIGEST-MD5
	$self->sendServer("USER $userid AUTH DIGEST-MD5");
	my $in = $self->readServer();
	next unless $self->{connected};
	if ($in =~ /^\+AUTHOK (\S+)/)
	{
	    # The string returned from the server is in the form:
	    # nonce="Y8wuf8TMc4T6WbRQOEW2h0/QosFDNDlf1SZI1psWkF8=",realm="yoke.local",qop="auth,auth-int,auth-conf",cipher="rc4-40,rc4-56,rc4,des,3des",maxbuf=4096,charset=utf-8,algorithm=md5-sess
	    my $challenge = pack('H*', $1);
	    print "got digest md5 challenge $challenge\n";
	    # REVISIT: extract these bits and use them.
	}
	else
	{
	    $self->{Parent}->log($main::LOG_ERR, "ApplePasswordServer, bad response from AUTH DIGEST-MD5 command: $in");
	    return;
	}
	
	my $nonce_b64 = MIME::Base64::encode_base64($nonce, '');
	my $cnonce_b64 = MIME::Base64::encode_base64($cnonce, '');
	my $auth = "username=\"$userid\",realm=\"$realm\",nonce=\"$nonce_b64\",cnonce=\"$cnonce_b64\",nc=$nc,qop=$qop,method=$method,cipher=rc4,maxbuf=4096,digest-uri=\"$digest_uri\",response=$response";

	print "will send $auth\n";

	my $auth_hex = unpack('H*', $auth);
	$self->sendServer("AUTH2 $auth_hex");
	$in = $self->readServer();
	next unless $self->{connected};
	# REVISIT: not finished
	return;
    }
    $self->{Parent}->log($main::LOG_ERR, "ApplePasswordServer, too many retries");
    return;
}

#####################################################################
# Encode a binary string into a Base 64 hex encoded string of the form
# {nnn}xxxx
# where nnn is the length of the unencoded binary string and xxxx is the base64 
# encoding of the string
sub binToB64
{
    my ($b) = @_;

    return '{' . length($b) . '}' . MIME::Base64::encode_base64($b, '');
}

#####################################################################
# And the reverse
sub B64ToBin
{
    my ($h) = @_;

    my $ret;
    if ($h =~ /^\{(\d+)\}(\S+)/)
    {
	$ret = MIME::Base64::decode_base64($2);
	substr($ret, $1, 0) = ''; # Truncate
    }
    return $ret;
}

#####################################################################
# Apple password Server supports either plaintext with CR/NL separators or CAST encryption
sub sendServer
{
    my ($self, $command) = @_;

    # Could do CAST encryption here
    $self->{Parent}->log($main::LOG_DEBUG, "ApplePasswordServer sends: $command");
    # REVISIT CAST encrypt here if required
    my $sock = $self->{socket};
    print $sock $command . "\r\n";
}

#####################################################################
# Caution: blocking read
sub readServer
{
    my ($self) = @_;

    # Could do CAST decryption here
    my $sock = $self->{socket};
    my $in = <$sock>;
    # Sigh, PS can disappear in the middle of a conversation
    if (!length($in))
    {
	$self->{Parent}->log($main::LOG_ERR, "ApplePasswordServer: read an empty reply. Peer probably disconnected: $!");
	$self->disconnected();
	return;
    }
    $self->{Parent}->log($main::LOG_DEBUG, "ApplePasswordServer read: $in");
    return $in;
}
1;
