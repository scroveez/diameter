# AuthURL.pm
#
# Object for handling Url Authentication.
##
# Author: Mauro Crovato (mauro@crovato.com.ar)
# Copyright (C) 2002 Open System Consultants
# $Id: AuthURL.pm,v 1.17 2012/05/29 01:23:24 mikem Exp $

package Radius::AuthURL;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use strict;
use HTTP::Request;
use LWP::UserAgent;
use Digest::MD5  qw(md5_base64);
use URI::Escape;

#####################################################################
# KeyWords Supported
%Radius::AuthURL::ConfigKeywords = 
(
 'Debug'              => 
 ['flag', 'This optional flag parameter specifies if any incoming authentication that result in Auth-Accept, will be logged with the Radiator logging system. The default is to not log.', 1],

 'Timeout'            => 
 ['integer',  'This optional parameter specifies the timeout (in seconds) for the http connection to the web server. The default 5.', 1],

 'UserParam'          => 
 ['string', 'This optional parameter specifies the name of the URL tag variable used to pass the Username being authenticated, to the URL The default is "user".', 1],

 'PasswordParam'      => 
 ['string', 'This optional parameter specifies the name of the URL tag variable used to pass the Password being authenticated, to the URL The default is "password".', 1],

 'AuthUrl'            => 
 ['string', 'This optional parameter specifies the complete URL that will be used to authenticate the username and password. It is usually set to the URL of a CGI or ASP program on a web server that you control. HTTPS is supported, but see the hint in the Radiator Reference manual for details on how to enable HTTPS support.', 0],

 'AcctUrl'            => 
 ['string', 'This optional parameter specifies the complete URL that will be used to save accounting data from Accounting-Request packets. All the attributes in the request will be sent as HTTP tags, using either GET or POST, depending on the setting of UrlMethod.', 0],

 'UrlMethod'          => 
 ['string', 'This optional parameter specifies what type of submit method is going to be used to pass user and pass to the URL. Possible values are GET or POST. It is not sensitive to case. The default is GET.', 1],

 'BadPasswordKeyword' => 
 ['string', 'This optional parameter specifies the name of the string that has to be found in the response from the web server, to select an Auth-Reject Bad Password response message The default is "BadPassword".', 1],

 'BadUserKeyword'     => 
 ['string', 'This optional parameter specifies the name of the string that has to be found in the response from the web server, to select an Auth-Reject Bad User response message The default is "BadUser".', 1],

'AuthChallengeKeyword'      => 
 ['string', 'This optional parameter specifies the name of the string that has to be found in the response from the web server, to select an Auth-Challenge response message The default is "AuthChallenge".', 1],

 'AuthOKKeyword'      => 
 ['string', 'This optional parameter specifies the name of the string that has to be found in the response from the web server, to select an Auth-Accept response message The default is "AuthOK".', 1],

 'PasswordEncryption' => 
 ['string', 'This optional parameter specifies the type of encryption that is going to be used, to send the password to the url. The options available are Clear, Crypt and MD5 (case insensitive). The default is "Clear".', 1],

'PasswordUriEscape'  =>
 ['string', 'This optional parameter specifies whether the password needs to be url-encoded or not. Options are "Clear", "Encode".', 1],

 'ChapChallengeParam'      => 
 ['string', 'For CHAP authentication, the name of the web parameter to use to send the CHAP challenge. Not used for PAP or other types of authentication. Defaults to  chap_challenge', 1],

 'ChapResponseParam'      => 
 ['string', 'For CHAP authentication, the name of the web parameter to use to send the CHAP response. Not used for PAP or other types of authentication. Defaults to  chap_response', 1],

 'MSChapChallengeParam'      => 
 ['string', 'For MSCHAP authentication, the name of the web parameter to use to send the MSCHAP challenge. Not used for PAP or other types of authentication. Defaults to  mschap_challenge', 1],

 'MSChapResponseParam'      => 
 ['string', 'For MSCHAP authentication, the name of the web parameter to use to send the MSCHAP response. Not used for PAP or other types of authentication. Defaults to  mschap_response', 1],

 'MSChapV2ChallengeParam'      => 
 ['string', 'For MSCHAPV2 authentication, the name of the web parameter to use to send the MSCHAPV2 challenge. Not used for PAP or other types of authentication. Defaults to  mschapv2_challenge', 1],

 'MSChapV2ResponseParam'      => 
 ['string', 'For MSCHAPV2 authentication, the name of the web parameter to use to send the MSCHAPV2 response. Not used for PAP or other types of authentication. Defaults to  mschapv2_response', 1],

 'CopyRequestItem'      => 
 ['stringarray', 'Adds a tagged item to the HTTP request. Format is CopyRequestItem xxx yyy. The text of yyy (which may be contain special characters) will be added to the HTTP request with the tag xxx. In the special case where yyy is not defined, the value of attribute named xxx will be  copied from the incoming RADIUS request and added to the HTTP request as the tagged item yyy. All values are HEX encoded before adding to the HTTP request. Multiple CopyRequestItem parameters are permitted, one per line.', 1],

 'CopyReplyItem'      => 
 ['stringarray', 'Copies an attribute=value pair in a successful HTTP response to the RADIUS reply. Format is CopyReplyItem xxx yyy. If a successful HTTP reply contains a string like "xxx=hexencodedvalue" the value will be copied to the RADIUS reply as attribute yyy=value. Multiple CopyReplyItem parameters are permitted, one per line.', 1],

 );

# RCS version number of this module
$Radius::AuthURL::VERSION = '$Revision: 1.17 $';

my $class = 'AuthUrl';

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{Debug} = 0;
    $self->{Timeout} = 5;
    $self->{UserParam} = 'user';    
    $self->{PasswordParam} = 'password';    
    $self->{AuthUrl} = 'http://127.0.0.1';
    $self->{UrlMethod} = 'GET';        
    $self->{BadPasswordKeyword} = 'BadPassword';    
    $self->{BadUserKeyword} = 'BadUser';    
    $self->{AuthOKKeyword} = 'AuthOK';    
    $self->{AuthChallengeKeyword} = 'AuthChallenge';  
    $self->{PasswordUriEscape} = 'Clear';
    $self->{PasswordEncryption} = 'Clear';    
    $self->{ChapChallengeParam} = 'chap_challenge',
    $self->{ChapResponseParam} = 'chap_response',
    $self->{MSChapChallengeParam} = 'mschap_challenge',
    $self->{MSChapResponseParam} = 'mschap_response',
    $self->{MSChapV2ChallengeParam} = 'mschapv2_challenge',
    $self->{MSChapV2ResponseParam} = 'mschapv2_response',
}

#####################################################################
# Handle a request
sub handle_request {
    my ($self, $p, $dummy, $extra_checks) = @_;

    return ($main::IGNORE, "Ignored due to IgnoreAuthentication") 
	if $self->{IgnoreAuthentication} && $p->code eq 'Access-Request';
    return ($main::IGNORE, "Ignored due to IgnoreAccounting") 
	if $self->{IgnoreAccounting} && $p->code eq 'Accounting-Request';

    my $user = $p->getUserName;
    if ($p->code eq 'Access-Request' && length $self->{'AuthUrl'}) 
    {    
	my ($attr, $challenge, $password);
	my %vars;
	if (defined ($attr = $p->getAttrByNum($Radius::Radius::CHAP_PASSWORD)))
	{
	    return ($main::REJECT, "Cant use AuthBy URL PasswordEncryption with CHAP")
		if ($self->{PasswordEncryption} !~ /clear/i );

	    my $challenge = $p->getAttrByNum($Radius::Radius::CHAP_CHALLENGE);
	    $challenge = $p->authenticator unless defined $challenge;
	    $vars{$self->{'UserParam'}} = $user;
	    $vars{$self->{'ChapChallengeParam'}} = unpack('H*', $challenge);
	    $vars{$self->{'ChapResponseParam'}} = unpack('H*', $attr);
	}
	elsif (   ($attr = $p->get_attr('MS-CHAP-Response'))
	       && ($challenge = $p->get_attr('MS-CHAP-Challenge')))
	{
	    # Its an MS-CHAP request
	    return ($main::REJECT, "Cant use AuthBy URL PasswordEncryption with MSCHAP")
		if ($self->{PasswordEncryption} !~ /clear/i );

	    $vars{$self->{'UserParam'}} = $user;
	    $vars{$self->{'MSChapChallengeParam'}} =  unpack('H*', $challenge);
	    $vars{$self->{'MSChapResponseParam'}} = unpack('H*', $attr);

	}
	elsif (   ($attr = $p->get_attr('MS-CHAP2-Response'))
	       && ($challenge = $p->get_attr('MS-CHAP-Challenge')))
	{
	    # Its an MS-CHAP V2 request
	    return ($main::REJECT, "Cant use AuthBy URL PasswordEncryption with MSCHAPV2")
		if ($self->{PasswordEncryption} !~ /clear/i );

	    $vars{$self->{'UserParam'}} = $user;
	    $vars{$self->{'MSChapV2ChallengeParam'}} = unpack('H*', $challenge);
	    $vars{$self->{'MSChapV2ResponseParam'}} = unpack('H*', $attr);
	}
	else
	{
	    # Assume its PAP
	    my $password = $p->decodedPassword();
	    
	    if ( $self->{PasswordEncryption} =~ /MD5/i ){
		$password = md5_base64($user.$password);
	    } elsif ( $self->{PasswordEncryption} =~ /crypt/i ){
		$password = crypt($password, $user);
	    }
	    $vars{$self->{'UserParam'}} = $user;
	    if ( $self->{PasswordUriEscape} =~ /encode/i )
	    {
		$vars{$self->{'PasswordParam'}} = uri_escape($password);
	    }
	    else
	    {
		  $vars{$self->{'PasswordParam'}} = $password;
	    }
	}

	# Maybe add (or change) some attributes
	foreach (@{$self->{CopyRequestItem}})
	{
	    my ($copyfrom, $dummy, $copyto) = /(\S+)(\s+(.*))?/;
	    my $copyfromattr;
	    if (defined $copyto)
	    {
		$copyfromattr = &Radius::Util::format_special($copyto, $p);
	    }
	    else
	    {
		$copyfromattr = $p->get_attr($copyfrom);
	    }
	    $vars{$copyfrom} = unpack('H*', $copyfromattr)
		if defined $copyfromattr;
	}

	# Build and send the request
	my $aresponse = MakeRequest($self->{'UrlMethod'}, $self->{'AuthUrl'}, \%vars, $self->{'Timeout'});

	if ($aresponse->{_rc}=='200'){ # Good Request 
	    # Let's check if is user and password ok

	    if ( $aresponse->{_content} =~ /$self->{'AuthOKKeyword'}/i )
	    { 
		# All OK, try to extract some reply items from the response
		foreach (@{$self->{CopyReplyItem}})
		{
		    my ($copyfrom, $copyto) = split(/\s+/);
		    # Default is to copy from HTTP to a RADIUS attribtue of the same name
		    $copyto = $copyfrom unless defined $copyto;
		    if ($aresponse->{_content} =~ /$copyfrom=([0-9a-fA-F]*)/)
		    {    
			$p->{rp}->add_attr($copyto, pack('H*', $1));
		    }
		}
		$self->log($main::LOG_DEBUG, "$class Auth OK for $user", $p);
		$self->adjustReply($p);
		$p->{Handler}->logPassword($user, $password, 'URL', 'OK', $p) if $p->{Handler};
		return ($main::ACCEPT);
		
	    } elsif( $aresponse->{_content} =~ /$self->{'BadUserKeyword'}/i ){ # Bad Username
		$self->log($main::LOG_DEBUG, "$class Bad Auth, User Error for $user", $p);
		return ($main::REJECT, "Bad Auth, Username Error for $user"); 
		
	    } elsif( $aresponse->{_content} =~ /$self->{'BadPasswordKeyword'}/i ){ # Bad Password
		$self->log($main::LOG_DEBUG, "$class Bad Auth, Password Error for $user", $p);
		return ($main::REJECT, "Bad Auth, Password Error for $user");
	    }
	    #added by VASCO
	    elsif($aresponse->{_content} =~ /$self->{'AuthChallengeKeyword'}/i){
		# Challenge provided, try to extract some reply items from the response
		foreach (@{$self->{CopyReplyItem}})
		{
		    my ($copyfrom, $copyto) = split(/\s+/);
		    # Default is to copy from HTTP to a RADIUS attribtue of the same name
		    $copyto = $copyfrom unless defined $copyto;
		    if ($aresponse->{_content} =~ /$copyfrom=([0-9a-fA-F]*)/)
		    {    
			$p->{rp}->add_attr($copyto, pack('H*', $1));
		    }
		}
		$self->log($main::LOG_DEBUG, "$class Auth OK for $user", $p);
		$p->{Handler}->logPassword($user, $password, 'URL', 'OK', $p) if $p->{Handler};
		return ($main::CHALLENGE);
	    }
	    #end VASCO
	    else {
		$self->log($main::LOG_DEBUG, "$class Bad Auth for $user", $p);
		return ($main::REJECT, "Bad Auth for $user"); 		
    	    }
	    
	} elsif( $aresponse->{_msg} =~/timeout/i ){ # Give Up
	    $self->log($main::LOG_DEBUG, "$class Timeout Request for $user in $self->{AuthUrl}", $p);
	    return ($main::REJECT, "Timeout Request for $user in $self->{AuthUrl}"); 	
	
	} else { # Bad Request
	    $self->log($main::LOG_DEBUG, "$class HTTP Bad Request for $user", $p);
	    return ($main::REJECT, "HTTP Bad Request for $user"); 
	}
    } 
    elsif ($p->code eq 'Accounting-Request' && length $self->{'AcctUrl'}) 
    {
	my $vars = {};
	foreach (@{$p->{Attributes}})
	{
	    $$vars{$_->[0]} = $_->[1];
	}

	my $aresponse=MakeRequest($self->{'UrlMethod'}, $self->{'AcctUrl'} , $vars, $self->{'Timeout'});

	if ($aresponse->{_rc}=='200')
	{ 
	    # Good Request 
	    # Handler will construct a generic reply for us
	    return ($main::ACCEPT);
	}
	else
	{
	    $self->log($main::LOG_DEBUG, "$class HTTP Bad Accounting Request for $user: $aresponse->{_msg}", $p);
	    return ($main::REJECT, "HTTP Bad Accounting Request for $user"); 
	}
    } 
    else 
    {
	# Handler will construct a generic reply for us
	return ($main::ACCEPT);
    }
}


#####################################################################
# Find the named user
sub findUser {
    my ($self, $name, $p) = @_;

    $self->log($main::LOG_DEBUG, "$class findUser", $p);
    return;
}

##############################################################
# Generate and Make a Http request
sub MakeRequest
{
    my ($method, $url, $vars, $timeout) = @_;

    # Cant handle https yet
    $url="http://$url" if ($url!~/^https?\:\/\//i);
    my $ua = LWP::UserAgent->new(timeout => $timeout);    
    my $response;
    if ($method=~/POST/i)
    {
	$response = $ua->post($url, Content => $vars);
    } 
    else 
    { 
	# default to GET
	my $content = join('&', map("$_=$$vars{$_}", keys(%$vars)));
	$response = $ua->get("$url?$content");
    }    
    return $response;
}


1;
