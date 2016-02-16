# AuthGeneric.pm
#
# Object for handling generic Authentication
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthGeneric.pm,v 1.228 2014/11/17 21:14:51 hvn Exp $

package Radius::AuthGeneric;
@ISA = qw(Radius::Configurable);
use Radius::Configurable;
use Radius::User;
use Radius::Util;
use Time::Local;
use Digest::SHA;
use strict;

# Return codes for handle_request
$main::ACCEPT = 0;      # Issue an accept for us
$main::REJECT = 1;      # Issue a reject for us
$main::IGNORE = 2;      # Dont reply at all
$main::CHALLENGE = 3;   # Issue a challenge
$main::REJECT_IMMEDIATE = 4;   # Reject, and dont fall through

%Radius::AuthGeneric::ConfigKeywords =
('FallThrough'                 => 
 ['flag', 
  'Not used', 
  3], # not used yet

 'Fork'                        => 
 ['flag', 
  'Forces the authentication module to fork(2) before handling the request. Fork should only be set if the authentication module or the way you have it configured is "slow" i.e. takes more than a fraction of a second to process the request.  Unix only', 
  2],

 'UseAddressHint'              => 
 ['flag', 
  'Forces Radiator to honour a Framed-IP-Address in an Access-Request request unless it is overridden by a Framed-IP-Address in the user\'s reply items. If you enable this, then users will get the IP Address they ask for. If there is a Framed-IP-Address reply item for a user, that will override anything they might request.', 
  1],

 'StripFromReply'              => 
 ['string', 
  'Strips the named attributes from Access-Accepts before replying to the originating client. The value is a comma separated list of Radius attribute names. StripFromReply removes attributes from the reply before AddToReply adds any to the reply. ',
  1],

 'AddToReply'                  => 
 ['string', 'Adds attributes reply packets. Value is a list of comma separated attribute value pairs all on one line, exactly as for any reply item. StripFromReply removes attributes from the reply before AddToReply adds any to the reply. You can use any of the special % formats in the attribute values. ', 
  1],

 'AddToReplyIfNotExist'        => 
 ['string', 
  'Similar to AddToReply, but only adds an attribute to a reply if and only if it is not already present in the reply. Therefore it can be used to add, but not override a reply attribute', 
  1],

 'AllowInReply'                => 
 ['string', 
  'Specifies the only attributes that are permitted in an Access-Accept. It is most useful to limit the attributes that will be passed back to the NAS from a proxy server. That way, you can prevent downstream customer Radius servers from sending back illegal or troublesome attributes to your NAS', 
  1],

 'DefaultReply'                => 
 ['string', 
  'Similar to AddToReply except it adds attributes to an Access-Accept only if there would otherwise be no reply attributes. StripFromReply will never remove any attributes added by DefaultReply. Value is a list of comma separated attribute value pairs all on one line, exactly as for any reply item. You can use any of the special % formats in the attribute values. ', 
  1],

 'FramedGroup'                 => 
 ['integer', 
  'similarly to Framed-Group reply items, but it applies to all Access-Requests authenticated by this AuthBy clause. If FramedGroup is set and a matching FramedGroupBaseAddress is set in the Client from where the request came, then a Framed-IP-Address reply item is automatically calculated by adding the NAS-Port in the request to the FramedGroupBaseAddress specified by FramedGroup. ', 
  2],

 'NoDefaultIfFound'            => 
 ['flag', 
  'Normally if Radiator searches for a user in the database and finds one, but the users check items fail, Radiator will then consult the DEFAULT user entry. However, if the NoDefaultIfFound parameter is set, Radiator will only look for a DEFAULT if there were no entries found in the user database for the user. ', 
  1],

 'NoDefault'                   => 
 ['flag', 
  'Normally if Radiator searches for a user in the database and either does not find one, or finds one but the users check items fail, Radiator will then consult the DEFAULT user entry. However, if the NoDefault parameter is set, Radiator will never look for a DEFAULT. ', 
  1],

 'DefaultSimultaneousUse'      => 
 ['integer', 
  'Defines a default value for Simultaneous-Use check items that will apply only if the user does not have their own user-specific Simultaneous-Use check item.', 
  1],

 'CaseInsensitivePasswords'    => 
 ['flag', 
  'Permits case insensitive password checking for authentication methods that support plaintext password checks, such as FILE, SQL, DBFILE and some others. It has no effect on CHAP or MSCHAP passwords, or on password checking involving any encrypted passwords.', 
  1],

 'UsernameMatchesWithoutRealm' => 
 ['flag', 
  'forces Windows Domain Controller type authenticators to strip any realm from the username before authenticating the name with the domain controller. This allows users to log in with \`user@realm\', even though their domain controller user name is just \`user\'. Supported by AuthBy ADSI, AuthBy IPASS, AuthBy NTLM, AuthBy NT, AuthBy PAM, AuthBy TACACSPLUS, and PEAP', 
  1],

 'RejectEmptyPassword'         => 
 ['flag', 
  'Forces any Access-Request with an empty password to be rejected. This is provided as a work around for some broken remote Radius servers (VMS Radius server in particular) that incorrectly accept requests with empty passwords.', 
  1],

 'AuthenticateAccounting'      => 
 ['flag', 
  'Forces Radiator to authenticate accounting requests (as well as the normal Access-Requests). It is very rarely required.', 2],

 'IgnoreAuthentication'        => 
 ['flag', 
  'Causes the AuthBy to IGNORE all authentication requests. This can be useful for providing fine control over authentication with multiple AuthBy clauses.', 
  1],

 'IgnoreAccounting'            => 
 ['flag', 
  'causes the AuthBy to IGNORE all accounting requests. This can be useful for providing fine control over authentication with multiple AuthBy clauses.', 
  1],

 'CachePasswords'              => 
 ['flag', 
  'Enables a user password cache in this AuthBy. It can be used to improve the performance of slow AuthBy clauses, or when large number of identical requests for the same user are likely to occur, or when when multiple request might result from a one-time-password (in a multi-link or wireless roaming environment) etc.', 
  1],

 'CachePasswordExpiry'         => 
 ['integer', 
  'If CachePasswords is enabled, this parameter determined the maximum age (in seconds) for cached passwords. Cached passwords that are more than this number of seconds old will not be used.', 
  1],

 'DynamicReply'                => 
 ['stringarray', 'Specifies reply items that will be eligible for run-time variable   substitution. That means that you can use any of the % substitutions in that reply item.', 
  1],

 'DynamicCheck'                => 
 ['stringarray', 
  'Specifies check items that will be eligible for run-time variable substitution prior to authentication. That means that you can use any of the % substitutions in that check item.', 
  1],

 'HandleAcctStatusTypes'       => 
 ['counthash', 
  'List of Acct-Status-Types that will be processed in Accounting requests. The value is a comma-separated list of valid Acct-Status-Type attribute values (see your dictionary for a full list) including, Start, Stop, Alive,  Modem-Start, Modem-Stop, Cancel, Accounting-On, Accounting-Off etc.', 
  2],

 'AccountingStartsOnly'        => 
 ['flag', 
  'In AuthBy clauses that handle accounting, forces it to only log Accounting Start requests to the database. All other Accounting requests are accepted and acknowledged, but are not stored in the database.', 
  1],

 'AccountingStopsOnly'         => 
 ['flag', 
  'In AuthBy clauses that handle accounting, forces it to only log Accounting Stop requests to the database. All other Accounting requests are accepted and acknowledged, but are not stored in the database.', 
  1],

 'AccountingAlivesOnly'        => 
 ['flag', 
  'In AuthBy clauses that handle accounting, forces it to only log Accounting Alive requests to the database. All other Accounting requests are accepted and acknowledged, but are not stored in the database.', 
  1],

 'AcctFailedLogFileName'       => 
 ['string', 
  'In AuthBy SQL, RADSEC and FREERADIUS clauses, the name of a file used to log failed Accounting-Request messages in the standard radius accounting log format. ', 
  1],

 'AcctLogFileFormatHook'              =>
 ['hook',
  'Specifies an optional Perl hook that will be run for each Accounting-Request message when defined. The value returned by the hook is printed to the failed accounting log file. By default no Hook is defined. A newline will be automatically appended.',
  1],

 'AcctLogFileFormat'           => 
 ['string', 
  'In clauses that can log accounting data to a file, specifies an alternate format for the failed accounting log file from the standard radius format.', 
  1],

 'CacheReplyHook'              => 
 ['hook', 
  'Perl hook that runs when a cached reply is about to be returned to the NAS because of CachePasswords.', 
  2],

 'AutoMPPEKeys'                => 
 ['flag', 
  'Automatically reply with MS-MPPE-Send-Key and MS-MPPE-Recv-Key computed from the password. Required for TLS, TTLS, PEAP and other EAP authentication protocols', 
  1],

 'RcryptKey'                   => 
 ['string', 
  'The key used for Rcrypt reversible encryption of passwords in the user database. Any password in the database read by this AuthBy and which is in the form "{rcrypt}anythingatall" will be interpreted as an Rcrypt password the RcryptKey wil be used to decrypt it. Rcrypt encrypted passwords are compatible with PAP, CHAP, and MS-CHAP V1 and V2', 
  1],

 'PacketTrace'                 => 
 ['flag', 
  'Forces all packets that pass through this module to be logged at trace level 4. This is useful for logging packets that pass through this clause in more detail than other clauses during testing or debugging. The packet tracing  will stay in effect until it passes through another clause with PacketTrace set to off or 0.', 
  1],

 'AcceptIfMissing'             => 
 ['flag', 
  'Normally, if a user is not present in the user database, they will always be rejected. If this optional parameter is set, and a user is not in the database they will be unconditionally accepted. If they are in the database file, they will be accepted if and only if their check items pass in the normal way.', 
  1],

 'EAPType'                     => 
 ['splitstringarray', 
  'Specifies which EAP authentication systems are permitted when EAP authentication is requested by the NAS. When an EAP Identity request is received, Radiator will reply with the first EAP type selected. If the NAS requests another type, it will only be permitted if that type is enabled. It is ignored and has no effect unless EAP authentication is requested', 1],

 'EAPContextTimeout'           => 
 ['integer', 
  'Specifies the maximum time period in seconds an EAP context will be retained. Defaults to 1000 seconds. You should not need to change this.', 
  2],

 'EAPAnonymous'                => 
 ['string', 
  'For tunnelling EAP types, such as TTLS and PEAP, specifies the User-Name that will be used in the Radius request resulting from the EAP inner request. Defaults to \`anonymous\'. Special characters may be used. %0 is replaced by the EAP Identity of the inner EAP request.', 
  1],

 'EAPTLS_CAFile'               => 
 ['string', 
  'For TLS based EAP types such as TLS, TTLS and PEAP, this parameter specifies the name of a file containing Certificate Authority (CA) root certificates that may be required to validate TLS client certificates. The certificates are expected to be in PEM format. The file can contain several root certificates for one or more CAs. Radiator will look for root certificates in EAPTLS_CAFile then in EAPTLS_CAPath, so there usually is no need to set both.', 
  1],

 'EAPTLS_CAPath'               => 
 ['string', 
  'For TLS based EAP types such as TLS, TTLS and PEAP, this parameter specifies the name of a directory containing CA root certificates that may be required to validate TLS client certificates. The certificates are expected to one per file in PEM format. The files names are looked up by the CA \`Subject Name\' hash value. Radiator will look for root certificates in EAPTLS_CAFile then in EAPTLS_CAPath, so there usually is no need to set both.', 
  1],

 'EAPTLS_CertificateFile'      => 
 ['string', 
  'For TLS based EAP types such as TLS, TTLS and PEAP, this parameter specifies the name of a file containing the Radius server certificate. The server certificate will be sent to the EAP client and validated by the client during EAP authentication. The certificate file may be in PEM or ASN1 format (depending on the setting of the EAPTLS_CertificateType parameter). The certificate file can also contain the server\'s TLS private key if the EAPTLS_PrivateKeyFile parameter specifies the same file.', 
  1],

 'EAPTLS_CertificateChainFile'      => 
 ['string', 
  'For TLS based EAP types such as TLS, TTLS and PEAP, this parameter specifies the name of a file containing a certificate chain for the Radius server certificate. The server certificate chain will be sent to the EAP client and validated by the client during EAP authentication. The certificate chain must be in PEM format. This should be used alternatively and/or additionally to EAPTLS_CertificateFile for explicitly constructing the server certificate chain which is sent to the client in addition to the server certificate.', 
  1],

 'EAPTLS_PrivateKeyFile'       => 
 ['string', 
  'For TLS based EAP types such as TLS, TTLS and PEAP, this optional parameter specifies the the name of the file containing the server\'s private key. It is sometimes in the same file as the server certificate (EAPTLS_CertificateFile). If the private key is encrypted (which is usually the case) then EAPTLS_PrivateKeyPassword is the key to decrypt it.', 
  1],

 'EAPTLS_PrivateKeyPassword'   => 
 ['string', 
  'For TLS based EAP types such as TLS, TTLS and PEAP, this optional parameter specifies the password that is to be used to decrypt the EAPTLS_PrivateKeyFile. Special characters are permitted.', 
  1],

 'EAPTLS_CertificateType'      => 
 ['string', 
  'Specifies the format of the EAPTLS_CertificateFile.', 
  1],

 'EAPTLS_RandomFile'           => 
 ['string', 
  'The name of a file containing randomness for use by TLS. You should not normally need to set this parameter.', 
  1],

 'EAPTLS_DHFile'               => 
 ['string', 
  'For TLS based EAP types such as TLS, TTLS and PEAP, this optional parameter specifies the name of the DH group. You should not normally need to set this parameter, but it may be required if you are using ephemeral DH keys.', 
  1],

 'EAPTLS_ECDH_Curve'               =>
 ['string',
  'For TLS based EAP types such as TLS, TTLS and PEAP, this optional parameter enables ephemeral EC keying by specifying the name of the elliptic curve to use. The default is to not enable ephemeral EC keying.',
  1],

 'EAPTLS_VerifyDepth'          => 
 ['integer', 
  'For TLS based EAP types such as TLS, TTLS and PEAP that have been configured to check client certificates, this optional parameter specifies a maximum depth that client certificates will be permitted. Defaults to 1, which means the client certificate must have been issued by the root CA.', 
  1],

 'EAPTLS_MaxFragmentSize'      => 
 ['integer', 
  'For TLS based EAP types such as TLS, TTLS and PEAP, this optional parameter specifies the maximum size in octets permitted for each TLS message fragment. Defaults to 2048, but many EAP clients, routers and wireless Access Points have limitations that require EAPTLS_MaxFragmentSize to be set as low as 1000 ', 
  1],

 'EAPTLS_CRLCheck'             => 
 ['flag', 
  'For TLS based EAP types such as TLS, TTLS and PEAP that have been configured to check client certificates, this optional parameter specifies that Certificate Revocation List must be checked for revoked certificates.', 
  1],

 'EAPTLS_CRLFile'              => 
 ['stringarray', 
  'For TLS based EAP types such as TLS, TTLS and PEAP, and where CRL checking has been enabled with EAPTLS_CRLCheck, this optional parameter specifies one or more CRL files that will be used to check client certificates for revocation.', 
  1],

 'EAPTLS_SessionResumption'    => 
 ['flag', 
  'For TLS based EAP types such as TLS, TTLS and PEAP, this optional parameter allows you to enable or disable support for TTLS Session Resumption and PEAP Fast Reconnect. ', 
  1],

 'EAPTLS_AllowUnsafeLegacyRenegotiation'    => 
 ['flag', 
  'For TLS based EAP types such as TLS, TTLS and PEAP, and with versions of OpenSSL 0.9.8m and later, this optional parameter enables legacy insecure renegotiation between OpenSSL and unpatched clients or servers. OpenSSL 0.9.8m and later always attempts to use secure renegotiation as described in RFC5746. This counters the prefix attack described in CVE-2009-3555 and elsewhere.', 
  1],

 'EAPTLS_SessionResumptionLimit' => 
 ['integer', 
  'For TLS based EAP types such as TLS, TTLS and PEAP, this optional parameter allows you to limit how long after the initial session that a session can be resumed (time in seconds). ', 
  1],

 'EAPTLSRewriteCertificateCommonName' => 
 ['stringarray', 
  'For TLS based EAP types such as TLS, TTLS and PEAP, this optional parameter allows you to rewrite the Common Name in the client\'s TLS certificate before using it to find the username in the Radiator database. Format is a perl substitution expression, such as: s/testUser/mikem/', 
  1],

 'EAPTLS_PEAPVersion'          => 
 ['integer', 
  'For PEAP, his optional parameter allows you to control which version of the draft PEAP protocol to honour. Defaults to 1. Set it to 0 for unusual clients, such as Funk Odyssey Client 2.22 or later.', 
  1],

 'EAPTLS_PEAPBrokenV1Label'    => 
 ['flag', 
  'Makes PEAP Version 1 support compatible with nonstandard PEAP V1 clients that use the old broken TLS encryption labels that appear to be used frequently, due to Microsofts use of the incorrect label in its V0 client.', 
  1],

 'EAPTLS_NoCheckId'            => 
 ['flag', 
  'For EAP-TLS authentication, this optional parameter prevents the comparison of the username with the certificate common name. The certificate will be accepted based only on the validity dates and the verification chain to the root certificate, and there is no requirement for the user to be in any Radiator user database. This allows Radiator to mimic the behaviour of some other Radius servers.', 
  1],

 'EAPTLS_CertificateVerifyHook'=> 
 ['hook', 
  'For EAP-TLS authentication, this optional parameter specifies a perl function that will be called after the request username or identity has been matched with the certificate CN. It is passed the certificate, and various other details, and returns a different user name which will be used to do the user database lookup.', 
  2],

 'EAPTLS_CommonNameHook'=> 
 ['hook', 
  'For EAP-TLS authentication, this optional parameter specifies a perl function that will be called to see if a certificate CN matches a username or some other attribute in the incoming request. If a match occurs, the hook must return the matched name, else undef. If not defined, the certificate CN will be macthed against User-Name of the EAP Identity, either with or without domin names.', 
  2],

 'EAPTLS_RequireClientCert'=> 
 ['flag', 
  'For TLS based authentication, such as PEAP and TTLS, this flag requires the EAP supplicant to present a valid client certificate during the TLS handshake.', 
  2],

 'EAPTLS_PolicyOID'       => 
 ['stringarray', 
  'When a TLS peer presents a certificate, this optional parameter enables certificate policy checking and specifies one or more policy OIDs that must be present in the certificate path. It sets the \'require explicit policy\' flag as defined in RFC3280. Requires Net-SSLeay 1.37 or later', 
  2],

 'DefaultLimit'                => 
 ['integer', 
  'The maximum number of DEFAULT users to look up in the database', 
  1],

 'AuthenticateAttribute'       => 
 ['string', 
  'Normally, Radiator uses the User-Name Radius attribute as the key to find a user in the user database. If the AuthenticateAttribute parameter is defined, it specifies the name of an alternative Radius attribute that will be used as the key during the lookup in the user database. This is useful in order to do authentication based on, say, the Calling-Station-Id:', 
  2],

 'RewriteUsername'             => 
 ['stringarray', 
  'Rewrite patterns to alter the User-Name in authentication and accounting requests before processing the request. Perl substitute and translate expressions are suported, such as s/^([^@]+).*/$1/ or tr/A-Z/a-z/', 
  1],

 'EAP_PEAP_MSCHAP_Convert'     => 
 ['flag', 
  'For EAP-PEAP MSCHAPV2 authentication, this optional parameter tells Radiator to convert the inner EAP-MSCHAPV2 request into a conventional Radius-MSCHAPV2 request. The new Radius-MSCHAPV2 request will be redespatched to the Handlers, where it can be detected and handled with <Handler ConvertedFromPEAP=1>.', 1],

 'EAP_LEAP_MSCHAP_Convert'     => 
 ['flag', 
  'For LEAP authentication, this optional parameter tells Radiator to convert the LEAP request into a conventional Radius-MSCHAP request. The new Radius-MSCHAP request will be redespatched to the Handlers, where it can be detected and handled with <Handler ConvertedFromLEAP=1>.', 
  1],
 
'EAP_GTC_PAP_Convert'     => 
 ['flag', 
  'For EAP-GTC authentication, this optional parameter tells Radiator to convert the EAP-GTC request into a conventional Radius-PAP request. The new Radius-PAP request will be redespatched to the Handlers, where it can be detected and handled with <Handler ConvertedFromGTC=1>.', 
  1],

 'TranslatePasswordHook'       => 
 ['hook', 
  'Perl hook that can be used to convert, translate or transform plaintext passwords after retreival from a user database and before comparison with the submitted password received from the client. ', 
  2],

 'CheckPasswordHook'       => 
 ['hook', 
  'Perl hook that can be used to compare passwords retrieved from a user database with the submitted password received from the client. The retrieved passwords must start with leading \'{OSC-pw-hook}\'. The hook must return true when the password is deemed correct. Useful for proprietary hash formats and other custom password check methods.', 
  2],

 'ClearTextTunnelPassword'     => 
 ['flag', 
  'prevents Radiator decrypting and reencrypting Tunnel-Password attributes in replies during proxying. This is provided in order to support older NASs that do not support encrypted Tunnel-Password.', 
  2],

 'NoCheckPassword'             => 
 ['flag', 
  'Forces this AuthBy clause not to check the users password.', 1],

 'PreHandlerHook'              => 
 ['hook', 
  'For EAP types that carry inner requests, specifies a hook to be called before the inner request is redispatched to a matching Realm or Handler', 
  2],

 'NoEAP'                       => 
 ['flag', 
  'Disables EAP authentication in this AuthBy. If the AuthBy would otherwise do EAP authentication, this parameter forces it to do conventional authentication. This can be useful for performing additional checks besides EAP authentication, for example when doing MAC Address whitelist checking as well as EAP authentication', 
  2],

 'UseTNCIMV'                   => 
 ['flag', 'For EAP-TTLS, enables support for TNC version 1 end-point security checks.', 2],

 'TNCAllowReply'               => 
 ['string', 
  'During TNC end-point security checks, specifies the reply items to be sent to the client if TNC determines the client is allowed to connect normally.', 
  2],

 'TNCIsolateReply'             => 
 ['string', 
  'During TNC end-point security checks, specifies the reply items to be sent to the client if TNC determines the client is only allowed to connect to the isolation (remediation) network.', 
  2],

 'TNCNoRecommendationReply'    => 
 ['string', 
  'During TNC end-point security checks, specifies the reply items to be sent to the client if TNC could not make a recommendation (such as when there is no TNC suport installed on the client)', 
  2],

 'EAPTTLS_NoAckRequired'       => 
 ['flag', 
  'workaround for a bug in some EAP TTLS supplicants,
  (notably PBG4 on MAC OSX) do not conform to the TTLS
  protocol specification, and do not understand the ACK sent
  by the server at the end of TLS negotiation and session
  resumption, resulting in session resumption not
  completing. The new EAPTTLS_NoAckRequired flag enables a workaround for such
  supplicants. Many other supplicants are happy with this too.', 
  2],

 'SIPDigestRealm'              => 
 ['string', 
  'During SIP authentication, specifies the Digest-Realm to be sent to the client during the SIP challenge', 
  2],

 'Blacklist'                   => 
 ['flag', 'Reverses the sense of authentication checks, making it easier to implement blacklists. If the user name matches the user database, then they will be rejected. If there is no match they will be accepted.', 
  1],

 'EAPFAST_PAC_Lifetime'        => 
 ['integer', 
  'For EAP-FAST, specifies the maximum lifetime for each PAC', 
  2],

 'EAPFAST_PAC_Reprovision'     => 
 ['integer', 
  'For EAP-FAST, specifies the time after which a PAC should be reprivisioned', 
  2],

 'SSLeayTrace'                 => ['integer', 'Obsolete. Not used', 3],

 'EAPErrorReject'     => 
 ['flag', 
  'If an EAP error occurs, REJECT instead of IGNORE. The RFCs say that IGNORE is the correct behaviour, but REJECT can work better in some load balancing situations', 
  2],

 'PasswordPrompt'     => 
 ['string', 
  'For AuthBys that support the feature, specifies the prompt to be used when asking for a password.', 
  2],

 );

# RCS version number of this module
$Radius::AuthGeneric::VERSION = '$Revision: 1.228 $';

@Radius::AuthGeneric::reasons =
    (
     'ACCEPT',
     'REJECT',
     'IGNORE',
     'CHALLENGE',
     'REJECT_IMMEDIATE',
     );

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
    $self->{CachePasswordExpiry} = 86400; # 1 day
    $self->{ObjType} = 'AuthBy'; # Automatically register this object
    $self->{EAPAnonymous} = 'anonymous'; # The default username for EAP tunnelled requests
    $self->{EAPTLS_VerifyDepth} = 1;
    $self->{EAPContextTimeout} = 1000; # Seconds
    $self->{EAPTLS_MaxFragmentSize} = 2048; # Max total payload EAPTLS reply
    $self->{EAPTLS_SessionResumption} = 1;
    $self->{EAPTLS_SessionResumptionLimit} = 43200;
    $self->{EAPTLS_PEAPVersion} = 0;
    $self->{SIPDigestRealm} = 'DefaultSipRealm';
    $self->{EAPFAST_PAC_Lifetime} = 90 * 24 * 60 * 60;
    $self->{EAPFAST_PAC_Reprovision} = 30 * 24 * 60 * 60;
    $self->{PasswordPrompt} = 'password';
}

#####################################################################
# Handle a request
# This function is called for each packet. $p points to a Radius::
# packet containing the original request. $dummy is an historical
# artifact, used to be $rp the reply packet
# you can use to reply, or else fill with attributes and get
# the caller to reply for you.
# $extra_checks is an AttrVal containing check items that 
# we must check for, regardless what other check items we might 
# find for the user. This is most often used for cascading 
# authentication with Auth-Type .
#
# The return value significant:
# If IGNORE, no reply will be sent by the caller on your behalf
# If ACCEPT, and acceptance appropriate to the type of request
# will be sent
# If REJECT, a rejection appropriate to the type of request
# will be sent
#
# The default implementation will do the standard checks for 
# a user that is found with the findUser() function.
# Returns an optional reason message for rejects
sub handle_request
{
    my ($self, $p, $dummy, $extra_checks) = @_;

    $p->{PacketTrace} = $self->{PacketTrace} 
        if defined  $self->{PacketTrace}; # Optional extra tracing

    my $type = ref($self);
    $self->log($main::LOG_DEBUG, "Handling with $type: $self->{Identifier}", $p);

    # Now we might fork before processing the request
    # Should only do this for "slow" authentication methods
    return ($main::IGNORE, 'forked')
	if $self->{Fork} && !$self->handlerFork();

    if ($p->code eq 'Access-Request' || $self->{AuthenticateAccounting})
    {
	return ($main::IGNORE, 'Ignored due to IgnoreAuthentication')
	    if $self->{IgnoreAuthentication};
	    
	# Maybe we have to handle EAP?
	if (!$self->{NoEAP} && defined $p->getAttrByNum($Radius::Radius::EAP_MESSAGE))
	{
	    my ($result, $reason);
	    eval {require Radius::EAP; 
		  ($result, $reason) = $self->authenticateUserEAP($p)};
	    if ($@)
	    {
		$self->log($main::LOG_ERR, "Could not handle an EAP request: $@");
		return ($main::REJECT, 'Could not handle an EAP request');
	    }
	    $self->log($main::LOG_DEBUG, "EAP result: $result, $reason", $p);
	    return ($result, $reason);
	}

	# Maybe its a request for a SIP nonce?
	if (defined $p->get_attr('Digest-Method')
	    && defined $p->get_attr('Digest-URI')
	    && !defined $p->get_attr('Digest-Nonce'))
	{
	    # Note: nonce has no integrity timestamp
	    $p->{rp}->add_attr('Digest-Nonce', unpack('H*', &Radius::Util::random_string(4)));
	    $p->{rp}->add_attr('Digest-Realm', $self->{'SIPDigestRealm'});
	    $p->{rp}->add_attr('Digest-Qop', 'auth'); # RFC 5090
	    $p->{rp}->add_attr('Digest-Algorithm', 'MD5'); # RFC 5090
	    $p->{rp}->add_attr('Message-Authenticator', "\000" x 16); # Will be filled in later
	    
	    # RFC4590 also permits us to add Digest-Domain, and Digest-Opaque here
	    return ($main::CHALLENGE, 'SIP Nonce');
	}

	# Its not an EAP request or a SIP nonce request
	# Maybe we need to use the cache?
	if ($self->{CachePasswords})
	{
	    my $cachedreply = $self->cachedReply($p);
	    if ($cachedreply)
	    {
		$self->log($main::LOG_DEBUG, "AuthGeneric: Using cached reply", $p);	
		$cachedreply->set_identifier($p->identifier());
		$cachedreply->set_authenticator($p->authenticator());
		$p->{rp} = $cachedreply;
		return ($main::ACCEPT);
	    }
	}

	# We loop looking for a user, starting with the user name
	# followed by DEFAULT, DEFAULT1, DEFAULT2 etc.
	# Continue until we get a match without Fall-Through set
	# or we run out of options
	my $checkResult = $main::ACCEPT;
	my ($user, $error, $found, $defaultNumber, $reason, $authenticated);
	my $initial_user_name = $p->getUserName();
	$initial_user_name =~ s/@[^@]*$//
	    if $self->{UsernameMatchesWithoutRealm};
	$initial_user_name = $p->get_attr($self->{AuthenticateAttribute})
	    if $self->{AuthenticateAttribute};
	my $user_name = $initial_user_name;
	if ($self->{RejectEmptyPassword} 
	    && $p->decodedPassword() eq ''
	    && !$p->getAttrByNum($Radius::Radius::CHAP_PASSWORD))
	{
	    $self->log($main::LOG_DEBUG, "$type rejected $user_name because of an empty password", $p);
	    return ($main::REJECT, 'Empty password');
	}

	# Try to find a suitable user that passes all the check items
	($user, $checkResult, $reason, $authenticated, $found) = 
	    $self->get_user($user_name, $p, $extra_checks, 1);

	if ($self->{Blacklist})
	{
	    if ($checkResult == $main::REJECT
		|| $checkResult == $main::REJECT_IMMEDIATE)
	    {
		$checkResult = $main::ACCEPT;
	    }
	    elsif ($checkResult == $main::ACCEPT)
	    {
		$checkResult = $main::REJECT;
		$reason = 'Blacklisted';
	    }
	}

	if ($authenticated)
	{
	    # Add and strip attributes before replying
	    $self->adjustReply($p);
	    $self->cacheReply($p, $p->{rp}) if $self->{CachePasswords};

	    return ($checkResult, $reason);
	}
	elsif ($checkResult == $main::REJECT_IMMEDIATE)
	{
	    # Prevents weird interactions between AcceptIfMissing and REJECT_IMMEDIATE
	    $self->clearCachedReply($p) if $self->{CachePasswords};
	    return ($main::REJECT_IMMEDIATE, $reason);
	}
	elsif ($self->{AcceptIfMissing} && !$found)
	{
	    # Add and strip attributes before replying
	    $self->adjustReply($p);
	    $self->cacheReply($p, $p->{rp}) if $self->{CachePasswords};
	    return ($main::ACCEPT); 
	}
	else
	{
	    # Handler sends Access-Reject
	    $self->clearCachedReply($p) if $self->{CachePasswords};
	    return ($checkResult, $reason); 
	}
    }
    else
    {
	# Any other type of request, we will just accept
	# This usually includes Accounting-Request
	return ($main::IGNORE, "Ignored due to IgnoreAccounting")
	    if $self->{IgnoreAccounting};

	# Handler will construct an appropriate reply for us
	return ($main::ACCEPT); 
    }
}

# user is set to the last user record found, undef if the last findUser returned no user
# found is the number of user record found, regardless of whether they authenticated
# authenticated is the number of user record that completed authentication correctly
sub get_user
{
    my ($self, $orig_user_name, $p, $extra_checks, $authorise) = @_;

    my ($user, $error, $defaultNumber, $authenticated, $found, $fall_through);
    my $type = ref($self);
    my $reason = 'No such user';
    my $checkResult = $main::REJECT;
    my $user_name = $orig_user_name; # May get turned into DEFAULTn
    # self->findUser is overridden by subclasses
    # For historical reasons, the ($user, $error) is a bit
    # unusual. If $error is true, then we had some
    # sort of database problem
    while (((($user, $error) = $self->findUser($user_name, $p, $p->{rp}, $orig_user_name, $defaultNumber))
	    && $user)
	   || $defaultNumber < 1)
    {
	return ($user, $main::IGNORE, "User database access error")
	    if $error; # something wrong with the database
	$self->log($main::LOG_DEBUG, "$type looks for match with $user_name [$p->{OriginalUserName}]", $p);
	
	# See if the user we found passes the check items
	if ($user)
	{
	    my $result = $main::ACCEPT;

	    # Found a user, even if check items may fail
	    $found++;

	    # First check an extra check items we may have
	    # got from a module that cascaded to us
	    $p->{did_sim_use} = undef;
	    ($result, $reason) = $self->checkAttributes($extra_checks, $p, $orig_user_name)
		if $extra_checks;
	    # Then check the check items for this user
	    ($result, $reason) = $self->checkUserAttributes($user, $p, $orig_user_name)
		if $result != $main::REJECT
		&& $result != $main::REJECT_IMMEDIATE;

	    # We only take notice of the first successful result
	    $checkResult = $result unless $fall_through;
	    $self->log($main::LOG_DEBUG, "$type $Radius::AuthGeneric::reasons[$result]: $reason: $user_name [$p->{OriginalUserName}]", $p);
	    if ($result != $main::REJECT
		&& $result != $main::REJECT_IMMEDIATE)
	    {
		# Add users reply items
		$fall_through = $self->authoriseUser($user, $p) if $authorise;
		$authenticated++;
		
		# If we did an Auth-Type to a non-synchronous
		# auth module, we return IGNORE here, because the
		# other auth module might reply for us one day
		# but we do need to report the user was found, else 
		# AcceptIfMissing will not work correctly
		return ($user, $result, $reason, 0, 1)
		    if $result == $main::IGNORE;
		
		# We only look for default users
		# if Fall-Through is set. We continue to look at
		# DEFAULT, DEFAULT1, DEFAULT2 etc until one of
		# them matches, or until Fall-Through is not set
		last unless $fall_through;
	    }
	    # REJECT_IMMEDIATE always prevents fallthrough
	    last if $checkResult == $main::REJECT_IMMEDIATE;
	    
	}
	else
	{
	    $self->log($main::LOG_DEBUG, "$type REJECT: No such user: $user_name [$p->{OriginalUserName}]", $p);
	}
	# Dont look at any DEFAULTs if NoDefaultIfFound is set
	# and a user exists (even if the user was rejected).
	last if $self->{NoDefault} 
	    || ($self->{NoDefaultIfFound} && $user) 
	    || ($self->{DefaultLimit} && $defaultNumber > $self->{DefaultLimit});
	
	# Next time round, we look for a DEFAULT
	$user_name = "DEFAULT$defaultNumber";
	$defaultNumber++;
    }

    return ($user, $checkResult, $reason, $authenticated, $found);
}

#####################################################################
# This subclassable function is intended to do all the work 
# of checking a user check items, (if any)
sub checkUserAttributes
{
    my ($self, $user, $p, $user_name) = @_;
    return $self->checkAttributes($user->get_check, $p, $user_name);
}

#####################################################################
# This subclassable function is intended to do all the work 
# to set up the per-user reply items for this user
# Returns true if need to fall through to another user for
# further authentication and authorisation.
sub authoriseUser
{
    my ($self, $user, $p) = @_;

    # handle framed-ip-address seperately so 
    # it will already
    # be in the reply and available for %a 
    # substitution
    my ($p_fip, $u_fip);
    if ($self->{UseAddressHint} 
	&& ($p_fip = $p->getAttrByNum($Radius::Radius::FRAMED_IP_ADDRESS))) 
    {
	$u_fip = $user->get_reply->get_attr('Framed-IP-Address');
	if (!defined $u_fip || $u_fip eq "255.255.255.254") 
	{
	    $p->{rp}->addAttrByNum($Radius::Radius::FRAMED_IP_ADDRESS, $p_fip);
	} 
	else 
	{
	    $p->{rp}->addAttrByNum($Radius::Radius::FRAMED_IP_ADDRESS, $u_fip);
	}
    } 
    elsif ($u_fip = $user->get_reply->get_attr('Framed-IP-Address')) 
    {
	$p->{rp}->addAttrByNum($Radius::Radius::FRAMED_IP_ADDRESS, $u_fip);
    }
    # Handle the users reply items, and
    # remember if we have to fall throuh
    return $self->appendUserReplyItems($p, $user);
}

#####################################################################
# Find the named user, return a User object if found for this
# authentication type else undef
# $name is the user name we want
# $p is the current request we are handling
sub findUser
{
    my ($self, $name, $p) = @_;

    my $type = ref($self);
    
    $self->log($main::LOG_ERR, "findUser not defined for $type");
    return;
}

#####################################################################
# Overrideable function that checks a plaintext password response
# $p is the current request
# $username is the users (rewritten) name
# $submitted_pw is the PAP password received from the user
# $pw is the coorrect password if known
sub check_plaintext
{
    my ($self, $p, $username, $submitted_pw, $pw) = @_;

    # Just ordinary old plaintext, look for an exact match
    # or a case insensitive match
    return $self->{CaseInsensitivePasswords}
           ? (lc $submitted_pw eq lc $pw) : ($submitted_pw eq $pw);
}

#####################################################################
# Overrideable function that checks a CHAP password response
# Also used by EAP_4 to check EAP-MD5 challenge
# $p is the current request
# $username is the users (rewritten) name
# $pw is the coorrect password if known
sub check_chap
{
    my ($self, $p, $username, $pw, $chapid, $challenge, $response) = @_;

    return Digest::MD5::md5($chapid . $pw . $challenge) eq $response;
}

#####################################################################
# Overrideable function that generates an MD5 challenge
# Used by EAP-MD5. 
sub md5_challenge
{
    my ($self, $context) = @_;

    $context->{md5_challenge} = &Radius::Util::random_string(16);
}

#####################################################################
# Overrideable funciton that checks MD5-Challenge responses for EAp-MD5 etc
sub check_md5
{
    my ($self, $context, $p, $username, $pw, $chapid, $challenge, $response) = @_;
    
    return $self->check_chap($p, $username, $pw, $chapid, $challenge, $response);
}

#####################################################################
# Overrideable function that checks a MSCHAP password response
# $p is the current request
# $username is the users (rewritten) name
# $nthash is the NT Hashed of the correct password
# $context may be present some persistent storage for handles etc
sub check_mschap
{
    my ($self, $p, $username, $nthash, $challenge, $response, 
	$usersessionkeydest, $lanmansessionkeydest, $context) = @_;

    return unless Radius::MSCHAP::ChallengeResponse($challenge, $nthash) eq $response;
    # Maybe generate a session key. 
    $$usersessionkeydest = Radius::MSCHAP::NtPasswordHash($nthash) if defined $usersessionkeydest;
    # We dont know how to generate the lasnmansessionkey

    return 1;
}

#####################################################################
# Overrideable function to generate the mschapv2 challenge
# Default behaviour is just random
sub mschapv2_challenge
{
     my ($self, $context, $p) = @_;

     $context->{mschapv2_challenge} = &Radius::Util::random_string(16)
     unless $context->{mschapv2_challenge};
}

#####################################################################
# Overrideable function that checks a MSCHAP password response
# $p is the current request
# $username is the users (rewritten) name
# $nthash is the NT Hashed of the correct password
# $sessionkeydest is a ref to a string where the MPPE keys will be returned
# $authenticator_responsedest is a ref to a string where the authenticator repsonse 
#  (with the S= prefix) will be returned
# $context may be present some persistent storage for handles etc
sub check_mschapv2
{
    my ($self, $p, $username, $nthash, $challenge, $peerchallenge, $response, 
	$mppekeys_dest, $authenticator_responsedest, $lanmansessionkeydest, $context) = @_;

    # Strip off any DOMAIN, else the mschapv2 auth response will fail
    $username =~ s/^(.*)\\//;
    return unless Radius::MSCHAP::ChallengeResponse
	(Radius::MSCHAP::ChallengeHash($peerchallenge, $challenge, $username), $nthash) eq $response;

    # Maybe generate MPPE keys. 
    my $usersessionkey = Radius::MSCHAP::NtPasswordHash($nthash);
    $$mppekeys_dest = Radius::MSCHAP::mppeGetKey($usersessionkey, $response, 16)
	if defined $mppekeys_dest;

    # Maybe generate an MSCHAP authenticator response
    $$authenticator_responsedest = &Radius::MSCHAP::GenerateAuthenticatorResponseHash
	($usersessionkey, $response, $peerchallenge, $challenge, $username)
        if defined $authenticator_responsedest;
    # We dont know how to generate the lanmansessionkey
    return 1;
}

#####################################################################
# $pw is the correct plaintext password
sub check_mschapv2_plaintext
{
    my ($self, $p, $username, $pw, $challenge, $peerchallenge, $response, 
	$mppekeys_dest, $authenticator_responsedest, $lanmansessionkeydest, $context) = @_;
 
    return $self->check_mschapv2
	($p, $username,
	 Radius::MSCHAP::NtPasswordHash(Radius::MSCHAP::ASCIItoUnicode($pw)),
	 $challenge, $peerchallenge, $response, 
	 $mppekeys_dest, $authenticator_responsedest, 
	 $lanmansessionkeydest, $context);
}

#####################################################################
# Check a submitted plaintext password against the correct NT hashed password.
# The correct hashed password may or may not be hex encoded
sub check_nthash
{
    my ($self, $p, $correct_pw, $submitted_pw) = @_;

    $correct_pw = pack('H*', $correct_pw) if length($correct_pw) == 32; # Hex?
    eval {require Radius::MSCHAP};
    if ($@)
    {
	$self->log($main::LOG_ERR, "Could not load Radius::MSCHAP to check an NT encrypted password: $@");
	return 0;
    }
    return Radius::MSCHAP::NtPasswordHash(Radius::MSCHAP::ASCIItoUnicode($submitted_pw)) 
	eq $correct_pw;
}

#####################################################################
# RFC2617 3.2.2
# $ra is optional ref to the place to put the Response-Auth
sub check_digest_md5
{
    my ($self, $p, $username, $realm, $nonce, $cnonce, $nc, $qop, 
	$method, $uri, $eb_hash, $algorithm, $response, $pw, $response_auth) = @_;

    no warnings "uninitialized";
    my ($ha1, $ha2, $rha2);
    if ($pw =~ /^{digest-md5-hex}([0-9a-f]{32})$/i)
    {
	# Password is already MD5 digestified version of $username:$realm:$correct_pw
	$ha1 = $1;
    }
    elsif ($algorithm eq 'MD5-sess')
    {
	$ha1 = Digest::MD5::md5_hex("$username:$realm:$pw:$nonce:$cnonce");
    }
    else
    {
	# MD5?
	$ha1 = Digest::MD5::md5_hex("$username:$realm:$pw");
    }

    if ($qop eq 'auth' || !defined $qop)
    {
	$ha2 = Digest::MD5::md5_hex("$method:$uri");
	$rha2 = Digest::MD5::md5_hex(":$uri");
    }
    elsif ($qop eq 'auth-int')
    {
	$ha2 = Digest::MD5::md5_hex("$method:$uri:$eb_hash");
	$rha2 = Digest::MD5::md5_hex(":$uri:$eb_hash");
    }

    my $calc_response;
    if (!defined $qop)
    {
	$calc_response = Digest::MD5::md5_hex("$ha1:$nonce:$ha2");
	$$response_auth = Digest::MD5::md5_hex("$ha1:$nonce:$rha2")
	    if $response_auth;
    }
    elsif ($qop eq 'auth' || $qop eq 'auth-int')
    {
	$calc_response = Digest::MD5::md5_hex("$ha1:$nonce:$nc:$cnonce:$qop:$ha2");
	$$response_auth = Digest::MD5::md5_hex("$ha1:$nonce:$nc:$cnonce:$qop:$rha2")
	    if $response_auth;
    }
    else
    {
	$self->log($main::LOG_WARNING, "Unknown HTTP Digest authentication QOP $qop");
    }
    return $response eq $calc_response;
}

#####################################################################
# $c is the mssql crypted password. $p is the submitted plaintext password
# Microsoft SQL crypted passwords consist of
# 1 octet == 1
# 1 octet == 0
# 4 octets of salt
# 20 octets comprised of SHA1(Unicode(plaintextpassword) . salt)
# 20 octets comprised of SHA1(Unicode(uppercase(plaintextpassword)) . salt)
# Password comparison is therefore case insensitive.
sub mssql_pwdcompare
{
    my ($c, $p) = @_;

    my ($head1, $head2, $salt, $c1, $c2) = unpack('C C a4 a20 a20', $c);
    # These are probably version numbers
    return unless $head1 == 1 && $head2 == 0;
    return 1 if Digest::SHA::sha1(join('', map {($_, "\0")} split(//, $p)) . $salt) eq $c1;
    return 1 if Digest::SHA::sha1(join('', map {($_, "\0")} split(//, uc($p))) . $salt) eq $c2;
    return;
}

#####################################################################
# Maybe decode, decrypt or translate a correct password to plaintext
sub translate_password
{
    my ($self, $password) = @_;

    if (defined $self->{RcryptKey} && $password =~ /^{rcrypt}(.*)$/i)
    {
	require Radius::Rcrypt;
	$password = &Radius::Rcrypt::decrypt($1, $self->{RcryptKey});
    }
    elsif ($password =~ /^{clear}(.*)$/)
    {
	$password = $1;
    }
    ($password) = $self->runHook('TranslatePasswordHook', undef, $password, $self)
	if defined $self->{TranslatePasswordHook};
    return $password;
}

#####################################################################
# Get a users plaintext password from a User record, and decrypt using rcrypt if required
sub get_plaintext_password
{
    my ($self, $user) = @_;

    my $password = $user->get_check->get_attr('User-Password') || $user->get_check->get_attr('Password');
    return $self->translate_password($password);
}

#####################################################################
# Check whether a plaintext or encrypted password match occurs. 
# $pw is the correct password, or the secret we share with the 
# user in the case of CHAP
# $user is the user name
# Will try to do CHAP authentication if this packet has a CHAP-Password.
# Returns 1 iff there is a password match
# Note that it is impossible to do CHAP authentication when we only have
# encrypted correct password available
# $encrypted is true if $pw (the correct password) is in some encrypted 
# format else its plaintext
sub check_password
{
    my ($self, $p, $pw, $user, $encrypted) = @_;

    return 1 if $self->{NoCheckPassword};

    my ($attr, $challenge);
    my $result = 0; # Default is fail
    my $submitted_pw = 'UNKNOWN';
    
    # Some databases, like Active Directory leave embedded NULs
    $pw =~ s/\0//g; 
    # Maybe we have a reversibly encrypted password? Dont auto-vivify $self
    if ($self && defined $self->{RcryptKey} 
	&& $pw =~ /^{rcrypt}(.*)$/i)
    {
	require Radius::Rcrypt;
	$pw = &Radius::Rcrypt::decrypt($1, $self->{RcryptKey});
    }
    # Maybe its a cleartext password
    elsif ($pw =~ /^{clear}(.*)$/i)
    {
	$pw = $1;
    }

    # Maybe convert/translate/munge password. Dont auto-vivify $self
    ($pw) = $self->runHook('TranslatePasswordHook', $p, $pw, $self, $user, $encrypted, $p) 
	if $self && defined $self->{TranslatePasswordHook};

    if (defined ($attr = $p->getAttrByNum($Radius::Radius::CHAP_PASSWORD)))
    {
	# Its a conventional CHAP request
	if ($encrypted)
	{
	    $self->log($main::LOG_WARNING, "Cant use encrypted passwords with CHAP");
	}
	else
	{
	    # Use MD5 to encrypt the correct password, and match it against
	    # what was sent to us in CHAP-Password.
	    # The request is expected to have the CHAP id as the first byte
	    # of CHAP-Password, with the rest of CHAP-Password being
	    # the result of encryption sent from the client
	    # we compute MD5(chap id + user_secret + challenge)
	    # If the result is the same as CHAP-Password+1, then we have a match.
	    # The challenge is sent by the client in CHAP-Challenge. 
	    # If that is not set, the challenge is in the authenticator
	    $challenge = $p->getAttrByNum($Radius::Radius::CHAP_CHALLENGE);
	    $challenge = $p->authenticator unless defined $challenge;
	    my $chapid = substr($attr, 0, 1);
	    my $response = substr($attr, 1);
	    $submitted_pw = 'UNKNOWN-CHAP';
	    $result = $self->check_chap($p, $user, $pw, $chapid, $challenge, $response);
	}
    }
    elsif (   ($attr = $p->get_attr('MS-CHAP-Response'))
	   && ($challenge = $p->get_attr('MS-CHAP-Challenge')))
    {
	# Its an MS-CHAP request
	eval {require Radius::MSCHAP};
	if ($@)
	{
	    $self->log($main::LOG_ERR, "Could not load Radius::MSCHAP to handle an MS-CHAP request: $@");
	    return 0;
	}


	# Unpack as per rfc2548
	my ($ident, $flags, $lmresponse, $ntresponse) = unpack('C C a24 a24', $attr);
	if ($flags == 1)
	{
	    my ($usersessionkey, $lanmansessionkey, $nthash);

	    # use the NT-Response
	    if ($pw =~ /^{nthash}([0-9a-hA-H]{32})$/)
	    {
		$pw = $1;
		$encrypted++;
	    }
	    if ($encrypted)
	    {
		# Expect that $pw is actually the NtPasswordHash
		# version of the correct password
		$nthash = $pw;
		$nthash = pack('H*', $nthash) if length $nthash == 32; # hex encoded?
	    }
	    else
	    {
		$nthash = Radius::MSCHAP::NtPasswordHash(Radius::MSCHAP::ASCIItoUnicode($pw));
		$lanmansessionkey = Radius::MSCHAP::LmPasswordHash($pw);
	    }
	    $result = $self->check_mschap($p, $user, $nthash, $challenge, $ntresponse, \$usersessionkey);
	    # Maybe automatically send back MS-CHAP-MPPE-Keys
	    # based on the password.

	    if ($result && $self->{AutoMPPEKeys})
	    {
		$p->{rp}->add_attr('MS-CHAP-MPPE-Keys', pack('a8 a16', $lanmansessionkey, $usersessionkey))
	    }
	}
	else
	{
	    # use the LM-Response
	    $self->log($main::LOG_ERR, "MS-CHAP LM-response not implemented");
	}
	$submitted_pw = 'UNKNOWN-MS-CHAP';
    }
    elsif (   ($attr = $p->get_attr('MS-CHAP2-Response'))
	   && ($challenge = $p->get_attr('MS-CHAP-Challenge')))
    {
	# Its an MS-CHAP V2 request
	# See draft-ietf-radius-ms-vsa-01.txt,
	# draft-ietf-pppext-mschap-v2-00.txt, RFC 2548, RFC3079
	eval {require Radius::MSCHAP};
	if ($@)
	{
	    $self->log($main::LOG_ERR, "Could not load Radius::MSCHAP to handle an MS-CHAP2 request: $@");
	    return 0;
	}

	# Unpack as per rfc2548
	my ($ident, $flags, $peerchallenge, $reserved, $response) = unpack('C C a16 a8 a24', $attr);

	my ($nthash, $authenticator_response, $mppekeys);
	if ($pw =~ /^{nthash}([0-9a-hA-H]{32})$/)
	{
	    $pw = $1;
	    $encrypted++;
	}
	if ($encrypted)
	{
	    # Expect that $pw is actually the NtPasswordHash
	    # version of the correct password
	    $nthash = $pw;
	    $nthash = pack('H*', $nthash) if length $nthash == 32; # hex encoded?
	    $result = $self->check_mschapv2($p, $user, $nthash, $challenge, $peerchallenge, $response, \$mppekeys, \$authenticator_response);
	}
	else
	{
	    $result = $self->check_mschapv2_plaintext($p, $user, $pw, $challenge, $peerchallenge, $response, \$mppekeys, \$authenticator_response);
	}

	if ($result && $p->{rp})
	{
	    # MS CHAP V2 requires a specific response in the reply
	    $p->{rp}->add_attr('MS-CHAP2-Success', pack('C a42', $ident, $authenticator_response));
	    if ($self->{AutoMPPEKeys})
	    {
		my ($send, $recv) = unpack('a16 a16', $mppekeys);

		# These will be encoded later by the client
		$p->{rp}->add_attr('MS-MPPE-Send-Key', $send);
		$p->{rp}->add_attr('MS-MPPE-Recv-Key', $recv);
	    }
	}
	$submitted_pw = 'UNKNOWN-MS-CHAP-V2';
    }
    elsif (defined($attr = $p->get_attr('Digest-Response')))
    {
	# SIP Digest RFC 2617 and RFC 4590 digest auth
	# We dont do md5-sess yet.
	my ($username, $realm, $nonce, $uri, $qop, $method, $nc, $cnonce, $algorithm, $eb_hash);
	my $sipattrs = join('', $p->get_attr('Digest-Attributes')); # May be multiple instances
	if (length $sipattrs)
	{
	    my @attrs;
	    # Unpack inner attributes from Digest-Attributes as per draft-sterman-aaa-sip-00.txt
	    while (length($sipattrs))
	    {
		my ($subtype, $sublength) = unpack('C C', $sipattrs);
		last if $sublength < 3;
		my $vallen = $sublength - 2;
		$attrs[$subtype] = unpack("x x a$vallen", $sipattrs);
		substr($sipattrs, 0, $sublength) = undef; # Strip that one off
	    }
	    $realm       = $attrs[1];
	    $nonce       = $attrs[2];
	    $method      = $attrs[3];
	    $uri         = $attrs[4];
	    $qop         = $attrs[5];
	    $algorithm   = $attrs[6];
	    $eb_hash     = $attrs[7];
	    $cnonce      = $attrs[8];
	    $nc          = $attrs[9];
	    $username    = $attrs[10];
	}
	else
	{
	    # Try to get the RFC 4590 SIP attributes.
	    # RFC4590 NASs support this instead of packing them into 
	    # Digest-Attributes. You will need
	    # special dictionary entries to support this
	    $username    = $p->get_attr('Digest-Username');
	    $realm       = $p->get_attr('Digest-Realm');
	    $nonce       = $p->get_attr('Digest-Nonce');
	    $uri         = $p->get_attr('Digest-URI');
	    $qop         = $p->get_attr('Digest-Qop');
	    $method      = $p->get_attr('Digest-Method');
	    $nc          = $p->get_attr('Digest-Nonce-Count');
	    $cnonce      = $p->get_attr('Digest-CNonce');
	    $eb_hash     = $p->get_attr('Digest-Entity-Body-Hash');
	    $algorithm   = $p->get_attr('Digest-Algorithm');
	}
	$algorithm = 'MD5' unless defined $algorithm;
	$method = 'INVITE'unless defined $method;
	$submitted_pw = 'UNKNOWN-SIP-DIGEST';
	# Removes escapes
	foreach ($username, $realm, $uri)
	{
	    $_ =~ s|\\\\|\\|;
	    $_ =~ s|\\'|'|;
	}
	# Revisit: could check for stale nonces here
#	print "username $username realm $realm nonce $nonce uri $uri qop $qop method $method nc $nc cnonce $cnonce eb_hash $eb_hash algorithm $algorithm \n";
	if (defined $username
	    && defined $realm
	    && defined $nonce 
	    && defined $uri)
	{
	    my $response_auth;
	    $result = $self->check_digest_md5
		($p, $username, $realm, $nonce, $cnonce, $nc, $qop, 
		 $method, $uri, $eb_hash, $algorithm, $attr, $pw, \$response_auth);
	    if ($result)
	    {
		# Add Response-Auth here per RFC5090
		$p->{rp}->add_attr('Digest-Response-Auth', $response_auth) 
		    if $qop eq 'auth' || !defined $qop;
		$p->{rp}->add_attr('Message-Authenticator', "\000" x 16); # Will be filled in later
	    }
	}
    }
    elsif (defined ($submitted_pw = $p->decodedPassword()))
    {
	$result = $self->check_plain_password($user, $submitted_pw, $pw, $p, $encrypted);
    }
    else
    {
	# else No CHAP-Password or User-Password, so fail
	$self->log($main::LOG_WARNING, "No CHAP-Password or User-Password in request: does your dictionary have User-Password in it?");
    }
    $p->{Handler}->logPassword($user, $submitted_pw, $pw, $result, $p) if $p->{Handler};
    return $result;
}

#####################################################################
# Check a plaintext password against any of the
# password database formats supported.
# Return true if the password is OK
sub check_plain_password
{
    my ($self, $user, $submitted_pw, $pw, $p, $encrypted) = @_;

    my $result;
#my $x = unpack('H*', $submitted_pw);
#print "FIXME: submitted PAP password '$submitted_pw' ($x), '$pw'\n";
    # Handle a number of encrypted password formats
    # This should be parameterised and extensible
    # Contributed by Justin Daminato <jd@ozemail.camtech.net.au>
    # See http://developer1.netscape.com:80/docs/technote/ldap/pass_sha.html
    if ($pw =~ /^{SS?HA}(.*)/i)
    {
    	$pw = $1; # Ignore the label
	eval 
	{
	    require MIME::Base64;
	
	    my ($hash, $salt) = unpack("a20a*", MIME::Base64::decode_base64($pw));
	    $result = ($hash eq Digest::SHA::sha1($submitted_pw . $salt));
	};
	if ($@)
	{
	    $self->log($main::LOG_ERR, "SHA Password check failed: $@");
	    return;
	}
    }
    elsif ($pw =~ /^{SS?HA(256|384|512)}(.*)/i)
    {
	my $hlen = $1;
	my $template = "a" . $hlen/8 . "a*";
    	$pw = $2;
	eval
	{
	    require MIME::Base64;

	    my ($hash, $salt) = unpack($template, MIME::Base64::decode_base64($pw));
	    if ($hlen == 256)
	    {
		$result = ($hash eq Digest::SHA::sha256($submitted_pw . $salt));
	    }
	    elsif ($hlen == 384)
	    {
		$result = ($hash eq Digest::SHA::sha384($submitted_pw . $salt));
	    }
	    else
	    {
		$result = ($hash eq Digest::SHA::sha512($submitted_pw . $salt));
	    }
	};
	if ($@)
	{
	    $self->log($main::LOG_ERR, "SHA$hlen Password check failed: $@");
	    return;
	}
    }
    elsif ($pw =~ /^{PBKDF2}(.*)/i)
    {

	my ($prf, $c, $salt, $hash) = ($1 =~ /^([^:]+):(\d+):([^:]+):([^:]+)$/);
	unless ($hash)
	{
	    $self->log($main::LOG_ERR, "Bad PBKDF2 format. Password check failed");
	    return;
	}
	unless ($prf eq 'HMACSHA1')
	{
	    $self->log($main::LOG_ERR, "Unknown PBKDF2 PRF $prf. Password check failed");
	    return;
	}
	eval
	{
	    require Radius::PBKDF;
	    require MIME::Base64;
	    $salt = MIME::Base64::decode($salt);
	    $hash = MIME::Base64::decode($hash);
	    $result = ($hash eq Radius::PBKDF::pbkdf2_hmac_sha1($submitted_pw, $salt, $c, 20));
	};
	if ($@)
	{
	    $self->log($main::LOG_ERR, "PBKDF2 Password check failed: $@");
	    return;
	}

    }
    elsif ($pw =~ /^{crypt}(.*)/i)
    {
	# Its a UNIX crypted password
	$result = (crypt($submitted_pw, $1) eq $1);
    }
    elsif ($pw =~ /^{mysql}(.*)/i)
    {
	# Its a MYSQL crypted password
	$result = (&Radius::Util::mysqlPassword($submitted_pw) eq $1);
    }
    elsif ($pw =~ /^{mssql}(.*)/i)
    {
	if (length($1) == 92)
	{
	    # Hexified
	    $result = &mssql_pwdcompare(pack('H*', $1), $submitted_pw);	
	}
	else
	{
	    # Binary
	    $result = &mssql_pwdcompare($1, $submitted_pw);	
	}
	# Its a Microsoft SQL pwdencrypt() crypted password (hexified)
    }
    elsif ($pw =~ /^{nthash}(.*)/i)
    {
	# Its an NT hashed password, probably hex encoded
	$result = $self->check_nthash($p, $1, $submitted_pw);
    }
    elsif ($pw =~ /^{dechpwd}(1|2|3)\|(\d+)\|([0-9a-f]+)/i)
    {
	# Dec Hashed Password as used in VAX etc
	# format is {dechpwd}algorithm|salt|hash
	# eg: for user MIKEM with password fred and algorithm DecHpwd::UAI_C_PURDY_S
	# {dechpwd}3|1234|85ad61e72a41dec4
	# Requires Authen-DecHpwd from CPAN
	eval 
	{
	    require Authen::DecHpwd;
	
	    $result = unpack('H*', Authen::DecHpwd::lgi_hpwd($user, $submitted_pw, $1, $2))
		eq $3;
	};
	if ($@)
	{
	    $self->log($main::LOG_ERR, "DEC Hashed Password check failed: $@");
	    return;
	}
    }
    # Jerome Fleury 09/02/2010 - check against Django style passwords
    elsif ($pw =~ /^(md5|sha1)\$([a-fA-F0-9]{5})\$([a-fA-F0-9]+)$/)
    {
	# split hash and salt
	my ($salt, $hash_passwd) = ($2, $3);
	my $h;
	if ($1 eq 'sha1') 
	{
	    $h = Digest::SHA::sha1_hex($salt.$submitted_pw);
	}
	elsif ($1 eq 'md5') 
	{
	    $h = Digest::MD5::md5_hex($salt.$submitted_pw);
	}
	$result = $h eq $hash_passwd;
    }
    elsif ($pw =~ /^\$1\$/)
    {
	# Linux standard MD5 encryption
	$result = (&Radius::Util::md5crypt($submitted_pw, $pw) eq $pw);
    }
    elsif ($pw =~ /^\$[56]\$.+\$/) 
    {
	# Linux SHA-256, SHA512 crypt
	$result = crypt($submitted_pw, $pw) eq $pw;
    }
    elsif ($pw =~ /^\$2[axy]\$.+\$/) 
    {
	# Blowfish crypt
	$result = crypt($submitted_pw, $pw) eq $pw;
    }
    elsif ($submitted_pw =~ /^Digest/i)
    {
	# Digest authentication from a web server or proxy
	# via Apache::AuthenRadius or similar
	$result = &check_digest_password($self, $user, $submitted_pw, $pw);
    }
    elsif ($pw =~ /^{MD5}/i)
    {
	#Support for MD5 with hexdigest and BASE64 encoding
	#Contributed by Johnathan Ingram <johnathani@bigfoot.com>
	
	my $cmp_pass;
	if ($pw =~ /\=$/)
	{
	    # BASE64 encoding:
	    $cmp_pass = '{MD5}' . Digest::MD5::md5_base64($submitted_pw) . '==';
	}
	else
	{
	    # Hex Digest:
	    $cmp_pass = '{MD5}' . Digest::MD5::md5_hex($submitted_pw);
	}
	
	$result = ($cmp_pass eq $pw);
    }
    elsif ($pw =~ /^{NS-MTA-MD5}(.*)/i)
    {
	# Ancient netscape mailserver format
	# first 32 bytes are the hex encoded hash.
	# Second 32 bytes are the salt (not hex encoded)
	my ($hash, $salt) = unpack('a32 a32', $1);
	$hash = pack('H*', $hash);
	my $h = Digest::MD5::md5(pack('a* C a* C a*', $salt, 89, $submitted_pw, 247, $salt));
	my $x = unpack('H*', $h);
	$result = $h eq $hash;
    }
    elsif (defined $self->{CheckPasswordHook} && $pw =~ /^{OSC-pw-hook}(.*)/)
    {
	($result) = $self->runHook('CheckPasswordHook', $p, $p, $submitted_pw, $1);
    }
    else
    {
	# Be compatible with some types of LDAP database passwords
	$pw = $1 if ($pw =~ /^{clear}(.*)$/);

	if ($encrypted)
	{
	    if (length($pw) == 13)
	    {
		# Just ordinary unix crypt
		$result = (crypt($submitted_pw, $pw) eq $pw);
	    }
            elsif ((length($pw) == 20) && ($pw =~ m:^_[./a-zA-Z\d]{4}:))
            {
                # DES Extended Format as used in BSD/OS (nee BSDI)
                #   also uses crypt(3), as long as the libcrypt library was 
                #   compiled with DES support.
                $result = (crypt($submitted_pw, $pw) eq $pw);
            }
	    else
	    {
		# NT Hashed password	
		$result = $self->check_nthash($p, $pw, $submitted_pw);
	    }
	}
	else
	{
	    $result = $self->check_plaintext($p, $user, $submitted_pw, $pw);
	}
    }
    return $result;
}

#####################################################################
# Check a plaintext passowrd against a digest authentication string
# of the kind that might be sent by Apache via 
# Apache::AuthenRadius or similar
# Return true if the password is OK
# RadKey algorithm digest encrypts the response like
# hex(HMAC_MD5("uri:nonce", 
#              hex(HMAC_MD5(HMAC_MD5(realm, username), secret))))
# For pache standard HTTP digest, the submitted password is something like:
# Digest username="fred", realm="Radius Test", nonce="1017924171", uri="/test", algorithm="md5", response="9bce3d58494e182295c71c728af6baec"
# or
# Digest username="zz", realm="Radius Test", qop="auth", algorithm="MD5", uri="/test", nonce="1018000482", nc=00000001, cnonce="b798c628f3f2591529f3d599e33bd656", response="a63541c566e0d2049f93a1af22577962", method="GET"
# See RFC 2617
sub check_digest_password
{
    my ($self, $user, $submitted_pw, $correct_pw) = @_;

    my ($algorithm) = $submitted_pw =~ /algorithm="([^"]*)"/;        #"
    if ($algorithm eq 'RadKey')
    {
	my $hash = $correct_pw; # the hash of realm/username/password
	# See if the password is already hashed
	if ($hash !~ /^[a-f0-9]{32}$/)
	{
	    my $realm;
	    $realm = $1 if $submitted_pw =~ /realm="([^"]*)"/;       #"
	    $hash = unpack 'H*', 
			   &Radius::Util::hmac_md5
			   ($hash, 
			    &Radius::Util::hmac_md5($user, $realm));
	}
	my ($uri) = $submitted_pw =~ /uri="([^"]*)"/;
	my ($nonce) = $submitted_pw =~ /nonce="([^"]*)"/;

	my $correct_response = 
            unpack 'H*', 
                   &Radius::Util::hmac_md5($hash, "$uri:$nonce");
	my ($response) = $submitted_pw =~ /response="([^"]*)"/;      #"

	return $response eq $correct_response;
    }
    elsif ($algorithm eq '' || lc $algorithm eq 'md5')
    {
	# Standard RFC2617 digest auth
	# We dont do md5-sess yet.
	my ($username) = $submitted_pw =~ /username="([^"]*)"/;      #"
	my ($realm)    = $submitted_pw =~ /realm="([^"]*)"/;      #"
	my ($response) = $submitted_pw =~ /response="([^"]*)"/;      #"
	my ($nonce)    = $submitted_pw =~ /nonce="([^"]*)"/;      #"
	my ($uri)      = $submitted_pw =~ /uri="([^"]*)"/;      #"
	my ($qop)      = $submitted_pw =~ /qop="([^"]*)"/;      #"

        # method is added by our patched version of AuthenRadius.pm
        # since we cant get it any other way, but there is no guarantee
        # it will be available, so default to GET
	my ($method)   = $submitted_pw =~ /method="([^"]*)"/;      #"
        $method ||= 'GET';
        my $ha1;
        if ($correct_pw =~ /^{digest-md5-hex}([0-9a-e]{32})$/i)
        {
            # Password is already MD5 digestified version of $username:$realm:$correct_pw
            $ha1 = $1;
        }
        else
        {
            $ha1 = Digest::MD5::md5_hex("$username:$realm:$correct_pw");
        }
        my $ha2 = Digest::MD5::md5_hex("$method:$uri");

        if (!defined $qop)
        {
            my $correct_response = Digest::MD5::md5_hex("$ha1:$nonce:$ha2");
            return $correct_response eq $response;
        }
        elsif ($qop eq 'auth')
        {
	    my ($nc) = $submitted_pw =~ /nc=(\w+)/;
            my ($cnonce) = $submitted_pw =~ /cnonce="([^"]*)"/;  #"
            my $correct_response = Digest::MD5::md5_hex
                     ("$ha1:$nonce:$nc:$cnonce:$qop:$ha2");
            return $correct_response eq $response;
        }
        else
        {
            # Cant do auth-int, since dont have entity-body
            $self->log($main::LOG_WARNING, "Unknown HTTP Digest authenticationQOP $qop");
	    return 0;
	}
    }
    else
    {
	$self->log($main::LOG_WARNING, "Unknown Digest authentication algorithm $algorithm is not implemented");
	return 0;
    }
}

#####################################################################
# This log function can be called eith erwith or without a 
# self pointer
# OBSOLETE: remove after version 5.6
sub safeLog
{
    my ($self, @args) = @_;

    $self ? $self->log(@args) : &main::log(@args);
}

#####################################################################
# Check that all the check items in $attr match the 
# corresponding items in the request packet $p
# Returns 1 if all the check items pass
# $p is the original request packet.
# Possible return values are:
# $main::REJECT, authentication failed
# $main::ACCEPT, authentication succeeded
# $main::IGNORE, authentication is deferred by a non-synchronous
#      auth method, which will reply directly at a later time
# This routine handles all the special types of check items, as
# well as ordinary check items, either as exact matches or as 
# regular expressions.
# Also returns an optional reason message for rejects
sub checkAttributes
{
    my ($self, $attr, $p, $orig_user_name) = @_;

    my $username = $p->getUserName();
    my $i = 0;
    my ($block_logon_from, $block_logon_until, $check_name, $value);
    while (($check_name, $value) = $attr->get_attr_val_n($i++))
    {
	#print "$self->{Identifier} checking '$check_name', '$value'\n";
	# Do dynamic replacements in selected check item
	$value = &Radius::Util::format_special($value, $p)
	    if $self && grep $check_name eq $_, @{$self->{DynamicCheck}};

	if (   $check_name eq 'Encrypted-Password' 
	       || $check_name eq 'Crypt-Password')
	{
	    # EAP passwords have already been checked
	    next if defined $p->getAttrByNum($Radius::Radius::EAP_MESSAGE);
	    return ($main::REJECT, "Bad Encrypted password")
		if !&check_password($self, $p, $value, $username, 1);
	}
	elsif (   $check_name eq 'Password'
	       || $check_name eq 'User-Password')
	{
	    # EAP passwords may have already been checked
	    next if defined $p->getAttrByNum($Radius::Radius::EAP_MESSAGE)
		&& !$self->{NoEAP};
	    return ($main::REJECT, "Bad Password")
		if !&check_password($self, $p, $value, $username);
	}
	elsif ($check_name eq 'Expiration' || $check_name eq 'ValidTo')
	{
	    # We cache the end date/tim in the packet for possible use with 
	    # Session-Timeout="Until Expiration"
	    $p->{ValidTo} = &Radius::Util::parseDate($value);
	    $self->log($main::LOG_DEBUG, "Expiration date converted to: $p->{ValidTo}");
	    
	    return ($main::REJECT, "Expiration date has passed")
		if ($p->{ValidTo} < time);
	}	
	elsif ($check_name eq 'ValidFrom')
	{
	    my $date = &Radius::Util::parseDate($value);
	    $self->log($main::LOG_DEBUG, "ValidFrom date converted to: $date");
	    
	    return ($main::REJECT, "ValidFrom date not reached yet")
		if ($date > time);
	}
	elsif ($check_name eq 'Simultaneous-Use')
	{
	    # If the value looks like an integer, then its
	    # the max session count, otherwise its the name of a file
	    # that contains the max session count
	    my $max_sessions;
	    if ($value =~ /\D/)
	    {
		# There is a non-digit, it must be a filename
		my $filename = &Radius::Util::format_special($value, $p);
		open(FILE, $filename)
		    || $self->log($main::LOG_WARNING, 
				  "Could not open Simultaneous-Use file $filename: $!");
		$max_sessions = <FILE>;
		close(FILE);
	    }
	    else
	    {
		$max_sessions = $value;
	    }
	    # Now we know the max number of permitted sessions
	    # Ask the session database to tell us if its too many
	    return ($main::REJECT, "Simultaneous-Use of $max_sessions exceeded")
		if Radius::SessGeneric::find($p->{Handler}->{SessionDatabase})->exceeded($max_sessions, $p->{OriginalUserName}, $p);
	    $p->{did_sim_use}++;
	}
	elsif ($check_name eq 'Auth-Type')
	{
	    if ($value =~ /^Reject(:(.*))?/)
	    {
		my $msg = "Rejected explicitly by Auth-Type=Reject";
		$msg = $2 if $2;
		return ($main::REJECT_IMMEDIATE, $msg);
	    }
	    elsif ($value eq 'Ignore')
	    {
		return ($main::IGNORE, "Ignored explicitly by Auth-Type=Ignore");
	    }
 	    elsif ($value eq 'Accept')
 	    {
 		return ($main::ACCEPT, "Accept explicitly by Auth-Type=Accept");
 	    }
  	    else
	    {
		# Damn, they want us to authenticate with 
		# a different method now. Why cant they 
		# make up their mind? So we find the 
		# AuthBy object from the name we give
		# then ask that object to authenticate
		# this user. This is pretty ugly, but is required
		# to support Auth-Type = System type check items
		my $auth_object;
		if ($auth_object = &Radius::AuthGeneric::find($value))
		{
		    # Any remaining attributes are used as
		    # extra check items for the cascaded-to module
		    my $extra = new Radius::AttrVal;
		    while (($check_name, $value) = 
			   $attr->get_attr_val_n($i++))
		    {
			$extra->add_attr($check_name, $value);
		    }
		    
		    return $auth_object->handle_request($p, $p->{rp}, $extra);
		}
		else
		{
		    my $reason = "Could not find Identifier for Auth-Type '$value'";
		    $self->log($main::LOG_WARNING, $reason, $p);
		       
		    return ($main::REJECT, $reason);
		}
	    }
	}
	elsif ($check_name eq 'Block-Logon-From')
	{
#	    print "Block-Logon-From $value\n";
	    # Now deprecatedU
	    $block_logon_from = &Radius::Util::parseTime($value);

	}
	elsif ($check_name eq 'Block-Logon-Until')
	{
#	    print "Block-Logon-Until $value\n";
	    # Now deprecated
	    $block_logon_until = &Radius::Util::parseTime($value);
	}
	elsif ($check_name eq 'Group')
	{
	    # We must check if the original user (not a DEFAULT)
	    # is in the group
	    my $realuser = $p->getUserName();
	    return ($main::REJECT, "User $realuser is not in Group $value")
		if !$self->userIsInGroup($realuser, $value, $p);
	}
	elsif ($check_name eq 'GroupList')
	{
	    my $realuser = $p->getUserName();
	    my ($group, $found);
	    foreach $group (split(/\s+/, $value))
	    {
		$found++, last 
		    if $self->userIsInGroup($realuser, $group, $p);
	    }
	    return ($main::REJECT, "User $realuser is not in any group in GroupList")
		unless $found;
	}
	elsif ($check_name eq 'Connect-Rate')
	{
	    # Specifies a maximum speed permitted for this user
	    # Connect-info is a string like '33600 LAPM/V42BIS'
	    my $connect_info = $p->getAttrByNum($Radius::Radius::CONNECT_INFO);
	    $connect_info = $p->get_attr('USR-Connect-Speed') 
		unless defined $connect_info;
	    no warnings "numeric"; # May not just be an integer
	    $connect_info += 0;
	    return ($main::REJECT,
		    "Connect-Rate $value does not allow a speed of $connect_info")
		if ($connect_info > $value);
	}
	elsif ($check_name eq 'eDir-Auth-Option')
	{
	    # If UseNovellNMASSequence is in use, 
	    # This will be checked by Radius::AuthLDAP2::checkUserAttributes
	}
	elsif ($check_name eq 'Realm')
	{
	    my ($name, $realmName) = split(/@/, $username);
	    return ($main::REJECT, "Realm does not match")
		unless match($self, $realmName, $check_name, $value);
	}
	elsif ($check_name eq 'NAS-Address-Port-List')
	{
	    # We keep a hash of filenames we have visited. Each entry
	    # is a hash of NAS IP addresses, each entry there is a 
	    # array of permitted port number ranges
	    my $permitted;
	    # The file name might have some macros in it: evaluate them now
	    my $filename = &Radius::Util::format_special($value, $p);
	    if (!defined($permitted = $Radius::AuthGeneric::nasportfiles{$filename}))
	    {
		if (open(FILE, $filename))
		{

		    $self->log($main::LOG_DEBUG, "NAS-Address-Port-List: reading $filename");
		    # Read the file. Its in format "address lowport-highport"
		    $permitted = {}; # Anonymous hash
		    while (<FILE>)
		    {
			chomp;
			next if /^#/ || /^\s*$/; # Skip comment and blank lines
			my ($address, $portspec);
			if ((($address, $portspec)= split(/\s+/)) == 2)
			{
			    $address = Radius::Util::inet_pton($address);
			    $address = join('.', unpack('C4', $address));
			    push (@{$permitted->{$address}}, $portspec);
			}
		    }
		    close(FILE);
		    $Radius::AuthGeneric::nasportfiles{$filename} = $permitted;
		}
		else
		{
		    $self->log($main::LOG_WARNING, 
			       "Could not open NAS-Address-Port-List file $filename: $!");
		}
	    }
	    # Now $permitted contains the data from the file
	    my $nas_id = $p->getNasId();

	    # 98/08/18 P.Chow - added for port restriction of iPass roamers
            $nas_id = '0.0.0.0' if ($nas_id eq 'i-Pass VNAS');
	    my $nas_port = $p->getAttrByNum($Radius::Radius::NAS_PORT);

	    my ($range, $accepted);
	    foreach $range (@{$permitted->{$nas_id}})
	    {
		my ($lowport, $highport) = split('-', $range);
		if ($nas_port >= $lowport && $nas_port <= $highport)
		{
		    $accepted++;
		    last; # Found at least one good one
		}
	    }

	    return ($main::REJECT,
		    "NAS-Address-Port-List: port $nas_port is not within an allowable port range for $nas_id")
		unless $accepted;
	}
	elsif ($check_name eq 'Prefix')
	{
 	    # We must check the original username so that we can
 	    # fall through multiple DEFAULTs with Prefixes
	    # and/or suffixes properly.
	    # Contributed by David Daney <daney@ibw.com.ni>
 	    my $userNameToTest = $p->{UsernameWithPrefixAndSuffix};
 	    $userNameToTest = $username unless $userNameToTest;

  	    # If the prefix is present, accept it and strip the prefix
 	    my $index = index($userNameToTest, $value);
  	    if ($index == 0)
  	    {
 		my $newName = substr($userNameToTest, $index + length($value));
 		$p->changeUserName($newName);
 		$p->{UsernameWithPrefixAndSuffix} = $userNameToTest;
 		$username = $newName;
  	    }
 	    else 
	    {
 		return($main::REJECT, "Username not prefixed with $value");
  	    }
  	}
	elsif ($check_name eq 'Suffix')
	{
 	    # We must check the original username so that we can
 	    # fall through multiple DEFAULTs with Prefixes
	    # and/or suffixes properly.
	    # Contributed by David Daney <daney@ibw.com.ni>
 	    my $userNameToTest = $p->{UsernameWithPrefixAndSuffix};
 	    $userNameToTest = $username unless $userNameToTest;

  	    # If the suffix is present, accept it and strip the suffix
	    my $index = index($userNameToTest, $value);
	    if ($index >= 0 
		&& $index == (length($userNameToTest) - length($value)))
  	    {
 		my $newName = substr($userNameToTest, 0, $index);
 		$p->changeUserName($newName);
 		$p->{UsernameWithPrefixAndSuffix} = $userNameToTest;
 		$username = $newName;
  	    }
 	    else 
	    {
 		return($main::REJECT, "Username not suffixed with $value");
  	    }
	}
	elsif ($check_name eq 'Time')
	{
	    # The format is consists of days specifiers followed 
	    # by hours intervals, multiple values
	    # separated by commas. 
	    # Day specifiers are Mo, Tu, We, Th, Fr, Sa, 
	    # Su and Wk meaning Mo-Fr and Al
	    # meaning all of them. 
	    # Hours intervals are specified as HHMM-HHMM 
	    # (hours_minutes). Thus, valid
	    # entries are: 
            #  Time = "MoTuWe0800-1400,Wk2200-0400" 
            #  Time = "Al1800-0600,Wk1000-1330" 
	    my @time = localtime(time);
	    my $current_tod = ($time[2] * 100) + $time[1];
	    my @items = split(/,/, $value);
	    my ($item, $permitted);
	    # Get each comma separated item
	    foreach $item (@items)
	    {
		# get the start and end times
		my ($start_time, $end_time) 
		    = $item =~ /(\d{4})-(\d{4})/;

		# See if we are in the time band permitted
		my $time_permitted 
		    = (   (   $start_time >= $end_time
		           && (   $current_tod >= $start_time
		               || $current_tod <= $end_time))
		       || (   $start_time < $end_time
			   && $current_tod >= $start_time
			   && $current_tod <= $end_time));

		# See if today is one of the days permitted
		my $current_day = ('Su','Mo','Tu','We','Th','Fr','Sa','Su')[$time[6]];
		my $day_permitted;
		$day_permitted++
		    if $item =~ /$current_day/; # This day
		$day_permitted++
		    if $item =~ /Al/;  # Any day
		$day_permitted++
		    if $time[6] >= 1 && $time[6] <= 5
			&& $item =~ /Wk/;  # Any week day
		
		if ($time_permitted && $day_permitted)
		{
		    $permitted++;
		    # Cache the end time, for use by Session-Timeout
		    # reply item in addReplyItem. Time is the 
		    # the end of the minute.
		    $time[0] = $time[1] = $time[2] = 0; #midnight
		    $p->{TimeEnd} = timelocal(@time)
			+ (int($end_time/100)*3600) 
			    + (($end_time%100)*60) + 60;
		    # Perhaps the end time is tomorrow?
		    $p->{TimeEnd} += 86400
			if ($end_time < $current_tod);
		    last;
		}
	    }

	    return ($main::REJECT, 'Time: not within an allowable Time range')
		unless $permitted;
	}
	elsif ($check_name eq 'Client-Id')
	{
	    # Livingston compatibility: check that the request came
	    # from the Client with this name
	    return ($main::REJECT, 'Client-Id does not match')
		unless match($self, $p->{Client}->{Name}, $check_name, $value);
	}
	elsif ($check_name eq 'Client-Identifier')
	{
	    # Check that the request came
	    # from the Client with this Identifier
	    return ($main::REJECT, 'Client-Identifier does not match')
		unless match($self, $p->{Client}->{Identifier}, $check_name, $value);
	}
	elsif ($check_name eq 'NasType')
	{
	    # Check that the NasType of the client it arrived from
	    return ($main::REJECT, 'NasType does not match')
		unless match($self, $p->{Client}->{NasType}, $check_name, $value);
	}
	elsif ($check_name eq 'Request-Type')
	{
	    # Check the request type code for this request
	    # Mostly useful for Handlers
	    return ($main::REJECT, 'Request-Type does not match')
		unless match($self, $p->code, $check_name, $value);
	}
	elsif ($check_name eq 'MS-Login-Hours')
	{
	    return ($main::REJECT, 'Outside allowed login hours')
		unless $self->checkLoginHours($value);
	}
	elsif ($check_name eq 'TunnelledByTTLS')
	{
	    return ($main::REJECT, 'TunnelledByTTLS check failed')
		unless ($p->{tunnelledByTTLS});
	}
	elsif ($check_name eq 'TunnelledByPEAP')
	{
	    return ($main::REJECT, 'TunnelledByPEAP check failed')
		unless ($p->{tunnelledByPEAP});
	}
	elsif ($check_name eq 'TunnelledByFAST')
	{
	    return ($main::REJECT, 'TunnelledByFAST check failed')
		unless ($p->{tunnelledByFAST});
	}
	elsif ($check_name eq 'EAPType')
	{
	    return ($main::REJECT, 'EAPType check failed')
		unless ($value == $p->{EAPType});
	}
	elsif ($check_name eq 'EAPTypeName')
	{
	    return ($main::REJECT, 'EAPTypeName check failed')
		unless ($value eq $p->{EAPTypeName});
	}
	elsif ($check_name eq 'RecvFromAddress')
	{
	    return ($main::REJECT, 'RecvFromAddress check failed')
		unless match($self, &Radius::Util::inet_ntop($p->{RecvFromAddress}), $check_name, $value);
	}
	elsif ($check_name eq 'RecvFromName')
	{
	    return ($main::REJECT, 'RecvFromName check failed')
		unless match($self, scalar &Radius::Util::gethostbyaddr($p->{RecvFromAddress}), $check_name, $value);
	}
	elsif (   $check_name eq 'Max-All-Session'
	       || $check_name eq 'Max-Daily-Session'
	       || $check_name eq 'Max-Hourly-Session'
	       || $check_name eq 'Max-Monthly-Session'
	       || $check_name eq 'Max-All-Octets'
	       || $check_name eq 'Max-Daily-Octets'
	       || $check_name eq 'Max-Hourly-Octets'
	       || $check_name eq 'Max-Monthly-Octets'
	       || $check_name eq 'Max-All-Gigawords'
	       || $check_name eq 'Max-Daily-Gigawords'
	       || $check_name eq 'Max-Hourly-Gigawords'
	       || $check_name eq 'Max-Monthly-Gigawords')
	{
	    # See if the superclass knows how to handle this
	    my $limitvalue = $self->getLimitValue($username, $check_name, $p);
	    if (defined $limitvalue)
	    {
		if ($check_name =~ /Session$/)
		{
		    # Apply valid-time-to for use with Session-Timeout = until ValidTo
		    # Apply the most restrictive one
		    my $validto = time + ($value - $limitvalue);
		    $p->{ValidTo} = $validto 
			if !defined $p->{ValidTo} || $validto < $p->{ValidTo};
		}
		return ($main::REJECT, "$check_name exceeded") 
		    if $limitvalue > $value;
	    }
	}
	else
	{
	    # Its some other check item. May be in either the request
	    # or the reply
	    my $attr;
	    if ($check_name =~ /^Reply:(.*)$/)
	    {
		# Get the value from the reply if prefixed with Reply:
		$attr = $p->{rp}->get_attr($1);
	    }
	    elsif ($check_name =~ /^GlobalVar:(.*)$/)
	    {
		$attr = &main::getVariable($1);
	    }
            elsif ($check_name =~ /^DiaRequest:(.*)$/)
            {
		if ($p->{diameter_request})
		{
		    my $decoded = '';
		    foreach (@{$p->{diameter_request}->{Attributes}})
		    {
			my ($attrnum, $vendornum, $flags, $rvalue) = @$_;
			$decoded = $p->{diameter_request}->decode($attrnum, $vendornum, $flags, $rvalue);
			my ($dname, $dtype) = $p->{diameter_request}->{Dictionary}->attrByNum($attrnum, $vendornum);
			$attr = $decoded,last if ($dname eq  $1);
		    }
		}
            }
	    else
	    {
		$attr = $p->get_attr($check_name);
	    }
	    no warnings "uninitialized";
	    return ($main::REJECT,
		    "Check item $check_name expression '$value' does not match '$attr' in request")
		unless match($self, $attr, $check_name, $value);
	}
    }

    # We have to defer this until the end of the loop, because
    # user might specify both Block-Logon check items
    if (defined $block_logon_from || defined $block_logon_until)
    {
	my @time = localtime(time);
	my $current_tod = ((($time[2] * 60) + $time[1]) * 60) + $time[0];

#	print "doing it $block_logon_from $block_logon_until, $current_tod\n";
	if (defined $block_logon_from)
	{
	    if (defined $block_logon_until)
	    {
		return ($main::REJECT, 'Not within allowed Block times')
		    if    ($block_logon_until >= $block_logon_from 
			   && $current_tod > $block_logon_from
			   && $current_tod < $block_logon_until)
			|| ($block_logon_until < $block_logon_from 
			    && ($current_tod > $block_logon_from
				|| $current_tod < $block_logon_until));
	    }
	    else
	    {
		return ($main::REJECT, 'Not within allowed Block times')
		    if $current_tod > $block_logon_from;
	    }
	}
	elsif (defined $block_logon_until)
	{
	    return ($main::REJECT, 'Not within allowed Block times')
		if $current_tod < $block_logon_until;
	}
	
    }
	

    # Check the DefaultSimultaneousUse if we did not get a per-user
    # one. Warning, dont do it if we were called by a Handler
    if (!$p->{did_sim_use} 
	&& $self 
	&& defined $self->{DefaultSimultaneousUse}
	&& Radius::SessGeneric::find($p->{Handler}->{SessionDatabase})->exceeded
	($self->{DefaultSimultaneousUse}, 
	 $p->{Handler}->{SessionDatabaseUseRewrittenName} 
	 ? $username : $p->{OriginalUserName}, 
	 $p))
    {
	return ($main::REJECT,
		"DefaultSimultaneousUse of $self->{DefaultSimultaneousUse} exceeded");
    }

    return ($main::ACCEPT, ''); 
}

#####################################################################
# Overridable function for getting the value for a limit check
# Return undef if you dont understand it
# else return the value
sub getLimitValue
{
    #my ($self, $username, $check_name, $p) = @_;
    return;
}


#####################################################################
# return list of group(s) the user is in
# Generic module has no idea how to do groups, so returns empty
# Should be overridden if the module has a specific understanding 
# of what a Group is
sub getUserGroups
{
    my ($self, $user, $p) = @_;
    $self->log($main::LOG_WARNING, 
	       "This AuthBy does not know how to get user Groups", $p);
    return; # No groups
}

#####################################################################
# Check if the user is in the group
# Generic module gets the users group list from getUserGroups
# Can be overridden if the module has a specific understanding 
# of what a Group is
sub userIsInGroup
{
    my ($self, $user, $group, $p) = @_;

    return 1 if grep { $_ eq $group } $self->getUserGroups($user, $p);
    return; # Not in any group
}

#####################################################################
# Find the AuthBy module with the identifier name given
# It was automatically registered by Configurable
# during object construction
sub find
{
    return &Radius::Configurable::find('AuthBy', $_[0]);
}

#####################################################################
# Forks this handler and arranges for the child to die
# after handling is completed.
# Return 0 if in parent or a problem prevented forking
# else return 1 which means you are in the child.
# $reap_fn is an optional ref to a subroutine that will be called when the
# child is reaped.
sub handlerFork
{
    my ($self, $reap_fn) = @_;

    # Only fork once: more than that is a waste of time.
    return 1 if $main::handler_forked;

    my $forked = &main::safeFork($reap_fn);

    # Tell main we are in a forked child
    # they will exit after the handler has terminated
    $main::handler_forked++
	if $forked;

    # A SIGCHLD handler has been established by main:: to 
    # reap all children of this process
    return $forked;
}

#####################################################################
# Process and append all the reply attributes for the user 
# to the reply. Exceptions:
# Fall-Through attribute causes us to keep looking after
# this user, so return 1
sub appendUserReplyItems
{
    my ($self, $p, $user) = @_;

    my $fall_through;
    my $i = 0;
    my ($name, $value);
    while (($name, $value) = 
	   $user->get_reply->get_attr_val_n($i++))
    {
	next if $name eq 'Framed-IP-Address';
	
	if ($name eq 'Fall-Through')
	{
	    $fall_through++;
	} 
	elsif ($name eq 'Exec-Program')
	{
	    my $cmd = &Radius::Util::format_special($value, $p);
	    system($cmd);
	    $self->log($main::LOG_DEBUG, "Ran Exec-Program '$cmd'. Result $?");
	}
	else
	{
	    $self->addReplyItem($name, $value, $p);
	}
    }
    return $fall_through;
}

#####################################################################
# Check for an exact alternation or regexp match. 
# 
sub match
{
    my ($self, $attr, $check_name, $value) = @_;

    no warnings "uninitialized";
    # See if it looks like a regexp or not
    if ($value =~ /^\/(.*)\/([ix]?)/)
    {
	my ($expr, $flags) = ($1, $2);
	my $match = eval {$attr =~ /(?$flags)$expr/};
	$self->log($main::LOG_ERR, "Error while doing regexp match for $check_name: $@")
	    if $@;
	return 1 if $match;
    }
    else
    {
	# Permit alternate possible values separated by '|'
	map {return 1 if $attr eq $_} split(/\|/, $value);
	# But that doesnt work for empty string matches
	return 1 if $value eq '' && $attr eq $value;
    }
    return;
}

#####################################################################
# Generic password caching follows
#####################################################################
# Record the fact that an access request was accepted, so we can
# maybe refer to it later if we lose contact with the remote server
# $p is the original request
# Only PAP passwords can be cached
sub cacheReply
{
    my ($self, $p) = @_;

    my $user_name = $p->getUserName();
    my $password = $p->decodedPassword();
    $self->{passwordCache}{$user_name} = [time, $password, $p->{rp}]
	if defined $password;
}

#####################################################################
sub clearCachedReply
{
    my ($self, $p) = @_;

    my $user_name = $p->getUserName();
    delete $self->{passwordCache}{$user_name};
}

#####################################################################
# Look for a previously cached password and reply for this user
sub cachedReply
{
    my ($self, $p) = @_;

    my $user_name = $p->getUserName();
    my $submitted_password = $p->decodedPassword();
    if (exists $self->{passwordCache}{$user_name})
    {
	# Get the cached password, and the time it was accepted
	my ($time, $password, $rp) = 
	    @{$self->{passwordCache}{$user_name}};
	if ($time > time - $self->{CachePasswordExpiry}
	    && $submitted_password eq $password)
	{
	    $self->runHook('CacheReplyHook', $p, $self, $user_name, $p, $rp);
	    return $rp;
	}
    }
    return undef; # No suitable cached reply available
}

#####################################################################
# Check whether the login hours vector permits login at the current
# time. 
# LoginHours is an array of bits, one per hour starting at 
# 0000 Sun UTC, 24 bits per day, 7 days. Caution, it
# might not actually be present (ie length == 0)
# This is compatible with the LoginHours bitmap you might get
# from microsoft Active Directory
# Return true of login is permitted, or if the bitmap is 0 length
# BUG ALERT: on some versions of perl on Win2000,
# the wday element ($utc[6]) is out by 1
sub checkLoginHours
{
    my ($self, $allowedhours) = @_;

    my @utc = gmtime(time);
    my $offset = ($utc[6] * 24) + $utc[2];
    return length($allowedhours) == 0
	|| vec($allowedhours, $offset, 1);
}

#####################################################################
# taken from AuthFILE
# Returns true if the file has been modified since the last time
# we looked, or if its not there
sub fileHasChanged
{
    my ($self, $file) = @_;

    no warnings qw(uninitialized);
    my $new_time = (stat($file))[9];
    my $ret = (!$new_time || $new_time != $self->{LastModTime}{$file});
    $self->{LastModTime}{$file} = $new_time;
    return $ret;
}

# Support for EAP-Token with most static password types
#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_start
{
    my ($self, $context, $user, $p) = @_;

    # This works with Odyssey Client. Nothing else works with 
    # EAP-GTC inside EAP-FAST
    return (2, "CHALLENGE=Enter your static password");
}

#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_continue
{
    my ($self, $context, $username, $password, $p) = @_;

    # Help some AuthBys that do direct password checking
    $p->{DecodedPassword} = $password;

    my ($user, $result, $reason) = $self->get_user($username, $p);
    if (!$user || $result != $main::ACCEPT)
    {
	return (0, "no such user $username");
    }
    
    # Got a user record for this user. Need the plaintext password now
    my $correct_password = $self->get_plaintext_password($user);
    return (1) unless defined $correct_password; # AuthBys that do direct password checking
    if ($self->check_plain_password($username, $password, $correct_password, $p))
    {
	$self->authoriseUser($user, $p);
	return (1);
    }

    return (0, 'Bad password');
}

#####################################################################
# This is also called by the EAP_6 GTC code
sub gtc_end
{
    my ($self, $context, $user, $p) = @_;
}

#####################################################################
# Function that converts a MS user name into a domain and bare user name
# based on the input user name and any config variables
sub crack_name
{
    my ($self, $name, $p) = @_;

    my $domain = &Radius::Util::format_special($self->{DefaultDomain}, $p);

    ($domain, $name) = ($1, $2)
	if ($name =~ /^([^\\]*)\\(.*)/);
    # Override the domain
    $domain = &Radius::Util::format_special($self->{Domain}, $p) if defined $self->{Domain};
    #print "Cracked username to $domain, $name\n";
    return ($domain, $name);
}

#####################################################################
# This is also called by the EAP_5 OTP code
# Fallback for modules that do not support EAP-OTP
sub otp_verify
{
#    my ($self, $user, $submitted_pw, $p, $context) = @_;
    return;
}

#####################################################################
# Create a new EAP-FAST PAC and return its OPAQUE
# The structure will autodelete after the lifetime expires.
# lifetime is the lifetime of the PAC in seconds
# This may be overridden by subclasses
# This default implementation creates and caches PACs in memory
sub create_eapfast_pac
{
    my ($self, $p) = @_;

    my $pac_opaque = &Radius::Util::random_string(32);
    my $ret = Radius::Context->new('EAP-FAST PAC:' . $pac_opaque, $self->{EAPFAST_PAC_Lifetime});
    # Maybe the key should be reversibly encrypted?
    $ret->{pac_key} = &Radius::Util::random_string(32);
    $ret->{pac_lifetime} = time() + $self->{EAPFAST_PAC_Lifetime};
    $ret->{pac_opaque} = $pac_opaque;
    return $ret;
}


#####################################################################
# Find a previously created EAP-FAST PAC given its OPAQUE.
# The returned hash contains the pac_lifetime and the pac_key, if available
# This may be overridden by subclasses
sub get_eapfast_pac
{
    my ($self, $pac_opaque, $p) = @_;

    return Radius::Context::find('EAP-FAST PAC:' . $pac_opaque);
}

sub redespatch
{
    my ($self, $p, $username, $realmName) = @_;

    my ($handler, $handled, $finder);
    foreach $finder (@Radius::Client::handlerFindFn)
    {
	if ($handler = &$finder($p, $username, $realmName))
	{
	    # Make sure the handler is updated with stats
	    push(@{$p->{StatsTrail}}, \%{$handler->{Statistics}});
	    
	    $handled = $handler->handle_request($p);
	    return $handled;
	}
    }
    $self->log($main::LOG_DEBUG, "Could not find Handler for redespatched request $self->{Identifier}", $p);
    return;
}

1;

