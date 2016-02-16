# Documentation.pm
#
# Module to encapsulate documentation of available Radidator 
# modules for use by ServerHTTP
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997-2001 Open System Consultants
# $Id: Documentation.pm,v 1.8 2013/09/06 12:58:30 hvn Exp $

package Radius::Documentation;

# RCS version number of this module
$Radius::Documentation::VERSION = '$Revision: 1.8 $';

# Key is object ref type
# Value is documentaiton about the use of that type of object
%Radius::Documentation::objects =
(
 'AddressAllocatorDHCP' => 'Works in conjunction with &lt;AuthBy DYNADDRESS&gt; and a DHCP server to dynamically allocate IP addresses.',

 'AddressAllocatorGeneric' => '',
 'AddressAllocatorSQL' => 'Works in conjunction with &lt;AuthBy DYNADDRESS&gt; to allocate IP addresses from an SQL database. The default behaviour is to allocate the oldest unused address from the RADPOOL table. During deallocation, the address is marked is unused. Addresses that remain in use for more than DefaultLeasePeriod seconds are automatically reclaimed (this protects against lost Accounting Stop requests).',

 'AES' => '',
 'ApplePasswordServer' => '',
 'AttrList' => '',
 'AttrVal' => '',
 'AuthACE' => 'Performs authentication directly to an RSA Security Authentication manager (formerly SecurID ACE/Server). See www.rsasecurity.com for details. RSA Security Authentication Manager provides a token-based one-time password system. AuthBy ACE requires the Authen-ACE4 Perl module from CPAN (pre-built binaries for Windows are available from OSC). Obsoleted by AuthBy RSAAM',

 'AuthADSI' => 'Authenticates from Windows Active Directory, which is the user information database on Windows 2000. It uses ADSI (Active Directory Service Interface) to get user information from any Active Directory service provider available to your Windows 2000 system. It is only available on Windows 2000 platforms.',

 'AuthCDB' => 'Authenticates users from a user database stored in a CDB database file. CDB is a fast, reliable, lightweight package for creating and reading constant databases. More details about CDB can be found at http://cr.yp.to/cdb.html. It is implemented in AuthCDB.pm, which was contributed by Pedro Melo (melo@ip.pt). It does not log (but does reply to) accounting requests. To use AuthBy CDB, you must install the CDB_File package from CPAN ',

# 'AuthCRYPTOCARD' => '',
 'AuthDBFILE' => 'Authenticates users from a user database stored in a DBM file in the standard Merit DBM format. It does not log (but does reply to) accounting requests. DBM files can be built from flat file user databases with the builddbm utility (see Section 8.0 on page 244).',

# 'AuthDIGIPASS' => 'use SQLDigipass',
 'AuthDIGIPASSGeneric' => '',
 'AuthDNSROAM' => 'Proxies Radius requests to remote Radius and/or RadSec servers based on the Realm in the User-Name. The appropriate server to send to and the protocol to use is discovered through DNS lookups configured through the Resolver clause. You must include a &lt;Resolver&gt; clause in your configuration if you intend to use &lt;AuthBy DNSROAM&gt;.',

 'AuthDYNADDRESS' => 'Used to dynamically allocate IP addresses in conjunction with &lt;AddressAllocator xxx&gt; clauses. There are two Address Allocation engines provided. &lt;AddressAllocator SQL&gt; can allocate addresses out of an SQL database. &lt;AddressAllocator DHCP&gt; can allocate addresses from a DHCP server.',

# 'AuthEAP' => '',
 'AuthEMERALD' => 'Provides authentication and accounting using the popular Emerald ISP billing package (version 3 and earlier) from IEA (http://www.emerald.iea.com). Users of Emerald 4 should use &lt;AuthBy EMERALD4&gt;',

 'AuthEMERALD4' => 'Provides authentication and accounting using the popular Emerald ISP billing package (version 4 and later) from IEA (http://www.emerald.iea.com)',

 'AuthEXTERNAL' => 'Authenticates by passing all requests to an external program, which is responsible for determining how to handle the request.',

 'AuthFIDELIO' => 'Authenticates users from Micros-Fidelio Opera. Opera is a popular hotel Property Management System from Micros Fidelio (http://www.micros.com).',

 'AuthFILE' => 'Authenticates users by checking them against a flat file user database.',

 'AuthFREERADIUSSQL' => 'Handles authentication and accounting from a FreeRadius compatible SQL database. The default SQL queries use the standard FreeRadius tables radcheck, radreply, radgroupcheck, radgroupreply and radacct. ',

 'AuthGeneric' => '',

 'AuthGROUP' => 'Allows you to conveniently define and group multiple AuthBy clauses. This is most useful where you need to be able to have multiple sets of authentication clauses, perhaps with different AuthByPolicy settings for each group. You can use an AuthBy GROUP (containing any number of AuthBy clauses) anywhere that a single AuthBy clause is permitted. AuthBy GROUP can be nested to any depth.',

 'AuthHASHBALANCE' => 'Distributes RADIUS requests among a set of RADIUS servers in such a way such that multiple related requests from the same user (such as EAP handshakes etc) will go to the same server (unless that server fails). This prevents EAP handshakes being distributed  among multiple servers, which would otherwise cause the EAP handshake to be rejected or ignored.',

 'AuthHTGROUP' => 'Checks group membership according to an Apache htgroup file. Apache is a popular HTTP server, and supports flat group files for authenticating web access. With &lt;AuthBy HTGROUP&gt; Radiator can authenticate users against the same files that Apache uses, in order to provide a single source of authentication information for both Apache and Radiator.',

 'AuthIMAP' => 'Authenticates from an IMAP server. Requires the Mail::IMAPClient perl module version 2.2.5 or better, available from CPAN. AuthBy IMAP can support SSL or non-SSL connections to the IMAP server. Use of SSL connections requires IO::Socket::SSL from CPAN and OpenSSL. AuthBy IMAP only supports PAP authentication in incoming Radius requests. CHAP and MS-CHAP are not supported, since the plaintext password is not available within Radiator.',

 'AuthINTERNAL' => 'Allows you permanently predefine how to reply to a request, depending only on the type of request. You can specify whether to ACCEPT, REJECT, IGNORE or CHALLENGE each type of request. The default behaviour is to IGNORE all requests. You can override the behaviour of each fixed result with an optional Perl hook, in which case the hook will return the result code.',

 'AuthIPASS' => 'Deprecated. Do not use. The preferred method of interoperating with iPASS is to proxy outbound requests from Radiator to the iPASS radius server, using &lt;AuthBy RADIUS&gt;. ',

# 'AuthJRADIUS' => 'incomplete',

 'AuthKRB5' => 'Authenticates using the Kerberos 5 authentication system, which is available on most types of operating system. It authenticates afrom a previously defined Kerberos KDC (Key Distribution Centre). AuthBy KRB5 can authenticate PAP and TTLS-PAP. Accounting are ACCEPTed but discarded. Requires the Authen::Krb5 module version 1.3 or later from CPAN.',

 'AuthLDAP' => 'Deprecated. AuthBy LDAP2 should be used for preference, as this authenticator uses an old LDAP interface. Authenticates by connecting to an LDAP server. Requires Clayton Donley\'s Net::LDAPapi module version 1.42 or better (Available from CPAN). ',

 'AuthLDAP2' => 'Authenticates by connecting to an LDAP server. Users can be authenticated by fetching the plaintext password from the LDAP server, or by using the server to authenticate a plaintext password.',

 'AuthLDAP_APS' => 'Finds user details in a Mac OS-X Directory Server LDAP database, and then authenticates the user password against a Mac OS-X Apple Password Server.Requires Crypt::OpenSSL::Random Crypt::OpenSSL::RSA Crypt::OpenSSL::Bignum MIME::Base64 Digest::HMAC_MD5',

 'AuthLDAP_MSISDN' => 'Deprecated. Authenticates using an LDAP database and records accounting in an MSISDN database. Requires Net::LDAPapi',

 'AuthLDAPDIGIPASS' => 'Provides authentication of Vasco Digipass tokens (http://www.vasco.com) from an LDAP database.',

 'AuthLDAPRADIUS' => 'Proxies requests to a target Radius server. The target host is determined by a lookup in an LDAP database. This allows the easy management of large numbers of downstream radius servers, such as in a wholesale ISP.',

 'AuthLDAPSDK' => 'Deprecated. AuthBy LDAP2 should be used for preference, as this authenticator uses an old LDAP interface. Authenticates by connecting to an LDAP server. Requires Netscape\'s PerLDAP module and the Netscape Directory SDK',

 'AuthLOADBALANCE' => 'Load Balancing proxy module. Incoming Radius requests are distributed between all the listsed hosts acccording to the relative values of their BogoMips attributes and the time the remote server takes to process requests. ',

 'AuthLogFILE' => 'Logs authentication successes and failures to a flat file.',

 'AuthLogGeneric' => '',

 'AuthLogSQL' => 'Logs authentication successes and failures to an SQL database.',

 'AuthLogSYSLOG' => 'Logs authentication successes and failures to a SYSLOG server',

 'AuthLSA' => 'Provides authentication against user passwords in any Windows Active Directory or NT Domain Controller, by using the Windows LSA (Local Security Authority). Since it accesses LSA directly, it can authenticate dialup or wireless passwords with PAP, CHAP, MSCHAP, MSCHAPV2, LEAP and PEAP. AuthBy LSA is only available on Windows 2000, 2003 and XP. (Windows XP Home edition is not supported). It requires the Win32-Lsa perl module from Open System Consultants. ',

 'AuthMOBILEIP' => 'Handles authentication replies for 3GPP2 Mobile IP. Place this AuthBy after the user authentication AuthBy.',

 'AuthMULTICAST' => 'Sends copies of some or all Radius requests to a number of remote Radius servers.',

 'AuthNISPLUS' => 'Provides authentication from a NIS+ database. It looks for user information in an NIS+ table, and uses that information as check and reply items for the user. It does not log (but does reply to) accounting requests. You will need to have a basic understanding of NIS+ databases in order to configure AuthBy NISPLUS. AuthBy NISPLUS requires the NISPlus Perl module from CPAN.',

 'AuthNT' => 'Authenticates users with the NT User Manager or Primary Domain Controller. It is implemented in AuthNT.pm. It does not log (but does reply to) accounting requests. AuthBy NT can not work with CHAP or MSCHAP authentication. Available on both Windows and Unix',

 'AuthNTLM' => 'Authenticates against a Windows Domain Controller, using the ntlm_auth program, which is part of the Samba suite (www.samba.org). ntlm_auth runs on all Unix and Linux platforms, and therefore &lt;AuthBy NTLM&gt; can be used on Unix or Linux to authenticate to a Windows Domain Controller. ',

 'AuthOPIE' => 'Authenticates from OPIE (onetime passwords in everything), a one-time password system based on S/Key, and written by  Craig Metz, see http://www.inner.net/opie, version opie-2.4 or better. It also requires the Perl OPIE module OPIE-0.75 or better from ftp://pooh.urbanrage.com/pub/perl. OPIE is only supported in Unix platforms. It can be used with PAP, but not CHAP or MS-CHAP. It can also be used with EAP-One-Time-Passwords and EAP-Generic-Token-Card authentication in 802.1X wired and wireless networks.',

 'AuthOTP' => 'Provides extensible and customisable to support a range of One-Time-Password (OTP) schemes, including automatic password generation and sending of passwords through a back-channel such as SMS. AuthBy OPT is suitable for authenticating 802.1X Wired and Wirelss access with custom one-time-password and token card authentication systems. ',

 'AuthPAM' => 'Provides authentication via any method supported by PAM (Pluggable Authentication Modules) on your host. Requires that PAM be installed and configured on your host, and it also requires the Perl module Authen-PAM-0.04 or later (available from CPAN). ',

 'AuthPLATYPUS' => 'Provides authentication and accounting using the popular Platypus ISP billing package from Boardtown (http://www.boardtown.com). ',

 'AuthPOP3' => 'Authenticates from a POP3 server, according to RFC1939. It requires the Mail::POP3Client perl module version 2.9 or better, available from CPAN. Supports both plaintext and APOP authentication in the POP server.',

 'AuthPORTLIMITCHECK' => 'Applies usage limits for arbitrary groups of users. Requires that you have a &lt;SessionDatabase SQL&gt; defined in your Radiator configuration. ',

 'AuthPRESENCESQL' => 'Authenticates users from an SQL database and records presence (current user location) to an SQL database. Implements a special form of RADIUS Access-Request that allows user presence data to be retrieved by suitably authorised devices. Can be used with telephone and VOIP systems to automatically route telephone calls according to the users current location.',

 'AuthRADIUS' => 'Acts as a proxy RADIUS server. Forwards all authentication and accounting requests for to another (possibly remote) Radius server. If and when the remote radius server replies, the reply will be forwarded back to the client that originally sent the request.',

# 'AuthRADKEY' => 'Obsolete. Do not use.',

 'AuthRADMIN' => 'Provides authentication and accounting using the RAdmin User Administration package from Open System Consultants (http://www.open.com.au/radmin). RAdmin is a complete web-based package that allows you to maintain your Radius user and accounting details in an SQL database. You can add, change and delete users, examine connection history, control simultaneous login, get reports on modem usage and many other functions. The combination of Radiator and RAdmin provides a complete solution to your Radius user administration requirements.',


 'AuthRADSEC' => 'Proxies RADIUS requests to a &lt;ServerRADSEC&gt; clause on remote Radiator using the RadSec secure reliable RADIUS proxying protocol. It can be used instead of AuthBy RADIUS when proxing across insecure or unreliable networks such as the internet. See the reference manual for more details about the RadSec protocol.',

 'AuthRODOPI' => 'Obsolete. Recent versions of Rodopi require the AuthBy RODOPIAAA package from Rodopi. Provides authentication and accounting using the popular Rodopi ISP billing package (http://www.rodopi.com). The combination of Radiator and Rodopi provides a very powerful and easy to use ISP billing and user management system.',

 'AuthRODOPIAAA' => 'Provides authentication and accounting using the popular Rodopi ISP billing package (http://www.rodopi.com). The combination of Radiator and Rodopi provides a very powerful and easy to use ISP billing and user management system.',

 'AuthROUNDROBIN' => 'Load Balancing module. The first incoming Radius request is proxied to the first server listed, the next to the second listed etc., until the list is exhausted, then it starts again at the top of the list. If at any time a proxied request does not receive a reply from a remote server, that server is marked as unavailable until FailureBackoffTime seconds has elapsed. Meanwhile that request is retransmitted to the next host due to be used.',

 'AuthRSAAM' => 'Authenticates from an RSA Authenitcation Manager 7.1 or later server. RSA AM is a token authentication system from RSA Security. Supports SecureID token cards, static passwords and OnDemand tokencodes deliverd by SMS or email. It requires SOAP::Lite and all its prerequisites for SSL, including Crypt::SSLeay or IO::Socket::SSL+Net::SSLeay from CPAN. AuthBy RSAAM supports all the features provided by AuthBy ACE and AuthBy RSAMOBILE, and therefore obsoletes those modules',

 'AuthRSAMOBILE' => 'Authenticates from an RSA Mobile server. RSA Mobile is a token authentication system from RSA Security. During authentication, the user provides a password, then the RSA Mobile server sends a one-time-password by SMS, pager etc. When the correct one-time-password is entered, then the authentication succeeds. It requires SOAP::Lite and all its prerequisites from CPAN. Obsoleted by AuthBy RSAAM',

 'AuthSAFEWORD' => 'Authenticates users from a local or remote SafeWord PremierAccess (SPA) server. SafeWord PremierAccess and tokens are available from SecureComputing (http://www.securecomputing.com). Supports PAP, CHAP, TTLS-PAP, EAP-OTP and EAP-GTC. Supports password changing.  Supports fixed (static) passwords and SafeWord Silver and Gold tokens.',

 'AuthSASLAUTHD' => 'Authenticates against a saslauthd server running on the same host as Radiator. Saslauthd is a Unix authentication server program, part of the Cyrus SASL suite. It can be configured to authenticate from a variety of sources, including PAM, Kerberos, DCE, shadow password files, IMAP, LDAP, SIA or a special SASL user password file. It is part of the Cyrus SASL suite.',

# 'AuthSBAUTH' => '',
# 'AuthSMARTCARD' => '',

 'AuthSOAP' => 'Handles authentication and accounting by sending it to a remote Radius server over TCP using the SOAP protocol. Each Radius request is transformed into a SOAP request, which  is sent by HTTP or HTTPS to a remote SOAP server. The Remote SOAP server can be any implementation, but example SOAP server code is provided with Radiator. AuthBy SOAP can be useful in order to tunnel Radius requests througth ports 80 or 443 in a firewall, where UDP port 1645 is not permitted throught the firewall. It can also be used to improve reliabilty in some environments by using TCP rather than UDP. ',

 'AuthSQL' => 'Authenticates users from an SQL database, and stores accounting records to an SQL database. AuthBy SQL is very powerful and configurable, and has many parameters in order to customize its behaviour, so please bear with us. You will need to have some familiarity with SQL and relational databases in order to configure and use AuthBy SQL.',

 'AuthSQLDIGIPASS' => 'Provides authentication of Vasco Digipass tokens (http://www.vasco.com) from an SQL database.',

 'AuthSQLHOTP' => 'Provides authentication of HOTP (RFC 4226) one-time-passwords with the HOTP secret stored in an SQL database. Conforms to the HOTP requirements of OATH (http://www.openauthentication.org)',

 'AuthSQLRADIUS' => 'Proxies requests to a target Radius server. The target host is determined by a table lookup in an SQL database. This allows the easy management of large numbers of downstream radius servers, such as in a wholesale ISP. It inherits from both AuthBy SQL and AuthBy RADIUS.',

 'AuthSQLYUBIKEY' => 'Authenticates Yubikey tokens from Yubico (yubico.com) against token details from an SQL database. Requires Auth:Yubikey_Decrypter and Crypt::Rijndael',

 'AuthSYSTEM' => 'Provides authentication with your getpwnam and getgrnam system calls. On most Unix hosts, that will mean authentication from the same user database that normal user logins occur from, whether that be /etc/passwd, NIS, YP, NIS+ etc. It is implemented in AuthSYSTEM.pm. This allows you to hide whether its password files, NIS+, PAM or whatever else might be installed on your system. It is not supported on Win95 or NT, or on systems (such as Solaris) with shadow password files (unless Radiator runs with root permissions).',

 'AuthTACACSPLUS' => 'provides authentication via a TacacsPlus server. It supports authentication only, not accounting or authorization.',

 'AuthTEST' => 'Always accepts authentication requests, and ignores (but replies to) accounting requests. Useful for testing purposes, but you should be sure not to leave them lying around in your configuration file, otherwise you might find that users are able to be authenticated when you really didn\'t want them to. ',

# 'AuthTIERSQL' => '',

 'AuthUNIX' => 'Authenticates users from a user database stored in a standard Unix password file or similar format.',

 'AuthURL' => 'Authenticates using HTTP from any URL. It can use any given CGI or ASP, that validates username and password. It requires the Digest::MD5 and HTTP::Request and LWP::UserAgent perl modules in libwww-perl-5.63 or later package available from CPAN. Supports both GET and POST Method for http querystrings.',

 'AuthVOLUMEBALANCE' => 'Load Balancing module. Incoming Radius requests are distributed between all the listed hosts acccording to the relative values of their BogoMips attributes.',

 'AuthWIMAX' => 'Authenticates WiMAX requests from an SQL database, generates WiMAX mobility keys and maintains a DeviceSession table in SQL. Requires Digest::SHA',

 'BigInt' => '',

 'Client' => 'A Client defines one or more RADIUS clients that this server is willing to accept requests from. You must specify at least the client name/address and a shared Secret. The Secret must match the one configured into the client device.',

 'ClientListLDAP' => 'Allows you to specify your Radius clients in an LDAP database in addition to (or instead of) your Radiator configuration file.',

 'ClientListSQL' => 'Allows you to specify your Radius clients in an SQL database table in addition to (or instead of) your Radiator configuration file.',

 'Configurable' => '',
 'Context' => '',
 'DES' => '',
 'DHCP' => '',
 'DiaAttrList' => '',
 'DiaClient' => '',
 'DiaDict' => '',
 'Diameter' => '',
 'DiaMsg' => '',
 'DiaPeer' => '',
 'Dictionary' => '',
 'Documentation' => '',
 'EAP' => '',
 'EAP_13' => '',
 'EAP_15' => '',
 'EAP_17' => '',
 'EAP_21' => '',
 'EAP_25' => '',
 'EAP_26' => '',
 'EAP_38' => '',
 'EAP_4' => '',
 'EAP_43' => '',
 'EAP_46' => '',
 'EAP_47' => '',
 'EAP_5' => '',
 'EAP_6' => '',
 'Fidelio' => '',
 'Finger' => '',

 'Handler' => 'A Handler handles all requests that match a specific test against one or more attributes. The Name contains the test to make, such as NAS-IP-Addres=1.2.3.4. Special characters are supported. You can define one or moreAuthBy clauses that will be used to authenticate all requests sent to this Handler, and the AuthBys will be checked in order until the AuthByPolicy is met.',

 'Host' => 'A remote RADIUS host to which RADIUS requests will be proxied',

 'IEEEfp' => '',
 'Ldap' => '',
 'Log' => '',

 'LogEMERALD' => 'Saves log messages to an Emerald SQL database',

 'LogFILE' => 'Saves log messages to a flat file',

 'LogGeneric' => '',
 'Logger' => '',
 'LogSQL' => 'Saves log messages to an SQL database',

 'LogSYSLOG' => 'Send log messages to a SYSLOG server',

 'Mib' => '',

 'Monitor' => 'Enables external client programs to make an (authenticated) TCP connection to Radiator, and use that connection to monitor, probe, modify and collect statistics from Radiator. One such external client program is Radar, a real-time interactive GUI that permits monitoring, plotting of statistics and much more. See http://www.open.com.au/radar for more details.
<p><b>Caution:</b>Careless configuration of Monitor can open security holes in your RADIUS server host. Use with care. ',

 'MSCHAP' => '',
 'Nas' => '',
 'PBKDF' => '',
 'Predicate' => '',
 'Radius' => '',
 'RadpwtstGui' => '',
 'RadSec' => '',
 'RadsecHost' => 'A remote RadSec host to which RadSec requests will be proxied',
 'Rcrypt' => '',
 'RDict' => '',

 'Realm' => 'A Realm handles all requests that have a specific realm in the User-Name (the realm is the part following any @ sign in the User-Name). You can define one or moreAuthBy clauses that will be used to authenticate all requests for that Realm, and the AuthBys will be checked in order until the AuthByPolicy is met.',

 'Resolver' => 'Provides DNS and name resolution services for the AuthBy DNSROAM clause. It is only required and should only be used if you have an AuthBy DNSROAM clause in your configuration.',

 'AuthDNSROAM::Route' => 'A hardwired route for AuthBy DNSROAM. All requests that match the Realm will be forwarded using RadSec or RADIUS Protocol.',

 'Select' => '',

 'ServerConfig' => 'ServerConfig defines the behaviour of the Radiator RADIUS server as a whole, and is the starting point for configuring Radiator. For the simplest RADIUS server configuration, you should define at least one Client and at least one Realm. Inside the Realm, you should define at least one AuthBy to do the authentication',

 'ServerDIAMETER' => 'Tells Radiator to act as a Diameter to RADIUS gateway. All Diameter requests received through the gateway will be converted into equivalent RADIUS requests and despatched to a matching Realm or Handler for authentication',

# 'ServerFarm' => '',

 'ServerHTTP' => 'Provides an (authenticated) web interface, allowing Radiator to be monitored, inspected and reconfigured from a standard web browser.<p><b>Caution:</b>Careless configuration of ServerHTTP can open security holes in your RADIUS server host. Use with care.',

# Dont want this to appear in selection lists yet: just for internal use
# 'ServerRADIUS' => 'Provides services for listening for RADIUS requests',

 'ServerRADSEC' => 'Accepts RadSec connections from AuthBy RADSEC clauses in other Radiators and processes RADIUS requests sent over the RadSec connection in a similar way to how a Client clause received conventional UDP RADIUS requests. RadSec can be used to provide secure reliable proxying of RADIUS requests from one Radiator to another, even over insecure networks. See http://www.open.com.au/radiator/radsec-whitepaper.pdf for more information about RadSec. Incoming RADIUS requests received over this ServerRADSEC will be despatched to a matching Realm or Handler for authentication',

 'ServerTACACSPLUS' => 'Tells Radiator to act as a Tacacs+ server. Tacacs+ is an older Authentication, Authorization and Accounting (AAA) protocol developed by Cisco, and supported by some Cisco devices. It uses TCP connections between the client (usually some kind of router) and the Tacacs+ server. Incoming TACACS+ requests will be converted into equivalent RADIUS requests and despatched to a matching Realm or Handler for authentication',

 'SessDBM' => 'Specifies an external DBM file Session Database. The Session Database is used to hold information about current sessions as part of Simultaneous-Use limit checking. It can also be used by external utilities for querying the on-line user population If you don\'t specify a SessionDatabase clause, the database will be kept internal to radiusd, which is faster, but does not make the data available to other processes.',

 'SessGeneric' => '',

 'SessINTERNAL' => 'The default Session Database. Per-user session information is kept internally within the Radiator process.',

 'SessNULL' => 'This type of session database stores no session details, and always permits multiple logins. It is useful in environments with large user populations, and where no simultaneous-use prevention is required. &lt;SessionDatabase NULL&gt; uses much less memory and fewer CPU cycles than &lt;SessionDatabase INTERNAL&gt; (which is the default session database).',

 'SessSQL' => 'Specifies an external SQL Session Database for radiusd. The Session Database is used to hold information about current sessions as part of Simultaneous-Use limit checking. It can also be used by external utilities for querying the on-line user population. If you don\'t specify a SessionDatabase clause in your configuration file, the database will be kept internal to radiusd, which is faster, but can\'t be used to synchronize multiple instances of Radiator.',

 'SimpleClient' => '',
 'SimpleRadsecClient' => '',
 'SNMP' => '',
 'SNMPAgent' => 'Enables an SNMP Agent that will allow you to fetch statistics from Radiator using SNMP version 1. Radiator supports all the SNMP objects described in the draft IETF standard defined in draft-ietf-radius-servmib-04.txt, as well as in the RADIUS Authentication Server MIB defined in RFC 2619 and RADIUS Accounting Server MIB defined in RFC 2621. Only SNMP V1 is supported.',

 'SOAPRequest' => '',
 'SqlDb' => '',
 'StateMachine' => '',

 'StatsLogFILE' => 'Logs statistics to a flat file.',

 'StatsLogGeneric' => '',

 'StatsLogSQL' => 'Logs statistics to an SQL database. ',

 'Stream' => '',
 'StreamTLS' => '',
 'TacacsClient' => '',
 'Tacacsplus' => '',
 'TLS' => '',
 'TLSConfig' => '',
 'TNC' => '',
 'User' => '',
 'Util' => '',
 'VivaNetCustomerConfiguration' => '',
 'Win32Service' => '',

 );


$Radius::Documentation::license = << 'EOF';
READ THIS SOFTWARE LICENSE AGREEMENT CAREFULLY BEFORE DOWNLOADING,
INSTALLING OR USING OPEN SYSTEM CONSULTANTS PTY LTD SUPPLIED
SOFTWARE. THIS DOCUMENT CONSTITUTES A LICENSE TO USE THE SOFTWARE ON
THE TERMS AND CONDITIONS APPEARING BELOW.

BY DOWNLOADING, INSTALLING OR USING THE SOFTWARE YOU ARE CONSENTING TO
BE BOUND BY THIS LICENSE. IF YOU ARE NOT THE LICENSEE THEN YOU MUST
HAVE AGREEMENT IN WRITING THAT THE LICENSEE WILL ABIDE BY THE TERMS OF
THIS AGREEMENT. IF YOU DO NOT AGREE TO ALL OF THE TERMS OF THIS
LICENSE, THEN DO NOT DOWNLOAD, INSTALL OR USE THE SOFTWARE.

The following terms govern your use of the Software except to the
extent a particular program (a) is the subject of a separate written
agreement with Open System Consultants Pty. Ltd. or (b) includes a
separate "click-on" license agreement as part of the installation
and/or download process. To the extent of a conflict between the
provisions of the foregoing documents, the order of precedence shall
be (1) the written agreement, (2) the click-on agreement, and (3) this
Software License.

This License Agreement is entered into between Open System Consultants
Pty. Ltd, the Agent and/or the owner of all rights in respect of the
software (herein referred to as "Licensor") of the one part and you,
the Licensee on the other.

The computer program(s) and related documentation and materials
(herein collectively referred to as "the Software") are licensed, not
sold, to the Licensee for use only upon the terms of this license, and
Licensor reserves any rights not expressly granted to
Licensee. Licensor retains ownership of all copies of the Software.

GRANT. Licensor hereby grants Licensee a non-exclusive,
non-transferable license to use the Software upon payment of the
License Fee until the expiry date of the license (if any). If no
expiry date is applicable to the license, then the license to use the
Software is perpetual. Licensor makes no guarantee of the frequency,
value, applicability or content of future updates or modifications to
the Software. The Software will only be made available to the Licensee
in electronic form for download.

The requirement to pay a license fee does not apply to evaluation or
beta copies for which Licensor does not charge a license
fee. Evaluation and beta licenses expire 30 calendar days from the
date of this agreement, unless otherwise agreed to in writing by
Licensor. On the date of expiry of the license, Licensee agrees to
either purchase the Software at the list price in force at that time
or to destroy all copies of the Software in electronic or other form,
including any copies on backup tapes or other media.

Licensee's use of the Software shall be limited to use on a single
hardware chassis, on a single central processing unit, as applicable,
or use on such greater number of chassis or central processing units
as Licensee may have paid the required License Fee.

The Software may only be installed and operated on equipment that is
owned and operated by the Licensee.

Licensee's use of the Software shall also be limited, as applicable
and set forth in Licensee's purchase order or in Open System
Consultants Pty. Ltd. product catalog, user documentation, or web
site, to a maximum number of (a) seats (i.e. users with access to the
installed Software), (b) concurrent users, sessions, ports, and/or
issued and outstanding IP addresses, and/or (c) central processing
unit cycles or instructions per second. Licensee's use of the Software
shall also be limited by any other restrictions set forth in
Licensee's purchase order or in Open System Consultants
Pty. Ltd. product catalog, user documentation or web site for the
Software.

Licensee may not: permit other individuals to use the Software except
under the terms listed above; translate, reverse engineer, decompile,
decrypt, disassemble (except to the extent applicable laws
specifically prohibit such restriction), or create derivative works
based on the Software; copy the Software (except for back-up
purposes); rent, lease, transfer, assign, sub-license or otherwise
transfer rights to the Software; or remove any proprietary notices or
labels on the Software.

TITLE. Title, ownership rights, and intellectual property rights in
and to the Software and any derived works shall remain solely with
Licensor. Where Licensor acts as the Agent of the Copyright holder,
title shall remain solely with the Copyright holder. The Software is
protected by the copyright laws of Australia and international
copyright treaties.

ASSIGNMENT. Neither party shall have the right to assign or transfer 
any duties, rights or obligations due hereunder without the express 
written consent of the other party, except that the Licensor may 
assign the Agreement to its successor or any entity acquiring all or 
substantially all of the assets of the Company.

DISCLAIMER OF WARRANTY. The Software is provided on an "AS IS" basis,
without warranty of any kind, including without limitation the
warranties of merchantability, fitness for a particular purpose and
non-infringement. The entire risk as to the quality and performance of
the Software is borne by you. Should the Software prove defective, you
and not Licensor assume the entire cost of any service and
repair. This disclaimer of warranty constitutes an essential part of
the agreement.

SOME STATES DO NOT ALLOW EXCLUSIONS OF AN IMPLIED WARRANTY, SO THIS
DISCLAIMER MAY NOT APPLY TO YOU AND YOU MAY HAVE OTHER LEGAL RIGHTS
THAT VARY FROM STATE TO STATE OR BY JURISDICTION. LIMITATION OF
LIABILITY. UNDER NO CIRCUMSTANCES AND UNDER NO LEGAL THEORY, TORT,
CONTRACT, OR OTHERWISE, SHALL LICENSOR OR ITS SUPPLIERS OR RESELLERS
BE LIABLE TO YOU OR ANY OTHER PERSON FOR ANY INDIRECT, SPECIAL,
INCIDENTAL, OR CONSEQUENTIAL OR PUNITIVE DAMAGES OF ANY CHARACTER
INCLUDING, WITHOUT LIMITATION, DAMAGES FOR LOSS OF GOODWILL, WORK
STOPPAGE, COMPUTER FAILURE OR MALFUNCTION, OR ANY AND ALL OTHER
COMMERCIAL DAMAGES OR LOSSES. IN NO EVENT WILL LICENSOR BE LIABLE FOR
ANY DAMAGES IN EXCESS OF LICENSOR'S LIST PRICE FOR A LICENSE TO THE
SOFTWARE, EVEN IF LICENSOR SHALL HAVE BEEN INFORMED OF THE POSSIBILITY
OF SUCH DAMAGES, OR FOR ANY CLAIM BY ANY OTHER PARTY. THIS LIMITATION
OF LIABILITY SHALL NOT APPLY TO LIABILITY FOR DEATH OR PERSONAL INJURY
TO THE EXTENT APPLICABLE LAW PROHIBITS SUCH LIMITATION. FURTHERMORE,
SOME STATES DO NOT ALLOW THE EXCLUSION OR LIMITATION OF INCIDENTAL OR
CONSEQUENTIAL DAMAGES, SO THIS LIMITATION AND EXCLUSION MAY NOT APPLY
TO YOU.

EXPORT RESTRICTIONS. This License Agreement is in addition expressly made
subject to any United States regulations and other restrictions regarding
export or re-export of computer software. Licensee agrees not to export or
re-export any Software or derivative thereof in contradiction to any such
applicable restriction.

PROPRIETARY NOTICES. Licensee agrees to maintain and reproduce all
copyright and other proprietary notices on all copies, in any form, of
the Software in the same form and manner that such copyright and other
proprietary notices are included on the Software. Except as expressly
authorized in this Agreement, Licensee shall not make any copies or
duplicates of any Software without the prior written permission of
Licensor. Licensee may make such backup copies of the Software as may
be necessary for Licensee's lawful use, provided Licensee affixes to
such copies all copyright, confidentiality, and proprietary notices
that appear on the original.

TERMINATION. This license will terminate automatically if Licensee
fails to comply with the limitations described above. On termination,
Licensee must destroy all copies of the Software in electronic or
other form, including any copies on backup tapes or other media. Upon
termination of this License for any reason, Licensee shall have no
right to refund of the whole or part of any License Fee paid.

MISCELLANEOUS. This Agreement represents the complete agreement
concerning this license between the parties and supersedes all prior
agreements and representations between them. It may be amended only by
a writing executed by both parties. If any provision of this Agreement
is held to be unenforceable for any reason, such provision shall be
reformed only to the extent necessary to make it enforceable. This
Agreement shall be governed by and construed under the laws of the
State of Queensland, Australia. The application the United Nations
Convention of Contracts for the International Sale of Goods is
expressly excluded.

Open System Consultants Pty. Ltd.
 Standard End User License Agreement Version 6.0
 Last Changed 2012-09-06


EOF

1;
