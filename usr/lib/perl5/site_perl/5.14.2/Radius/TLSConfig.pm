# TLSConfig.pm
#
# Reusable configuration definitions and documentation for 
# modules that support TLS
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997-2007 Open System Consultants
# $Id: TLSConfig.pm,v 1.7 2014/09/25 18:27:06 hvn Exp $

package Radius::TLSConfig;
use Radius::Util;
use Time::Local;
use strict;

# Keywords common to both TLS clients and servers
@Radius::TLSConfig::commonkeywords =
(
 'TLS_CAFile'                  => 
 ['string', 
  'Name of a file containing Certificate Authority (CA) root certificates that may be required to validate TLS client certificates. The certificates are expected to be in PEM format. The file can contain several root certificates for one or more CAs. Radiator will look for root certificates in TLS_CAFile then in TLS_CAPath, so there usually is no need to set both.', 
  1],
 'TLS_CAPath'                  => 
 ['string', 
  'Directory containing CA root certificates that may be required to validate TLS client certificates. The certificates are expected to one per file in PEM format. The files names are looked up by the CA \`Subject Name\' hash value. Radiator will look for root certificates in TLS_CAFile then in TLS_CAPath, so there usually is no need to set both.', 
  1],
 'TLS_CertificateFile'         => 
 ['string', 
  'Name of a file containing a server certificate. The server certificate will be sent to the TLS client and validated by the client during connection. The certificate file may be in PEM or ASN1 format (depending on the setting of the TLS_CertificateType parameter). The certificate file can also contain the server\'s TLS private key if the TLS_PrivateKeyFile parameter specifies the same file.', 
  1],
 'TLS_CertificateChainFile'         => 
 ['string', 
  'Name of a file containing a server certificate chain. The server certificate chain will be sent to the TLS client and validated by the client during connection. The certificate chain must be in PEM format. This should be used alternatively and/or additionally to TLS_CertificateChainFile for explicitly constructing the server certificate chain which is sent to the client in addition to the server certificate.', 
  1],
 'TLS_CertificateType'         => 
 ['string', 
  'Specifies the format of the TLS_CertificateFile. ', 
  1],
 'TLS_PrivateKeyFile'          => 
 ['string', 
  'Name of the file containing the server\'s private key. It is sometimes in the same file as the server certificate (EAPTLS_CertificateFile). If the private key is encrypted (which is usually the case) then EAPTLS_PrivateKeyPassword is the key to decrypt it', 
  1],
 'TLS_PrivateKeyPassword'      => 
 ['string', 
  'Password that is to be used to decrypt the EAPTLS_PrivateKeyFile. Special characters are permitted.', 
  1],
 'TLS_RandomFile'              => 
 ['string', 
  'Name of a file containing randomness. You should not normally need to set this parameter.', 
  1],
 'TLS_DHFile'                  => 
 ['string', 
  'Name of the DH group. You should not normally need to set this parameter, but it may be required if you are using ephemeral DH keys.', 
  1],
 'TLS_ECDH_Curve'               =>
 ['string',
  'This optional parameter enables ephemeral EC keying by specifying the name of the elliptic curve to use. The default is to not enable ephemeral EC keying.',
  1],
 'TLS_CRLCheck'                => 
 ['flag', 
  'Specifies that Certificate Revocation List must be checked for revoked certificates.', 
  1],
 'TLS_CRLFile'                 => 
 ['stringarray', 
  'Where CRL checking has been enabled with TLS_CRLCheck, specifies one or more CRL files that will be used to check client certificates for revocation.', 
  1],
 'TLS_SessionResumption'       => 
 ['flag', 
  'Allows you to enable or disable support for TLS Session Resumption ', 
  1],
 'TLS_SessionResumptionLimit'  => 
 ['integer', 
  'Specifies the limit how long (in seconds) after the initial session that a SSL session can be resumed.', 
  1],
 'TLS_ExpectedPeerName'        => 
 ['string', 
  'When a TLS peer presents a certificate, this optional parameter specifies a regular expression pattern that is required to match the Subject in that certificate. ".+" means to accept any Subject.', 
  1],
 'TLS_SubjectAltNameURI'       => 
 ['string', 
  'When a TLS peer presents a certificate, this optional parameter specifies a regular expression pattern that can match against a subjectAltName of type URI in that certificate.', 
  1],
 'TLS_CertificateFingerprint'       => 
 ['stringarray', 
  'When a TLS peer presents a certificate, this optional parameter specifies one or more fingerprints, one of which must match the fingerprint of the peer certificate. Format is algorithm:fingerprint, for example, sha-1:8E:94:50:0E:2F:D6:DE:16:1D:84:76:FE:2F:14:33:2D:AC:57:04:FF, md5:2A:2D:F1:44:40:81:22:D4:60:6D:9A:B0:F4:BF:DD:24 sha-256:EC:14:77:FA:33:AD:2C:20:FF:D2:C8:1C:46:31:73:04:28:9E:ED:12:D7:8E:79:A0:24:C0:DE:0B:88:A9:DB:3C.', 
  1],
 'TLS_PolicyOID'       => 
 ['stringarray', 
  'When a TLS peer presents a certificate, this optional parameter enables certificate policy checking and specifies one or more policy OIDs that must be present in the certificate path. It sets the \'require explicit policy\' flag as defined in RFC3280. Requires Net-SSLeay 1.37 or later', 
  2],
 );

# Standard keywords for TLS clients
@Radius::TLSConfig::clientkeywords =
(
 @Radius::TLSConfig::commonkeywords,

 'TLS_SRVName'       => 
 ['string', 
  'Specifies a DNS SRV Name to use to match against possible SubjectAltName:SRV extensions in the server certificate. If TLS_SRVName is specified and the server certificate contains SubjectAltName:SRV extensions, none of which match TLS_SRVName, the certificate will not be accepted. Format is _service._transport.name (this is the same format SRV names appear in DNS records). For example "_radsec._tcp.example.com". Only service and name are matched.', 
  2],

 );

# Standard keywords for TLS servers
@Radius::TLSConfig::serverkeywords =
(
 @Radius::TLSConfig::commonkeywords,

 'TLS_RequireClientCert'       => 
 ['flag', 
  'Specifies that the server requires each client to present a valid client certificate during SSL handshake. If no valid certificate (according to the root certificate(s) installed on the server using TLS_CAFile or TLS_CAPath), the SSL handshake will fail and the connection will be disconnected.', 
  1],

 );

