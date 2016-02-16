# DiaAttrList.pm
#
# Routines for storing lists of Diameter attributes
#
# Each attribute is stored in raw (on-the-wire) format, as an array in $self->{Attributes}
# each entry in the array is like:
#  [attrnum, vendornum, flags, value]
#
# These routines permit attributes to be added, removed and accessed. Attrtibues are
# always accessed using attributes numbers and vendor numbers. Values are always
# passed in and out as raw perl strings, already packed as Diamter values. 
# They do not understand integers or floats: every value
# is an octet string.
#  append($attrnum, $vendornum, $flags, @values)
#  @($attrnum, $vendornum, $flags, $value) = delete($attrnum, $vendornum)
#  ($attrnum, $vendornum, $flags, $value) = delete_n($index)
#  @values = get($attrnum, $vendornum)
#  $value = get($attrnum, $vendornum) # Gets the first match only
#  ($attrnum, $vendornum, $flags, $value) = get_details($attrnum, $vendornum) # first match only
#  ($attrnum, $vendornum, $flags, $value) = get_n($index)
#  change_n($index, $attrnum, $vendornum, $flags, $value)
#
#
# These routines provide packing and unpacking of perl primitives to raw Diameter octet strings,
# According to the attribute type given in a dictionary.
# Integers and floats are packed from perl types into 4 and 8 octet strings.
# A ref to an DiaAttrList can be packed into a Grouped type.
# Everything else is treated like an OctetString
#  $rawvalue = assemble($attrnum, $vendornum, $flags, $perlvalue)
#  $perlvalue = disassemble($attrnum, $vendornum, $flags, $rawvalue)
#
# These routines provide encoding and decoding from readable natural langage strings
# to perl types suitable for packing and unpacking into attributes
#  $perlvalue = encode($attrnum, $vendornum, $flags, $object-or-string)
#  $object-or-string = decode($attrnum, $vendornum, $flags, $object-or-string)
#
# Part of the Radius project.
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2004 Open System Consultants
# $Id: DiaAttrList.pm,v 1.15 2014/11/26 21:45:49 hvn Exp $
package Radius::DiaAttrList;
use base ('Radius::AttrList');
use Radius::IEEEfp;
use Radius::BigInt;
use Socket;
use strict;

# RCS version number of this module
$Radius::DiaAttrList::VERSION = '$Revision: 1.15 $';

# Attribute codes
$Radius::DiaAttrList::ACODE_ACCT_INTERIN_INTERVAL          = 85;
$Radius::DiaAttrList::ACODE_ACCOUNTING_REALTIME_REQUIRED   = 483;
$Radius::DiaAttrList::ACODE_ACCT_MULTI_SESSION_ID          = 50;
$Radius::DiaAttrList::ACODE_ACCOUNTING_RECORD_NUMBER       = 485;
$Radius::DiaAttrList::ACODE_ACCOUNTING_RECORD_TYPE         = 480;
$Radius::DiaAttrList::ACODE_ACCOUNTING_SESSION_ID          = 44;
$Radius::DiaAttrList::ACODE_ACCOUNTING_SUB_SESSION_ID      = 287;
$Radius::DiaAttrList::ACODE_ACCT_APPLICATION_ID            = 259;
$Radius::DiaAttrList::ACODE_AUTH_APPLICATION_ID            = 258;
$Radius::DiaAttrList::ACODE_AUTH_REQUEST_TYPE              = 274;
$Radius::DiaAttrList::ACODE_AUTHORIZATION_LIFETIME         = 291;
$Radius::DiaAttrList::ACODE_AUTH_GRACE_PERIOD              = 276;
$Radius::DiaAttrList::ACODE_AUTH_SESSION_STATE             = 277;
$Radius::DiaAttrList::ACODE_RE_AUTH_REQUEST_TYPE           = 285;
$Radius::DiaAttrList::ACODE_CLASS                          = 25;
$Radius::DiaAttrList::ACODE_DESTINATION_HOST               = 293;
$Radius::DiaAttrList::ACODE_DESTINATION_REALM              = 283;
$Radius::DiaAttrList::ACODE_DISCONNECT_CAUSE               = 273;
$Radius::DiaAttrList::ACODE_E2E_SEQUENCE_AVP               = 300;
$Radius::DiaAttrList::ACODE_ERROR_MESSAGE                  = 281;
$Radius::DiaAttrList::ACODE_ERROR_REPORTING_HOST           = 294;
$Radius::DiaAttrList::ACODE_EVENT_TIMESTAMP                = 55;
$Radius::DiaAttrList::ACODE_EXPERIMENTAL_RESULT            = 297;
$Radius::DiaAttrList::ACODE_EXPERIMENTAL_RESULT_CODE       = 298;
$Radius::DiaAttrList::ACODE_FAILED_AVP                     = 279;
$Radius::DiaAttrList::ACODE_FIRMWARE_REVISION              = 267;
$Radius::DiaAttrList::ACODE_HOST_IP_ADDRESS                = 257;
$Radius::DiaAttrList::ACODE_INBAND_SECURITY_ID             = 299;
$Radius::DiaAttrList::ACODE_MULTI_ROUND_TIMEOUT            = 272;
$Radius::DiaAttrList::ACODE_ORIGIN_HOST                    = 264;
$Radius::DiaAttrList::ACODE_ORIGIN_REALM                   = 296;
$Radius::DiaAttrList::ACODE_ORIGIN_STATE_ID                = 278;
$Radius::DiaAttrList::ACODE_PRODUCT_NAME                   = 269;
$Radius::DiaAttrList::ACODE_PROXY_HOST                     = 280;
$Radius::DiaAttrList::ACODE_PROXY_INFO                     = 284;
$Radius::DiaAttrList::ACODE_PROXY_STATE                    = 33;
$Radius::DiaAttrList::ACODE_REDIRECT_HOST                  = 292;
$Radius::DiaAttrList::ACODE_REDIRECT_HOST_USAGE            = 261;
$Radius::DiaAttrList::ACODE_REDIRECT_MAX_CACHE_TIME        = 262;
$Radius::DiaAttrList::ACODE_RESULT_CODE                    = 268;
$Radius::DiaAttrList::ACODE_ROUTE_RECORD                   = 282;
$Radius::DiaAttrList::ACODE_SESSION_ID                     = 263;
$Radius::DiaAttrList::ACODE_SESSION_TIMEOUT                = 27;
$Radius::DiaAttrList::ACODE_SESSION_BINDING                = 270;
$Radius::DiaAttrList::ACODE_SESSION_SERVER_FAILOVER        = 271;
$Radius::DiaAttrList::ACODE_SUPPORTED_VENDOR_ID            = 265;
$Radius::DiaAttrList::ACODE_TERMINATION_CAUSE              = 295;
$Radius::DiaAttrList::ACODE_USER_NAME                      = 1;
$Radius::DiaAttrList::ACODE_VENDOR_ID                      = 266;
$Radius::DiaAttrList::ACODE_VENDOR_SPECIFIC_APPLICATION_ID = 260;

# Vendor codes
$Radius::DiaAttrList::VCODE_BASE = 0;
$Radius::DiaAttrList::VCODE_MICROSOFT = 311;
$Radius::DiaAttrList::VCODE_OSC = 9048;
$Radius::DiaAttrList::VCODE_3GPP = 10415;

# Attribute flags
$Radius::DiaAttrList::AFLAG_NULL      = 0x00;
$Radius::DiaAttrList::AFLAG_VENDOR    = 0x80;
$Radius::DiaAttrList::AFLAG_MANDATORY = 0x40;
$Radius::DiaAttrList::AFLAG_PRIVATE   = 0x20;

# Core enumerated attribute values
# Accounting-Realtime-Required
$Radius::DiaAttrList::ACCOUNTING_REALTIME_REQUIRED_DELIVER_AND_GRANT  = 1;
$Radius::DiaAttrList::ACCOUNTING_REALTIME_REQUIRED_GRANT_AND_STORE    = 2;
$Radius::DiaAttrList::ACCOUNTING_REALTIME_REQUIRED_GRANT_AND_LOSE     = 3;

# Accounting-Record-Type
$Radius::DiaAttrList::ACCOUNTING_RECORD_TYPE_EVENT_RECORD             = 1;
$Radius::DiaAttrList::ACCOUNTING_RECORD_TYPE_START_RECORD             = 2;
$Radius::DiaAttrList::ACCOUNTING_RECORD_TYPE_INTERIM_RECORD           = 3;
$Radius::DiaAttrList::ACCOUNTING_RECORD_TYPE_STOP_RECORD              = 4;

# Auth-Request-Type
$Radius::DiaAttrList::AUTH_REQUEST_TYPE_AUTHENTICATE_ONLY             = 1;
$Radius::DiaAttrList::AUTH_REQUEST_TYPE_AUTHORIZE_ONLY                = 2;
$Radius::DiaAttrList::AUTH_REQUEST_TYPE_AUTHORIZE_AUTHENTICATE        = 3;

# Auth-Session-State
$Radius::DiaAttrList::AUTH_SESSION_STATE_STATE_MAINTAINED             = 0;
$Radius::DiaAttrList::AUTH_SESSION_STATE_NO_STATE_MAINTAINED          = 1;

# Disconnect-Cause
$Radius::DiaAttrList::DISCONNECT_CAUSE_REBOOTING                      = 0;
$Radius::DiaAttrList::DISCONNECT_CAUSE_BUSY                           = 1;
$Radius::DiaAttrList::DISCONNECT_CAUSE_DO_NOT_WANT_TO_TALK_TO_YOU     = 2;

# Inband-Security-Id
$Radius::DiaAttrList::INBAND_SECURITY_ID_NO_INBAND_SECURITY           = 0;
$Radius::DiaAttrList::INBAND_SECURITY_ID_TLS                          = 1;

# Re-Auth-Request-Type
$Radius::DiaAttrList::RE_AUTH_REQUEST_TYPE_AUTHORIZE_ONLY             = 0;
$Radius::DiaAttrList::RE_AUTH_REQUEST_TYPE_AUTHORIZE_AUTHENTICATE     = 1;

# Redirect-Host-Usage
$Radius::DiaAttrList::REDIRECT_HOST_USAGE_DONT_CACHE                  = 0;
$Radius::DiaAttrList::REDIRECT_HOST_USAGE_ALL_SESSION                 = 1;
$Radius::DiaAttrList::REDIRECT_HOST_USAGE_ALL_REALM                   = 2;
$Radius::DiaAttrList::REDIRECT_HOST_USAGE_REALM_AND_APLICATION        = 3;
$Radius::DiaAttrList::REDIRECT_HOST_USAGE_ALL_APPLICATION             = 4;
$Radius::DiaAttrList::REDIRECT_HOST_USAGE_ALL_HOST                    = 5;
$Radius::DiaAttrList::REDIRECT_HOST_USAGE_ALL_USER                    = 6;

# Result-Code
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_MULTI_ROUND_AUTH           = 1001;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_SUCCESS                    = 2001;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_LIMITED_SUCCESS            = 2002;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_COMMAND_UNSUPPORTED        = 3001;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_UNABLE_TO_DELIVER          = 3002;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_REALM_NOT_SERVED           = 3003;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_TOO_BUSY                   = 3004;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_LOOP_DETECTED              = 3005;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_REDIRECT_INDICATION        = 3006;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_APPLICATION_UNSUPPORTED    = 3007;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_INVALID_HDR_BITS           = 3008;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_INVALID_AVP_BITS           = 3009;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_UNKNOWN_PEER               = 3010;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_AUTHENTICATION_REJECTED    = 4001;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_OUT_OF_SPACE               = 4002;
$Radius::DiaAttrList::RESULT_CODE_ELECTION_LOST                       = 4003;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_AVP_UNSUPPORTED            = 5001;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_UNKNOWN_SESSION_ID         = 5002;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_AUTHORIZATION_REJECTED     = 5003;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_INVALID_AVP_VALUE          = 5004;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_MISSING_AVP                = 5005;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_RESOURCES_EXCEEDED         = 5006;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_CONTRADICTING_AVPS         = 5007;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_AVP_NOT_ALLOWED            = 5008;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_AVP_OCCURS_TOO_MANY_TIMES  = 5009;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_NO_COMMON_APPLICATION      = 5010;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_UNSUPPORTED_VERSION        = 5011;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_UNABLE_TO_COMPLY           = 5012;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_INVALID_BIT_IN_HEADER      = 5013;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_INVALID_AVP_LENGTH         = 5014;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_INVALID_MESSAGE_LENGTH     = 5015;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_INVALID_AVP_BIT_COMBO      = 5016;
$Radius::DiaAttrList::RESULT_CODE_DIAMETER_NO_COMMON_SECURITY         = 5017;

# Session-Binding
$Radius::DiaAttrList::SESSION_BINDING_RE_AUTH                         = 1;
$Radius::DiaAttrList::SESSION_BINDING_STR                             = 2;
$Radius::DiaAttrList::SESSION_BINDING_ACCOUNTING                      = 4;

# Session-Server-Failover
$Radius::DiaAttrList::SESSION_SERVER_FAILOVER_REFUSE_SERVICE          = 0;
$Radius::DiaAttrList::SESSION_SERVER_FAILOVER_TRY_AGAIN               = 1;
$Radius::DiaAttrList::SESSION_SERVER_FAILOVER_ALLOW_SERVICE           = 2;
$Radius::DiaAttrList::SESSION_SERVER_FAILOVER_TRY_AGAIN_ALLOW_SERVICE = 3;

# Termination-Cause
$Radius::DiaAttrList::TERMINATION_CAUSE_DIAMETER_LOGOUT               = 1;
$Radius::DiaAttrList::TERMINATION_CAUSE_DIAMETER_SERVICE_NOT_PROVIDED = 2;
$Radius::DiaAttrList::TERMINATION_CAUSE_DIAMETER_BAD_ANSWER           = 3;
$Radius::DiaAttrList::TERMINATION_CAUSE_DIAMETER_ADMINISTRATIVE       = 4;
$Radius::DiaAttrList::TERMINATION_CAUSE_DIAMETER_LINK_BROKEN          = 5;
$Radius::DiaAttrList::TERMINATION_CAUSE_DIAMETER_AUTH_EXPIRED         = 6;
$Radius::DiaAttrList::TERMINATION_CAUSE_DIAMETER_USER_MOVED           = 7;
$Radius::DiaAttrList::TERMINATION_CAUSE_DIAMETER_SESSION_TIMEOUT      = 8;

# From draft-ietf-aaa-diameter-nasreq-14.txt:
$Radius::DiaAttrList::ACODE_NAS_IDENTIFIER                            = 32;
$Radius::DiaAttrList::ACODE_NAS_IP_ADDRESS                            = 4;
$Radius::DiaAttrList::ACODE_NAS_IPV6_ADDRESS                          = 95;
$Radius::DiaAttrList::ACODE_STATE                                     = 24;
$Radius::DiaAttrList::ACODE_TERMINATION_CAUSE                         = 295;

$Radius::DiaAttrList::ACODE_ACCOUNTING_INPUT_OCTETS                   = 363;
$Radius::DiaAttrList::ACODE_ACCOUNTING_OUTPUT_OCTETS                  = 364;
$Radius::DiaAttrList::ACODE_ACCOUNTING_INPUT_PACKETS                  = 365;
$Radius::DiaAttrList::ACODE_ACCOUNTING_OUTPUT_PACKETS                 = 366;
$Radius::DiaAttrList::ACODE_ACCT_SESSION_TIME                         = 46;
$Radius::DiaAttrList::ACODE_ACCT_AUTHENTIC                            = 45;
$Radius::DiaAttrList::ACODE_ACCOUNTING_AUTH_METHOD                    = 406;
$Radius::DiaAttrList::ACODE_ACCT_DELAY_TIME                           = 41;
$Radius::DiaAttrList::ACODE_ACCT_LINK_COUNT                           = 51;
$Radius::DiaAttrList::ACODE_ACCT_TUNNEL_CONNECTION                    = 68;
$Radius::DiaAttrList::ACODE_ACCT_TUNNEL_PACKETS_LOST                  = 86;
$Radius::DiaAttrList::ACODE_ARAP_FEATURES                             = 71;
$Radius::DiaAttrList::ACODE_ARAP_PASSWORD                             = 70;
$Radius::DiaAttrList::ACODE_ARAP_CHALLENGE_RESPONSE                   = 84;
$Radius::DiaAttrList::ACODE_ARAP_SECURITY                             = 73;
$Radius::DiaAttrList::ACODE_ARAP_SECURITY_DATA                        = 74;
$Radius::DiaAttrList::ACODE_ARAP_ZONE_ACCESS                          = 72;
$Radius::DiaAttrList::ACODE_CALLBACK_NUMBER                           = 19;
$Radius::DiaAttrList::ACODE_CALLBACK_ID                               = 20;
$Radius::DiaAttrList::ACODE_CALLED_STATION_ID                         = 30;
$Radius::DiaAttrList::ACODE_CALLING_STATION_ID                        = 31;
$Radius::DiaAttrList::ACODE_CHAP_AUTH                                 = 402;
$Radius::DiaAttrList::ACODE_CHAP_ALGORITHM                            = 403;
$Radius::DiaAttrList::ACODE_CHAP_CHALLENGE                            = 60;
$Radius::DiaAttrList::ACODE_CHAP_IDENT                                = 404;
$Radius::DiaAttrList::ACODE_CHAP_RESPONSE                             = 405;
$Radius::DiaAttrList::ACODE_CONFIGURATION_TOKEN                       = 78;
$Radius::DiaAttrList::ACODE_CONNECT_INFO                              = 77;
$Radius::DiaAttrList::ACODE_FILTER_ID                                 = 11;
$Radius::DiaAttrList::ACODE_FRAMED_PROTOCOL                           = 7;
$Radius::DiaAttrList::ACODE_FRAMED_ROUTING                            = 10;
$Radius::DiaAttrList::ACODE_FRAMED_MTU                                = 12;
$Radius::DiaAttrList::ACODE_FRAMED_COMPRESSION                        = 13;
$Radius::DiaAttrList::ACODE_FRAMED_IP_ADDRESS                         = 8;
$Radius::DiaAttrList::ACODE_FRAMED_IP_NETMASK                         = 9;
$Radius::DiaAttrList::ACODE_FRAMED_ROUTE                              = 22;
$Radius::DiaAttrList::ACODE_FRAMED_POOL                               = 88;
$Radius::DiaAttrList::ACODE_FRAMED_INTERFACE_ID                       = 96;
$Radius::DiaAttrList::ACODE_FRAMED_IPV6_PREFIX                        = 97;
$Radius::DiaAttrList::ACODE_FRAMED_IPV6_ROUTE                         = 99;
$Radius::DiaAttrList::ACODE_FRAMED_IPV6_POOL                          = 100;
$Radius::DiaAttrList::ACODE_FRAMED_IPX_NETWORK                        = 23;
$Radius::DiaAttrList::ACODE_FRAMED_APPLETALK_LINK                     = 37;
$Radius::DiaAttrList::ACODE_FRAMED_APPLETALK_NETWORK                  = 38;
$Radius::DiaAttrList::ACODE_FRAMED_APPLETALK_ZONE                     = 39;
$Radius::DiaAttrList::ACODE_IDLE_TIMEOUT                              = 28;
$Radius::DiaAttrList::ACODE_LOGIN_IP_HOST                             = 14;
$Radius::DiaAttrList::ACODE_LOGIN_IPV6_HOST                           = 98;
$Radius::DiaAttrList::ACODE_LOGIN_SERVICE                             = 15;
$Radius::DiaAttrList::ACODE_LOGIN_TCP_PORT                            = 16;
$Radius::DiaAttrList::ACODE_LOGIN_LAT_SERVICE                         = 34;
$Radius::DiaAttrList::ACODE_LOGIN_LAT_NODE                            = 35;
$Radius::DiaAttrList::ACODE_LOGIN_LAT_GROUP                           = 36;
$Radius::DiaAttrList::ACODE_NAS_FILTER_RULE                           = 400;
$Radius::DiaAttrList::ACODE_NAS_IDENTIFIER                            = 32;
$Radius::DiaAttrList::ACODE_NAS_IP_ADDRESS                            = 4;
$Radius::DiaAttrList::ACODE_NAS_IPV6_ADDRESS                          = 95;
$Radius::DiaAttrList::ACODE_NAS_PORT                                  = 5;
$Radius::DiaAttrList::ACODE_NAS_PORT_ID                               = 87;
$Radius::DiaAttrList::ACODE_NAS_PORT_TYPE                             = 61;
$Radius::DiaAttrList::ACODE_ORIGINATING_LINE_INFO                     = 94;
$Radius::DiaAttrList::ACODE_ORIGIN_AAA_PROTOCOL                       = 408;
$Radius::DiaAttrList::ACODE_PASSWORD_RETRY                            = 75;
$Radius::DiaAttrList::ACODE_PORT_LIMIT                                = 62;
$Radius::DiaAttrList::ACODE_PROMPT                                    = 76;
$Radius::DiaAttrList::ACODE_REPLY_MESSAGE                             = 18;
$Radius::DiaAttrList::ACODE_SERVICE_TYPE                              = 6;
$Radius::DiaAttrList::ACODE_STATE                                     = 24;
$Radius::DiaAttrList::ACODE_TERMINATION_ACTION                        = 19;
$Radius::DiaAttrList::ACODE_TUNNELING                                 = 401;
$Radius::DiaAttrList::ACODE_TUNNEL_TYPE                               = 64;
$Radius::DiaAttrList::ACODE_TUNNEL_MEDIUM_TYPE                        = 65;
$Radius::DiaAttrList::ACODE_TUNNEL_CLIENT_ENDPOINT                    = 66;
$Radius::DiaAttrList::ACODE_TUNNEL_SERVER_ENDPOINT                    = 67;
$Radius::DiaAttrList::ACODE_TUNNEL_PASSWORD                           = 69;
$Radius::DiaAttrList::ACODE_TUNNEL_PRIVATE_GROUP_ID                   = 81;
$Radius::DiaAttrList::ACODE_TUNNEL_ASSIGNMENT_ID                      = 82;
$Radius::DiaAttrList::ACODE_TUNNEL_PREFERENCE                         = 83;
$Radius::DiaAttrList::ACODE_TUNNEL_CLIENT_AUTH_ID                     = 90;
$Radius::DiaAttrList::ACODE_TUNNEL_SERVER_AUTH_ID                     = 91;
$Radius::DiaAttrList::ACODE_USER_PASSWORD                             = 2;

$Radius::DiaAttrList::CHAP_ALGORITHM_CHAP_WITH_MD5                    = 5;

# From RFC 4072
$Radius::DiaAttrList::ACODE_EAP_PAYLOAD                               = 462;
$Radius::DiaAttrList::ACODE_EAP_REISSUED_PAYLOAD                      = 463;
$Radius::DiaAttrList::ACODE_EAP_MASTER_SESSION_KEY                    = 464;
$Radius::DiaAttrList::ACODE_EAP_KEY_NAME                              = 102;
$Radius::DiaAttrList::ACODE_ACCOUNTING_EAP_AUTH_METHOD                = 465;

# Microsoft
$Radius::DiaAttrList::ACODE_MS_CHAP_RESPONSE                          = 1;
$Radius::DiaAttrList::ACODE_MS_CHAP_CHALLENGE                         = 11;
$Radius::DiaAttrList::ACODE_MS_CHAP2_RESPONSE                         = 25;

# SIP
$Radius::DiaAttrList::ACODE_SIP_DIGEST_RESPONSE                       = 206;
$Radius::DiaAttrList::ACODE_SIP_DIGEST_ATTRIBUTES                     = 207;

#######################################################
# 3GPP VSAs follow

# A number of attributes from different spefications are used over WX
# and SWX reference points. The attributes below are used when
# Radiator connects to 4G/LTE HSS or Ulticom gateway over Wx/SWx.

# 3GPP TS 29.229 V11.4.0: Cx and Dx interfaces based on the Diameter protocol; Protocol details
#
$Radius::DiaAttrList::ACODE_3GPP_SIP_NUMBER_AUTH_ITEMS          = 607;
$Radius::DiaAttrList::ACODE_3GPP_SIP_AUTHENTICATION_SCHEME      = 608;
$Radius::DiaAttrList::ACODE_3GPP_SIP_AUTHENTICATE               = 609;
$Radius::DiaAttrList::ACODE_3GPP_SIP_AUTHORIZATION              = 610;
$Radius::DiaAttrList::ACODE_3GPP_SIP_AUTHENTICATION_CONTEXT     = 611;
$Radius::DiaAttrList::ACODE_3GPP_SIP_AUTH_DATA_ITEM             = 612;
$Radius::DiaAttrList::ACODE_3GPP_SIP_ITEM_NUMBER                = 613;
$Radius::DiaAttrList::ACODE_3GPP_CONFIDENTIALITY_KEY            = 625;
$Radius::DiaAttrList::ACODE_3GPP_INTEGRITY_KEY                  = 626;

# 3GPP TS 29.234 V11.2.0: 3GPP system to Wireless Local Area Network (WLAN) interworking; Stage 3
# Wx reference point
#
$Radius::DiaAttrList::ACODE_3GPP_AUTHENTICATION_METHOD          = 300;
$Radius::DiaAttrList::ACODE_3GPP_AUTHENTICATION_INFORMATION_SIM = 301;
$Radius::DiaAttrList::ACODE_3GPP_AUTHORIZATION_INFORMATION_SIM  = 302;

# Values for ACODE_3GPP_AUTHENTICATION_METHOD
$Radius::DiaAttrList::AUTHENTICATION_METHOD_SIM                    = 0;
$Radius::DiaAttrList::AUTHENTICATION_METHOD_AKA                    = 1;

# These are the type-specific routines for packing attributes from Perl types
# into Diameter attributes, based on the type of the attribute
# Each function is passed the args:
#   encoder(self, dictionary, value, attrname, attrtype, attrnum, vendorid, flags)
# and is required to return the packed attribute, else undef.
# The key is the lowercase name of the attribute type
%Radius::DiaAttrList::encoders =
    (
     'unsigned32'  => sub { return pack('N', $_[2])},
     'unsigned64'  => sub { return &Radius::BigInt::pack64u($_[2])},
     'integer32'   => sub { return pack('N', $_[2] < 0 ? 0xffffffff + $_[2] + 1 : $$_[2])},
     'integer64'   => sub { return &Radius::BigInt::pack64s($_[2])},
     'float32'     => sub { return &Radius::IEEEfp::pack_s($_[2])},
     'float64'     => sub { return &Radius::IEEEfp::pack_d($_[2])},
     'time'        => sub { return pack('N', $_[2])},
     'address'     => sub { return pack('na*', 1, $_[2]) if length $_[2] == 4; return pack('na*', 2, $_[2])},
     'grouped'     => sub { return $_[2]->assemble()},
     'enumerated'  => sub { my @v = $_[1]->valByName($_[3], $_[2]); 
			    return pack('N', defined $v[1] ? $v[1] : $_[2])},
     'vendor'      => sub { my @v = $_[1]->vendorByName($_[2]); 
			    return pack('N', defined $v[1] ? $v[1] : $_[2])},

     # Local workaround for 3GPP TS 29.061 RADIUS compatibility.
     'enumerated8' => sub { my @v = $_[1]->valByName($_[3], $_[2]); 
			    return pack('C', defined $v[1] ? $v[1] : $_[2])},

     # These are currently returned directly.
     'utf8string'       => sub { return $_[2]},
     'octetstring'      => sub { return $_[2]},
     'diameteridentity' => sub { return $_[2]},
     'diameteruri'      => sub { return $_[2]},
     'ipfilterrule'     => sub { return $_[2]},
     'qosfilterrule'    => sub { return $_[2]},
     );

# Called like decoder($self, $dict, $value, attrname, attrtype, attrnum, vendorid, flags)
%Radius::DiaAttrList::decoders =
    (
     'unsigned32'  => sub { return unpack('N', $_[2])},
     'unsigned64'  => sub { return &Radius::BigInt::unpack64u($_[2])},
     'integer32'   => sub { my $u = unpack('N', $_[2]); return $u & 0x80000000 ? $u - 1 - 0xffffffff : $u},
     'integer64'   => sub { return &Radius::BigInt::unpack64s($_[2])},
     'float32'     => sub { return &Radius::IEEEfp::unpack_s($_[2])},
     'float64'     => sub { return &Radius::IEEEfp::unpack_d($_[2])},
     'time'        => sub { return unpack('N', $_[2])},
     'address'     => sub { my ($at, $a) = unpack('n a*', $_[2]); 
                            return Socket::inet_ntoa($_[2]) if (length($_[2]) == 4); # workarround : pre draft 16 
			    return Socket::inet_ntoa($a) if $at == 1; # IPv4
			    return Radius::Util::inet_ntop($a) if $at == 2; # IPv6
			    return $_[2]},
     'grouped'     => sub { my $l = Radius::DiaAttrList->new(Dictionary => $_[1]);
			    $l->disassemble($_[2]); return $l},
     'enumerated'  => sub { my @v = $_[1]->valByNum($_[3], unpack('N', $_[2])); 
			    return defined $v[0] ? $v[0] : $_[2]; },
     'vendor'      => sub { my $u = unpack('N', $_[2]); my @v = $_[1]->vendorByNum($u); 
			    return defined $v[0] ? $v[0] : $u; },

     # Local workaround for 3GPP TS 29.061 RADIUS compatibility.
     'enumerated8' => sub { my @v = $_[1]->valByNum($_[3], unpack('C', $_[2])); 
			    return defined $v[0] ? $v[0] : $_[2]; },

     # These are currently returned directly.
     'utf8string'       => sub { return $_[2]},
     'octetstring'      => sub { return $_[2]},
     'diameteridentity' => sub { return $_[2]},
     'diameteruri'      => sub { return $_[2]},
     'ipfilterrule'     => sub { return $_[2]},
     'qosfilterrule'    => sub { return $_[2]},
     );

%Radius::DiaAttrList::flags2letter = 
    ( 128 => 'V',
       64 => 'M',
       32 => 'P',
    );

%Radius::DiaAttrList::letters2flag = reverse(%Radius::DiaAttrList::flags2letter);

#####################################################################
sub new
{
    my ($class, @args) = @_;

    return $class->SUPER::new(Dictionary => $Radius::DiaDict::default, @args);
}

#####################################################################
sub disassemble
{
    my ($self, $data) = @_;

    my $count;
    while (length $data >= 8)
    {
	my ($attrnum, $avpflen) = unpack('N N', $data);
	my $flags = $avpflen >> 24;
	my $avplen = $avpflen & 0xffffff;  # Does not include padding to 32bit boundary
	my ($vendornum, $datalen, $avpdata);

	if ($flags & $Radius::DiaAttrList::AFLAG_VENDOR)
	{
	    # Have a vendor id
	    if ($avplen < 12)
	    {
		# REVISIT: log bad length
		last;
	    }
	    $datalen = $avplen - 12;
	    ($attrnum, $avpflen, $vendornum, $avpdata) = unpack("N N N a$datalen", $data);
	}
	else
	{
	    if ($avplen < 8)
	    {
		# REVISIT: log bad length
		last;
	    }
	    $datalen = $avplen - 8;
	    ($attrnum, $avpflen, $avpdata) = unpack("N N a$datalen", $data);
	    $vendornum = 0;
	}
	push(@{$self->{Attributes}}, [$attrnum, $vendornum, $flags, $avpdata]);

	# Remove the processed AVP. The 
	my $padlen = ($avplen + 3) & 0xfffffffc; # The padded length

	substr($data, 0, $padlen, '');
	$count++;
    }
    return $count;
}

#####################################################################
sub assemble
{
    my ($self) = @_;

    my $data = '';
    foreach (@{$self->{Attributes}})
    {
	# Each item is [$attrnum, $vendornum, $flags, $data]
	# Padding to multiple of 4 octets: Hmm RFC is silent on how to 
	# recover the correct length
	$$_[3] = '' unless defined $$_[3];     # Prevent warnings
	my $len = length($$_[3]);              # The real data length
	my $padlen = ($len + 3) & 0xfffffffc;  # The padded data length

	$data .= $$_[1] ? pack("N N N a$padlen", $$_[0], ($$_[2] | $Radius::DiaAttrList::AFLAG_VENDOR) << 24 | ($len + 12), $$_[1], $$_[3])
	    : pack("N N a$padlen", $$_[0], ($$_[2] << 24) | ($len + 8), $$_[3]);
    }
    return $data;
}
#####################################################################
sub grouped_attr
{
    my $self = shift;
    my $group = Radius::DiaAttrList->new(Dictionary => $self->{Dictionary});
    $group->add_attr(@{$_}) foreach @_;
    return $group;
}


#####################################################################
# Find and call the type-specific attribute packer
# If one cant be found, pack the same as an OctetString (ie, no packing)
sub encode
{
    my ($self, $attrnum, $vendornum, $flags, @values) = @_;

    my $dict = $self->{Dictionary};
    my @attrdesc = $dict && $dict->attrByNum($attrnum, $vendornum);
    # (name, type, number, vendorid, flags)

    my $p = $Radius::DiaAttrList::encoders{lc $attrdesc[1]}
        if defined $attrdesc[1];

    # For each value, if there is a known encoder, call it, else return with no encoding
    return map {$p ? &$p($self, $dict, $_, @attrdesc) : $_} @values if wantarray;
    return $p ? &$p($self, $dict, $values[0], @attrdesc) : $values[0];
}

#####################################################################
# Find and call the type-specific attribute packer
# If one cant be found, pack the same as an OctetString (ie, no packing)
sub decode
{
    my ($self, $attrnum, $vendornum, $flags, @values) = @_;

    my $dict = $self->{Dictionary};
    my @attrdesc = $dict && $dict->attrByNum($attrnum, $vendornum);
    # (name, type, number, vendorid, flags)

    my $p = $Radius::DiaAttrList::decoders{lc $attrdesc[1]}
        if @attrdesc;
    # For each value, if there is a known decoder, call it, else return with no encoding
    return map {$p ? &$p($self, $dict, $_, @attrdesc) : $_} @values if wantarray;
    return $p ? &$p($self, $dict, $values[0], @attrdesc) : $values[0];
}

#####################################################################
# Find and call the type-specific attribute formatters
# If one cant be found, pack the same as an OctetString (ie, no packing)
sub format_one
{
    my ($self, $attrnum, $vendornum, $flags, $value,$prefix) = @_;

    my $dict = $self->{Dictionary};
    my @attrdesc = $dict && $dict->attrByNum($attrnum, $vendornum);

    # (name, type, number, vendorid, flags)
    my $p = $Radius::DiaAttrList::decoders{lc $attrdesc[1]}
        if @attrdesc;
    $value = &$p($self, $dict, $value, @attrdesc) if $p;

    # Maybe its a grouped attribute that we need to further format
    if ($p && $attrdesc[1] eq 'Grouped' && $value && ref($value) eq 'Radius::DiaAttrList')
    {
        $prefix .= '   ';
	$value = "\n" . $value->format($dict, $prefix);
    }
    else
    {
	# Make sure all characters are printable
	$value = '' unless defined $value;
	$value =~ s/([\000-\037\177-\377])/<${\ord($1)}>/g;
    }

    $attrnum += 0;
    $vendornum += 0;
    my $attrname = $attrdesc[0] || "Attr-$vendornum-$attrnum";
    my $textFlags = '';
    $textFlags .= (($flags & $_ ) ? $Radius::DiaAttrList::flags2letter{$_} : '.') foreach ((128,64,32));
    return "    $attrname: $textFlags, $value";
}



1;
