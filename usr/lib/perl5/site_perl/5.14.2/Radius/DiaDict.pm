# DiaDict.pm
#
# Routines for managing the Diameter attibute dictionary
#
# Part of the Radius project.
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2004 Open System Consultants
# $Id: DiaDict.pm,v 1.15 2014/09/10 20:57:43 hvn Exp $

package Radius::DiaDict;
use base ('Radius::Dictionary');
use Radius::DiaMsg;
use strict;

# RCS version number of this module
$Radius::DiaDict::VERSION = '$Revision: 1.15 $';

$Radius::DiaDict::default = undef;

# List of basic and derived Diameter types known by this dictionary.
# Enumerated8 is a local workaround for 3GPP TS 29.061 RADIUS compatibility.
@Radius::DiaDict::known_types = qw(OctetString Integer32 Integer64
    Unsigned32 Unsigned64 Float32 Float64 Grouped Address Time
    UTF8String DiameterIdentity DiameterURI Enumerated IPFilterRule
    QoSFilterRule Enumerated8);

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();

    # Load standard Diameter attributes. We need to reset the handle
    # position for the next instantion to work.
    my $data_pos = tell DATA;
    $self->load_handle(*DATA, ref $self);
    seek DATA, $data_pos, 0;

    $self->load_file($self->{Filename}) if length $self->{Filename};

    # Is this to be the default dict?
    unless ($Radius::DiaDict::default)
    {
	$Radius::DiaDict::default = $self;

	# Attributes for Diameter base, NASREQ, Mobile Ipv4, base
	# accounting, EAP, SIP and relay application IDs are currently
	# defined in the base dictionary.
	$Radius::DiaDict::dicts{$Radius::DiaMsg::APPID_BASE} = $self;
	$Radius::DiaDict::dicts{$Radius::DiaMsg::APPID_NASREQ} = $self;
	$Radius::DiaDict::dicts{$Radius::DiaMsg::APPID_MOBILE_IP} = $self;
	$Radius::DiaDict::dicts{$Radius::DiaMsg::APPID_BASE_ACCOUNTING} = $self;
	$Radius::DiaDict::dicts{$Radius::DiaMsg::APPID_DIAMETER_EAP} = $self;
	$Radius::DiaDict::dicts{$Radius::DiaMsg::APPID_DIAMETER_SIP} = $self;
	$Radius::DiaDict::dicts{$Radius::DiaMsg::APPID_RELAY} = $self;
    }

    return $self;
}

#####################################################################
# Return 1 if we know this Diameter type. Return 0 otherwise.
sub is_known_type
{
    my ($self, $type) = @_;

    return (grep {lc $type eq lc $_} @Radius::DiaDict::known_types) ? 1 : 0;
}

# Resolve flag names to binary values
sub resolve_flags
{
    my ($self, $name, $vendor, $flags) = @_;

    my $bits = 0;

    # V (vendor) bit is not a separate attribute flag in
    # dictionary. We set it first and follow with flags, if any.
    $bits |= $Radius::DiaAttrList::letters2flag{V} if $vendor;
    return $bits unless $flags;

    foreach my $letter (split (/,/, $flags))
    {
	my $flagvalue = $Radius::DiaAttrList::letters2flag{$letter};
	if (defined $flagvalue)
	{
	    $bits |= $flagvalue;
	    next;
	}
	$self->log($main::LOG_WARNING, "Bad flags value '$flags' for Diameter attribute $name");
    }

    return $bits;
}

1;

# Here follows the standard Diameter core attributes from RFC 6733
__DATA__
ATTRIBUTE Acct-Interim-Interval              85     Unsigned32 M
ATTRIBUTE Accounting-Realtime-Required      483     Enumerated M
ATTRIBUTE Acct-Multi-Session-Id              50     UTF8String M
ATTRIBUTE Accounting-Record-Number          485     Unsigned32 M
ATTRIBUTE Accounting-Record-Type            480     Enumerated M
ATTRIBUTE Accounting-Session-Id              44     OctetString M
ATTRIBUTE Accounting-Sub-Session-Id         287     Unsigned64 M
ATTRIBUTE Acct-Application-Id               259     Enumerated M
VALUE    Acct-Application-Id		BASE            0
VALUE    Acct-Application-Id		NASREQ          1
VALUE    Acct-Application-Id		MOBILE_IP       2
VALUE    Acct-Application-Id		BASE_ACCOUNTING 3
VALUE    Acct-Application-Id		CREDIT_CONTROL  4
VALUE    Acct-Application-Id		DIAMETER_EAP    5
VALUE    Acct-Application-Id		DIAMETER_SIP    6
VALUE    Acct-Application-Id		RELAY           4294967295
ATTRIBUTE Auth-Application-Id               258     Enumerated M
VALUE    Auth-Application-Id		BASE            0
VALUE    Auth-Application-Id		NASREQ          1
VALUE    Auth-Application-Id		MOBILE_IP       2
VALUE    Auth-Application-Id		BASE_ACCOUNTING 3
VALUE    Auth-Application-Id		CREDIT_CONTROL  4
VALUE    Auth-Application-Id		DIAMETER_EAP    5
VALUE    Auth-Application-Id		DIAMETER_SIP    6
VALUE    Auth-Application-Id		DIAMETER_MIP6I  7
VALUE    Auth-Application-Id		DIAMETER_MIP6A  8
VALUE    Auth-Application-Id		DIAMETER_QOS    9
VALUE    Auth-Application-Id		DIAMETER_CAPABILITIES_UPDATE 10
VALUE    Auth-Application-Id		DIAMETER_IKESK  11
VALUE    Auth-Application-Id		DIAMETER_NAT    12
VALUE    Auth-Application-Id		3GPP_CX         16777216
VALUE    Auth-Application-Id		3GPP_SH         16777217
VALUE    Auth-Application-Id		3GPP_RE         16777218
VALUE    Auth-Application-Id		3GPP_WX         16777219
VALUE    Auth-Application-Id		3GPP_ZN         16777220
VALUE    Auth-Application-Id		3GPP_ZH         16777221
VALUE    Auth-Application-Id		3GPP_GQ         16777222
VALUE    Auth-Application-Id		3GPP_GMB        16777223
VALUE    Auth-Application-Id		3GPP_GX         16777224
VALUE    Auth-Application-Id		3GPP_GX_OVER_GY 16777225
VALUE    Auth-Application-Id		3GPP_MM10       16777226
VALUE    Auth-Application-Id		ERICSSON_MSI                      16777227 
VALUE    Auth-Application-Id		ERICSSON_ZX                       16777228 
VALUE    Auth-Application-Id		3GPP_RX                           16777229 
VALUE    Auth-Application-Id		3GPP_PR                           16777230 
VALUE    Auth-Application-Id		ETSI_E4                           16777231 
VALUE    Auth-Application-Id		ERICSSON_CHARGING_CIP             16777232 
VALUE    Auth-Application-Id		ERICSSON_MM                       16777233 
VALUE    Auth-Application-Id		VODAFONE_GX_PLUS                  16777234 
VALUE    Auth-Application-Id		ITU_T_RS                          16777235 
VALUE    Auth-Application-Id		3GPP_RX                           16777236 
VALUE    Auth-Application-Id		3GPP2_TY                          16777237 
VALUE    Auth-Application-Id		3GPP_GX                           16777238 
VALUE    Auth-Application-Id		JUNIPER_CLUSTER                   16777239 
VALUE    Auth-Application-Id		JUNIPER_POLICY_CONTROL_AAA        16777240 
VALUE    Auth-Application-Id		IPTEGO_USPI                       16777241 
VALUE    Auth-Application-Id		COVERGENCE_SPECIFIC_SIP_ROUTING   16777242 
VALUE    Auth-Application-Id		POLICY_PROCESSING                 16777243 
VALUE    Auth-Application-Id		JUNIPER_POLICY_CONTROL_JSRC       16777244 
VALUE    Auth-Application-Id		ITU_T_S_TC1                       16777245 
VALUE    Auth-Application-Id		NSN_UCTF                          16777246 
VALUE    Auth-Application-Id		3GPP2_CAN_ACCESS_AUTHN_AND_AUTHZ  16777247 
VALUE    Auth-Application-Id		3GPP2_WLAN_INTERWORKING_AAA       16777248 
VALUE    Auth-Application-Id		3GPP2_WLAN_INTERWORKING_ACCT      16777249 
VALUE    Auth-Application-Id		3GPP_STA                          16777250 
VALUE    Auth-Application-Id		3GPP_S6A                          16777251 
VALUE    Auth-Application-Id		3GPP_S13                          16777252 
VALUE    Auth-Application-Id		ETSI_RE                           16777253 
VALUE    Auth-Application-Id		ETSI_GOCAP                        16777254 
VALUE    Auth-Application-Id		SLG                               16777255 
VALUE    Auth-Application-Id		ITU_T_RW                          16777256 
VALUE    Auth-Application-Id		ETSI_A4                           16777257 
VALUE    Auth-Application-Id		ITU_T_RT                          16777258 
VALUE    Auth-Application-Id		CARA                              16777259 
VALUE    Auth-Application-Id		CAMA                              16777260 
VALUE    Auth-Application-Id		FEMTOCELL_EXT_TO_DIAM_EAP_APP     16777261 
VALUE    Auth-Application-Id		ITU_T_RU                          16777262 
VALUE    Auth-Application-Id		ITU_T_NG                          16777263 
VALUE    Auth-Application-Id		3GPP_SWM                          16777264 
VALUE    Auth-Application-Id		3GPP_SWX                          16777265 
VALUE    Auth-Application-Id		3GPP_GXX                          16777266 
VALUE    Auth-Application-Id		3GPP_S9                           16777267 
VALUE    Auth-Application-Id		3GPP_ZPN                          16777268 
VALUE    Auth-Application-Id		ERICSSON_HSI                      16777269 
VALUE    Auth-Application-Id		JUNIPER_EXAMPLE                   16777270 
VALUE    Auth-Application-Id		ITU_T_RI                          16777271 
VALUE    Auth-Application-Id		3GPP_S6B                          16777272 
VALUE    Auth-Application-Id		JUNIPER_JGX                       16777273 
VALUE    Auth-Application-Id		ITU_T_RD                          16777274 
VALUE    Auth-Application-Id		ADMI_NOTIFICATION_APP             16777275 
VALUE    Auth-Application-Id		ADMI_MESSAGING_INTERFACE_APP      16777276 
VALUE    Auth-Application-Id		PETER_SERVICE_VSI                 16777277 
VALUE    Auth-Application-Id		ETSI_RR_REQUEST_MODEL             16777278 
VALUE    Auth-Application-Id		ETSI_RR_DELEGATED_MODEL           16777279 
VALUE    Auth-Application-Id		WIMAX_HRPD_INTERWORKING           16777280 
VALUE    Auth-Application-Id		WIMAX_WNAAADA                     16777281 
VALUE    Auth-Application-Id		WIMAX_WNADA                       16777282 
VALUE    Auth-Application-Id		WIMAX_WM4DA                       16777283 
VALUE    Auth-Application-Id		WIMAX_WM6DA                       16777284 
VALUE    Auth-Application-Id		WIMAX_WDDA                        16777285 
VALUE    Auth-Application-Id		WIMAX_WLAADA                      16777286 
VALUE    Auth-Application-Id		WIMAX_PCC_R3_P                    16777287 
VALUE    Auth-Application-Id		WIMAX_PCC_R3_OFC                  16777288 
VALUE    Auth-Application-Id		WIMAX_PCC_R3_OFC_PRIME            16777289 
VALUE    Auth-Application-Id		WIMAX_PCC_R3_OC                   16777290 
VALUE    Auth-Application-Id		3GPP_SLH                          16777291 
VALUE    Auth-Application-Id		3GPP_SGMB                         16777292 
VALUE    Auth-Application-Id		CMDI                              16777293 
VALUE    Auth-Application-Id		CAMIANT_DRMA                      16777294 
VALUE    Auth-Application-Id		PILTE_INTERWORKING_DIAM_APP       16777295 
VALUE    Auth-Application-Id		JUNIPER_SESSIONS_RECOVERY         16777296 
VALUE    Auth-Application-Id		VEDICIS_LIVEPROXY                 16777297 
VALUE    Auth-Application-Id		PI_STAR_3GPP2_DIA_APP             16777298 
VALUE    Auth-Application-Id		SANDVINE_RF_PLUS                  16777299 
VALUE    Auth-Application-Id		SUBSCRIPTION_INFORMATION_APP      16777300 
VALUE    Auth-Application-Id		ERICSSON_CHARGING_DCIP            16777301 
VALUE    Auth-Application-Id		3GPP_SY                           16777302 
VALUE    Auth-Application-Id		3GPP_SD                           16777303 
VALUE    Auth-Application-Id		ERICSSON_SY                       16777304 
VALUE    Auth-Application-Id		HP_DTD                            16777305 
VALUE    Auth-Application-Id		M9_ITF_BTW_MLM_PE_P_AND_MLM_PE_C  16777306 
VALUE    Auth-Application-Id		ITU_T_M13                         16777307 
VALUE    Auth-Application-Id		3GPP_S7A                          16777308 
VALUE    Auth-Application-Id		3GPP_TSP                          16777309 
VALUE    Auth-Application-Id		3GPP_S6M                          16777310 
VALUE    Auth-Application-Id		3GPP_T4                           16777311 
VALUE    Auth-Application-Id		3GPP_S6C                          16777312 
VALUE    Auth-Application-Id		3GPP_SGD                          16777313 
VALUE    Auth-Application-Id		INTRADO_SLG                       16777314 
VALUE    Auth-Application-Id		ERICSSON_DSC                      16777315 
VALUE    Auth-Application-Id		VERIZON_FEMTO_LOC                 16777316 
VALUE    Auth-Application-Id		NSN_HD_APP                        16777317 
VALUE    Auth-Application-Id		3GPP_S15                          16777318 
VALUE    Auth-Application-Id		3GPP_S9A                          16777319 
VALUE    Auth-Application-Id		3GPP_S9A_STAR                     16777320 
VALUE    Auth-Application-Id		GATEWAY_LOCATION_APP              16777321 
VALUE    Auth-Application-Id		VERIZON_SESSION_RECOVERY          16777322 
VALUE    Auth-Application-Id		RELAY           4294967295

ATTRIBUTE User-Name                           1     UTF8String M
ATTRIBUTE Class                              25     OctetString M
ATTRIBUTE Session-Timeout                    27     Unsigned32 M
ATTRIBUTE Proxy-State                        33     OctetString M
ATTRIBUTE Event-Timestamp                    55     Time M
ATTRIBUTE Auth-Session-State                277     Enumerated M
ATTRIBUTE Host-IP-Address                   257     Address M
ATTRIBUTE Vendor-Specific-Application-Id    260     Grouped M
ATTRIBUTE Redirect-Host-Usage               261     Enumerated M
ATTRIBUTE Redirect-Max-Cache-Time           262     Unsigned32 M
ATTRIBUTE Session-Id                        263     UTF8String M
ATTRIBUTE Origin-Host                       264     DiameterIdentity M
ATTRIBUTE Supported-Vendor-Id               265     Unsigned32 M
ATTRIBUTE Vendor-Id                         266     Unsigned32 M
ATTRIBUTE Firmware-Revision                 267     Unsigned32
ATTRIBUTE Result-Code                       268     Enumerated M
ATTRIBUTE Product-Name                      269     UTF8String
ATTRIBUTE Session-Binding                   270     Enumerated M
ATTRIBUTE Session-Server-Failover           271     Enumerated M
ATTRIBUTE Multi-Round-Timeout               272     Unsigned32 M
ATTRIBUTE Disconnect-Cause                  273     Enumerated M
ATTRIBUTE Auth-Request-Type                 274     Enumerated M
ATTRIBUTE Auth-Grace-Period                 276     Unsigned32 M
ATTRIBUTE Origin-State-Id                   278     Unsigned32 M
ATTRIBUTE Failed-AVP                        279     Grouped M
ATTRIBUTE Proxy-Host                        280     DiameterIdentity M
ATTRIBUTE Error-Message                     281     UTF8String
ATTRIBUTE Route-Record                      282     DiameterIdentity M
ATTRIBUTE Destination-Realm                 283     DiameterIdentity M
ATTRIBUTE Proxy-Info                        284     Grouped M
ATTRIBUTE Re-Auth-Request-Type              285     Enumerated M
ATTRIBUTE Authorization-Lifetime            291     Unsigned32 M
ATTRIBUTE Redirect-Host                     292     DiameterURI M
ATTRIBUTE Destination-Host                  293     DiameterIdentity M
ATTRIBUTE Error-Reporting-Host              294     DiameterIdentity
ATTRIBUTE Termination-Cause                 295     Enumerated M
ATTRIBUTE Origin-Realm                      296     DiameterIdentity M
ATTRIBUTE Experimental-Result               297     Grouped M
ATTRIBUTE Experimental-Result-Code          298     Unsigned32 M
ATTRIBUTE Inband-Security-Id                299     Enumerated M
# E2E-Sequence-AVP was obsoleted by RFC 6733
ATTRIBUTE E2E-Sequence-AVP                  300     Grouped M

VALUE Accounting-Realtime-Required          DELIVER_AND_GRANT             1
VALUE Accounting-Realtime-Required          GRANT_AND_STORE               2
VALUE Accounting-Realtime-Required          GRANT_AND_LOSE                3

VALUE Accounting-Record-Type                EVENT_RECORD                  1
VALUE Accounting-Record-Type                START_RECORD                  2
VALUE Accounting-Record-Type                INTERIM_RECORD                3
VALUE Accounting-Record-Type                STOP_RECORD                   4

VALUE Auth-Request-Type                     AUTHENTICATE_ONLY             1
VALUE Auth-Request-Type                     AUTHORIZE_ONLY                2
VALUE Auth-Request-Type                     AUTHORIZE_AUTHENTICATE        3

VALUE Auth-Session-State                    STATE_MAINTAINED              0
VALUE Auth-Session-State                    NO_STATE_MAINTAINED           1

VALUE Re-Auth-Request-Type                  AUTHORIZE_ONLY                0
VALUE Re-Auth-Request-Type                  AUTHORIZE_AUTHENTICATE        1

VALUE Disconnect-Cause                      REBOOTING                     0
VALUE Disconnect-Cause                      BUSY                          1
VALUE Disconnect-Cause                      DO_NOT_WANT_TO_TALK_TO_YOU    2

VALUE Redirect-Host-Usage                   DONT_CACHE                    0
VALUE Redirect-Host-Usage                   ALL_SESSION                   1
VALUE Redirect-Host-Usage                   ALL_REALM                     2
VALUE Redirect-Host-Usage                   REALM_AND_APPLICATION         3
VALUE Redirect-Host-Usage                   ALL_APPLICATION               4
VALUE Redirect-Host-Usage                   ALL_HOST                      5
VALUE Redirect-Host-Usage                   ALL_USER                      6

# [RFC3588]
VALUE    Result-Code     DIAMETER_REDIRECT_INDICATION                     3006
VALUE    Result-Code     DIAMETER_INVALID_AVP_BITS                        3009
VALUE    Result-Code     DIAMETER_UNABLE_TO_COMPLY                        5012
VALUE    Result-Code     DIAMETER_UNABLE_TO_DELIVER                       3002
VALUE    Result-Code     DIAMETER_AVP_UNSUPPORTED                         5001
VALUE    Result-Code     DIAMETER_LIMITED_SUCCESS                         2002
VALUE    Result-Code     DIAMETER_SUCCESS                                 2001
VALUE    Result-Code     DIAMETER_INVALID_AVP_LENGTH                      5014
VALUE    Result-Code     DIAMETER_UNSUPPORTED_VERSION                     5011
VALUE    Result-Code     DIAMETER_NO_COMMON_SECURITY                      5017
VALUE    Result-Code     DIAMETER_INVALID_AVP_BIT_COMBO                   5016
VALUE    Result-Code     DIAMETER_UNKNOWN_SESSION_ID                      5002
VALUE    Result-Code     DIAMETER_INVALID_BIT_IN_HEADER                   5013
VALUE    Result-Code     DIAMETER_AVP_OCCURS_TOO_MANY_TIMES               5009
VALUE    Result-Code     DIAMETER_INVALID_HDR_BITS                        3008
VALUE    Result-Code     DIAMETER_APPLICATION_UNSUPPORTED                 3007
VALUE    Result-Code     DIAMETER_AUTHENTICATION_REJECTED                 4001
VALUE    Result-Code     DIAMETER_AUTHORIZATION_REJECTED                  5003
VALUE    Result-Code     DIAMETER_OUT_OF_SPACE                    4002
VALUE    Result-Code     DIAMETER_TOO_BUSY                        3004
VALUE    Result-Code     DIAMETER_COMMAND_UNSUPPORTED                     3001
VALUE    Result-Code     DIAMETER_UNKNOWN_PEER                    3010
VALUE    Result-Code     ELECTION_LOST                    4003
VALUE    Result-Code     DIAMETER_NO_COMMON_APPLICATION                   5010
VALUE    Result-Code     DIAMETER_INVALID_MESSAGE_LENGTH                  5015
VALUE    Result-Code     DIAMETER_INVALID_AVP_VALUE                       5004
VALUE    Result-Code     DIAMETER_LOOP_DETECTED                   3005
VALUE    Result-Code     DIAMETER_MISSING_AVP                     5005
VALUE    Result-Code     DIAMETER_REALM_NOT_SERVED                        3003
VALUE    Result-Code     DIAMETER_AVP_NOT_ALLOWED                         5008
VALUE    Result-Code     DIAMETER_MULTI_ROUND_AUTH                        1001
VALUE    Result-Code     DIAMETER_RESOURCES_EXCEEDED                      5006
VALUE    Result-Code     DIAMETER_CONTRADICTING_AVPS                      5007
# [RFC4004]
VALUE    Result-Code     DIAMETER_ERROR_END_TO_END_MIP_KEY_ENCRYPTION     5025
VALUE    Result-Code     DIAMETER_ERROR_NO_FOREIGN_HA_SERVICE             5024
VALUE    Result-Code     DIAMETER_ERROR_MIP_REPLY_FAILURE                 4005
VALUE    Result-Code     DIAMETER_ERROR_BAD_KEY                   4007
VALUE    Result-Code     DIAMETER_ERROR_MIP_FILTER_NOT_SUPPORTED          4008
VALUE    Result-Code     DIAMETER_ERROR_HA_NOT_AVAILABLE                  4006
# [RFC4006]
VALUE    Result-Code     DIAMETER_USER_UNKNOWN                    5030
VALUE    Result-Code     DIAMETER_CREDIT_CONTROL_NOT_APPLICABLE           4011
VALUE    Result-Code     DIAMETER_RATING_FAILED                   5031
VALUE    Result-Code     DIAMETER_END_USER_SERVICE_DENIED                 4010
VALUE    Result-Code     DIAMETER_CREDIT_LIMIT_REACHED                    4012
# [RFC4740]
VALUE    Result-Code     DIAMETER_FIRST_REGISTRATION                      2003
VALUE    Result-Code     DIAMETER_SUBSEQUENT_REGISTRATION                 2004
VALUE    Result-Code     DIAMETER_UNREGISTERED_SERVICE                    2005
VALUE    Result-Code     DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED          2006
VALUE    Result-Code     DIAMETER_SERVER_SELECTION                        2007
VALUE    Result-Code     DIAMETER_SUCCESS_AUTH_SENT_SERVER_NOT_STORED     2008
VALUE    Result-Code     DIAMETER_USER_NAME_REQUIRED                      4013
VALUE    Result-Code     DIAMETER_ERROR_USER_UNKNOWN                      5032
VALUE    Result-Code     DIAMETER_ERROR_IDENTITIES_DONT_MATCH             5033
VALUE    Result-Code     DIAMETER_ERROR_IDENTITY_NOT_REGISTERED           5034
VALUE    Result-Code     DIAMETER_ERROR_ROAMING_NOT_ALLOWED               5035
VALUE    Result-Code     DIAMETER_ERROR_IDENTITY_ALREADY_REGISTERED       5036
VALUE    Result-Code     DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED         5037
VALUE    Result-Code     DIAMETER_ERROR_IN_ASSIGNMENT_TYPE                5038
VALUE    Result-Code     DIAMETER_ERROR_TOO_MUCH_DATA                     5039
VALUE    Result-Code     DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA           5040
# [RFC4849]
VALUE    Result-Code     DIAMETER_RADIUS_AVP_UNTRANSLATABLE               5018

VALUE    Session-Binding	RE_AUTH                                   1
VALUE    Session-Binding	STR                                       2
VALUE    Session-Binding	ACCOUNTING                                4

VALUE Session-Server-Failover               REFUSE_SERVICE                0 
VALUE Session-Server-Failover               TRY_AGAIN                     1
VALUE Session-Server-Failover               ALLOW_SERVICE                 2
VALUE Session-Server-Failover               TRY_AGAIN_ALLOW_SERVICE       3

VALUE Termination-Cause                     DIAMETER_LOGOUT               1
VALUE Termination-Cause                     DIAMETER_SERVICE_NOT_PROVIDED 2
VALUE Termination-Cause                     DIAMETER_BAD_ANSWER           3
VALUE Termination-Cause                     DIAMETER_ADMINISTRATIVE       4
VALUE Termination-Cause                     DIAMETER_LINK_BROKEN          5
VALUE Termination-Cause                     DIAMETER_AUTH_EXPIRED         6
VALUE Termination-Cause                     DIAMETER_USER_MOVED           7
VALUE Termination-Cause                     DIAMETER_SESSION_TIMEOUT      8

VALUE Inband-Security-Id                    NO_INBAND_SECURITY            0
VALUE Inband-Security-Id                    TLS                           1


# From RFC 4005 and current RFC 7155
# Diameter NASREQ

ATTRIBUTE User-Password                      2     OctetString M
ATTRIBUTE NAS-Port                           5     Unsigned32 M
ATTRIBUTE Service-Type                       6     Enumerated M
ATTRIBUTE Framed-Protocol                    7     Enumerated M
ATTRIBUTE Framed-IP-Address                  8     OctetString M
ATTRIBUTE Framed-IP-Netmask                  9     OctetString M
ATTRIBUTE Termination-Action                19     Enumerated M
ATTRIBUTE Framed-Routing                    10     Enumerated M
ATTRIBUTE Filter-Id                         11     UTF8String M
ATTRIBUTE Framed-MTU                        12     Unsigned32 M
ATTRIBUTE Framed-Compression                13     Enumerated M
ATTRIBUTE Login-IP-Host                     14     OctetString M
ATTRIBUTE Login-Service                     15     Enumerated M
ATTRIBUTE Login-TCP-Port                    16     Unsigned32 M
ATTRIBUTE Reply-Message                     18     UTF8String M
ATTRIBUTE Callback-Number                   19     UTF8String M
ATTRIBUTE Callback-Id                       20     UTF8String M
ATTRIBUTE Framed-Route                      22     UTF8String M
ATTRIBUTE Framed-IPX-Network                23     UTF8String M
ATTRIBUTE Idle-Timeout                      28     Unsigned32 M
ATTRIBUTE Called-Station-Id                 30     UTF8String M
ATTRIBUTE Calling-Station-Id                31     UTF8String M
ATTRIBUTE Login-LAT-Service                 34     OctetString M
ATTRIBUTE Login-LAT-Node                    35     OctetString M
ATTRIBUTE Login-LAT-Group                   36     OctetString M
ATTRIBUTE Framed-Appletalk-Link             37     Unsigned32 M
ATTRIBUTE Framed-Appletalk-Network          38     Unsigned32 M
ATTRIBUTE Framed-Appletalk-Zone             39     OctetString M
ATTRIBUTE Acct-Delay-Time                   41     Unsigned32 M
ATTRIBUTE Acct-Authentic                    45     Enumerated M
ATTRIBUTE Acct-Session-Time                 46     Unsigned32 M
ATTRIBUTE Acct-Link-Count                   51     Unsigned32 M
ATTRIBUTE CHAP-Challenge                    60     OctetString M
ATTRIBUTE NAS-Port-Type                     61     Enumerated M
ATTRIBUTE Port-Limit                        62     Unsigned32 M
ATTRIBUTE Login-LAT-Port                    63     OctetString M
ATTRIBUTE Tunnel-Type                       64     Enumerated M
ATTRIBUTE Tunnel-Medium-Type                65     Enumerated M
ATTRIBUTE Tunnel-Client-Endpoint            66     UTF8String M
ATTRIBUTE Tunnel-Server-Endpoint            67     UTF8String M
ATTRIBUTE Acct-Tunnel-Connection            68     OctetString M
ATTRIBUTE Tunnel-Password                   69     OctetString M
ATTRIBUTE ARAP-Password                     70     OctetString M
ATTRIBUTE ARAP-Features                     71     OctetString M
ATTRIBUTE ARAP-Zone-Access                  72     Enumerated M
ATTRIBUTE ARAP-Security                     73     Unsigned32 M
ATTRIBUTE ARAP-Security-Data                74     OctetString M
ATTRIBUTE Password-Retry                    75     Unsigned32 M
ATTRIBUTE Prompt                            76     Enumerated M
ATTRIBUTE Connect-Info                      77     UTF8String M
ATTRIBUTE Configuration-Token               78     OctetString M
ATTRIBUTE Tunnel-Private-Group-Id           81     UTF8String M
ATTRIBUTE Tunnel-Assignment-Id              82     OctetString M
ATTRIBUTE Tunnel-Preference                 83     Unsigned32 M
ATTRIBUTE ARAP-Challenge-Response           84     OctetString M
ATTRIBUTE Acct-Tunnel-Packets-Lost          86     Unsigned32 M
ATTRIBUTE NAS-Port-Id                       87     UTF8String M
ATTRIBUTE Framed-Pool                       88     OctetString M
ATTRIBUTE Tunnel-Client-Auth-Id             90     OctetString M
ATTRIBUTE Tunnel-Server-Auth-Id             91     OctetString M
ATTRIBUTE Originating-Line-Info             94     OctetString M
ATTRIBUTE Framed-Interface-Id               96     Unsigned64 M
ATTRIBUTE Framed-IPv6-Prefix                97     OctetString M
ATTRIBUTE Login-IPv6-Host                   98     OctetString M
ATTRIBUTE Framed-IPv6-Route                 99     UTF8String M
ATTRIBUTE Framed-IPv6-Pool                 100     OctetString M
ATTRIBUTE Accounting-Input-Octets          363     Unsigned64 M
ATTRIBUTE Accounting-Output-Octets         364     Unsigned64 M
ATTRIBUTE Accounting-Input-Packets         365     Unsigned64 M
ATTRIBUTE Accounting-Output-Packets        366     Unsigned64 M
ATTRIBUTE NAS-Filter-Rule                  400     IPFilterRule M
ATTRIBUTE Tunneling                        401     Grouped M
ATTRIBUTE CHAP-Auth                        402     Grouped M
ATTRIBUTE CHAP-Algorithm                   403     Enumerated M
ATTRIBUTE CHAP-Ident                       404     OctetString M
ATTRIBUTE CHAP-Response                    405     OctetString M
ATTRIBUTE Accounting-Auth-Method           406     Enumerated M
ATTRIBUTE QoS-Filter-Rule                  407     QoSFilterRule
# [RFC4005]
ATTRIBUTE NAS-IP-Address                     4     OctetString M
ATTRIBUTE State                             24     OctetString M
ATTRIBUTE NAS-Identifier                    32     UTF8String M
ATTRIBUTE NAS-IPv6-Address                  95     OctetString M
ATTRIBUTE Origin-AAA-Protocol              408     Enumerated M
VALUE    Origin-AAA-Protocol     RADIUS                                         1

# [RFC4004]
ATTRIBUTE MIP-FA-to-HA-SPI                 318     Unsigned32 M
ATTRIBUTE MIP-FA-to-MN-SPI                 319     Unsigned32 M
ATTRIBUTE MIP-Reg-Request                  320     OctetString M
ATTRIBUTE MIP-Reg-Reply                    321     OctetString M
ATTRIBUTE MIP-MN-AAA-Auth                  322     Grouped M
ATTRIBUTE MIP-HA-to-FA-SPI                 323     Unsigned32 M
ATTRIBUTE MIP-MN-to-FA-MSA                 325     Grouped M
ATTRIBUTE MIP-FA-to-MN-MSA                 326     Grouped M
ATTRIBUTE MIP-FA-to-HA-MSA                 328     Grouped M
ATTRIBUTE MIP-HA-to-FA-MSA                 329     Grouped M
ATTRIBUTE MIP-MN-to-HA-MSA                 331     Grouped M
ATTRIBUTE MIP-HA-to-MN-MSA                 332     Grouped M
ATTRIBUTE MIP-Mobile-Node-Address          333     Address M
ATTRIBUTE MIP-Home-Agent-Address           334     Address M
ATTRIBUTE MIP-Nonce                        335     OctetString M
ATTRIBUTE MIP-Candidate-Home-Agent-Host    336     DiameterIdentity M
ATTRIBUTE MIP-Feature-Vector               337     Enumerated M
ATTRIBUTE MIP-Auth-Input-Data-Length       338     Unsigned32 M
ATTRIBUTE MIP-Authenticator-Length         339     Unsigned32 M
ATTRIBUTE MIP-Authenticator-Offset         340     Unsigned32 M
ATTRIBUTE MIP-MN-AAA-SPI                   341     Unsigned32 M
ATTRIBUTE MIP-Filter-Rule                  342     IPFilterRule M
ATTRIBUTE MIP-Session-Key                  343     OctetString M
ATTRIBUTE MIP-FA-Challenge                 344     OctetString M
ATTRIBUTE MIP-Algorithm-Type               345     Enumerated M
ATTRIBUTE MIP-Replay-Mode                  346     Enumerated M
ATTRIBUTE MIP-Originating-Foreign-AAA      347     Grouped M
ATTRIBUTE MIP-Home-Agent-Host              348     DiameterIdentity M
ATTRIBUTE MIP-MSA-Lifetime                 367     Unsigned32 M
# [RFC4004]
VALUE    MIP-Feature-Vector     Mobile-Node-Home-Address-Requested              1
VALUE    MIP-Feature-Vector     Home-Address-Allocatable-Only-in-Home-Realm     2
VALUE    MIP-Feature-Vector     Home-Agent-Requested                            4
VALUE    MIP-Feature-Vector     Foreign-Home-Agent-Available                    8
VALUE    MIP-Feature-Vector     MN-HA-Key-Request                              16
VALUE    MIP-Feature-Vector     MN-FA-Key-Request                              32
VALUE    MIP-Feature-Vector     FA-HA-Key-Request                              64
VALUE    MIP-Feature-Vector     Home-Agent-In-Foreign-Network                 128
VALUE    MIP-Feature-Vector     Co-Located-Mobile-Node                        256

VALUE    MIP-Algorithm-Type     HMAC-SHA-1                                      2

VALUE    MIP-Replay-Mode         None                                           1
VALUE    MIP-Replay-Mode         Timestamps                                     2
VALUE    MIP-Replay-Mode         Nonces                                         3


# [RFC4740]
ATTRIBUTE SIP-Accounting-Information       368     Grouped M
ATTRIBUTE SIP-Accounting-Server-URI        369     DiameterURI M
ATTRIBUTE SIP-Credit-Control-Server-URI    370     DiameterURI M
ATTRIBUTE SIP-Server-URI                   371     UTF8String M
ATTRIBUTE SIP-Server-Capabilities          372     Grouped M
ATTRIBUTE SIP-Mandatory-Capability         373     Unsigned32 M
ATTRIBUTE SIP-Optional-Capability          374     Unsigned32 M
ATTRIBUTE SIP-Server-Assignment-Type       375     Enumerated M
ATTRIBUTE SIP-Auth-Data-Item               376     Grouped M
ATTRIBUTE SIP-Authentication-Scheme        377     Enumerated M
ATTRIBUTE SIP-Item-Number                  378     Unsigned32 M
ATTRIBUTE SIP-Authenticate                 379     Grouped M
ATTRIBUTE SIP-Authorization                380     Grouped M
ATTRIBUTE SIP-Authentication-Info          381     Grouped M
ATTRIBUTE SIP-Number-Auth-Items            382     Unsigned32 M
ATTRIBUTE SIP-Deregistration-Reason        383     Grouped M
ATTRIBUTE SIP-Reason-Code                  384     Enumerated M
ATTRIBUTE SIP-Reason-Info                  385     UTF8String M
ATTRIBUTE SIP-Visited-Network-Id           386     UTF8String M
ATTRIBUTE SIP-User-Authorization-Type      387     Enumerated M
ATTRIBUTE SIP-Supported-User-Data-Type     388     UTF8String M
ATTRIBUTE SIP-User-Data                    389     Grouped M
ATTRIBUTE SIP-User-Data-Type               390     UTF8String M
ATTRIBUTE SIP-User-Data-Contents           391     OctetString M
ATTRIBUTE SIP-User-Data-Already-Available  392     Enumerated M
ATTRIBUTE SIP-Method                       393     UTF8String M
VALUE    SIP-Server-Assignment-Type      NO_ASSIGNMENT                            0
VALUE    SIP-Server-Assignment-Type      REGISTRATION                             1
VALUE    SIP-Server-Assignment-Type      RE_REGISTRATION                          2
VALUE    SIP-Server-Assignment-Type      UNREGISTERED_USER                        3
VALUE    SIP-Server-Assignment-Type      TIMEOUT_DEREGISTRATION                   4
VALUE    SIP-Server-Assignment-Type      USER_DEREGISTRATION                      5
VALUE    SIP-Server-Assignment-Type      TIMEOUT_DEREGISTRATION_STORE_SERVER_NAME 6
VALUE    SIP-Server-Assignment-Type      USER_DEREGISTRATION_STORE_SERVER_NAME    7
VALUE    SIP-Server-Assignment-Type      ADMINISTRATIVE_DEREGISTRATION            8
VALUE    SIP-Server-Assignment-Type      AUTHENTICATION_FAILURE                   9
VALUE    SIP-Server-Assignment-Type      AUTHENTICATION_TIMEOUT                  10
VALUE    SIP-Server-Assignment-Type      DEREGISTRATION_TOO_MUCH_DATA            11

VALUE    SIP-Server-Assignment-Type      DIGEST                                   0

VALUE    SIP-Reason-Code         PERMANENT_TERMINATION                            0
VALUE    SIP-Reason-Code         NEW_SIP_SERVER_ASSIGNED                          1
VALUE    SIP-Reason-Code         SIP_SERVER_CHANGE                                2
VALUE    SIP-Reason-Code         REMOVE_SIP_SERVER                                3

VALUE    SIP-User-Authorization-Type     REGISTRATION                             0
VALUE    SIP-User-Authorization-Type     DEREGISTRATION                           1
VALUE    SIP-User-Authorization-Type     REGISTRATION_AND_CAPABILITIES            2

VALUE    SIP-User-Data-Already-Available         USER_DATA_NOT_AVAILABLE          0
VALUE    SIP-User-Data-Already-Available         USER_DATA_ALREADY_AVAILABLE      1

# From RFC 4072:
ATTRIBUTE EAP-Key-Name                     102    OctetString M
ATTRIBUTE EAP-Payload                      462    OctetString M
ATTRIBUTE EAP-Reissued-Payload             463    OctetString M
ATTRIBUTE EAP-Master-Session-Key           464    OctetString M
ATTRIBUTE Accounting-EAP-Auth-Method       465    Unsigned64 M

VALUE Acct-Authentic                        RADIUS                      1
VALUE Acct-Authentic                        Local                       2
VALUE Acct-Authentic                        Remote                      3
VALUE Acct-Authentic                        Diameter                    4
VALUE Acct-Authentic                        PowerLink128              100

VALUE Accounting-Auth-Method                PAP                         1 
VALUE Accounting-Auth-Method                CHAP                        2
VALUE Accounting-Auth-Method                MS-CHAP-1                   3
VALUE Accounting-Auth-Method                MS-CHAP-2                   4
VALUE Accounting-Auth-Method                EAP                         5
VALUE Accounting-Auth-Method                None                        7

VALUE CHAP-Algorithm                        CHAP-With-MD5               5

VALUE Framed-Compression                    None                        0
VALUE Framed-Compression                    Van-Jacobsen-TCP-IP         1
# This is the correct and preferred spelling:
VALUE Framed-Compression                    Van-Jacobson-TCP-IP         1
VALUE Framed-Compression                    IPX-Header-Compression      2
VALUE Framed-Compression                    Stac-LZS                    3
              

VALUE Framed-Protocol                       PPP                         1
VALUE Framed-Protocol                       SLIP                        2
VALUE Framed-Protocol                       ARA                         3
VALUE Framed-Protocol                       Gandalf                     4
VALUE Framed-Protocol                       XYLOGICS-IPX-SLIP           5
VALUE Framed-Protocol                       X75                         6
VALUE Framed-Protocol                       GPRS-PDP-Context            7
VALUE Framed-Protocol                       Ascend-ARA                255
VALUE Framed-Protocol                       MPP                       256
VALUE Framed-Protocol                       EURAW                     257
VALUE Framed-Protocol                       EUUI                      258
VALUE Framed-Protocol                       X25                       259
VALUE Framed-Protocol                       COMB                      260
VALUE Framed-Protocol                       FR                        261

VALUE Framed-Routing                        None                        0
VALUE Framed-Routing                        Broadcast                   1
VALUE Framed-Routing                        Listen                      2
VALUE Framed-Routing                        Broadcast-Listen            3

VALUE Login-Service                         Telnet                      0
VALUE Login-Service                         Rlogin                      1
VALUE Login-Service                         TCP-Clear                   2
VALUE Login-Service                         PortMaster                  3
VALUE Login-Service                         LAT                         4
VALUE Login-Service                         X.25-PAD                    5
VALUE Login-Service                         X.25-T3POS                  6
VALUE Login-Service                         TCP-Clear-Quiet             8

VALUE NAS-Port-Type                         Async                       0
VALUE NAS-Port-Type                         Sync                        1
VALUE NAS-Port-Type                         ISDN                        2
VALUE NAS-Port-Type                         ISDN-V120                   3
VALUE NAS-Port-Type                         ISDN-V110                   4
VALUE NAS-Port-Type                         Virtual                     5
VALUE NAS-Port-Type                         PIAFS                       6
VALUE NAS-Port-Type                         HDLC-Clear-Channel          7
VALUE NAS-Port-Type                         X.25                        8
VALUE NAS-Port-Type                         X.75                        9
VALUE NAS-Port-Type                         G.3-Fax                     10
VALUE NAS-Port-Type                         SDSL                        11
VALUE NAS-Port-Type                         ADSL-CAP                    12
VALUE NAS-Port-Type                         ADSL-DMT                    13
VALUE NAS-Port-Type                         IDSL                        14
VALUE NAS-Port-Type                         Ethernet                    15
VALUE NAS-Port-Type                         xDSL                        16
VALUE NAS-Port-Type                         Cable                       17
VALUE NAS-Port-Type                         Wireless-Other              18
VALUE NAS-Port-Type                         Wireless-IEEE-802-11        19
VALUE NAS-Port-Type                         Token-Ring                  20
VALUE NAS-Port-Type                         FDDI                        21
VALUE NAS-Port-Type                         Wireless-CDMA2000           22
VALUE NAS-Port-Type                         Wireless-UMTS               23
VALUE NAS-Port-Type                         Wireless-1X-EV              24
VALUE NAS-Port-Type                         IAPP                        25

VALUE Originating-Line-Info                 POTS                         0
VALUE Originating-Line-Info                 Multiparty                   1
VALUE Originating-Line-Info                 ANI-Failure                  2
VALUE Originating-Line-Info                 ANI-Observed                 3
VALUE Originating-Line-Info                 ONI-Observed                 4
VALUE Originating-Line-Info                 ANI-Failure-Observed         5
VALUE Originating-Line-Info                 Station-Level-Rating         6
VALUE Originating-Line-Info                 Special-Operator-Handling    7
VALUE Originating-Line-Info                 InterLATA-restricted         8
VALUE Originating-Line-Info                 Test-Call                   10
VALUE Originating-Line-Info                 Automatic-Identified-Outward-Dialing 20
VALUE Originating-Line-Info                 Coin-or-Non-Coin            23
VALUE Originating-Line-Info                 Toll-Free-Non-Pay           24
VALUE Originating-Line-Info                 Toll-Free-Pay               25
VALUE Originating-Line-Info                 Toll-Free-Coin-Control      27
VALUE Originating-Line-Info                 Prison-Inmate-Service       29
VALUE Originating-Line-Info                 Intercept-Blank             30
VALUE Originating-Line-Info                 Intercept-Trouble           31
VALUE Originating-Line-Info                 Intercept-Regular           32
VALUE Originating-Line-Info                 Telco-Operator-Handled      34
VALUE Originating-Line-Info                 OUTWATS                     52
VALUE Originating-Line-Info                 TRS-Unrestricted            60
VALUE Originating-Line-Info                 Cellular-Wireless-PCS-1     61
VALUE Originating-Line-Info                 Cellular-Wireless-PCS-2     62
VALUE Originating-Line-Info                 Cellular-Wireless-PCS-Roaming 63
VALUE Originating-Line-Info                 TRS-Hotel                   66
VALUE Originating-Line-Info                 TRS-Restricted              67
VALUE Originating-Line-Info                 Pay-Station-No-Coin         70
VALUE Originating-Line-Info                 Private-Virtual             93

VALUE Prompt                                No-Echo                      0
VALUE Prompt                                Echo                         1

VALUE Service-Type                          Login-User                   1
VALUE Service-Type                          Framed-User                  2
VALUE Service-Type                          Callback-Login-User          3
VALUE Service-Type                          Callback-Framed-User         4
VALUE Service-Type                          Outbound-User                5
VALUE Service-Type                          Administrative-User          6
VALUE Service-Type                          NAS-Prompt-User              7
VALUE Service-Type                          Authenticate-Only            8
VALUE Service-Type                          Callback-Admin-User          9
VALUE Service-Type                          Call-Check                   10
VALUE Service-Type                          Callback-Administrative      11
VALUE Service-Type                          Voice                        12
VALUE Service-Type                          Fax                          13
VALUE Service-Type                          Modem-Relay                  14
VALUE Service-Type                          IAPP-Register                15
VALUE Service-Type                          IAPP-AP-Check                16
VALUE Service-Type                          Authorize-Only               17
VALUE Service-Type                          Cisco-VoIP                   98
VALUE Service-Type                          Framed-User-Roaming         100
VALUE Service-Type                          GRIC-PhoneHandset-User      102
VALUE Service-Type                          GRIC-PhonePC-User           103
VALUE Service-Type                          GRIC-Fax-User               104
VALUE Service-Type                          GRIC-PhoneHandset-User-Roaming 105
VALUE Service-Type                          GRIC-PhonePC-User-Roaming   106
VALUE Service-Type                          GRIC-Fax-User-Roaming       107
VALUE Service-Type                          GRIC-Login-User-Roaming     108
VALUE Service-Type                          Call-Check-User             129

# These names need to match the names in the Radius dictionary for value mapping purposes
VALUE Termination-Cause                     User-Request                11
VALUE Termination-Cause                     Lost-Carrier                12
VALUE Termination-Cause                     Lost-Service                13
VALUE Termination-Cause                     Idle-Timeout                14
VALUE Termination-Cause                     Session-Timeout             15
VALUE Termination-Cause                     Admin-Reset                 16
VALUE Termination-Cause                     Admin-Reboot                17
VALUE Termination-Cause                     Port-Error                  18
VALUE Termination-Cause                     NAS-Error                   19
VALUE Termination-Cause                     NAS-Request                 20
VALUE Termination-Cause                     NAS-Reboot                  21
VALUE Termination-Cause                     Port-Unneeded               22
VALUE Termination-Cause                     Port-Preempted              23
VALUE Termination-Cause                     Port-Suspended              24
VALUE Termination-Cause                     Service-Unavailable         25
VALUE Termination-Cause                     Callback                    26
VALUE Termination-Cause                     User-Error                  27
VALUE Termination-Cause                     Host-Request                28
VALUE Termination-Cause                     Supplicant-Restart          29
VALUE Termination-Cause                     Reauthentication-Failure    30
VALUE Termination-Cause                     Port-Reinit                 31
VALUE Termination-Cause                     Port-Disabled               32

VALUE Tunnel-Medium-Type                    IP                          1
VALUE Tunnel-Medium-Type                    X25                         2
VALUE Tunnel-Medium-Type                    ATM                         3
VALUE Tunnel-Medium-Type                    Frame-Relay                 4
VALUE Tunnel-Medium-Type                    BBN-1822                    5
VALUE Tunnel-Medium-Type                    802                         6
VALUE Tunnel-Medium-Type                    H-163                       7
VALUE Tunnel-Medium-Type                    H-164                       8
VALUE Tunnel-Medium-Type                    F-69                        9
VALUE Tunnel-Medium-Type                    X-121                      10
VALUE Tunnel-Medium-Type                    IPX                        11
VALUE Tunnel-Medium-Type                    Appletalk                  12
VALUE Tunnel-Medium-Type                    Decnet-IV                  13
VALUE Tunnel-Medium-Type                    Banyan-Vines               14
VALUE Tunnel-Medium-Type                    H-164-NSAP                 15

VALUE Tunnel-Type                           PPTP                         1
VALUE Tunnel-Type                           L2F                          2
VALUE Tunnel-Type                           L2TP                         3
VALUE Tunnel-Type                           ATMP                         4
VALUE Tunnel-Type                           VTP                          5
VALUE Tunnel-Type                           AH                           6
VALUE Tunnel-Type                           IP                           7
VALUE Tunnel-Type                           MIN-IP                       8
VALUE Tunnel-Type                           ESP                          9
VALUE Tunnel-Type                           GRE                         10
VALUE Tunnel-Type                           DVS                         11
VALUE Tunnel-Type                           IP-in-IP                    12
VALUE Tunnel-Type                           VLAN                        13

# RFC 4006: Diameter Credit-Control Application
#

VENDOR		3GPP	10415
# 3GPP TS 29.061 V11.5.0: Interworking between the Public Land Mobile Network (PLMN) supporting packet based services and Packet Data Networks (PDN)
# Note: these are actually RADIUS attributes that are also used with Diameter.
# This is why there are aliases and we use non-Diameter type Enumerated8.
#
VENDORATTR      10415   3GPP-IMSI                      		1       UTF8String
VENDORATTR      10415   3GPP-Charging-Id               		2       OctetString
VENDORATTR      10415   3GPP-PDP-Type                  		3       Enumerated
VENDORATTR      10415   3GPP-Charging-Gateway-Address  		4       OctetString
VENDORATTR      10415   3GPP-CG-Address                		4       OctetString
VENDORATTR      10415   3GPP-GPRS-Negotiated-QoS-Profile	5       UTF8String
VENDORATTR      10415   3GPP-GPRS-QoS-Profile          		5       UTF8String
VENDORATTR      10415   3GPP-SGSN-Address              		6       OctetString
VENDORATTR      10415   3GPP-GGSN-Address              		7       OctetString
VENDORATTR      10415   3GPP-IMSI-MCC-MNC              		8       UTF8String
VENDORATTR      10415   3GPP-GGSN-MCC-MNC              		9       UTF8String
VENDORATTR      10415   3GPP-NSAPI                     		10      OctetString
VENDORATTR      10415   3GPP-Session-Stop-Indicator    		11      OctetString
VENDORATTR      10415   3GPP-Selection-Mode            		12      UTF8String
VENDORATTR      10415   3GPP-Charging-Characteristics  		13      UTF8String
VENDORATTR      10415   3GPP-Charging-Gateway-IPv6-Address	14      OctetString
VENDORATTR      10415   3GPP-CG-IPv6-address			14      OctetString
VENDORATTR      10415   3GPP-SGSN-IPv6-Address			15      OctetString
VENDORATTR      10415   3GPP-GGSN-IPv6-Address			16      OctetString
VENDORATTR      10415   3GPP-IPv6-DNS-Servers			17      OctetString
VENDORATTR      10415   3GPP-SGSN-MCC-MNC	 		18      UTF8String
VENDORATTR      10415   3GPP-Teardown-Indicator        		19      OctetString
VENDORATTR      10415   3GPP-IMEISV                    		20      OctetString
VENDORATTR      10415   3GPP-RAT-Type                  		21      Enumerated8
VENDORATTR      10415   3GPP-User-Location-Info        		22      OctetString
VENDORATTR      10415   3GPP-MS-Timezone               		23      OctetString
VENDORATTR      10415   3GPP-Camel-Charging-Info       		24      OctetString
VENDORATTR      10415   3GPP-Packet-Filter             		25      OctetString
VENDORATTR      10415   3GPP-Negotiated-DSCP           		26      OctetString
VENDORATTR      10415   3GPP-Allocate-IP-Type			27	Enumerated8

# IP was used for value 0 in the original documents and changed later to IPv4
VALUE	3GPP-PDP-Type               IPv4	0
VALUE	3GPP-PDP-Type               IP		0
VALUE	3GPP-PDP-Type               PPP		1
VALUE	3GPP-PDP-Type               IPv6	2
VALUE	3GPP-PDP-Type               IPv4v6	3

# From 3GPP TS 29.274 V11.8.0
VALUE	3GPP-RAT-Type               reserved		0
VALUE	3GPP-RAT-Type               UTRAN		1
VALUE	3GPP-RAT-Type               GERAN		2
VALUE	3GPP-RAT-Type               WLAN		3
VALUE	3GPP-RAT-Type               GAN			4
VALUE	3GPP-RAT-Type               HSPA-Evolution	5
VALUE	3GPP-RAT-Type               EUTRAN		6
VALUE	3GPP-RAT-Type               Virtual		7
# From 3GPP TS 29.061 V11.5.0
VALUE	3GPP-RAT-Type               IEEE-802.16e	101
VALUE	3GPP-RAT-Type               3GGP2-eHRPD		102
VALUE	3GPP-RAT-Type               3GGP2-HRPD		103
VALUE	3GPP-RAT-Type               3GGP2-1xRTT		104
VALUE	3GPP-RAT-Type               3GGP2-UMB		105

VALUE	3GPP-Allocate-IP-Type       Do-Not-Allocate-IPv4-Address-Or-IPv6-Prefix     0
VALUE	3GPP-Allocate-IP-Type       Allocate-IPv4-Address                           1
VALUE	3GPP-Allocate-IP-Type       Allocate-IPv6-Prefix                            2
VALUE	3GPP-Allocate-IP-Type       Allocate-IPv4-Address-And-IPv6-Prefix           3

# These are from: "ETSI TS 129 230 V6.3.0 (2005-03)"
# http://www.etsi.org/deliver/etsi_ts/129200_129299/129230/06.03.00_60/ts_129230v060300p.pdf
VENDORATTR	10415	3GPP-Authentication-Method			300	Enumerated
VENDORATTR	10415	3GPP-Authentication-Information-SIM		301	OctetString
VENDORATTR	10415	3GPP-Authorization-Information-SIM		302	OctetString

VALUE    3GPP-Authentication-Method                  EAP_SIM		0
VALUE    3GPP-Authentication-Method                  EAP_AKA		1

# These are effectively from: "ETSI TS 129 229 V5.11.0 (2005-09)"
# http://www.etsi.org/deliver/etsi_ts/129200_129299/129229/05.11.00_60/ts_129229v051100p.pdf
VENDORATTR	10415	3GPP-SIP-Number-Auth-Items			607	Unsigned32
VENDORATTR	10415	3GPP-SIP-Authentication-Scheme		608	UTF8String
VENDORATTR	10415	3GPP-SIP-Authenticate			609	OctetString
VENDORATTR	10415	3GPP-SIP-Authorization			610	OctetString
VENDORATTR	10415	3GPP-SIP-Authentication-Context		611	OctetString
VENDORATTR	10415	3GPP-SIP-Auth-Data-Item			612	Grouped
VENDORATTR	10415	3GPP-SIP-Item-Number			613	Unsigned32
VENDORATTR	10415	3GPP-Confidentiality-Key		625	OctetString
VENDORATTR	10415	3GPP-Integrity-Key			626	OctetString
VENDORATTR	10415	3GPP-SIP-Digest-Authenticate		635	Grouped

VENDORATTR	10415	3GPP-MSISDN				701	OctetString
VENDORATTR	10415	3GPP-Time-Quota-Threshold		868	Unsigned32
VENDORATTR	10415	3GPP-Volume-Quota-Threshold		869	Unsigned32
VENDORATTR	10415	3GPP-Trigger-Type			870	Enumerated
VENDORATTR	10415	3GPP-Quota-Holding-Time			871	Unsigned32
VENDORATTR	10415	3GPP-Reporting-Reason			872	Enumerated
VENDORATTR	10415	3GPP-Service-Information		873	Grouped
VENDORATTR	10415	3GPP-PS-Information			874	Grouped
VENDORATTR	10415	3GPP-WLAN-Information			875	UTF8String
VENDORATTR	10415	3GPP-IMS-Information			876	UTF8String
VENDORATTR	10415	3GPP-MMS-Information			877	Grouped
VENDORATTR	10415	3GPP-MMS-Information			877	UTF8String
VENDORATTR	10415	3GPP-LCS-Information			878	Grouped
VENDORATTR	10415	3GPP-PoC-Information			879	UTF8String
VENDORATTR	10415	3GPP-MBMS-Information			880	UTF8String
VENDORATTR	10415	3GPP-Quota-Consumption-Time		881	Unsigned32
VENDORATTR	10415	3GPP-Originator-Address			886	Grouped
VENDORATTR	10415	3GPP-Expires				888	Unsigned32
VENDORATTR	10415	3GPP-Address-Data			897	UTF8String
VENDORATTR	10415	3GPP-Address-Domain			898	Grouped
VENDORATTR	10415	3GPP-Address-Type			899	Enumerated
VENDORATTR	10415	3GPP-Charging-Rule-Base-Name		1004	UTF8String

# 3GPP TS 32.299: Telecommunication management; Charging management; Diameter charging applications
#
VENDORATTR	10415	3GPP-Domain-Name			1200	UTF8String
VENDORATTR	10415	3GPP-Recipient-Address			1201	Grouped
VENDORATTR	10415	3GPP-Submission-Time			1202	Time
VENDORATTR	10415	3GPP-MM-Content-Type			1203	Grouped
VENDORATTR	10415	3GPP-Type-Number			1204	Enumerated
VENDORATTR	10415	3GPP-Additional-Type-Information	1205	UTF8String
VENDORATTR	10415	3GPP-Content-Size			1206	Unsigned32
VENDORATTR	10415	3GPP-Additional-Content-Information	1207	Grouped
VENDORATTR	10415	3GPP-Message-Id				1210	UTF8String
VENDORATTR	10415	3GPP-Message-Type			1211	Enumerated
VENDORATTR	10415	3GPP-Message-Size			1212	Unsigned32
VENDORATTR	10415	3GPP-Message-Class			1213	Grouped
VENDORATTR	10415	3GPP-Class-Identifier			1214	Enumerated
VENDORATTR	10415	3GPP-Token-Text				1215	UTF8String
VENDORATTR	10415	3GPP-Delivery-Report-Requested		1216	Enumerated
VENDORATTR	10415	3GPP-Applic-ID				1218	UTF8String
VENDORATTR	10415	3GPP-Read-Reply-Report-Requested	1222	Enumerated
VENDORATTR	10415	3GPP-PDP-Address			1227	Address
VENDORATTR	10415	3GPP-SGSN-Address			1228	Address
VENDORATTR	10415	LCS-Client-Dialed-By-MS		1233	UTF8String
VENDORATTR	10415   LCS-Client-External-ID		1234	UTF8String
VENDORATTR	10415   LCS-Client-ID			1232	Grouped
VENDORATTR	10415   LCS-Client-Name			1235	Grouped
VENDORATTR	10415   LCS-Data-Coding-Scheme		1236	UTF8String
VENDORATTR	10415   LCS-Format-Indicator		1237	Enumerated
VENDORATTR	10415   LCS-Name-String			1238	UTF8String
VENDORATTR	10415   LCS-Requestor-ID		1239	Grouped
VENDORATTR	10415   LCS-Requestor-ID-String		1240	UTF8String
VENDORATTR	10415   LCS-Client-Type			1241	Enumerated
# 32.299 Change Requests CR 0335 and CR 0336 change Location-Estimate to OctetString from UTF8String
VENDORATTR	10415   Location-Estimate		1242	OctetString
VENDORATTR	10415   Location-Estimate-Type		1243	Enumerated
VENDORATTR	10415   Location-Type			1244	Grouped
VENDORATTR	10415   Positioning-Data		1245	UTF8String


VALUE    3GPP-Address-Type                            e-mail_address                   0
VALUE    3GPP-Address-Type                            MSISDN                           1
VALUE    3GPP-Address-Type                            IPv4_Address                     2
VALUE    3GPP-Address-Type                            IPv6_Address                     3
VALUE    3GPP-Address-Type                            Numeric_Shortcode                4
VALUE    3GPP-Address-Type                            Alphanumeric_Shortcode           5
VALUE    3GPP-Address-Type                            Other                            6

VALUE    3GPP-Class-Identifier	Personal	0
VALUE    3GPP-Class-Identifier	Advertisement	1
VALUE    3GPP-Class-Identifier	Informational	2
VALUE    3GPP-Class-Identifier	Auto	3

VALUE    3GPP-Delivery-Report-Requested	No	0
VALUE    3GPP-Delivery-Report-Requested	Yes	1

VALUE    LCS-Client-Type	EMERGENCY_SERVICES	0
VALUE    LCS-Client-Type	VALUE_ADDED_SERVICES	1
VALUE    LCS-Client-Type	PLMN_OPERATOR_SERVICES	2
VALUE    LCS-Client-Type	LAWFUL_INTERCEPT_SERVICES	3

VALUE    LCS-Format-Indicator	LOGICAL_NAME	0
VALUE    LCS-Format-Indicator	EMAIL_ADDRESS	1
VALUE    LCS-Format-Indicator	MSISDN	2
VALUE    LCS-Format-Indicator	URL	3
VALUE    LCS-Format-Indicator	SIP_URL	4

VALUE    Location-Estimate-Type	CURRENT_LOCATION	0
VALUE    Location-Estimate-Type	CURRENT_LAST_KNOWN_LOCATION	1
VALUE    Location-Estimate-Type	INITIAL_LOCATION	2
VALUE    Location-Estimate-Type	ACTIVATE_DEFERRED_LOCATION	3
VALUE    Location-Estimate-Type	CANCEL_DEFERRED_LOCATION	4

VALUE    3GPP-Message-Type	m-send-req	1
VALUE    3GPP-Message-Type	m-send-conf	2
VALUE    3GPP-Message-Type	m-notification-ind	3
VALUE    3GPP-Message-Type	m-notifyresp-ind	4

VALUE    3GPP-Read-Reply-Report-Requested	No	0
VALUE    3GPP-Read-Reply-Report-Requested	Yes	1

VALUE    3GPP-Reporting-Reason	THRESHOLD	0
VALUE    3GPP-Reporting-Reason	QHT	1
VALUE    3GPP-Reporting-Reason	FINAL	2
VALUE    3GPP-Reporting-Reason	QUOTA_EXHAUSTED	3
VALUE    3GPP-Reporting-Reason	VALIDITY_TIME	4
VALUE    3GPP-Reporting-Reason	OTHER_QUOTA_TYPE	5
VALUE    3GPP-Reporting-Reason	RATING_CONDITION_CHANGE	6
VALUE    3GPP-Reporting-Reason	FORCED_REAUTHORISATION	7
VALUE    3GPP-Reporting-Reason	POOL_EXHAUSTED	8

VALUE    3GPP-Trigger-Type	CHANGE_IN_SGSN_IP_ADDRESS	1
VALUE    3GPP-Trigger-Type	CHANGE_IN_QOS			2
VALUE    3GPP-Trigger-Type	CHANGE_IN_LOCATION		3
VALUE    3GPP-Trigger-Type	CHANGE_IN_RAT			4
VALUE    3GPP-Trigger-Type	CHANGEINQOS_TRAFFIC_CLASS	10
VALUE    3GPP-Trigger-Type	CHANGEINQOS_RELIABILITY_CLASS	11
VALUE    3GPP-Trigger-Type	CHANGEINQOS_DELAY_CLASS		12
VALUE    3GPP-Trigger-Type	CHANGEINQOS_PEAK_THROUGHPUT	13
VALUE    3GPP-Trigger-Type	CHANGEINQOS_PRECEDENCE_CLASS	14
VALUE    3GPP-Trigger-Type	CHANGEINQOS_MEAN_THROUGHPUT	15
VALUE    3GPP-Trigger-Type	CHANGEINQOS_MAXIMUM_BIT_RATE_FOR_UPLINK	16
VALUE    3GPP-Trigger-Type	CHANGEINQOS_MAXIMUM_BIT_RATE_FOR_DOWNLINK	17
VALUE    3GPP-Trigger-Type	CHANGEINQOS_RESIDUAL_BER	18
VALUE    3GPP-Trigger-Type	CHANGEINQOS_SDU_ERROR_RATIO	19
VALUE    3GPP-Trigger-Type	CHANGEINQOS_TRANSFER_DELAY	20
VALUE    3GPP-Trigger-Type	CHANGEINQOS_TRAFFIC_HANDLING_PRIORITY	21
VALUE    3GPP-Trigger-Type	CHANGEINQOS_GUARANTEED_BIT_RATE_FOR_UPLINK	22
VALUE    3GPP-Trigger-Type	CHANGEINQOS_GUARANTEED_BIT_RATE_FOR_DOWNLINK	23
VALUE    3GPP-Trigger-Type	CHANGEINLOCATION_MCC	30
VALUE    3GPP-Trigger-Type	CHANGEINLOCATION_MNC	31
VALUE    3GPP-Trigger-Type	CHANGEINLOCATION_RAC	32
VALUE    3GPP-Trigger-Type	CHANGEINLOCATION_LAC	33
VALUE    3GPP-Trigger-Type	CHANGEINLOCATION_CellId	34
VALUE    3GPP-Trigger-Type	CHANGEINPARTICIPANTS_Number	50

VALUE    3GPP-Type-Number	text/*	1
VALUE    3GPP-Type-Number	text/html	2
VALUE    3GPP-Type-Number	text/plain	3
VALUE    3GPP-Type-Number	video/*	4F
VALUE    3GPP-Type-Number	text/x-vCalendar	6
VALUE    3GPP-Type-Number	image/*	28
VALUE    3GPP-Type-Number	image/gif	29
VALUE    3GPP-Type-Number	image/jpeg	30
VALUE    3GPP-Type-Number	image/tiff	31
VALUE    3GPP-Type-Number	image/png	32
VALUE    3GPP-Type-Number	image/vnd.wap.wbmp	33
VALUE    3GPP-Type-Number	application/vnd.wap.multipart.*	34
VALUE    3GPP-Type-Number	audio/*	50


