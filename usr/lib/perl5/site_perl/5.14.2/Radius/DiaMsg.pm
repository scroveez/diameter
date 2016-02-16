# DiaMsg.pm
#
# Routines for packing and unpacking Diameter message
#
# Part of the Radius project.
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2004 Open System Consultants
# $Id: DiaMsg.pm,v 1.11 2014/01/27 21:56:40 hvn Exp $
package Radius::DiaMsg;
use base ('Radius::DiaAttrList');
use strict;

# RCS version number of this module
$Radius::DiaMsg::VERSION = '$Revision: 1.11 $';

# Base Command codes
$Radius::DiaMsg::CODE_ASR              = 274;
$Radius::DiaMsg::CODE_ACR              = 271;
$Radius::DiaMsg::CODE_CER              = 257;
$Radius::DiaMsg::CODE_DWR              = 280;
$Radius::DiaMsg::CODE_DPR              = 282;
$Radius::DiaMsg::CODE_RAR              = 258;
$Radius::DiaMsg::CODE_STR              = 275;
$Radius::DiaMsg::CODE_CCR              = 272;

#RFC 4740
$Radius::DiaMsg::CODE_UAR              = 283;
$Radius::DiaMsg::CODE_SAR              = 284;
$Radius::DiaMsg::CODE_LIR              = 285;
$Radius::DiaMsg::CODE_MAR              = 286;
$Radius::DiaMsg::CODE_RTR              = 287;
$Radius::DiaMsg::CODE_PPR              = 288;

# RFC 4004
$Radius::DiaMsg::CODE_AMR              = 260;
$Radius::DiaMsg::CODE_HAR              = 262;

# Base command flags
$Radius::DiaMsg::FLAG_REQUEST          = 0x80;
$Radius::DiaMsg::FLAG_PROXIABLE        = 0x40;
$Radius::DiaMsg::FLAG_ERROR            = 0x20;
$Radius::DiaMsg::FLAG_RETRANSMITTED    = 0x10;

$Radius::DiaMsg::APPID_BASE            = 0;
$Radius::DiaMsg::APPID_NASREQ          = 1;
$Radius::DiaMsg::APPID_MOBILE_IP       = 2;
$Radius::DiaMsg::APPID_BASE_ACCOUNTING = 3;
$Radius::DiaMsg::APPID_CREDIT_CONTROL  = 4;
$Radius::DiaMsg::APPID_RELAY           = 0xffffffff;


# From http://www.iana.org/assignments/aaa-parameters
$Radius::DiaMsg::APPID_DIAMETER_EAP                     = 5 ;                   # [RFC4072]
$Radius::DiaMsg::APPID_DIAMETER_SIP                     = 6 ;                   # [RFC4740]
$Radius::DiaMsg::APPID_DIAMETER_MIP6I                   = 7 ;                   # [RFC5778]
$Radius::DiaMsg::APPID_DIAMETER_MIP6A                   = 8 ;                   # [RFC5778]
$Radius::DiaMsg::APPID_DIAMETER_QOS                     = 9 ;                   # [RFC5866]
$Radius::DiaMsg::APPID_DIAMETER_CAPABILITIES_UPDATE     = 10 ;                  # [RFC-ietf-dime-capablities-update-07]
$Radius::DiaMsg::APPID_DIAMETER_IKESK                   = 11 ;                  # [RFC-ietf-dime-ikev2-psk-diameter-11]
$Radius::DiaMsg::APPID_DIAMETER_NAT                     = 12 ;                  # [RFC-ietf-dime-nat-control-17]

$Radius::DiaMsg::APPID_3GPP_CX                          = 16777216 ;            # [3GPP-TS-29.228]
$Radius::DiaMsg::APPID_3GPP_SH                          = 16777217 ;            # [3GPP-TS-29.328]
$Radius::DiaMsg::APPID_3GPP_RE                          = 16777218 ;            # [3GPP-TS-32.296]
$Radius::DiaMsg::APPID_3GPP_WX                          = 16777219 ;            # [3GPP-TS-29.234]
$Radius::DiaMsg::APPID_3GPP_ZN                          = 16777220 ;            # [3GPP-TS-29.109]
$Radius::DiaMsg::APPID_3GPP_ZH                          = 16777221 ;            # [3GPP-TS-29.109]
$Radius::DiaMsg::APPID_3GPP_GQ                          = 16777222 ;            # [3GPP-TS-29.209]
$Radius::DiaMsg::APPID_3GPP_GMB                         = 16777223 ;            # [3GPP-TS-29.061]
$Radius::DiaMsg::APPID_3GPP_GX_REL6                     = 16777224 ;            # [3GPP-TS-29.210]
$Radius::DiaMsg::APPID_3GPP_GX_OVER_GY                  = 16777225 ;            # [3GPP-TS-29.210]
$Radius::DiaMsg::APPID_3GPP_MM10                        = 16777226 ;            # [3GPP-TS-29.140]
$Radius::DiaMsg::APPID_ERICSSON_MSI                     = 16777227 ;            # [Blanco]
$Radius::DiaMsg::APPID_ERICSSON_ZX                      = 16777228 ;            # [Blanco]
$Radius::DiaMsg::APPID_3GPP_RX_REL6                     = 16777229 ;            # [3GPP-TS-29.211]
$Radius::DiaMsg::APPID_3GPP_PR                          = 16777230 ;            # [3GPP-TS-29.234]
$Radius::DiaMsg::APPID_ETSI_E4                          = 16777231 ;            # [ETSI-ES-283-034]
$Radius::DiaMsg::APPID_ERICSSON_CHARGING_CIP            = 16777232 ;            # [Almen]
$Radius::DiaMsg::APPID_ERICSSON_MM                      = 16777233 ;            # [Blanco]
$Radius::DiaMsg::APPID_VODAFONE_GX_PLUS                 = 16777234 ;            # [Oertel]
$Radius::DiaMsg::APPID_ITU_T_RS                         = 16777235 ;            # [ITU-T-Rec.-Q.3301.1]
$Radius::DiaMsg::APPID_3GPP_RX                          = 16777236 ;            # [3GPP-TS-29.214]
$Radius::DiaMsg::APPID_3GPP2_TY                         = 16777237 ;            # [Mahendran]
$Radius::DiaMsg::APPID_3GPP_GX                          = 16777238 ;            # [3GPP-TS-29.212]
$Radius::DiaMsg::APPID_JUNIPER_CLUSTER                  = 16777239 ;            # [Dzhitenov]
$Radius::DiaMsg::APPID_JUNIPER_POLICY_CONTROL_AAA       = 16777240 ;            # [Ries]
$Radius::DiaMsg::APPID_IPTEGO_USPI                      = 16777241 ;            # [Schubert]
$Radius::DiaMsg::APPID_COVERGENCE_SPECIFIC_SIP_ROUTING  = 16777242 ;            # [Del-Vecchio]
$Radius::DiaMsg::APPID_POLICY_PROCESSING                = 16777243 ;            # [OMA-PEEM-V1.0]
$Radius::DiaMsg::APPID_JUNIPER_POLICY_CONTROL_JSRC      = 16777244 ;            # [Chang]
$Radius::DiaMsg::APPID_ITU_T_S_TC1                      = 16777245 ;            # [ITU-T Recommendation Q.3221][Kwihoon_Kim]
$Radius::DiaMsg::APPID_NSN_UCTF                         = 16777246 ;            # [http://www.3gpp.org/ftp/Specs/][Dan_D_Albuquerque]
$Radius::DiaMsg::APPID_3GPP2_CAN_ACCESS_AUTHN_AND_AUTHZ = 16777247 ;            # [ftp://ftp.3gpp2.org/TSGX/Projects/][Avi_Lior]
$Radius::DiaMsg::APPID_3GPP2_WLAN_INTERWORKING_AAA      = 16777248 ;            # [ftp://ftp.3gpp2.org/TSGX/Projects/][Avi_Lior]
$Radius::DiaMsg::APPID_3GPP2_WLAN_INTERWORKING_ACCT     = 16777249 ;            # [ftp://ftp.3gpp2.org/TSGX/Projects/][Avi_Lior]
$Radius::DiaMsg::APPID_3GPP_STA                         = 16777250 ;            # [3GPP TS 29.273][Kimmo_Kymalainen]
$Radius::DiaMsg::APPID_3GPP_S6A                         = 16777251 ;            # [3GPP TS 29.272][Kimmo_Kymalainen]
$Radius::DiaMsg::APPID_3GPP_S13                         = 16777252 ;            # [3GPP TS 29.272][Kimmo_Kymalainen]
$Radius::DiaMsg::APPID_ETSI_RE                          = 16777253 ;            # [ETSI TS 183 060][Shicheng_Hu]
$Radius::DiaMsg::APPID_ETSI_GOCAP                       = 16777254 ;            # [ETSI ES 283 039][Shicheng_Hu]
$Radius::DiaMsg::APPID_SLG                              = 16777255 ;            # [3GPP TS 29.172][Kimmo_Kymalainen]
$Radius::DiaMsg::APPID_ITU_T_RW                         = 16777256 ;            # [ITU-T Rec. Q.3303.3][RFC5431]
$Radius::DiaMsg::APPID_ETSI_A4                          = 16777257 ;            # [Shicheng_Hu]
$Radius::DiaMsg::APPID_ITU_T_RT                         = 16777258 ;            # [ITU-T Rec. Q.3305.1][Tom_Taylor]
$Radius::DiaMsg::APPID_CARA                             = 16777259 ;            # [Sachin_Rathee]
$Radius::DiaMsg::APPID_CAMA                             = 16777260 ;            # [Sachin_Rathee]
$Radius::DiaMsg::APPID_FEMTOCELL_EXT_TO_DIAM_EAP_APP    = 16777261 ;            # [Vitaly_Dzhitenov]
$Radius::DiaMsg::APPID_ITU_T_RU                         = 16777262 ;            # [ITU-T Rec. Q.nacp.Ru Q.nacp.Ru][Hyungseok_Chung]
$Radius::DiaMsg::APPID_ITU_T_NG                         = 16777263 ;            # [ITU-T Rec. Q.nacp.Ru Q.nacp.Ru][Kwihoon_Kim]
$Radius::DiaMsg::APPID_3GPP_SWM                         = 16777264 ;            # [3GPP TS 29.273][Kimmo_Kymalainen]
$Radius::DiaMsg::APPID_3GPP_SWX                         = 16777265 ;            # [3GPP TS 29.273][Kimmo_Kymalainen]
$Radius::DiaMsg::APPID_3GPP_GXX                         = 16777266 ;            # [3GPP TS 29.212][Kimmo_Kymalainen]
$Radius::DiaMsg::APPID_3GPP_S9                          = 16777267 ;            # [3GPP TS 29.215][Kimmo_Kymalainen]
$Radius::DiaMsg::APPID_3GPP_ZPN                         = 16777268 ;            # [3GPP TS 29.109][Kimmo_Kymalainen]
$Radius::DiaMsg::APPID_ERICSSON_HSI                     = 16777269 ;            # [German_Blanco]
$Radius::DiaMsg::APPID_JUNIPER_EXAMPLE                  = 16777270 ;            # [Aleksey_Romanov]
$Radius::DiaMsg::APPID_ITU_T_RI                         = 16777271 ;            # [ITU-T Rec. Q.3307.1][Michiaki_Hayashi]
$Radius::DiaMsg::APPID_3GPP_S6B                         = 16777272 ;            # [3GPP TS 29.273][Kimmo_Kymalainen]
$Radius::DiaMsg::APPID_JUNIPER_JGX                      = 16777273 ;            # [Claudio_Lordello]
$Radius::DiaMsg::APPID_ITU_T_RD                         = 16777274 ;            # [ITU-T Rec. Q.3306.1][Janusz_Pieczerak]
$Radius::DiaMsg::APPID_ADMI_NOTIFICATION_APP            = 16777275 ;            # [Tomas_Menzl]
$Radius::DiaMsg::APPID_ADMI_MESSAGING_INTERFACE_APP     = 16777276 ;            # [Tomas_Menzl]
$Radius::DiaMsg::APPID_PETER_SERVICE_VSI                = 16777277 ;            # [Alexey_Grishin]
$Radius::DiaMsg::APPID_ETSI_RR_REQUEST_MODEL            = 16777278 ;            # [ETSI TS 183 071][Miguel_Angel_Reina_Ortega]
$Radius::DiaMsg::APPID_ETSI_RR_DELEGATED_MODEL          = 16777279 ;            # [ETSI TS 183 071][Miguel_Angel_Reina_Ortega]
$Radius::DiaMsg::APPID_WIMAX_HRPD_INTERWORKING          = 16777280 ;            # [3GPP2 X.S0058-0 v1.0][Avi_Lior]
$Radius::DiaMsg::APPID_WIMAX_WNAAADA                    = 16777281 ;            # [WiMAX Release 1.5][Avi_Lior]
$Radius::DiaMsg::APPID_WIMAX_WNADA                      = 16777282 ;            # [WiMAX Release 1.5][Avi_Lior]
$Radius::DiaMsg::APPID_WIMAX_WM4DA                      = 16777283 ;            # [WiMAX Release 1.5][Avi_Lior]
$Radius::DiaMsg::APPID_WIMAX_WM6DA                      = 16777284 ;            # [WiMAX Release 1.5][Avi_Lior]
$Radius::DiaMsg::APPID_WIMAX_WDDA                       = 16777285 ;            # [WiMAX Release 1.5][Avi_Lior]
$Radius::DiaMsg::APPID_WIMAX_WLAADA                     = 16777286 ;            # [WiMAX Release 1.5][Avi_Lior]
$Radius::DiaMsg::APPID_WIMAX_PCC_R3_P                   = 16777287 ;            # [WiMAX Release 1.5][Avi_Lior]
$Radius::DiaMsg::APPID_WIMAX_PCC_R3_OFC                 = 16777288 ;            # [WiMAX Release 1.5][Avi_Lior]
$Radius::DiaMsg::APPID_WIMAX_PCC_R3_OFC_PRIME           = 16777289 ;            # [WiMAX Release 1.5][Avi_Lior]
$Radius::DiaMsg::APPID_WIMAX_PCC_R3_OC                  = 16777290 ;            # [WiMAX Release 1.5][Avi_Lior]
$Radius::DiaMsg::APPID_3GPP_SLH                         = 16777291 ;            # [3GPP TS 29.173][Kimmo_Kymalainen]
$Radius::DiaMsg::APPID_3GPP_SGMB                        = 16777292 ;            # [3GPP TS 29.061][Kimmo_Kymalainen]
$Radius::DiaMsg::APPID_CMDI                             = 16777293 ;            # [Sanjiv_Parikh]
$Radius::DiaMsg::APPID_CAMIANT_DRMA                     = 16777294 ;            # [Tarek_Abou-Assali][Michael_Mercurio]
$Radius::DiaMsg::APPID_PILTE_INTERWORKING_DIAM_APP      = 16777295 ;            # [3GPP2 publication X.S0057][Avi_Lior]
$Radius::DiaMsg::APPID_JUNIPER_SESSIONS_RECOVERY        = 16777296 ;            # [Aleksey_Romanov]
$Radius::DiaMsg::APPID_VEDICIS_LIVEPROXY                = 16777297 ;            # [Francois-Frederic_Ozog]
$Radius::DiaMsg::APPID_PI_STAR_3GPP2_DIA_APP            = 16777298 ;            # [3GPP2 publication X.S0057A E-UTRAN eHRPD][Avi_Lior]
$Radius::DiaMsg::APPID_SANDVINE_RF_PLUS                 = 16777299 ;            # [Yoni_Eitan]
$Radius::DiaMsg::APPID_SUBSCRIPTION_INFORMATION_APP     = 16777300 ;            # [Lars_Anglert]
$Radius::DiaMsg::APPID_ERICSSON_CHARGING_DCIP           = 16777301 ;            # [Lars_Anglert]
$Radius::DiaMsg::APPID_3GPP_SY                          = 16777302 ;            # [3GPP TS 29.219][Kimmo_Kymalainen]
$Radius::DiaMsg::APPID_3GPP_SD                          = 16777303 ;            # [3GPP TS 29.212][Kimmo_Kymalainen]
$Radius::DiaMsg::APPID_ERICSSON_SY                      = 16777304 ;            # [Lars_Anglert]
$Radius::DiaMsg::APPID_HP_DTD                           = 16777305 ;            # [Chiranjeev_Agrawal][J_V_Kishore]
$Radius::DiaMsg::APPID_M9_ITF_BTW_MLM_PE_P_AND_MLM_PE_C = 16777306 ;            # [ITU-T Q5/Sg11][Jin_Seek_Choi]
$Radius::DiaMsg::APPID_ITU_T_M13                        = 16777307 ;            # [ITU-T Q.3230][Kwihoon_Kim]
$Radius::DiaMsg::APPID_3GPP_S7A                         = 16777308 ;            # [3GPP TS 29.272][Kimmo_Kymalainen]
$Radius::DiaMsg::APPID_3GPP_TSP                         = 16777309 ;            # [3GPP TS 29.368][Kimmo_Kymalainen]
$Radius::DiaMsg::APPID_3GPP_S6M                         = 16777310 ;            # [3GPP TS 29.336][Kimmo_Kymalainen]
$Radius::DiaMsg::APPID_3GPP_T4                          = 16777311 ;            # [3GPP TS 29.337][Kimmo_Kymalainen]
$Radius::DiaMsg::APPID_3GPP_S6C                         = 16777312 ;            # [3GPP TS 29.338][Kimmo_Kymalainen]
$Radius::DiaMsg::APPID_3GPP_SGD                         = 16777313 ;            # [3GPP TS 29.338][Kimmo_Kymalainen]
$Radius::DiaMsg::APPID_INTRADO_SLG                      = 16777314 ;            # [Scott_Luallin]
$Radius::DiaMsg::APPID_ERICSSON_DSC                     = 16777315 ;            # [Klaus_Turina]
$Radius::DiaMsg::APPID_VERIZON_FEMTO_LOC                = 16777316 ;            # [Niranjan_Avula]
$Radius::DiaMsg::APPID_NSN_HD_APP                       = 16777317 ;            # [Hannes_Tschofenig]
$Radius::DiaMsg::APPID_3GPP_S15                         = 16777318 ;            # [3GPP TS 29.212][Kimmo_Kymalainen]
$Radius::DiaMsg::APPID_3GPP_S9A                         = 16777319 ;            # [3GPP TS 29.215][Kimmo_Kymalainen]
$Radius::DiaMsg::APPID_3GPP_S9A_STAR                    = 16777320 ;            # [3GPP TS 29.215][Kimmo_Kymalainen]
$Radius::DiaMsg::APPID_GATEWAY_LOCATION_APP             = 16777321 ;            # [Steve_Donovan]
$Radius::DiaMsg::APPID_VERIZON_SESSION_RECOVERY         = 16777322 ;            # [Niranjan_Avula]

# From draft-ietf-aaa-diameter-nasreq-14.txt, RFC4005
$Radius::DiaMsg::CODE_AA                  = 265;
$Radius::DiaMsg::CODE_RE_AUTH             = 258;
$Radius::DiaMsg::CODE_SESSION_TERMINATION = 275;
$Radius::DiaMsg::CODE_ABORT_SESSION       = 274;
$Radius::DiaMsg::CODE_ACCOUNTING          = 271;


# RFC 4006
$Radius::DiaMsg::CODE_CREDIT_CONTROL      = 272;

# From RFC 4072
$Radius::DiaMsg::CODE_DER                 = 268;

# 3GPP TS 29.230
$Radius::DiaMsg::CODE_UAR                 = 300;
$Radius::DiaMsg::CODE_SAR                 = 301;
$Radius::DiaMsg::CODE_LIR                 = 302;
$Radius::DiaMsg::CODE_MAR                 = 303;
$Radius::DiaMsg::CODE_RTR                 = 304;
$Radius::DiaMsg::CODE_PPR                 = 305;
$Radius::DiaMsg::CODE_UDR                 = 306;
$Radius::DiaMsg::CODE_PUR                 = 307;
$Radius::DiaMsg::CODE_SNR                 = 308;
$Radius::DiaMsg::CODE_PNR                 = 309;
$Radius::DiaMsg::CODE_BIR                 = 310;
$Radius::DiaMsg::CODE_MPR                 = 311;


# Vendor IDs
$Radius::DiaMsg::VENDOR_OSC               = 9048;
$Radius::DiaMsg::VENDOR_3GPP              = 10415;

# Maps requests command code numbers to readable names
%Radius::DiaMsg::code_to_name =
    (
     $Radius::DiaMsg::CODE_ASR                 => 'ASR',
     $Radius::DiaMsg::CODE_ACR                 => 'ACR',
     $Radius::DiaMsg::CODE_CER                 => 'CER',
     $Radius::DiaMsg::CODE_DWR                 => 'DWR',
     $Radius::DiaMsg::CODE_DPR                 => 'DPR',
     $Radius::DiaMsg::CODE_RAR                 => 'RAR',
     $Radius::DiaMsg::CODE_STR                 => 'STR',

     # From draft-ietf-aaa-diameter-nasreq-14.txt
     $Radius::DiaMsg::CODE_AA                  => 'AA',
     $Radius::DiaMsg::CODE_RE_AUTH             => 'Re-Auth',
     $Radius::DiaMsg::CODE_SESSION_TERMINATION => 'Session-Termination',
     $Radius::DiaMsg::CODE_ABORT_SESSION       => 'Abort-Session',
     $Radius::DiaMsg::CODE_ACCOUNTING          => 'Accounting',

     # From RFC 4072
     $Radius::DiaMsg::CODE_DER                 => 'EAP',
     
     # From RFC 4006
     $Radius::DiaMsg::CODE_CCR                 => 'Credit-Control',

     # 3GPP TS 29.230
     $Radius::DiaMsg::CODE_UAR                 => "User-Authorization",
     $Radius::DiaMsg::CODE_SAR                 => "Server-Assignment",
     $Radius::DiaMsg::CODE_LIR                 => "Location-Info",
     $Radius::DiaMsg::CODE_MAR                 => "Multimedia-Auth",
     $Radius::DiaMsg::CODE_RTR                 => "Registration-Termination",
     $Radius::DiaMsg::CODE_PPR                 => "Push-Profile",
     $Radius::DiaMsg::CODE_UDR                 => "User-Data",
     $Radius::DiaMsg::CODE_PUR                 => "Profile-Update",
     $Radius::DiaMsg::CODE_SNR                 => "Subscribe-Notifications",
     $Radius::DiaMsg::CODE_PNR                 => "Push-Notification",
     $Radius::DiaMsg::CODE_BIR                 => "Boostrapping-Info",
     $Radius::DiaMsg::CODE_MPR                 => "Message-Process",

     );
# A reverse map of code names to code numbers
%Radius::DiaMsg::name_to_code = reverse(%Radius::DiaMsg::code_to_name);

# Maps request application numbers to readable names
%Radius::DiaMsg::appcode_to_name =
    (
     $Radius::DiaMsg::APPID_BASE                            => 'Base',
     $Radius::DiaMsg::APPID_NASREQ                          => 'Nasreq',
     $Radius::DiaMsg::APPID_MOBILE_IP                       => 'MobileIP',
     $Radius::DiaMsg::APPID_BASE_ACCOUNTING                 => 'Base Accounting',
     $Radius::DiaMsg::APPID_CREDIT_CONTROL                  => 'Credit Control',
     $Radius::DiaMsg::APPID_DIAMETER_SIP                    => 'SIP Aplication',   # RFC 4740
     $Radius::DiaMsg::APPID_RELAY                           => 'Relay',

     $Radius::DiaMsg::APPID_DIAMETER_EAP                    => 'Diameter-EAP',
     $Radius::DiaMsg::APPID_DIAMETER_SIP                    => 'Diameter-SIP',
     $Radius::DiaMsg::APPID_DIAMETER_MIP6I                  => 'Diameter-MIP6i',
     $Radius::DiaMsg::APPID_DIAMETER_MIP6A                  => 'Diameter-MIP6a',
     $Radius::DiaMsg::APPID_DIAMETER_QOS                    => 'Diameter-QoS',
     $Radius::DiaMsg::APPID_DIAMETER_CAPABILITIES_UPDATE    => 'Diameter-Capabilities-Update',
     $Radius::DiaMsg::APPID_DIAMETER_IKESK                  => 'Diameter-IKESK',  
     $Radius::DiaMsg::APPID_DIAMETER_NAT                    => 'Diameter-NAT',    
     
     $Radius::DiaMsg::APPID_3GPP_CX                         => '3GPP-Cx',   
     $Radius::DiaMsg::APPID_3GPP_SH                         => '3GPP-Sh',
     $Radius::DiaMsg::APPID_3GPP_RE                         => '3GPP-Re',
     $Radius::DiaMsg::APPID_3GPP_WX                         => '3GPP-Wx',
     $Radius::DiaMsg::APPID_3GPP_ZN                         => '3GPP-Zn',
     $Radius::DiaMsg::APPID_3GPP_ZH                         => '3GPP-Zh',
     $Radius::DiaMsg::APPID_3GPP_GQ                         => '3GPP-Gq',
     $Radius::DiaMsg::APPID_3GPP_GMB                        => '3GPP-Gmb',
     $Radius::DiaMsg::APPID_3GPP_GX_REL6                    => '3GPP-Gx Release 6',
     $Radius::DiaMsg::APPID_3GPP_GX_OVER_GY                 => '3GPP-Gx-Gy',
     $Radius::DiaMsg::APPID_3GPP_MM10                       => '3GPP-MM10',
     $Radius::DiaMsg::APPID_ERICSSON_MSI                    => 'Ericsson-MSI',
     $Radius::DiaMsg::APPID_ERICSSON_ZX                     => 'Ericsson-Zx',
     $Radius::DiaMsg::APPID_3GPP_RX_REL6                    => '3GPP-Rx Release 6',
     $Radius::DiaMsg::APPID_3GPP_PR                         => '3GPP-Pr',  
     $Radius::DiaMsg::APPID_ETSI_E4                         => 'ETSI-E4',
     $Radius::DiaMsg::APPID_ERICSSON_CHARGING_CIP           => 'Ericsson-Charging-CIP',
     $Radius::DiaMsg::APPID_ERICSSON_MM                     => 'Ericsson-Mm',
     $Radius::DiaMsg::APPID_VODAFONE_GX_PLUS                => 'Vodafone-Gx+',
     $Radius::DiaMsg::APPID_ITU_T_RS                        => 'ITU-T-Rs',
     $Radius::DiaMsg::APPID_3GPP_RX                         => '3GPP-Rx',
     $Radius::DiaMsg::APPID_3GPP2_TY                        => '3GPP2-Ty',
     $Radius::DiaMsg::APPID_3GPP_GX                         => '3GPP-Gx',
     $Radius::DiaMsg::APPID_JUNIPER_CLUSTER                 => 'Juniper-Cluster',
     $Radius::DiaMsg::APPID_JUNIPER_POLICY_CONTROL_AAA      => 'Juniper-Policy-Control',
     $Radius::DiaMsg::APPID_IPTEGO_USPI                     => 'Iptego-USPI',
     $Radius::DiaMsg::APPID_COVERGENCE_SPECIFIC_SIP_ROUTING => 'Convergence-Specific-SIP-Routing',
     $Radius::DiaMsg::APPID_POLICY_PROCESSING               => 'Policy-Processing',
     $Radius::DiaMsg::APPID_JUNIPER_POLICY_CONTROL_JSRC     => 'Juniper-Policy-Control-JSRC',
     $Radius::DiaMsg::APPID_ITU_T_S_TC1                     => 'ITU-T S-TC1',
     $Radius::DiaMsg::APPID_NSN_UCTF                        => 'NSN Unified Charging Trigger Function (UCTF)',
     $Radius::DiaMsg::APPID_3GPP2_CAN_ACCESS_AUTHN_AND_AUTHZ => '3GPP2 CAN Access Authentication and Authorization',
     $Radius::DiaMsg::APPID_3GPP2_WLAN_INTERWORKING_AAA     => '3GPP2 WLAN Interworking Access Authentication and Authorization',
     $Radius::DiaMsg::APPID_3GPP2_WLAN_INTERWORKING_ACCT    => '3GPP2 WLAN Interworking Accounting',
     $Radius::DiaMsg::APPID_3GPP_STA                        => '3GPP Sta',
     $Radius::DiaMsg::APPID_3GPP_S6A                        => '3GPP S6a',
     $Radius::DiaMsg::APPID_3GPP_S13                        => '3GPP S13',
     $Radius::DiaMsg::APPID_ETSI_RE                         => 'ETSI Re',
     $Radius::DiaMsg::APPID_ETSI_GOCAP                      => 'ETSI GOCAP',
     $Radius::DiaMsg::APPID_SLG                             => 'SLg',
     $Radius::DiaMsg::APPID_ITU_T_RW                        => 'ITU-T Rw',
     $Radius::DiaMsg::APPID_ETSI_A4                         => 'ETSI a4',
     $Radius::DiaMsg::APPID_ITU_T_RT                        => 'ITU-T Rt',
     $Radius::DiaMsg::APPID_CARA                            => 'CARA',
     $Radius::DiaMsg::APPID_CAMA                            => 'CAMA',
     $Radius::DiaMsg::APPID_FEMTOCELL_EXT_TO_DIAM_EAP_APP   => 'Femtocell extension to Diameter EAP Application',
     $Radius::DiaMsg::APPID_ITU_T_RU                        => 'ITU-T Ru',
     $Radius::DiaMsg::APPID_ITU_T_NG                        => 'ITU-T Ng',
     $Radius::DiaMsg::APPID_3GPP_SWM                        => '3GPP SWm',
     $Radius::DiaMsg::APPID_3GPP_SWX                        => '3GPP SWx',
     $Radius::DiaMsg::APPID_3GPP_GXX                        => '3GPP Gxx',
     $Radius::DiaMsg::APPID_3GPP_S9                         => '3GPP S9',
     $Radius::DiaMsg::APPID_3GPP_ZPN                        => '3GPP Zpn',
     $Radius::DiaMsg::APPID_ERICSSON_HSI                    => 'Ericsson HSI',
     $Radius::DiaMsg::APPID_JUNIPER_EXAMPLE                 => 'Juniper-Example',
     $Radius::DiaMsg::APPID_ITU_T_RI                        => 'ITU-T Ri',
     $Radius::DiaMsg::APPID_3GPP_S6B                        => '3GPP S6b',
     $Radius::DiaMsg::APPID_JUNIPER_JGX                     => 'Juniper JGx',
     $Radius::DiaMsg::APPID_ITU_T_RD                        => 'ITU-T Rd',
     $Radius::DiaMsg::APPID_ADMI_NOTIFICATION_APP           => 'ADMI Notification Application',
     $Radius::DiaMsg::APPID_ADMI_MESSAGING_INTERFACE_APP    => 'ADMI Messaging Interface Application',
     $Radius::DiaMsg::APPID_PETER_SERVICE_VSI               => 'Peter-Service VSI',
     $Radius::DiaMsg::APPID_ETSI_RR_REQUEST_MODEL           => 'ETSI Rr request model',
     $Radius::DiaMsg::APPID_ETSI_RR_DELEGATED_MODEL         => 'ETSI Rr delegated model',
     $Radius::DiaMsg::APPID_WIMAX_HRPD_INTERWORKING         => 'WIMAX HRPD Interworking',
     $Radius::DiaMsg::APPID_WIMAX_WNAAADA                   => 'WiMAX Network Access Authentication and Authorization Diameter Application (WNAAADA)',
     $Radius::DiaMsg::APPID_WIMAX_WNADA                     => 'WiMAX Network Accounting Diameter Application (WNADA)',
     $Radius::DiaMsg::APPID_WIMAX_WM4DA                     => 'WiMAX MIP4 Diameter Application (WM4DA)',
     $Radius::DiaMsg::APPID_WIMAX_WM6DA                     => 'WiMAX MIP6 Diameter Application (WM6DA)',
     $Radius::DiaMsg::APPID_WIMAX_WDDA                      => 'WiMAX DHCP Diameter Application (WDDA)',
     $Radius::DiaMsg::APPID_WIMAX_WLAADA                    => 'WiMAX-Location-Authentication-Authorization Diameter Application (WLAADA)',
     $Radius::DiaMsg::APPID_WIMAX_PCC_R3_P                  => 'WiMAX-Policy-and-Charging-Control-R3-Policies Diameter Application (WiMAX PCC-R3-P)',
     $Radius::DiaMsg::APPID_WIMAX_PCC_R3_OFC                => 'WiMAX-Policy-and-Charging-Control-R3-OFfline-Charging Diameter Application (WiMAX PCC-R3-OFC)',
     $Radius::DiaMsg::APPID_WIMAX_PCC_R3_OFC_PRIME          => 'WiMAX-Policy-and-Charging-Control-R3-Offline-Charging-Prime Diameter Application (WiMAX PCC-R3-OFC-PRIME)',
     $Radius::DiaMsg::APPID_WIMAX_PCC_R3_OC                 => 'WiMAX-Policy-and-Charging-Control-R3-Online-Charging Diameter Application (WiMAX PCC-R3-OC)',
     $Radius::DiaMsg::APPID_3GPP_SLH                        => '3GPP SLh',
     $Radius::DiaMsg::APPID_3GPP_SGMB                       => '3GPP SGmb',
     $Radius::DiaMsg::APPID_CMDI                            => 'CMDI - Cloudmark Diameter Interface',
     $Radius::DiaMsg::APPID_CAMIANT_DRMA                    => 'Camiant DRMA',
     $Radius::DiaMsg::APPID_PILTE_INTERWORKING_DIAM_APP     => 'PiLTE Interworking Diameter Application',
     $Radius::DiaMsg::APPID_JUNIPER_SESSIONS_RECOVERY       => 'Juniper-Sessions-Recovery (JSR)',
     $Radius::DiaMsg::APPID_VEDICIS_LIVEPROXY               => 'Vedicis LiveProxy',
     $Radius::DiaMsg::APPID_PI_STAR_3GPP2_DIA_APP           => 'Pi*3GPP2 Diameter Application',
     $Radius::DiaMsg::APPID_SANDVINE_RF_PLUS                => 'Sandvine Rf+',
     $Radius::DiaMsg::APPID_SUBSCRIPTION_INFORMATION_APP    => 'Subscription Information Application',
     $Radius::DiaMsg::APPID_ERICSSON_CHARGING_DCIP          => 'Ericsson Charging-DCIP',
     $Radius::DiaMsg::APPID_3GPP_SY                         => '3GPP Sy',
     $Radius::DiaMsg::APPID_3GPP_SD                         => '3GPP Sd',
     $Radius::DiaMsg::APPID_ERICSSON_SY                     => 'Ericsson Sy',
     $Radius::DiaMsg::APPID_HP_DTD                          => 'HP DTD',
     $Radius::DiaMsg::APPID_M9_ITF_BTW_MLM_PE_P_AND_MLM_PE_C => 'M9 interface between MLM-PE(P) and MLM-PE(C)',
     $Radius::DiaMsg::APPID_ITU_T_M13                       => 'ITU-T M13',
     $Radius::DiaMsg::APPID_3GPP_S7A                        => '3GPP S7a',
     $Radius::DiaMsg::APPID_3GPP_TSP                        => '3GPP Tsp',
     $Radius::DiaMsg::APPID_3GPP_S6M                        => '3GPP S6m',
     $Radius::DiaMsg::APPID_3GPP_T4                         => '3GPP T4',
     $Radius::DiaMsg::APPID_3GPP_S6C                        => '3GPP S6c',
     $Radius::DiaMsg::APPID_3GPP_SGD                        => '3GPP SGd',
     $Radius::DiaMsg::APPID_INTRADO_SLG                     => 'Intrado-SLg',
     $Radius::DiaMsg::APPID_ERICSSON_DSC                    => 'Ericsson Diameter Signalling Controller Application (DSC)',
     $Radius::DiaMsg::APPID_VERIZON_FEMTO_LOC               => 'Verizon-Femto-Loc',
     $Radius::DiaMsg::APPID_NSN_HD_APP                      => 'Nokia Siemens Networks (NSN) Hd Application',
     $Radius::DiaMsg::APPID_3GPP_S15                        => '3GPP S15',
     $Radius::DiaMsg::APPID_3GPP_S9A                        => '3GPP S9a',
     $Radius::DiaMsg::APPID_3GPP_S9A_STAR                   => '3GPP S9a*',
     $Radius::DiaMsg::APPID_GATEWAY_LOCATION_APP            => 'Gateway Location Application',
     $Radius::DiaMsg::APPID_VERIZON_SESSION_RECOVERY        => 'Verizon Session Recovery',
    );

# A reverse map of app names to app numbers
%Radius::DiaMsg::appname_to_code = reverse(%Radius::DiaMsg::appcode_to_name);

# Maps vendor code numbers to readable names
%Radius::DiaMsg::vendorid_to_name =
    (
     $Radius::DiaMsg::VENDOR_OSC                 => 'OSC',
     $Radius::DiaMsg::VENDOR_3GPP                => '3GPP',
    );

# A reverse map of vendor codes to vendor names
%Radius::DiaMsg::vendorname_to_id = reverse(%Radius::DiaMsg::vendorid_to_name);

# Next end-to-end ID to use
# Initial value as per RFC 3588
$Radius::DiaMsg::next_eeid = ((time & 0xfff) << 20);

#####################################################################
sub new
{
    my ($class, @args) = @_;

    my $self = $class->SUPER::new
	(Version => 1, Aid => $Radius::DiaMsg::APPID_BASE, 
	 Flags => 0, Hhid => 0, Eeid => 0, 
	 Protocol => 'diameter', 
	 @args);
    $self->disassemble($self->{Data}) if defined $self->{Data};
    return $self;
}

#####################################################################
# Construct a new request suitable for sending to another host.
# Sets the end-to-end ID.
sub new_request
{
    my ($self, @args) = @_;

    my $new = Radius::DiaMsg->new(Version => 1, 
				  Eeid => $Radius::DiaMsg::next_eeid++, 
				  @args);
    return $new;
}

#####################################################################
# Construct a new message which is a reply to the one given
sub new_reply
{
    my ($self, @args) = @_;

    my $new = Radius::DiaMsg->new(Version => 1, 
				  Code => $self->code(), 
				  Aid => $self->aid(), 
				  Hhid => $self->hhid(), 
				  Eeid => $self->eeid(), 
				  Dictionary => $self->{Dictionary},
				  @args);
    $new->{replyToMsg} = $self;
    $new->{Flags} |= ($self->flags() & $Radius::DiaMsg::FLAG_PROXIABLE);
    my $session_id = $self->get($Radius::DiaAttrList::ACODE_SESSION_ID);
    $new->add_attr($Radius::DiaAttrList::ACODE_SESSION_ID, 0,
		    $Radius::DiaAttrList::AFLAG_MANDATORY, $session_id)
	if defined $session_id;
    my @proxy_info = $self->get($Radius::DiaAttrList::ACODE_PROXY_INFO);
    $new->add_attr($Radius::DiaAttrList::ACODE_PROXY_INFO, 0,
		    $Radius::DiaAttrList::AFLAG_MANDATORY, @proxy_info)
	if scalar @proxy_info;
    

    return $new;
}

#####################################################################
sub disassemble
{
    my ($self, $data) = @_;

    return if length $data < 20;

    # Unpack the header
    my ($verslen, $ccode, $aid, $hhid, $eeid, $avps) = unpack('N N N N N a*', $data);
    $self->{Version} = $verslen >> 24;
    $self->{Length}  = $verslen & 0xffffff;
    $self->{Flags}   = $ccode >> 24;
    $self->{Code}    = $ccode & 0xffffff;
    $self->{Aid}     = $aid;
    $self->{Hhid}    = $hhid;
    $self->{Eeid}    = $eeid;

    # Load Application specific dictionary if any.
    $self->{Dictionary} = $Radius::DiaDict::dicts{$self->{Aid}};
    $self->{Dictionary} = $Radius::DiaDict::default unless $self->{Dictionary};

    # Unpack any AVPs
    $self->SUPER::disassemble($avps);
}

#####################################################################
sub assemble
{
    my ($self) = @_;

    my $avps = $self->SUPER::assemble();
    return pack('N N N N N a*', 
		$self->{Version} << 24 | (length($avps) + 20),
		$self->{Flags} << 24 | $self->{Code},
		$self->{Aid},
		$self->{Hhid},
		$self->{Eeid},
		$avps);
}

#####################################################################
# Accessors
sub version { $_[0]->{Version}}
sub flags   { $_[0]->{Flags}}
sub code    { $_[0]->{Code}}
sub aid     { $_[0]->{Aid}}
sub hhid    { $_[0]->{Hhid}}
sub eeid    { $_[0]->{Eeid}}

#####################################################################
# Manipulators
sub set_version { $_[0]->{Version} = $_[1]}
sub set_flags   { $_[0]->{Flags}   = $_[1]}
sub set_code    { $_[0]->{Code}    = $_[1]}
sub set_aid     { $_[0]->{Aid}     = $_[1]}
sub set_hhid    { $_[0]->{Hhid}    = $_[1]}
sub set_eeid    { $_[0]->{Eeid}    = $_[1]}

#####################################################################
# Pretty-Print the message contents
sub format
{
    my ($self) = @_;

    my $meaning = '';
    $meaning .= 'R' if $self->{Flags} & $Radius::DiaMsg::FLAG_REQUEST;
    $meaning .= 'P' if $self->{Flags} & $Radius::DiaMsg::FLAG_PROXIABLE;
    $meaning .= 'E' if $self->{Flags} & $Radius::DiaMsg::FLAG_ERROR;
    $meaning .= 'T' if $self->{Flags} & $Radius::DiaMsg::FLAG_RETRANSMITTED;
    my $flags = sprintf('0x%x', $self->{Flags});
    my $codename = $Radius::DiaMsg::code_to_name{$self->{Code}} || 'unknown';
    my $appname = $Radius::DiaMsg::appcode_to_name{$self->{Aid}} || 'unknown';
    return "  Code:           $self->{Code} ($codename)
  Version:        $self->{Version}
  Flags:          $flags ($meaning)
  Application ID: $self->{Aid} ($appname)
  Hop-to-Hop ID:  $self->{Hhid}
  End-to-End ID:  $self->{Eeid}
  Attributes:\n" . $self->SUPER::format($self->{Dictionary});
}

1;
