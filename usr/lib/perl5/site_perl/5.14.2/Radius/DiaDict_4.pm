# DiaDict_4.pm
#
# Dictionary for the Diameter Credit Control application
#
# Part of the Radius project.
# Author: Heikki Vatiainen (hvn@open.com.au)
# Copyright (C) 2014 Open System Consultants
# $Id: DiaDict_4.pm,v 1.2 2014/07/30 21:01:31 hvn Exp $

package Radius::DiaDict_4;
use strict;
use warnings;

# RCS version number of this module
$Radius::DiaDict_4::VERSION = '$Revision: 1.2 $';

#####################################################################
sub get_handle
{
    return *DATA;
}


# Here follows the Diameter attributes for Diameter Credit Control application
__DATA__

ATTRIBUTE	CC-Correlation-Id	411	OctetString		M
ATTRIBUTE	CC-Input-Octets		412	Unsigned64		M
ATTRIBUTE	CC-Money		413	Grouped			M
ATTRIBUTE	CC-Output-Octets	414	Unsigned64		M
ATTRIBUTE	CC-Request-Number	415	Unsigned32		M
ATTRIBUTE	CC-Request-Type		416	Enumerated		M
ATTRIBUTE	CC-Service-Specific-Units	417	Unsigned64	M
ATTRIBUTE	CC-Session-Failover	418	Enumerated		M
ATTRIBUTE	CC-Sub-Session-Id	419	Unsigned64		M
ATTRIBUTE	CC-Time			420	Unsigned32		M
ATTRIBUTE	CC-Total-Octets		421	Unsigned64		M
ATTRIBUTE	CC-Unit-Type		454	Enumerated		M
ATTRIBUTE	Check-Balance-Result	422	Enumerated		M
ATTRIBUTE	Cost-Information	423	Grouped			M
ATTRIBUTE	Cost-Unit		424	UTF8String		M
ATTRIBUTE	Currency-Code		425	Unsigned32		M
ATTRIBUTE	Credit-Control		426	Enumerated		M
ATTRIBUTE	Credit-Control-Failure-Handling		427	Enumerated	M
ATTRIBUTE	Direct-Debiting-Failure-Handling	428	Enumerated	M
ATTRIBUTE	Exponent			429	Integer32	M
ATTRIBUTE	Final-Unit-Indication		430	Grouped		M
ATTRIBUTE	Granted-Service-Unit		431	Grouped		M
ATTRIBUTE	Rating-Group			432	Unsigned32	M
ATTRIBUTE	Redirect-Address-Type		433	Enumerated	M
ATTRIBUTE	Redirect-Server			434	Grouped		M
ATTRIBUTE	Redirect-Server-Address		435	UTF8String	M
ATTRIBUTE	Requested-Action		436	Enumerated	M
ATTRIBUTE	Requested-Service-Unit		437	Grouped		M
ATTRIBUTE	Restriction-Filter-Rule		438	IPFilterRule	M
ATTRIBUTE	Service-Identifier		439	Unsigned32	M
ATTRIBUTE	Service-Parameter-Info		440	Grouped		M
ATTRIBUTE	Service-Parameter-Type		441	Enumerated	M
ATTRIBUTE	Service-Parameter-Value		442	OctetString	M
ATTRIBUTE	Subscription-Id			443	Grouped		M
ATTRIBUTE	Subscription-Id-Data		444	UTF8String	M
ATTRIBUTE	Unit-Value			445	Grouped		M
ATTRIBUTE	Used-Service-Unit		446	Grouped		M
ATTRIBUTE	Value-Digits			447	Integer64	M
ATTRIBUTE	Validity-Time			448	Unsigned32	M
ATTRIBUTE	Final-Unit-Action		449	Enumerated	M
ATTRIBUTE	Subscription-Id-Type		450	Enumerated	M
ATTRIBUTE	Tariff-Time-Change		451	Time		M
ATTRIBUTE	Tariff-Change-Usage		452	Enumerated	M
ATTRIBUTE	G-S-U-Pool-Identifier		453	Unsigned32	M
ATTRIBUTE	Multiple-Services-Indicator	455	Enumerated	M
ATTRIBUTE	Multiple-Services-Credit-Control	456	Grouped	M
ATTRIBUTE	G-S-U-Pool-Reference		457	Grouped		M
ATTRIBUTE	User-Equipment-Info		458	Grouped		M
ATTRIBUTE	User-Equipment-Info-Type	459	Enumerated	M
ATTRIBUTE	User-Equipment-Info-Value	460	OctetString	M
ATTRIBUTE	Service-Context-Id		461	UTF8String	M

VALUE    CC-Request-Type                         INITIAL_REQUEST	          1
VALUE    CC-Request-Type                         UPDATE_REQUEST                   2
VALUE    CC-Request-Type                         TERMINATION_REQUEST              3
VALUE    CC-Request-Type                         EVENT_REQUEST                    4

VALUE    CC-Session-Failover                     FAILOVER_NOT_SUPPORTED           0
VALUE    CC-Session-Failover                     FAILOVER_SUPPORTED               1

VALUE    CC-Unit-Type	TIME	0
VALUE    CC-Unit-Type	MONEY	1
VALUE    CC-Unit-Type	TOTAL-OCTETS	2
VALUE    CC-Unit-Type	INPUT-OCTETS	3
VALUE    CC-Unit-Type	OUTPUT-OCTETS	4
VALUE    CC-Unit-Type	SERVICE-SPECIFIC-UNITS	5

VALUE    Check-Balance-Result	ENOUGH_CREDIT	0
VALUE    Check-Balance-Result	NO_CREDIT	1

VALUE    Credit-Control	CREDIT_AUTHORIZATION	0
VALUE    Credit-Control	CREDIT_AUTHORIZATION	0
VALUE    Credit-Control	RE_AUTHORIZATION	1

VALUE    Credit-Control-Failure-Handling	TERMINATE	0
VALUE    Credit-Control-Failure-Handling	CONTINUE	1
VALUE    Credit-Control-Failure-Handling	RETRY_AND_TERMINATE	2

VALUE    Direct-Debiting-Failure-Handling	CONTINUE	1
VALUE    Direct-Debiting-Failure-Handling	TERMINATE_OR_BUFFER	0

VALUE    Redirect-Address-Type	IPv4_Address	0
VALUE    Redirect-Address-Type	IPV6_ADDRESS	1
VALUE    Redirect-Address-Type	URL	2
VALUE    Redirect-Address-Type	SIP_URI	3

VALUE    Requested-Action	DIRECT_DEBITING	0
VALUE    Requested-Action	REFUND_ACCOUNT	1
VALUE    Requested-Action	CHECK_BALANCE	2
VALUE    Requested-Action	PRICE_ENQUIRY	3

VALUE    Service-Parameter-Type	Provider-Id_	2852192357
VALUE    Service-Parameter-Type	Time-Date-Offset	2852192358
VALUE    Service-Parameter-Type	Calling-Party-Address	2852192359
VALUE    Service-Parameter-Type	Called-Party-Address	2852192360
VALUE    Service-Parameter-Type	Redirecting-Party-Address	2852192361
VALUE    Service-Parameter-Type	Calling-Party-Category	2852192362
VALUE    Service-Parameter-Type	Call-Type	2852192363
VALUE    Service-Parameter-Type	Service-Direction	2852192364
VALUE    Service-Parameter-Type	Origin-Zone	2852192365
VALUE    Service-Parameter-Type	Terminating-Zone	2852192366
VALUE    Service-Parameter-Type	Band-Label	2852192367
VALUE    Service-Parameter-Type	Delivered-QoS	2852192368
VALUE    Service-Parameter-Type	Content-Type	2852192369
VALUE    Service-Parameter-Type	Serving-Network-Id	2852192370
VALUE    Service-Parameter-Type	Service-Type	2852192371
VALUE    Service-Parameter-Type	Content_Value_Type	2852192372
VALUE    Service-Parameter-Type	Content_Value	2852192373
VALUE    Service-Parameter-Type	Feature_Type	2852192374
VALUE    Service-Parameter-Type	Dial_Zone_Plan	2852192375
VALUE    Service-Parameter-Type	Call_Event	2852192376
VALUE    Service-Parameter-Type	Data_Transfer_Type	2852192377
VALUE    Service-Parameter-Type	Protocol_Type	2852192378
VALUE    Service-Parameter-Type	Original_Calling_Party_Address	2852192379
VALUE    Service-Parameter-Type	Original_Called_Party_Adress	2852192380
VALUE    Service-Parameter-Type	NOA_of_Calling_Party_Address	2852192381
VALUE    Service-Parameter-Type	Original_Location_Information	2852192382
VALUE    Service-Parameter-Type	Terminating_Location_Information	2852192383
VALUE    Service-Parameter-Type	Roaming_Flag	2852192384
VALUE    Service-Parameter-Type	Allowed_Call_Duration	2852192385
VALUE    Service-Parameter-Type	Remaining_Balance	2852192386
VALUE    Service-Parameter-Type	Currency_Label	2852192387
VALUE    Service-Parameter-Type	Release_Scenario	2852192388
VALUE    Service-Parameter-Type	Service-Delivery-Time	2852192389
VALUE    Service-Parameter-Type	User-Serving-MSC-PC	2852192390
VALUE    Service-Parameter-Type	User-Serving-SMSC-GTA	2852192391
VALUE    Service-Parameter-Type	Call-Reference	2852192392
VALUE    Service-Parameter-Type	User-Rate	2852192393
VALUE    Service-Parameter-Type	Information-Transfer-Cap	2852192394
VALUE    Service-Parameter-Type	Synch-Asynch	2852192395
VALUE    Service-Parameter-Type	User-Info-Layer1-Protocol	2852192396
VALUE    Service-Parameter-Type	SS7-Network-Type	2852192397
VALUE    Service-Parameter-Type	Balance-Indicator	2852192398
VALUE    Service-Parameter-Type	Merchant-ID	2852192399
VALUE    Service-Parameter-Type	PIN	2852192400
VALUE    Service-Parameter-Type	Location_Number	2852192538
VALUE    Service-Parameter-Type	CellID_LAI	2852192539
VALUE    Service-Parameter-Type	VLR_Number	2852192540
VALUE    Service-Parameter-Type	MSRN	2852192541
VALUE    Service-Parameter-Type	Forwarded_Call	2852192542
VALUE    Service-Parameter-Type	Early_Call_Forwarding	2852192543
VALUE    Service-Parameter-Type	Voice_Mail_Request	2852192544
VALUE    Service-Parameter-Type	Call_Category	2852192545
VALUE    Service-Parameter-Type	Original_Group_ID	2852192546
VALUE    Service-Parameter-Type	Zone_Status	2852192547
VALUE    Service-Parameter-Type	User-Defined-Service-Parameter-Info_(1)	2852192757
VALUE    Service-Parameter-Type	User-Defined-Service-Parameter-Info_(2)	2852192758
VALUE    Service-Parameter-Type	User-Defined-Service-Parameter-Info_(3)	2852192759
VALUE    Service-Parameter-Type	User-Defined-Service-Parameter-Info_(4)	2852192760
VALUE    Service-Parameter-Type	User-Defined-Service-Parameter-Info_(5)	2852192761

VALUE    Final-Unit-Action	TERMINATE	0
VALUE    Final-Unit-Action	REDIRECT	1
VALUE    Final-Unit-Action	RESTRICT_ACCESS	2

VALUE    Subscription-Id-Type	END_USER_E164	0
VALUE    Subscription-Id-Type	END_USER_IMSI	1
VALUE    Subscription-Id-Type	END_USER_NAI	3
VALUE    Subscription-Id-Type	END_USER_PRIVATE	4
VALUE    Subscription-Id-Type	END_USER_SIP_URI	2

VALUE    Tariff-Change-Usage	UNIT_BEFORE_TARIFF_CHANGE	0
VALUE    Tariff-Change-Usage	UNIT_AFTER_TARIFF_CHANGE	1
VALUE    Tariff-Change-Usage	UNIT_INDETERMINATE	2

VALUE    Multiple-Services-Indicator	MULTIPLE_SERVICES_NOT_SUPPORTED	0
VALUE    Multiple-Services-Indicator	MULTIPLE_SERVICES_SUPPORTED	1

VALUE    User-Equipment-Info-Type	IMEISV	0
VALUE    User-Equipment-Info-Type	MAC	1
VALUE    User-Equipment-Info-Type	EUI64	2
VALUE    User-Equipment-Info-Type	MODIFIED_EUI64	3
