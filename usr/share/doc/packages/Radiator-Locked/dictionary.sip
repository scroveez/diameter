# This is a specialised dictionary for recognising 
# SIP radius attributes as described in RFC 4590
#
# They are included in this separate dictionary because they conflict with 
# other common and standard attributes.
# They override a number of attributes in the standard dictionary.
#
# The version of this file that was use before RFC 4590. and compliant with
# draft-sterman-aaa-sip-00.txt can be found in goodies/dictionary.sip.pre-rfc
#
# You can append this to your standard dictionary in Radiator with
# a Radiator configuration parameter like this:
# DictionaryFile %D/dictionary,%D/dictionary.sip
# See goodies/sip.cfg for an example configuration
#
# Author: Mike McCauley mikem@open.com.au
# $Id: dictionary.sip,v 1.5 2007/02/10 06:04:44 mikem Exp $

ATTRIBUTE	Digest-Response	        103	string
ATTRIBUTE	Digest-Realm	        104	string
ATTRIBUTE	Digest-Nonce	        105	string
ATTRIBUTE	Digest-Response-Auth    106	string
ATTRIBUTE	Digest-Nextnonce        107	string
ATTRIBUTE	Digest-Method	        108	string
ATTRIBUTE	Digest-URI	        109	string
ATTRIBUTE	Digest-Qop	        110	string
ATTRIBUTE	Digest-Algorithm        111	string
ATTRIBUTE	Digest-Entity-Body-Hash 112	string
ATTRIBUTE	Digest-CNonce	        113	string
ATTRIBUTE	Digest-Nonce-Count      114	string
ATTRIBUTE	Digest-Username	        115	string
ATTRIBUTE	Digest-Opaque	        116	string
ATTRIBUTE	Digest-Auth-Param	117	string
ATTRIBUTE	Digest-AKA-Auts	        118	string
ATTRIBUTE	Digest-Domain	        119	string
ATTRIBUTE	Digest-Stale	        120	string
ATTRIBUTE	Digest-HA1	        121	string
ATTRIBUTE	SIP-AOR	                122	string

ATTRIBUTE       Digest-Attributes       207     binary
