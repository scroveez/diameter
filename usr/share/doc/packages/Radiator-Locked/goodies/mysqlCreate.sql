# mysqlCreate.sql
# Create the simplest MYSQL database suitable for use by AuthSQL
# In a real system, you will probably want much more than the
# minimum set of columns for each table.
# There is also an example RADONLINE table that will work with SessSQL
# and its default parameters.
#
# You can create this database with these commands:
# mysql -uroot -prootpw
#   create database radius;
#   grant all privileges on radius.* to 'mikem'@'localhost' identified by 'fred';
#   flush privileges;
#   exit
# mysql -Dradius -umikem -pfred <goodies/mysqlCreate.sql
# 
# $Id: mysqlCreate.sql,v 1.22 2011/09/29 21:51:03 mikem Exp $

# Vape any old versions
drop table if exists SUBSCRIBERS;
drop table if exists ACCOUNTING;
drop table if exists RADONLINE;
drop table if exists RADLOG;
drop table if exists RADPOOL;
drop table if exists RADCLIENTLIST;
drop table if exists RADSQLRADIUS;
drop table if exists RADSQLRADIUSINDIRECT;
drop table if exists RADSTATSLOG;
drop table if exists RADAUTHLOG;
drop table if exists RADLASTAUTH;
drop table if exists TBL_VASCODP;
drop table if exists EAPFAST_PAC;
drop table if exists GROUPS;
drop table if exists RADSQLAUTHBY;


# You must have at least a USERNAME and PASSWORD column.
# You can have ENCRYPTEDPASSWORD if you define EncryptedPasswordColumn
# in the config file.
# You can have REPLYATTR if you define ReplyAttrColumn in the config file
# You can have CHECKATTR if you define CheckAttrColumn in the config file
# The exact names of the columns and this table can be changed with the
# config file, but the names given here are the defaults.
create table SUBSCRIBERS (
	USERNAME	char(50) NOT NULL,	# Users login name, including realm
	PASSWORD	char(50),	# Cleartext password
	ENCRYPTEDPASSWORD char(50),	# Optional encrypted password
	CHECKATTR	char(200),	# Optional check radius attributes
	REPLYATTR	char(200),	# Optional reply radius attributes
	TIMELEFT	int,		# Seconds left (see prepaid.cfg)
	UNIQUE 		USERNAME_I (USERNAME)
);

# You must have at least username and timestamp
# You can add more feilds to the database, but you will also
# have to change AcctColumnDef to make sure they get inserted
create table ACCOUNTING (
	USERNAME	char(50) NOT NULL, # From User-Name 
	TIME_STAMP	int,      # Time this was received (since 1970)
	ACCTSTATUSTYPE	char(10),
	ACCTDELAYTIME	int,
	ACCTINPUTOCTETS	int,
	ACCTOUTPUTOCTETS int,
	ACCTSESSIONID	char(30),
	ACCTSESSIONTIME	int,	  # Length of the session in secs
	ACCTTERMINATECAUSE int,
	NASIDENTIFIER	char(50),
	NASPORT		int,
	FRAMEDIPADDRESS	char(22),
	INDEX ACCOUNTING_I (USERNAME)
);

# This is a sample user that is used by test.pl during testing
insert into SUBSCRIBERS (
	USERNAME, 
	PASSWORD, 
	ENCRYPTEDPASSWORD,
	CHECKATTR,
	REPLYATTR,
	TIMELEFT
	) 
	values (
	'mikem', 
	'fred', 
	'1xMKc0GIVUNbE',
	'Service-Type = Framed-User',
	'Framed-Protocol = PPP,Framed-IP-Netmask = 255.255.255.0,cisco-avpair = "testing testing"',
	100
	);
	
# An entry for each user _currently_ on line, for use by
# <SessionDatabase SQL>
# You can add more fields to this database, but you will also
# need to adjust AddQuery to store the additional values.
# You _must_ have at least 
# USERNAME, NASIDENTIFIER, NASPORT and ACCTSESSIONID, which
# is the unique key in this table.
create table RADONLINE (
	USERNAME	char(50) NOT NULL,
	NASIDENTIFIER	char(50) NOT NULL,
	NASPORT		int NOT NULL,
	ACCTSESSIONID	char(30) NOT NULL,
	TIME_STAMP	int,
	FRAMEDIPADDRESS	char(22),
	NASPORTTYPE	char(10),
	SERVICETYPE	char(20),

	UNIQUE RADONLINE_I (NASIDENTIFIER, NASPORT),
	INDEX RADONLINE_I2 (USERNAME)
);

# An entry for each allocatable address for AllocateAddress SQL
# STATE: 0=free, 1=allocated
# TIME_STAMP: last time it changed state
# YIADDR: the IP address to be allocated
create table RADPOOL (
	STATE		int NOT NULL,
	TIME_STAMP	int,
	EXPIRY		int,
	USERNAME	char(50),
	POOL		char(50) NOT NULL,
	YIADDR		char(50) NOT NULL,
	SUBNETMASK	char(50) NOT NULL,
	DNSSERVER	char(50),

	UNIQUE RADPOOL_I (YIADDR),
	INDEX RADPOOL_I2 (POOL)
);

# A table for storing log messages with LogSQL
# These are the minimum requirements
create table RADLOG (
	TIME_STAMP	int,
	PRIORITY	int,
	MESSAGE		char(200)
);

# A table for storing Client definitions
# This table is accessed by ClientListSQL at
# startup to initialise a list of Clients
create table RADCLIENTLIST (
	NASIDENTIFIER			char(50) NOT NULL,
	SECRET				char(50) NOT NULL,
	IGNOREACCTSIGNATURE		int,
	DUPINTERVAL			int,
	DEFAULTREALM			char(50),
	NASTYPE				char(20),
	SNMPCOMMUNITY			char(20),
	LIVINGSTONOFFS			int,
	LIVINGSTONHOLE			int,
	FRAMEDGROUPBASEADDRESS		char(50),
	FRAMEDGROUPMAXPORTSPERCLASSC	int,
	REWRITEUSERNAME			char(50),
	NOIGNOREDUPLICATES		char(50),
	PREHANDLERHOOK			char(50),
	UNIQUE 				NASIDENTIFIER_I (NASIDENTIFIER)
);	

# This is a sample Client that is used for testing
insert into RADCLIENTLIST (
	NASIDENTIFIER, 
	SECRET, 
	DUPINTERVAL
	) 
	values (
	'203.63.154.1', 
	'mysecret', 
	0
	);
	
# An example table for AuthBy SQLRADIUS
# Contains an entry for each realm to be proxied, along with
# target server information. For a simple system, set the TARGETNAME
# to be the Relam to be proxied, and use the defualt HostSelect
# in AuthBy SQLRADIUS. For more complicated systems, see below.
# FAILUREPOLICY determines what to do if the request cant be forwarded
# can be one of the return codes documented in AuthGeneric.pm, ie
# 0 -> ACCEPT, 1 -> REJECT, 2 -> IGNORE. NULL will default to IGNORE
create table RADSQLRADIUS (
       TARGETNAME			char(50),
       HOST1				char(50),
       HOST2				char(50),
       SECRET				char(50),
       AUTHPORT				char(20),
       ACCTPORT				char(20),
       RETRIES				int,
       RETRYTIMEOUT			int,
       USEOLDASCENDPASSWORDS		int,
       SERVERHASBROKENPORTNUMBERS	int,
       SERVERHASBROKENADDRESSES		int,
       IGNOREREPLYSIGNATURE		int,
       FAILUREPOLICY			int,
       FAILUREBACKOFFTIME		int,
       MAXFAILEDREQUESTS		int,
       MAXFAILEDGRACETIME		int,
       UNIQUE 				RADSQLRADIUS_I (TARGETNAME)
       );

# If you have many called-station-ids or realms mapping to and single
# target radius server, you can have an indirect table like this one
# and set your HostSelect to be a join between tables
create table RADSQLRADIUSINDIRECT (
       SOURCENAME			char(50),
       TARGETNAME			char(50),
       UNIQUE 				RADSQLRADIUSINDIRECT_I (SOURCENAME)
       );


# This table works with default StatsLogSQL
create table RADSTATSLOG (
       TIME_STAMP			int,
       TYPE				char(20),
       IDENTIFIER			char(30),
       ACCESSACCEPTS			int,
       ACCESSCHALLENGES			int,
       ACCESSREJECTS			int,
       ACCESSREQUESTS			int,
       ACCOUNTINGREQUESTS		int,
       ACCOUNTINGRESPONSES		int,
       BADAUTHACCESSREQUESTS		int,
       BADAUTHACCOUNTINGREQUESTS	int,
       BADAUTHREQUESTS			int,
       DROPPEDACCESSREQUESTS		int,
       DROPPEDACCOUNTINGREQUESTS	int,
       DROPPEDREQUESTS			int,
       DUPACCESSREQUESTS		int,
       DUPACCOUNTINGREQUESTS		int,
       DUPLICATEREQUESTS		int,
       MALFORMEDACCESSREQUESTS		int,
       MALFORMEDACCOUNTINGREQUESTS	int,
       PROXIEDNOREPLY			int,
       PROXIEDREQUESTS			int,
       REQUESTS				int,
       RESPONSETIME			decimal(12,6)
);

# Table for recording successful and unsuccessful login attempts
# This table could be used to work with a Radiator AuthLog like this:
#<AuthLog SQL>
#	DBSource	dbi:mysql:radmin:localhost
#	DBUsername	radmin
#	DBAuth		radminpw
#	LogSuccess
#	SuccessQuery insert into RADAUTHLOG (TIME_STAMP, USERNAME, TYPE) values (%t, '%n', 1)
#	LogFailure
#	FailureQuery insert into RADAUTHLOG (TIME_STAMP, USERNAME, TYPE, REASON) values (%t, '%n', 0, %1)
#</AuthLog>
create table RADAUTHLOG (
	TIME_STAMP	int,
	USERNAME	char(50),
	TYPE		int,
	REASON		char(50),
	INDEX USERNAME_I (USERNAME)
);

# This table can be used in the example EAP-TTLS hook goodies/eap_anon_hook.pl
# It is a lookaside table used to work out who the real user is for TTLS accounting
# requests that would otherwise look like they are from 'anonymous'
create table RADLASTAUTH (
	USERNAME	char(50) NOT NULL,
	NASIDENTIFIER	char(50) NOT NULL,
	NASPORT		int NOT NULL,
	ACCTSESSIONID	char(30),
	TIME_STAMP	int,

	UNIQUE RADLASTAUTH_I (NASIDENTIFIER, NASPORT, ACCTSESSIONID)
);

# This is similar to the example Vasco table from 'VACMAN Controller Integration Samples 3.0.0.1'
# You can use it with the digipass.pl command line program included in the
# Authen-Digipass bundle to import, assign, list Digipass tokens.
# See goodies/digipass.cfg for exmaple config file that will 
# authenticate Vasco Digipass token data in this table.
# For a web-based GUI for managing users and Digipass tokens, see http://www.open.com.au/radmin
CREATE TABLE TBL_VASCODP
	(DIGIPASS 	char(22) PRIMARY KEY, 
	USER_ID 	char(100),               # NULL if not assigned
	DP_TYPE 	char(5), 
	ALGO_TYPE 	char(2), 		# Not used by Radiator
	DP_DATA 	char(248)
);

# This table can be used to hold EAP-FAST PACS (either pre-provisioned, or created on demand by
# by Radiator
# PAC_OPAQUE is hex encoded key that is used to retrieve the actual session key
# PAC_LIFETIME is the expppiry time in seconds UNix epoch
# PAC_KEY is the session key hex encoded used to provision  the EAP-FAST session
CREATE TABLE EAPFAST_PAC
	(PAC_OPAQUE 	char(64) PRIMARY KEY,
	PAC_LIFETIME	int, 
	PAC_KEY		char(64)
);

# This table can be used to hold which group(s) a user belongs to
CREATE TABLE GROUPS
	(
	USERNAME	char(50) NOT NULL,
	GROUPNAME	char(50) NOT NULL
);

insert into GROUPS (USERNAME, GROUPNAME) values ('mikem', 'group1'), ('mikem', 'group2');

# Contents of this table can used with AuthBy SQLAUTHBY to select an LDAP server
# based on the TARGETNAME realm
CREATE TABLE RADSQLAUTHBY
(
       TARGETNAME			char(50),
       HOST				char(50),
       PORT				char(50),
       AUTHDN				char(100),
       AUTHPASSWORD			char(50),
       BASEDN				char(100),
       USERNAMEATTR			char(100),
       PASSWORDATTR			char(100),
       HOLDSERVERCONNECTION		int,
       UNIQUE 				RADSQLAUTHBY_I (TARGETNAME)
);

# 2 test LDAP servers
insert into RADSQLAUTHBY 
(TARGETNAME, HOST, PORT, AUTHDN, AUTHPASSWORD, BASEDN, USERNAMEATTR, PASSWORDATTR, HOLDSERVERCONNECTION)
values
('realm1', 'localhost', NULL, 'cn=Manager, dc=example, dc=com', 'secret', 'dc=example, dc=com', 'cn', 'userPassword', 1),
('realm2', 'someotherhost', '1234', 'cn=Manager, dc=anotherexample, dc=com', 'xxsecret', 'dc=anotherexample, dc=com', 'cn', 'userPassword', 1);
