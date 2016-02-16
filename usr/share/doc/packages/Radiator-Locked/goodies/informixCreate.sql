-- informixCreate.sql
-- create a simple SQL database for use by AuthSQL
-- In a real system, you will probably want much more than the
-- minimum set of columns for each table.
-- There is also an example RADONLINE table that will work with SessSQL
-- and its default parameters
--
-- $Id: informixCreate.sql,v 1.6 2005/01/25 05:16:45 mikem Exp $

-- Vape any old versions
drop table SUBSCRIBERS;
drop table ACCOUNTING;
drop table RADONLINE;
drop table RADPOOL;
drop table RADLOG;
drop table RADCLIENTLIST;
drop table RADSQLRADIUS;
drop table RADSQLRADIUSINDIRECT;
drop table RADSTATSLOG;
drop table RADAUTHLOG;
drop table RADLASTAUTH;
drop table TBL_VASCODP;

-- You must have at least a USERNAME and PASSWORD column.
-- You can have ENCRYPTEDPASSWORD if you define EncryptedPasswordColumn
-- in the config file.
-- You can have REPLYATTR if you define ReplyAttrColumn in the config file
-- You can have CHECKATTR if you define CheckAttrColumn in the config file
-- The exact names of the columns and this table can be changed with the
-- config file, but the names given here are the defaults.
create table SUBSCRIBERS (
	USERNAME	varchar(50) primary key,
					-- Users login name, including realm
	PASSWORD	varchar(50),	-- Cleartext password
	ENCRYPTEDPASSWORD varchar(50),	-- Optional encrypted password
	CHECKATTR	varchar(200),	-- Optional check radius attributes
	REPLYATTR	varchar(200)	-- Optional reply radius attributes
);

-- You may want to have an index on USERNAME for fast lookup with something like:
-- create unique index USERNAME_I on SUBSCRIBERS (USERNAME);

-- You must have at least username and timestamp
create table ACCOUNTING (
	USERNAME	varchar(50),	-- From User-Name 
	TIME_STAMP	int,		-- Time this was received (since 1970)
	ACCTSTATUSTYPE	varchar(10),
	ACCTDELAYTIME	int,
	ACCTINPUTOCTETS	int,
	ACCTOUTPUTOCTETS int,
	ACCTSESSIONID	varchar(30),
	ACCTSESSIONTIME	int,		-- Length of the session in secs
	ACCTTERMINATECAUSE int,
	NASIDENTIFIER	varchar(50),
	NASPORT		int,
	FRAMEDIPADDRESS	varchar(22)
);

-- Do you need an index? 
--create index ACCOUNTING_I on ACCOUNTING (USERNAME);

-- This is a sample user that is used by test.pl during testing
insert into SUBSCRIBERS (
	USERNAME, 
	PASSWORD, 
	ENCRYPTEDPASSWORD,
	CHECKATTR,
	REPLYATTR
	) 
	values (
	'mikem', 
	'fred', 
	'1xMKc0GIVUNbE',
	'Service-Type = Framed-User',
	'Framed-Protocol = PPP,Framed-IP-Netmask = 255.255.255.0,cisco-avpair = "testing testing"'
	);
	
-- An entry for each user _currently_ on line, for use by
-- <SessionDatabase SQL>
-- You can add more fields to this database, but you will also
-- need to adjust AddQuery to store the additional values.
-- You _must_ have at least 
-- USERNAME, NASIDENTIFIER, NASPORT and ACCTSESSIONID, which
-- is the unique key in this table.
create table RADONLINE (
	USERNAME	varchar(50),
	NASIDENTIFIER	varchar(50),
	NASPORT		int,
	ACCTSESSIONID	varchar(30),
	TIME_STAMP	int,
	FRAMEDIPADDRESS	varchar(22),
	NASPORTTYPE	varchar(10),
	SERVICETYPE	varchar(20)
);

-- Do you need an index?
create unique index RADONLINE_I on RADONLINE 
(NASIDENTIFIER, NASPORT);
create index RADONLINE_I2 on RADONLINE 
(USERNAME);


-- An entry for each allocatable address for AllocateAddress SQL
-- STATE: 0=free, 1=allocated
-- TIME_STAMP: last time it changed state
-- YIADDR: the IP address to be allocated
create table RADPOOL (
	STATE		int NOT NULL,
	TIME_STAMP	int,
	EXPIRY		int,
	USERNAME	varchar(50),
	POOL		varchar(50) NOT NULL,
	YIADDR		varchar(50) NOT NULL,
	SUBNETMASK	varchar(50) NOT NULL,
	DNSSERVER	varchar(50)
);
create unique index RADPOOL_I on RADPOOL (YIADDR);
create index RADPOOL_I2 on RADPOOL (POOL);

-- A table for storing log messages with LogSQL
-- These are the minimum requirements
create table RADLOG (
	TIME_STAMP	int,
	PRIORITY	int,
	MESSAGE		varchar(200)
);

-- A table for storing Client definitions
-- This table is accessed by ClientListSQL at
-- startup to initialise a list of Clients
create table RADCLIENTLIST (
	NASIDENTIFIER			varchar(50) NOT NULL,
	SECRET				varchar(50) NOT NULL,
	IGNOREACCTSIGNATURE		int,
	DUPINTERVAL			int,
	DEFAULTREALM			varchar(50),
	NASTYPE				varchar(20),
	SNMPCOMMUNITY			varchar(20),
	LIVINGSTONOFFS			int,
	LIVINGSTONHOLE			int,
	FRAMEDGROUPBASEADDRESS		varchar(50),
	FRAMEDGROUPMAXPORTSPERCLASSC	int,
	REWRITEUSERNAME			varchar(50),
	NOIGNOREDUPLICATES		varchar(50),
	PREHANDLERHOOK			varchar(50)
);
create unique index NASIDENTIFIER_I on RADCLIENTLIST (NASIDENTIFIER);

-- This is a sample Client that is used for testing
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
	
-- An example table for AuthBy SQLRADIUS
-- Contains an entry for each realm to be proxied, along with
-- target server information. For a simple system, set the TARGETNAME
-- to be the Relam to be proxied, and use the defualt HostSelect
-- in AuthBy SQLRADIUS. For more complicated systems, see below.
-- FAILUREPOLICY determines what to do if the request cant be forwarded
-- can be one of the return codes documented in AuthGeneric.pm, ie
-- 0 -> ACCEPT, 1 -> REJECT, 2 -> IGNORE. NULL will default to IGNORE
create table RADSQLRADIUS (
       TARGETNAME			varchar(50),
       HOST1				varchar(50),
       HOST2				varchar(50),
       SECRET				varchar(50),
       AUTHPORT				varchar(20),
       ACCTPORT				varchar(20),
       RETRIES				int,
       RETRYTIMEOUT			int,
       USEOLDASCENDPASSWORDS		int,
       SERVERHASBROKENPORTNUMBERS	int,
       SERVERHASBROKENADDRESSES		int,
       IGNOREREPLYSIGNATURE		int,
       FAILUREPOLICY			int
       );
create unique index RADSQLRADIUS_I on RADSQLRADIUS  (TARGETNAME);


-- If you have many called-station-ids or realms mapping to and single
-- target radius server, you can have an indirect table like this one
-- and set your HostSelect to be a join between tables
create table RADSQLRADIUSINDIRECT (
       SOURCENAME			varchar(50),
       TARGETNAME			varchar(50)
       );
create unique index RADSQLRADIUSINDIRECT_I on RADSQLRADIUSINDIRECT (SOURCENAME);

-- This table works with default StatsLogSQL
create table RADSTATSLOG (
       TIME_STAMP			int,
       TYPE				varchar(20),
       IDENTIFIER			varchar(30),
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

-- Table for recording successful and unsuccessful login attempts
-- This table could be used to work with a Radiator AuthLog like this:
--<AuthLog SQL>
--	DBSource	dbi:mysql:radmin:localhost
--	DBUsername	radmin
--	DBAuth		radminpw
--	LogSuccess
--	SuccessQuery insert into RADAUTHLOG (TIME_STAMP, USERNAME, TYPE) values (%t, '%n', 1)
--	LogFailure
--	FailureQuery insert into RADAUTHLOG (TIME_STAMP, USERNAME, TYPE, REASON) values (%t, '%n', 0, %1)
--</AuthLog>
create table RADAUTHLOG (
	TIME_STAMP	int,
	USERNAME	varchar(50),
	TYPE		int,
	REASON		varchar(50)
);
create index  USERNAME_I on RADAUTHLOG (USERNAME);

-- This table can be used in the example EAP-TTLS hook goodies/eap_anon_hook.pl
-- It is a lookaside table used to work out who the real user is for TTLS accounting
-- requests that would otherwise look like they are from 'anonymous'
create table RADLASTAUTH (
	USERNAME	varchar(50) NOT NULL,
	NASIDENTIFIER	varchar(50) NOT NULL,
	NASPORT		int NOT NULL,
	ACCTSESSIONID	varchar(30),
	TIME_STAMP	int
);
create unique index RADLASTAUTH_I on RADLASTAUTH (NASIDENTIFIER, NASPORT, ACCTSESSIONID);

-- This is similar to the example Vasco table from 'VACMAN Controller Integration Samples 3.0.0.1'
-- You can use it with the digipass.pl command line program included in the
-- Authen-Digipass bundle to import, assign, list Digipass tokens.
-- See goodies/digipass.cfg for exmaple config file that will 
-- authenticate Vasco Digipass token data in this table.
-- For a web-based GUI for managing users and Digipass tokens, see http://www.open.com.au/radmin
create table TBL_VASCODP
	(DIGIPASS 			varchar(22), 
	USER_ID 			varchar(100),
	DP_TYPE 			varchar(5), 
	ALGO_TYPE 			varchar(2), 
	DP_DATA 			varchar(248)
);
create unique index TBL_VASCODP_I on TBL_VASCODP (DIGIPASS);
