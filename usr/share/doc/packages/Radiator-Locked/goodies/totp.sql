-- totp.sql
--
-- Create a sample database for use with AuthBy TOTP
--
-- 3+1+1 sample users are inserted. Usernames starting with mikem use RFC 6238 test data and have no PIN.
-- User fred has the PIN of 'fred'
-- User google has test data that is compatible with Google Authenticator: 6 digiest with SHA1 based HMAC
--
-- You can create this database with these commands:
-- mysql -uroot -prootpw
--   create database radius;
--   grant all privileges on radius.* to 'mikem'@'localhost' identified by 'fred';
--   flush privileges;
--   exit
-- mysql -Dradius -umikem -pfred <goodies/totp.sql
--
-- Author: Mike McCauley (mikem@open.com.au)
-- Copyright (C) 2009 Open System Consultants
-- $Id: totp.sql,v 1.5 2014/11/13 20:31:27 hvn Exp $

drop table if exists totpkeys;

create table totpkeys
(
	id int not null auto_increment,
	active boolean default false,
	created datetime not null,
	accessed datetime not null,

	username varchar(100) unique not null,
        tokenId text,				-- Optional for finding by token ID
	pin text,             			-- Optional
       	secret varchar(130) unique not null, 	-- Hex encoded secret key for the token.
	digits int default 6,          		-- truncation length
	bad_logins int default 0,    		-- last bad was at time accessed
	last_timestep int,           		-- Last TOTP timestep validated

	-- If these are defined, they override the defaults and configuration file parameters
	algorithm text not null,     		-- Hash algorithm for the HMAC
	timestep int default 30,		-- X: The time step in seconds
	timestep_origin int default 0,		-- T0: Unix time to start counting time steps

	primary key (id)
);

-- Test records. This is the the same token as the test data in RFC 6238
-- Supported by, for example, FreeOTP Authenticator: 8 digit TOTP, no pin
-- Note: some implementations, such as Google Authenticator, do not support 8 digit TOTPs
insert into totpkeys values (1, 1, now(), now(), 'mikem', NULL, NULL, '3132333435363738393031323334353637383930', 8, 0, NULL, 'SHA1', 30, 0);
insert into totpkeys values (2, 1, now(), now(), 'mikem256', NULL, NULL, '3132333435363738393031323334353637383930313233343536373839303132', 8, 0, NULL, 'SHA256', 30, 0);
insert into totpkeys values (3, 1, now(), now(), 'mikem512', NULL, NULL, '31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334', 8, 0, NULL, 'SHA512', 30, 0);

-- Pin required, 6 digits
-- The hex key 1111111111111111111111111111111111111111 here is the result of entering
-- manual RFC 3548 base32 key of 'CEIR CEIR CEIR CEIR CEIR CEIR CEIR CEIR'
insert into totpkeys values (4, 1, now(), now(), 'fred', NULL, 'fred', '1111111111111111111111111111111111111111', 6, 0, NULL, 'SHA1', 30, 0);

-- Google Authenticator app compatible data: no pin, 6 digits and HMAC-SHA-1
-- Note that in Google Authenticator, manual entry of keys is in RFC 3548 base32 key strings.
-- The hex key 0000000000000000000000000000000000000000 here is the result of entering
-- manual RFC 3548 base32 key of 'AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA'
insert into totpkeys values (5, 1, now(), now(), 'google', NULL, NULL, '0000000000000000000000000000000000000000', 6, 0, NULL, 'SHA1', 30, 0);
