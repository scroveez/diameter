# hotp.sql
# 
# Create a sample database for use with AuthBy HOTP
#
# 2 sample users are inserted. mikem has no PIN and fred has the PIN of 'fred'
# The HOTP secrets are the one given in RFC 4226#
#
# You can create this database with these commands:
# mysql -uroot -prootpw
#   create database radius;
#   grant all privileges on radius.* to 'mikem'@'localhost' identified by 'fred';
#   flush privileges;
#   exit
# mysql -Dradius -umikem -pfred <goodies/hotp.sql
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2009 Open System Consultants
# $Id: hotp.sql,v 1.4 2012/08/23 08:07:59 mikem Exp $

drop table if exists hotpkeys; 

create table hotpkeys
(
	id int not null auto_increment,
      	active boolean default false,
	created datetime not null,
	accessed datetime not null,

	username varchar(60) unique not null,
        tokenId varchar(60),         # Optional for finding by token ID
	pin varchar(60),             # optional
       	secret varchar(60) not null, # Hex encoded secret for the token. RFC requires at least 128 bits
	digits int default 6,        # truncation length
	counter_high int default 0,  # high 32 bits
	counter_low int default 0,   # low 32 bits
	bad_logins int default 0,    # last bad was at time accessed

       primary key (id)

);

# Test records. This is the the same token as the test data in RFC 4226
# 6 digit HOTP starting at counter 0
# The resulting HOTPs should be, in order:
# 755224 287082 359152 969429 338314 254676 287922 162583 399871 520489 

# No pin
insert into hotpkeys values (1, 1, now(), now(), 'mikem', NULL, NULL, '3132333435363738393031323334353637383930', 6, 0, 0, 0);

# Pin required
insert into hotpkeys values (2, 1, now(), now(), 'fred', NULL, 'fred', '3132333435363738393031323334353637383930', 6, 0, 0, 0);

# Some test records for various sample tokens used as OSC
# No pin iphone DS3 OATH app test
insert into hotpkeys values (3, 1, now(), now(), 'ds3', NULL, NULL, 'd8f828609e0f4056f852e4c9d75605099f483e20', 6, 0, 0, 0);

# No pin iphone OATH Token app (Event based) test
insert into hotpkeys values (4, 1, now(), now(), 'oathtoken', NULL, NULL, 'b906daef6d002ec6cc89106df25f8268ce28f95e', 6, 0, 0, 0);

# No pin iphone Google Authenticator app (Event based) test
# Note that in Google Authenticator, manual entry of keys is in RFC 3548 base32 key strings.
# The hex key 0000000000000000000000000000000000000000 here is the result of entering
# manual  RFC 3548 base32 key of 'aaaaaaaaaaaaaaaaaaaa'
insert into hotpkeys values (5, 1, now(), now(), 'google', NULL, NULL, '0000000000000000000000000000000000000000', 6, 0, 0, 0);

