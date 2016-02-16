# motp.sql
# 
# Create a sample database for use with AuthBy SQLMOTP
#
# 1 sample users are inserted. mikem has PIN 1234 and a secret of '7ac61d4736f51a2b'
#
# You can create this database with these commands:
# mysql -uroot -prootpw
#   create database radius;
#   grant all privileges on radius.* to 'mikem'@'localhost' identified by 'fred';
#   flush privileges;
#   exit
# mysql -Dradius -umikem -pfred <goodies/motp.sql
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2009 Open System Consultants
# $Id: motp.sql,v 1.1 2009/12/16 04:18:46 mikem Exp $

drop table if exists mobileotp; 

create table mobileotp
(
      	active boolean default false,
	created datetime not null,
	accessed datetime not null,
	userId varchar(60) unique not null,
        tokenId varchar(60),         # Optional for finding by token ID
	pin varchar(60) not NULL,    # 4 digit PIN
       	secret varchar(60) not null, # Hex encoded version of 8 octets of secret

       primary key (userId)

);

# Test records. 

insert into mobileotp values (1, now(), now(), 'mikem', NULL, '1234', '7ac61d4736f51a2b');

