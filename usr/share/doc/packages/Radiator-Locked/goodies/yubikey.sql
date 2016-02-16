-- Sample Yubikey database for use with Radiator and goodies/yubikey.cfg
-- Compatible with Various Yubico servers
-- You can use this as a starting point fopr your user authentication
--
-- create database yubico;
-- grant all privileges on yubico.* to 'readwrite'@'localhost' identified by 'password';
-- flush privileges;

drop table if exists yubikeys; 
drop table if exists clients; 
drop table if exists perms; 

-- Not used by Radiator
create table perms (
       id int not null auto_increment,

       verify_otp boolean default false,

       add_clients boolean default false,
       delete_clients boolean default false,

       add_keys boolean default false,
       delete_keys boolean default false,
       
       primary key (id)
) ENGINE=InnoDB;


-- Use this to map usernames to yubikeys. IN this context a 'client' is a user
create table clients (
       id int not null auto_increment,
       perm_id int not null,

       active boolean default false,
       created datetime not null,
       email varchar(255) unique not null, -- User name
       secret varchar(60) not null,        -- static password

       primary key (id),
       foreign key (perm_id) references perms(id)
) ENGINE=InnoDB;

-- use this to identify each key
-- userId is actually the secretId, and _may_ be used as the user name too
create table yubikeys (
       id int not null auto_increment,
       client_id int not null,

       active boolean default false,
       created datetime not null,
       accessed datetime not null,

       tokenId varchar(60) unique not null, -- also called the Public Identity, modhex
       userId varchar(60) unique not null,  -- the secret-id or Private Identity, hex
       secret varchar(60) not null,         -- AES secret key in hex

       counter int default 0,
       low int default 0,
       high int default 0,

       primary key (id),
       foreign key (client_id) references clients(id)
) ENGINE=InnoDB;

-- alter table yubikeys change tokenId tokenId varchar(60) binary;

insert into perms values(1,true,true,true,true,true);

insert into clients values(1,1,true,now(), "mikem","fred");

-- from ./YKPersonalization of test key
-- fixed: m:vvcjnihvlfbv
-- uid: h:5a50d3651e91
-- key: h:829e70e675b46c610c6fa1c62d6d8fff
-- acc_code: h:000000000000
-- ticket_flags: APPEND_CR
-- config_flags: 
-- extended_flags: 

insert into yubikeys values (1, 1, 1, now(), now(), 'vvcjnihvlfbv', '5a50d3651e91', '829e70e675b46c610c6fa1c62d6d8fff', 0, 0, 0);

-- Can now use 
-- radiusd -config goodies/yubikey.cfg
-- and test with
-- radpwtst -noacct -user mikem -password vvcjnihvlfbvnnhtrhdtkktctfnicfccgfbventrlhrca
