SET client_encoding = 'SQL_ASCII';
SET check_function_bodies = false;

SET SESSION AUTHORIZATION 'postgres';

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA public TO PUBLIC;

COMMENT ON SCHEMA public IS 'ck';

SET SESSION AUTHORIZATION 'postgres';

SET search_path = public, pg_catalog;

CREATE TABLE users (
    userid bigint NOT NULL,
    username character varying(256) NOT NULL,
    status character varying(256) DEFAULT ''::character varying NOT NULL,
    emailaddress character varying(256) NOT NULL,
    joineddate timestamp with time zone NOT NULL,
    passwordhash character varying(256) NOT NULL,
    secondaryuserid character varying(64) NOT NULL,
    salt character varying(256) DEFAULT ''::character varying NOT NULL,
    userdata text DEFAULT ''::text NOT NULL,
    userbits bigint NOT NULL,
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) DEFAULT ''::character varying NOT NULL,
    createcode character varying(128) DEFAULT ''::character varying NOT NULL,
    createinet character varying(128) DEFAULT ''::character varying NOT NULL,
    expirydate timestamp with time zone DEFAULT '6666-06-06 06:06:06+00',
    PRIMARY KEY (userid, expirydate)
);
CREATE UNIQUE INDEX usersusername ON users USING btree (username, expirydate);


CREATE TABLE useratts (
    userid bigint NOT NULL,
    attname character varying(64) NOT NULL,
    status character varying(256) DEFAULT ''::character varying NOT NULL,
    attstr character varying(256) DEFAULT ''::character varying NOT NULL,
    attstr2 character varying(256) DEFAULT ''::character varying NOT NULL,
    attnum bigint DEFAULT 0 NOT NULL,
    attnum2 bigint DEFAULT 0 NOT NULL,
    attdate timestamp with time zone DEFAULT '1970-01-01 00:00:00+00',
    attdate2 timestamp with time zone DEFAULT '1970-01-01 00:00:00+00',
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) DEFAULT ''::character varying NOT NULL,
    createcode character varying(128) DEFAULT ''::character varying NOT NULL,
    createinet character varying(128) DEFAULT ''::character varying NOT NULL,
    expirydate timestamp with time zone DEFAULT '6666-06-06 06:06:06+00',
    PRIMARY KEY (userid, attname, expirydate)
);


CREATE TABLE workers (
    workerid bigint NOT NULL, -- unique per record
    userid bigint NOT NULL,
    workername character varying(256) NOT NULL,
    difficultydefault integer DEFAULT 0 NOT NULL, -- 0 means default
    idlenotificationenabled char DEFAULT 'n'::character varying NOT NULL,
    idlenotificationtime integer DEFAULT 10 NOT NULL,
    workerbits bigint NOT NULL,
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) DEFAULT ''::character varying NOT NULL,
    createcode character varying(128) DEFAULT ''::character varying NOT NULL,
    createinet character varying(128) DEFAULT ''::character varying NOT NULL,
    expirydate timestamp with time zone DEFAULT '6666-06-06 06:06:06+00',
    PRIMARY KEY (workerid, expirydate)
);
CREATE UNIQUE INDEX workersuserid ON workers USING btree (userid, workername, expirydate);


CREATE TABLE paymentaddresses (
    paymentaddressid bigint NOT NULL, -- unique per record
    userid bigint NOT NULL,
    payaddress character varying(256) DEFAULT ''::character varying NOT NULL,
    payratio integer DEFAULT 1000000 NOT NULL,
    payname character varying(64) DEFAULT ''::character varying NOT NULL,
    status char DEFAULT ' ' NOT NULL,
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) DEFAULT ''::character varying NOT NULL,
    createcode character varying(128) DEFAULT ''::character varying NOT NULL,
    createinet character varying(128) DEFAULT ''::character varying NOT NULL,
    expirydate timestamp with time zone DEFAULT '6666-06-06 06:06:06+00',
    PRIMARY KEY (paymentaddressid, expirydate)
);
CREATE UNIQUE INDEX payadduserid ON paymentaddresses USING btree (userid, payaddress, expirydate);


CREATE TABLE payments (
    paymentid bigint NOT NULL, -- unique per record
    payoutid bigint NOT NULL,
    userid bigint NOT NULL,
    subname character varying(256) NOT NULL,
    paydate timestamp with time zone NOT NULL,
    payaddress character varying(256) DEFAULT ''::character varying NOT NULL,
    originaltxn character varying(256) DEFAULT ''::character varying NOT NULL,
    amount bigint NOT NULL, -- satoshis
    diffacc float DEFAULT 0 NOT NULL,
    committxn character varying(256) DEFAULT ''::character varying NOT NULL,
    commitblockhash character varying(256) DEFAULT ''::character varying NOT NULL,
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) DEFAULT ''::character varying NOT NULL,
    createcode character varying(128) DEFAULT ''::character varying NOT NULL,
    createinet character varying(128) DEFAULT ''::character varying NOT NULL,
    expirydate timestamp with time zone DEFAULT '6666-06-06 06:06:06+00',
    PRIMARY KEY (paymentid, expirydate)
);
CREATE UNIQUE INDEX payuserid ON payments USING btree (payoutid, userid, subname, payaddress, originaltxn, expirydate);


CREATE TABLE accountbalance ( -- summarised from miningpayouts and payments - RAM only
    userid bigint NOT NULL,
    confirmedpaid bigint DEFAULT 0 NOT NULL, -- satoshis
    confirmedunpaid bigint DEFAULT 0 NOT NULL, -- satoshis
    pendingconfirm bigint DEFAULT 0 NOT NULL, -- satoshis
    heightupdate integer not NULL,
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) DEFAULT ''::character varying NOT NULL,
    createcode character varying(128) DEFAULT ''::character varying NOT NULL,
    createinet character varying(128) DEFAULT ''::character varying NOT NULL,
    modifydate timestamp with time zone DEFAULT '6666-06-06 06:06:06+00',
    modifyby character varying(64) DEFAULT ''::character varying NOT NULL,
    modifycode character varying(128) DEFAULT ''::character varying NOT NULL,
    modifyinet character varying(128) DEFAULT ''::character varying NOT NULL,
    PRIMARY KEY (userid)
);


CREATE TABLE accountadjustment ( -- manual corrections
    userid bigint NOT NULL,
    authority character varying(256) NOT NULL,
    reason text NOT NULL,
    message character varying(256) NOT NULL,
    amount bigint DEFAULT 0 NOT NULL, -- satoshis
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) DEFAULT ''::character varying NOT NULL,
    createcode character varying(128) DEFAULT ''::character varying NOT NULL,
    createinet character varying(128) DEFAULT ''::character varying NOT NULL,
    expirydate timestamp with time zone DEFAULT '6666-06-06 06:06:06+00',
    PRIMARY KEY (userid, createdate, expirydate)
);


CREATE TABLE idcontrol  (
    idname character varying(64) NOT NULL,
    lastid bigint DEFAULT 1 NOT NULL,
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) DEFAULT ''::character varying NOT NULL,
    createcode character varying(128) DEFAULT ''::character varying NOT NULL,
    createinet character varying(128) DEFAULT ''::character varying NOT NULL,
    modifydate timestamp with time zone DEFAULT '6666-06-06 06:06:06+00',
    modifyby character varying(64) DEFAULT ''::character varying NOT NULL,
    modifycode character varying(128) DEFAULT ''::character varying NOT NULL,
    modifyinet character varying(128) DEFAULT ''::character varying NOT NULL,
    PRIMARY KEY (idname)
);


CREATE TABLE optioncontrol (
    optionname character varying(64) NOT NULL,
    optionvalue text NOT NULL,
    activationdate timestamp with time zone DEFAULT '6666-06-06 06:06:06+00',
    activationheight integer DEFAULT 999999999,
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) DEFAULT ''::character varying NOT NULL,
    createcode character varying(128) DEFAULT ''::character varying NOT NULL,
    createinet character varying(128) DEFAULT ''::character varying NOT NULL,
    expirydate timestamp with time zone DEFAULT '6666-06-06 06:06:06+00',
    PRIMARY KEY (optionname, activationdate, activationheight, expirydate)
);


CREATE TABLE workinfo (
    workinfoid bigint NOT NULL, -- unique per record
    poolinstance character varying(256) NOT NULL,
    transactiontree text DEFAULT ''::text NOT NULL,
    merklehash text DEFAULT ''::text NOT NULL,
    prevhash character varying(256) NOT NULL,
    coinbase1 character varying(256) NOT NULL,
    coinbase2 character varying(511) NOT NULL,
    version character varying(64) NOT NULL,
    bits character varying(64) NOT NULL,
    ntime character varying(64) NOT NULL,
    reward bigint NOT NULL, -- satoshis
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) DEFAULT ''::character varying NOT NULL,
    createcode character varying(128) DEFAULT ''::character varying NOT NULL,
    createinet character varying(128) DEFAULT ''::character varying NOT NULL,
    expirydate timestamp with time zone DEFAULT '6666-06-06 06:06:06+00',
    PRIMARY KEY (workinfoid, expirydate)
);


CREATE TABLE shares ( -- only shares with sdiff >= -D minsdiff are stored in the DB
    workinfoid bigint NOT NULL,
    userid bigint NOT NULL,
    workername character varying(256) NOT NULL,
    clientid integer NOT NULL,
    enonce1 character varying(64) NOT NULL,
    nonce2 character varying(256) NOT NULL,
    nonce character varying(64) NOT NULL,
    diff float NOT NULL,
    sdiff float NOT NULL,
    errn integer NOT NULL,
    error character varying(64) DEFAULT ''::character varying NOT NULL, -- optional
    secondaryuserid character varying(64) NOT NULL,
    ntime character varying(64) NOT NULL,
    minsdiff float NOT NULL,
    agent character varying(128) DEFAULT ''::character varying NOT NULL,
    address character varying(128) DEFAULT ''::character varying NOT NULL,
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) DEFAULT ''::character varying NOT NULL,
    createcode character varying(128) DEFAULT ''::character varying NOT NULL,
    createinet character varying(128) DEFAULT ''::character varying NOT NULL,
    expirydate timestamp with time zone DEFAULT '6666-06-06 06:06:06+00',
    PRIMARY KEY (workinfoid, userid, workername, enonce1, nonce2, nonce, expirydate)
);


CREATE TABLE shareerrors ( -- not stored in the db - only in log files
    workinfoid bigint NOT NULL,
    userid bigint NOT NULL,
    workername character varying(256) NOT NULL,
    clientid integer NOT NULL,
    errn integer NOT NULL,
    error character varying(64) DEFAULT ''::character varying NOT NULL, -- optional
    secondaryuserid character varying(64) NOT NULL,
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) DEFAULT ''::character varying NOT NULL,
    createcode character varying(128) DEFAULT ''::character varying NOT NULL,
    createinet character varying(128) DEFAULT ''::character varying NOT NULL,
    expirydate timestamp with time zone DEFAULT '6666-06-06 06:06:06+00',
    PRIMARY KEY (workinfoid, userid, workername, clientid, createdate, expirydate)
);


CREATE TABLE marks ( -- workinfoids to make workmarkers
    poolinstance character varying(256) NOT NULL,
    workinfoid bigint NOT NULL,
    description character varying(256) DEFAULT ''::character varying NOT NULL,
    extra character varying(256) DEFAULT ''::character varying NOT NULL,
    marktype char NOT NULL, -- 'b'lock 'p'plns-begin 's'hift-begin 'e'=shift-end
    status char NOT NULL,
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) DEFAULT ''::character varying NOT NULL,
    createcode character varying(128) DEFAULT ''::character varying NOT NULL,
    createinet character varying(128) DEFAULT ''::character varying NOT NULL,
    expirydate timestamp with time zone DEFAULT '6666-06-06 06:06:06+00',
    PRIMARY KEY (poolinstance, workinfoid, expirydate)
);


CREATE TABLE workmarkers ( -- range of workinfo for share accounting
    markerid bigint NOT NULL,
    poolinstance character varying(256) NOT NULL,
    workinfoidend bigint NOT NULL,
    workinfoidstart bigint NOT NULL,
    description character varying(256) DEFAULT ''::character varying NOT NULL,
    status char NOT NULL,
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) DEFAULT ''::character varying NOT NULL,
    createcode character varying(128) DEFAULT ''::character varying NOT NULL,
    createinet character varying(128) DEFAULT ''::character varying NOT NULL,
    expirydate timestamp with time zone DEFAULT '6666-06-06 06:06:06+00',
    PRIMARY KEY (markerid, expirydate)
);


CREATE TABLE markersummary ( -- sum of sharesummary for a workinfo range
    markerid bigint NOT NULL,
    userid bigint NOT NULL,
    workername character varying(256) NOT NULL,
    diffacc float NOT NULL,
    diffsta float NOT NULL,
    diffdup float NOT NULL,
    diffhi float NOT NULL,
    diffrej float NOT NULL,
    shareacc float NOT NULL,
    sharesta float NOT NULL,
    sharedup float NOT NULL,
    sharehi float NOT NULL,
    sharerej float NOT NULL,
    sharecount bigint NOT NULL,
    errorcount bigint NOT NULL,
    firstshare timestamp with time zone NOT NULL,
    lastshare timestamp with time zone NOT NULL,
    firstshareacc timestamp with time zone NOT NULL,
    lastshareacc timestamp with time zone NOT NULL,
    lastdiffacc float NOT NULL,
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) NOT NULL,
    createcode character varying(128) NOT NULL,
    createinet character varying(128) NOT NULL,
    modifydate timestamp with time zone NOT NULL,
    modifyby character varying(64) NOT NULL,
    modifycode character varying(128) NOT NULL,
    modifyinet character varying(128) NOT NULL,
    PRIMARY KEY (markerid, userid, workername)
);


-- this is optionally filled, for statistical analysis - see code
CREATE TABLE keysummary (
    markerid bigint NOT NULL,
    keytype char NOT NULL,
    key character varying(128) NOT NULL,
    diffacc float NOT NULL,
    diffsta float NOT NULL,
    diffdup float NOT NULL,
    diffhi float NOT NULL,
    diffrej float NOT NULL,
    shareacc float NOT NULL,
    sharesta float NOT NULL,
    sharedup float NOT NULL,
    sharehi float NOT NULL,
    sharerej float NOT NULL,
    sharecount bigint NOT NULL,
    errorcount bigint NOT NULL,
    firstshare timestamp with time zone NOT NULL,
    lastshare timestamp with time zone NOT NULL,
    firstshareacc timestamp with time zone NOT NULL,
    lastshareacc timestamp with time zone NOT NULL,
    lastdiffacc float NOT NULL,
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) NOT NULL,
    createcode character varying(128) NOT NULL,
    createinet character varying(128) NOT NULL,
    PRIMARY KEY (markerid, keytype, key)
);


CREATE TABLE blocks (
    height integer not NULL,
    blockhash character varying(256) NOT NULL,
    workinfoid bigint NOT NULL,
    userid bigint NOT NULL,
    workername character varying(256) NOT NULL,
    clientid integer NOT NULL,
    enonce1 character varying(64) NOT NULL,
    nonce2 character varying(256) NOT NULL,
    nonce character varying(64) NOT NULL,
    reward bigint NOT NULL, -- satoshis
    confirmed char DEFAULT '' NOT NULL,
    info character varying(64) DEFAULT ''::character varying NOT NULL,
    diffacc float DEFAULT 0 NOT NULL,
    diffinv float DEFAULT 0 NOT NULL,
    shareacc float DEFAULT 0 NOT NULL,
    shareinv float DEFAULT 0 NOT NULL,
    elapsed bigint DEFAULT 0 NOT NULL,
    statsconfirmed char DEFAULT 'N' NOT NULL,
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) DEFAULT ''::character varying NOT NULL,
    createcode character varying(128) DEFAULT ''::character varying NOT NULL,
    createinet character varying(128) DEFAULT ''::character varying NOT NULL,
    expirydate timestamp with time zone DEFAULT '6666-06-06 06:06:06+00',
    PRIMARY KEY (height, blockhash, expirydate)
);


CREATE TABLE miningpayouts (
    payoutid bigint NOT NULL,
    userid bigint NOT NULL,
    diffacc float DEFAULT 0 NOT NULL,
    amount bigint DEFAULT 0 NOT NULL, -- satoshis
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) DEFAULT ''::character varying NOT NULL,
    createcode character varying(128) DEFAULT ''::character varying NOT NULL,
    createinet character varying(128) DEFAULT ''::character varying NOT NULL,
    expirydate timestamp with time zone DEFAULT '6666-06-06 06:06:06+00',
    PRIMARY KEY (payoutid, userid, expirydate)
);


CREATE TABLE payouts (
    payoutid bigint NOT NULL, -- unique per record
    height integer not NULL,
    blockhash character varying(256) NOT NULL,
    minerreward bigint NOT NULL, -- satoshis
    workinfoidstart bigint NOT NULL,
    workinfoidend bigint NOT NULL, -- should be block workinfoid
    elapsed bigint NOT NULL,
    status char DEFAULT ' ' NOT NULL,
    diffwanted float DEFAULT 0 NOT NULL,
    diffused float DEFAULT 0 NOT NULL,
    shareacc float DEFAULT 0 NOT NULL,
    lastshareacc timestamp with time zone NOT NULL,
    stats text DEFAULT ''::text NOT NULL,
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) DEFAULT ''::character varying NOT NULL,
    createcode character varying(128) DEFAULT ''::character varying NOT NULL,
    createinet character varying(128) DEFAULT ''::character varying NOT NULL,
    expirydate timestamp with time zone DEFAULT '6666-06-06 06:06:06+00',
    PRIMARY KEY (payoutid, expirydate)
);
CREATE UNIQUE INDEX payoutsblock ON payouts USING btree (height, blockhash, expirydate);


CREATE TABLE eventlog (
    eventlogid bigint NOT NULL,
    poolinstance character varying(256) NOT NULL,
    eventlogcode character varying(64) NOT NULL,
    eventlogdescription text NOT NULL,
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) DEFAULT ''::character varying NOT NULL,
    createcode character varying(128) DEFAULT ''::character varying NOT NULL,
    createinet character varying(128) DEFAULT ''::character varying NOT NULL,
    expirydate timestamp with time zone DEFAULT '6666-06-06 06:06:06+00',
    PRIMARY KEY (eventlogid, expirydate)
);


CREATE TABLE auths (
    authid bigint NOT NULL, -- unique per record
    poolinstance character varying(256) NOT NULL,
    userid bigint NOT NULL,
    workername character varying(256) NOT NULL,
    clientid integer NOT NULL,
    enonce1 character varying(64) NOT NULL,
    useragent character varying(256) NOT NULL,
    preauth char DEFAULT 'N' NOT NULL,
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) DEFAULT ''::character varying NOT NULL,
    createcode character varying(128) DEFAULT ''::character varying NOT NULL,
    createinet character varying(128) DEFAULT ''::character varying NOT NULL,
    expirydate timestamp with time zone DEFAULT '6666-06-06 06:06:06+00',
    PRIMARY KEY (authid, expirydate)
);


CREATE TABLE poolstats (
    poolinstance character varying(256) NOT NULL,
    elapsed bigint NOT NULL,
    users integer NOT NULL,
    workers integer NOT NULL,
    hashrate float NOT NULL,
    hashrate5m float NOT NULL,
    hashrate1hr float NOT NULL,
    hashrate24hr float NOT NULL,
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) DEFAULT ''::character varying NOT NULL,
    createcode character varying(128) DEFAULT ''::character varying NOT NULL,
    createinet character varying(128) DEFAULT ''::character varying NOT NULL,
    PRIMARY KEY (poolinstance, createdate)
);


CREATE TABLE userstats (
    userid bigint NOT NULL,
    workername character varying(256) NOT NULL,
    elapsed bigint NOT NULL,
    hashrate float NOT NULL,
    hashrate5m float NOT NULL,
    hashrate1hr float NOT NULL,
    hashrate24hr float NOT NULL,
    summarylevel char NOT NULL,
    summarycount integer NOT NULL,
    statsdate timestamp with time zone NOT NULL,
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) DEFAULT ''::character varying NOT NULL,
    createcode character varying(128) DEFAULT ''::character varying NOT NULL,
    createinet character varying(128) DEFAULT ''::character varying NOT NULL,
    PRIMARY KEY (userid, workername, summarylevel, statsdate)
);


CREATE TABLE version (
    vlock integer NOT NULL,
    version character varying(256) NOT NULL,
    PRIMARY KEY (vlock)
);

insert into version (vlock,version) values (1,'1.0.7');
