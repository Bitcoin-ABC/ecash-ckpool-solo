SET SESSION AUTHORIZATION 'postgres';

BEGIN transaction;

DO $$
DECLARE ver TEXT;
BEGIN

 UPDATE version set version='1.0.0' where vlock=1 and version='0.9.6';

 IF found THEN
  RETURN;
 END IF;

 SELECT version into ver from version
  WHERE vlock=1;

 RAISE EXCEPTION 'Wrong DB version - expect "0.9.6" - found "%"', ver;

END $$;

DROP TABLE payments;
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

DROP TABLE accountbalance;
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

DROP TABLE miningpayouts;
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

insert into idcontrol (idname,lastid,createdate,createby) values ('payoutid',999,now(),'1.0.0update');

END transaction;
