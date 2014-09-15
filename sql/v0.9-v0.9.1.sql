SET SESSION AUTHORIZATION 'postgres';

BEGIN transaction;

DO $$
DECLARE ver TEXT;
BEGIN

 UPDATE version set version='0.9.1' where vlock=1 and version='0.9';

 IF found THEN
  RETURN;
 END IF;

 SELECT version into ver from version
  WHERE vlock=1;

 RAISE EXCEPTION 'Wrong DB version - expect "0.9" - found "%"', ver;

END $$;

CREATE TABLE useratts (
    userid bigint NOT NULL,
    attname character varying(64) NOT NULL,
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

ALTER TABLE ONLY users
  ADD COLUMN salt character varying(256) DEFAULT ''::character varying NOT NULL;

END transaction;
