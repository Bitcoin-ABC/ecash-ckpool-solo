SET SESSION AUTHORIZATION 'postgres';

BEGIN transaction;

DO $$
DECLARE ver TEXT;
BEGIN

 UPDATE version set version='0.9' where vlock=1 and version='0.8';

 IF found THEN
  RETURN;
 END IF;

 SELECT version into ver from version
  WHERE vlock=1;

 RAISE EXCEPTION 'Wrong DB version - expect "0.8" - found "%"', ver;

END $$;

DROP TABLE IF EXISTS workmarkers;

CREATE TABLE workmarkers (
    markerid bigint NOT NULL,
    workinfoidend bigint NOT NULL,
    workinfoidstart bigint NOT NULL,
    description character varying(256) DEFAULT ''::character varying NOT NULL,
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) DEFAULT ''::character varying NOT NULL,
    createcode character varying(128) DEFAULT ''::character varying NOT NULL,
    createinet character varying(128) DEFAULT ''::character varying NOT NULL,
    expirydate timestamp with time zone DEFAULT '6666-06-06 06:06:06+00',
    PRIMARY KEY (markerid)
);

ALTER TABLE ONLY blocks
  DROP COLUMN differr,
  DROP COLUMN sharecount,
  DROP COLUMN errorcount,
  ADD COLUMN diffinv float DEFAULT 0 NOT NULL,
  ADD COLUMN shareacc float DEFAULT 0 NOT NULL,
  ADD COLUMN shareinv float DEFAULT 0 NOT NULL,
  ADD COLUMN statsconfirmed char DEFAULT 'N' NOT NULL;

END transaction;
