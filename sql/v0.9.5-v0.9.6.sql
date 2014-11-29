SET SESSION AUTHORIZATION 'postgres';

BEGIN transaction;

DO $$
DECLARE ver TEXT;
BEGIN

 UPDATE version set version='0.9.6' where vlock=1 and version='0.9.5';

 IF found THEN
  RETURN;
 END IF;

 SELECT version into ver from version
  WHERE vlock=1;

 RAISE EXCEPTION 'Wrong DB version - expect "0.9.5" - found "%"', ver;

END $$;

DROP TABLE marks;

CREATE TABLE marks ( -- workinfoids to make workmarkers
    poolinstance character varying(256) NOT NULL,
    workinfoid bigint NOT NULL,
    description character varying(256) DEFAULT ''::character varying NOT NULL,
    extra character varying(256) DEFAULT ''::character varying NOT NULL,
    marktype char NOT NULL, -- 'b'lock(end) 'p'plns-begin 's'hift-begin 'e'=shift-end
    status char NOT NULL,
    createdate timestamp with time zone NOT NULL,
    createby character varying(64) DEFAULT ''::character varying NOT NULL,
    createcode character varying(128) DEFAULT ''::character varying NOT NULL,
    createinet character varying(128) DEFAULT ''::character varying NOT NULL,
    expirydate timestamp with time zone DEFAULT '6666-06-06 06:06:06+00',
    PRIMARY KEY (poolinstance, workinfoid, expirydate)
);

END transaction;
