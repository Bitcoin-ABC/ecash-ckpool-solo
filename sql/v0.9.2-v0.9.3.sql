SET SESSION AUTHORIZATION 'postgres';

BEGIN transaction;

DO $$
DECLARE ver TEXT;
BEGIN

 UPDATE version set version='0.9.3' where vlock=1 and version='0.9.2';

 IF found THEN
  RETURN;
 END IF;

 SELECT version into ver from version
  WHERE vlock=1;

 RAISE EXCEPTION 'Wrong DB version - expect "0.9.2" - found "%"', ver;

END $$;

DROP table workmarkers;

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
    PRIMARY KEY (markerid)
);

DROP table markersummary;

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

END transaction;
