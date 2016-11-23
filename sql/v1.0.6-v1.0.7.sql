SET SESSION AUTHORIZATION 'postgres';

BEGIN transaction;

DO $$
DECLARE ver TEXT;
BEGIN

 UPDATE version set version='1.0.7' where vlock=1 and version='1.0.6';

 IF found THEN
  RETURN;
 END IF;

 SELECT version into ver from version
  WHERE vlock=1;

 RAISE EXCEPTION 'Wrong DB version - expect "1.0.6" - found "%"', ver;

END $$;

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

-- only in RAM so no need for it in the DB - for a while now
DROP table sharesummary;

END transaction;
