SET SESSION AUTHORIZATION 'postgres';

BEGIN transaction;

DO $$
DECLARE ver TEXT;
BEGIN

 UPDATE version set version='0.9.4' where vlock=1 and version='0.9.3';

 IF found THEN
  RETURN;
 END IF;

 SELECT version into ver from version
  WHERE vlock=1;

 RAISE EXCEPTION 'Wrong DB version - expect "0.9.3" - found "%"', ver;

END $$;

ALTER TABLE sharesummary DROP CONSTRAINT sharesummary_pkey;

ALTER TABLE sharesummary ADD CONSTRAINT sharesummary_pkey
 PRIMARY KEY (workinfoid, userid, workername);

END transaction;
