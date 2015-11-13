SET SESSION AUTHORIZATION 'postgres';

BEGIN transaction;

DO $$
DECLARE ver TEXT;
BEGIN

 UPDATE version set version='1.0.2' where vlock=1 and version='1.0.1';

 IF found THEN
  RETURN;
 END IF;

 SELECT version into ver from version
  WHERE vlock=1;

 RAISE EXCEPTION 'Wrong DB version - expect "1.0.1" - found "%"', ver;

END $$;

ALTER TABLE ONLY blocks
  ADD COLUMN info character varying(64) DEFAULT ''::character varying NOT NULL;

END transaction;
