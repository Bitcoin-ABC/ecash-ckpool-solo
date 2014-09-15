SET SESSION AUTHORIZATION 'postgres';

BEGIN transaction;

DO $$
DECLARE ver TEXT;
BEGIN

 UPDATE version set version='0.9.2' where vlock=1 and version='0.9.1';

 IF found THEN
  RETURN;
 END IF;

 SELECT version into ver from version
  WHERE vlock=1;

 RAISE EXCEPTION 'Wrong DB version - expect "0.9.1" - found "%"', ver;

END $$;

ALTER TABLE ONLY useratts
  ADD COLUMN status character varying(256) DEFAULT ''::character varying NOT NULL;

ALTER TABLE ONLY users
  ADD COLUMN status character varying(256) DEFAULT ''::character varying NOT NULL;

END transaction;
