SET SESSION AUTHORIZATION 'postgres';

BEGIN transaction;

DO $$
DECLARE ver TEXT;
BEGIN

 UPDATE version set version='1.0.6' where vlock=1 and version='1.0.5';

 IF found THEN
  RETURN;
 END IF;

 SELECT version into ver from version
  WHERE vlock=1;

 RAISE EXCEPTION 'Wrong DB version - expect "1.0.5" - found "%"', ver;

END $$;

ALTER TABLE ONLY shares
  ADD COLUMN agent character varying(128) DEFAULT ''::character varying NOT NULL,
  ADD COLUMN address character varying(128) DEFAULT ''::character varying NOT NULL;

END transaction;
