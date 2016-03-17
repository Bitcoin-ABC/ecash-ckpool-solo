SET SESSION AUTHORIZATION 'postgres';

BEGIN transaction;

DO $$
DECLARE ver TEXT;
BEGIN

 UPDATE version set version='1.0.5' where vlock=1 and version='1.0.4';

 IF found THEN
  RETURN;
 END IF;

 SELECT version into ver from version
  WHERE vlock=1;

 RAISE EXCEPTION 'Wrong DB version - expect "1.0.4" - found "%"', ver;

END $$;

ALTER TABLE ONLY shares
  ADD COLUMN ntime character varying(64) DEFAULT ''::character varying NOT NULL,
  ADD COLUMN minsdiff float DEFAULT 0::float NOT NULL;

ALTER TABLE ONLY shares
  ALTER COLUMN ntime DROP DEFAULT,
  ALTER COLUMN minsdiff DROP DEFAULT;

END transaction;
