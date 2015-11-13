SET SESSION AUTHORIZATION 'postgres';

BEGIN transaction;

DO $$
DECLARE ver TEXT;
BEGIN

 UPDATE version set version='1.0.4' where vlock=1 and version='1.0.3';

 IF found THEN
  RETURN;
 END IF;

 SELECT version into ver from version
  WHERE vlock=1;

 RAISE EXCEPTION 'Wrong DB version - expect "1.0.3" - found "%"', ver;

END $$;

ALTER TABLE ONLY paymentaddresses
  ADD COLUMN payname character varying(64) DEFAULT ''::character varying NOT NULL,
  ADD COLUMN status char DEFAULT ' ' NOT NULL;

END transaction;
