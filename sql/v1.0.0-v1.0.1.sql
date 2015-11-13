SET SESSION AUTHORIZATION 'postgres';

BEGIN transaction;

DO $$
DECLARE ver TEXT;
BEGIN

 UPDATE version set version='1.0.1' where vlock=1 and version='1.0.0';

 IF found THEN
  RETURN;
 END IF;

 SELECT version into ver from version
  WHERE vlock=1;

 RAISE EXCEPTION 'Wrong DB version - expect "1.0.0" - found "%"', ver;

END $$;

ALTER TABLE ONLY users
  ADD COLUMN userdata text DEFAULT ''::text NOT NULL,
  ADD COLUMN userbits bigint NOT NULL DEFAULT 0;

ALTER TABLE ONLY users
  ALTER COLUMN userbits DROP DEFAULT;

-- match based on ckdb_data.c like_address()
UPDATE users set userbits=1 where username ~ '[13][A-HJ-NP-Za-km-z1-9]{15,}';

ALTER TABLE ONLY workers
  ADD COLUMN workerbits bigint NOT NULL DEFAULT 0;

ALTER TABLE ONLY workers
  ALTER COLUMN workerbits DROP DEFAULT;

END transaction;
