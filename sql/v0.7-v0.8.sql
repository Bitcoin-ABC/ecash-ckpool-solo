SET SESSION AUTHORIZATION 'postgres';

BEGIN transaction;

DO $$
DECLARE ver TEXT;
BEGIN

 UPDATE version set version='0.8' where vlock=1 and version='0.7';

 IF found THEN
  RETURN;
 END IF;

 SELECT version into ver from version
  WHERE vlock=1;

 RAISE EXCEPTION 'Wrong DB version - expect "0.7" - found "%"', ver;

END $$;

ALTER TABLE ONLY auths
  ADD COLUMN preauth char DEFAULT 'N' NOT NULL;

ALTER TABLE ONLY blocks
  ADD COLUMN diffacc float DEFAULT 0 NOT NULL,
  ADD COLUMN differr float DEFAULT 0 NOT NULL,
  ADD COLUMN sharecount bigint DEFAULT 0 NOT NULL,
  ADD COLUMN errorcount bigint DEFAULT 0 NOT NULL,
  ADD COLUMN elapsed bigint DEFAULT 0 NOT NULL;

END transaction;
