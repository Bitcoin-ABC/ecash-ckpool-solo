SET SESSION AUTHORIZATION 'postgres';

BEGIN transaction;

DO $$
DECLARE ver TEXT;
BEGIN

 UPDATE version set version='1.0.3' where vlock=1 and version='1.0.2';

 IF found THEN
  RETURN;
 END IF;

 SELECT version into ver from version
  WHERE vlock=1;

 RAISE EXCEPTION 'Wrong DB version - expect "1.0.2" - found "%"', ver;

END $$;

ALTER TABLE ONLY markersummary
  ADD COLUMN firstshareacc timestamp with time zone DEFAULT '1970-01-01 00:00:00+00' NOT NULL,
  ADD COLUMN lastshareacc timestamp with time zone DEFAULT '1970-01-01 00:00:00+00' NOT NULL;

ALTER TABLE ONLY markersummary
  ALTER COLUMN firstshareacc DROP DEFAULT,
  ALTER COLUMN lastshareacc DROP DEFAULT;

ALTER TABLE ONLY sharesummary
  ADD COLUMN firstshareacc timestamp with time zone DEFAULT '1970-01-01 00:00:00+00' NOT NULL,
  ADD COLUMN lastshareacc timestamp with time zone DEFAULT '1970-01-01 00:00:00+00' NOT NULL;

ALTER TABLE ONLY sharesummary
  ALTER COLUMN firstshareacc DROP DEFAULT,
  ALTER COLUMN lastshareacc DROP DEFAULT;

END transaction;
