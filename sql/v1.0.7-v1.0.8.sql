SET SESSION AUTHORIZATION 'postgres';

BEGIN transaction;

DO $$
DECLARE ver TEXT;
BEGIN

 UPDATE version set version='1.0.8' where vlock=1 and version='1.0.7';

 IF found THEN
  RETURN;
 END IF;

 SELECT version into ver from version
  WHERE vlock=1;

 RAISE EXCEPTION 'Wrong DB version - expect "1.0.7" - found "%"', ver;

END $$;

ALTER TABLE workinfo ALTER COLUMN coinbase2 TYPE varchar(511);

END transaction;
