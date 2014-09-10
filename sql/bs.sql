SET SESSION AUTHORIZATION 'postgres';

DO $$
DECLARE
 hi  INT;
 hi0 INT;
 wi  BIGINT;
 wi0 BIGINT;
 ssc INT;
 da BIGINT;
BEGIN
 hi := 318177;

 -- This will randomly choose between multiple blocks of the same height
 --  if we happen to orphan ourselves
 select workinfoid from blocks where height = hi
	and expirydate > '6666-06-01' into wi;
 IF NOT found THEN
  RAISE EXCEPTION 'Block % not found', hi;
 END IF;

 select max(height) from blocks where height < hi into hi0;
 IF NOT found THEN
  wi0 := -1;
 ELSE
  select workinfoid from blocks where height = hi0
	and expirydate > '6666-06-01' into Wi0;
 END IF;

 RAISE WARNING 'Block: %(%)', hi, wi;
 RAISE WARNING 'Previous block: %(%)', hi0, wi0;

 select count(*) from sharesummary where workinfoid > wi0
	and workinfoid <= wi and complete = 'n' into ssc;

 IF ssc > 0 THEN
  RAISE EXCEPTION 'Unaged sharesummary records: %', ssc;
 ELSE
  select sum(diffacc) from sharesummary where workinfoid > wi0
	and workinfoid <= wi into da;

  RAISE WARNING 'diffacc: %', to_char(da::bigint, 'FM999,999,999,999,999,990');
 END IF;
END $$;
