-- SQL to calculate a block's diffacc (difficulty accepted)
-- This should match the block's confirmed diffacc
--  i.e. when a block has statsconfirmed='Y'
-- If the block has any unaged sharesummaries,
--  the script will abort and report the count
-- Sharesummaries are aged at ~10 minutes after the next workinfo,
--  after the sharesummary's workinfo, was first generated
-- You need to set the block number at line 21 - hi := blockheight;

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
 --  if we happen to orphan ourselves on block 'hi'
 select workinfoid from blocks where height = hi
	and expirydate > '6666-06-01' limit 1 into wi;
 IF NOT found THEN
  RAISE EXCEPTION 'Block % not found', hi;
 END IF;

 select max(height) from blocks where height < hi into hi0;
 IF hi0 is NULL THEN
  wi0 := -1;
 ELSE
  -- This will randomly choose between multiple blocks of the same height
  --  if we happen to orphan ourselves on block 'hi0'
  select workinfoid from blocks where height = hi0
	and expirydate > '6666-06-01' limit 1 into wi0;
 END IF;

 RAISE NOTICE 'Block: %(%)', hi, wi;

 IF hi0 is NULL THEN
  RAISE NOTICE 'No previous block';
 ELSE
  RAISE NOTICE 'Previous block: %(%)', hi0, wi0;
 END IF;

 select count(*) from sharesummary where workinfoid > wi0
	and workinfoid <= wi and complete = 'n' into ssc;

 IF ssc > 0 THEN
  RAISE EXCEPTION 'Unaged sharesummary records: %', ssc;
 ELSE
  select sum(diffacc) from sharesummary where workinfoid > wi0
	and workinfoid <= wi into da;

  RAISE NOTICE 'diffacc: %', to_char(da::bigint, 'FM999,999,999,999,999,990');
 END IF;
END $$;
