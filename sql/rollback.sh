#!/bin/bash
#
# WARNING!!!
# 1) Don't use this
# 2) If you do use this, only use it if your "ckpool's ckdb logfiles"
#	(CCLs) are 100% certainly OK
#	Data in the DB will be lost if the rollback requires reloading
#	data that is missing from the CCLs
# 3) If you do use this, make sure ckdb is NOT running
# 4) The rollback is only for the tables that are generated from the CCLs
#	If you need data from other tables, see tabdump.sql
# 5) If you need to reload missing data that may or may not be in the CCLs
#	then you need to convince Kano to update the ckdb -y option to handle
#	that, with the current db, and also add code to the -y option to
#	update the DB
#	i.e. the ckdb -y options/code need updating
# 6) Blocks commands manually entered using ckpmsg (confirm,orphan,reject,etc)
#	will not be automatically restored if you use -b, you'll need to redo
#	them again manually
#
# The basic use of this script is for when something goes wrong with the
#	database and the CCLs are OK - so you can roll back to before the
#	database problem and reload all the data
#
# It may be unnecessary to delete/expire blocks records since the reload will
#	attempt to load all old and new blocks records in the CCLs being
#	reloaded, no matter what
#	Also, deleting blocks history will lose all manual block changes
#	done with confirms, orphans, rejects, etc
#	However, if the block summarisations are wrong or the blocks table is
#	corrupt, you will need to delete/expire them to correct them and then
#	redo the manual blocks changes after reloading
#
# Deleting markersummaries would only be an option if you know for sure
#	that all data is in the CCLs
# It would be ideal to do a markersummary table dump before a rollback
# However, -e will be OK if the CCLs aren't missing anything reqired for
#	the reload
#
# In all cases, if data is missing between the start and end of the
#  rollback, then the reload SEQ checking will report it, unless ...
#  by coincidence the missing data is at the end of a ckpool sequence
#  and no gaps exist in the data before the truncation point
# e.g. seqall goes from N..M then a new SEQ starts at 0..
#  however if there actually was data after M, but all missing exactly up
#  to before the SEQ restart 0 point, then ckdb couldn't know this unless
#  the data was inconsistent
#
# -c will show you record counts but not change anything
#
# -e will of course allow you to compare all but markersummary, before and
#    after rolling back, by manually comparing the expired record with the
#    new replacement unexpired record - but it deletes the markersummary data
# -e is untidy simply because it leaves around unnecesary data, if the
#    reload after the rollback is not missing anything and succeeds
# -e deletes all the records that were already expired so you will lose
#    the original DB history of those records, however a reload should
#    regenerate a similar history
#
# -m is the same as -e except it doesn't touch markersummary at all
# -m will probably cause duplicate markersummary issues for ckdb
#
# -r ... use at your own risk :) - but is the best option if nothing is
#    missing from your CCLs
#    it simply deletes all reload data back to the specified point and
#    that data should all reappear with a successful reload
#
usAge()
{
 echo "usAge: `basename $0` [-b] [-n] -c|-e|-r|-m workinfoid"
 echo " Preferred option is just -e as long as you aren't missing reload data"
 echo " The order of options must match the usAge order"
 echo
 echo " -b = include blocks when deleting/expiring (otherwise left untouched)"
 echo
 echo " -n = use 'now()' instead of the date timestamp of now, for expiry date"
 echo
 echo " -c = report the counts of rows that would be affected, but don't do it"
 echo
 echo " -e = rollback by deleteing expired data and expiring unexpired data,"
 echo "      but deleting markersummary"
 echo
 echo " -r = rollback by deleting all relevant data (expired or unexpired)"
 echo " -m = rollback by deleteing expired data and expiring unexpired data,"
 echo "      but don't touch markersummary"
 echo "      N.B. -m is expected to cause problems with ckdb"
 echo
 echo " generates the sql on stdout, that you would feed into pgsql"
 echo
 echo " Read `basename $0` for a more detailed explanation"
 exit 1
}
#
idctl()
{
 echo "\\echo 'update idcontrol $1'
update idcontrol
set lastid=(select max($1) from $2),
modifydate=$n,modifyby='$idn',
modifycode='$mc',modifyinet='$mi'
where idname='$1';"
}
#
process()
{
 # so all stamps are exactly the same
 now="`date +%s`"
 idn="rollback_${wi}_`date -d "@$now" '+%Y%m%d%H%M%S%:::z'`"
 mc="`basename $0`"
 mi="127.0.0.1"
 if [ "$usenow" ] ; then
	n="now()"
 else
	n="'`date -u -d "@$now" '+%Y-%m-%d %H:%M:%S+00'`'"
 fi
 ex="expirydate = $n"
 unex="expirydate > '6666-06-01'"
 oldex="expirydate < '6666-06-01'"
 #
 if [ "$opt" = "-c" ] ; then
	echo "\\echo 'count markersummary'"
	echo "select count(*),min(markerid) as min_markerid,max(markerid) as max_markerid,"
	echo " sum(diffacc) as sum_diffacc,min(firstshare) as min_firstshare,"
	echo " max(lastshareacc) as max_lastshareacc,max(lastshare) as max_lastshare"
	echo "  from markersummary where markerid in"
	echo "   (select distinct markerid from workmarkers where workinfoidend >= $wi);"
 fi
 if [ "$opt" = "-r" -o "$opt" = "-e" ] ; then
	echo "\\echo 'delete markersummary'"
	echo "delete from markersummary where markerid in"
	echo " (select distinct markerid from workmarkers where workinfoidend >= $wi);"
 fi
 #
 if [ "$opt" = "-c" ] ; then
	echo "\\echo 'count marks'"
	echo "select count(*),min(workinfoid) as min_workinfoid,"
	echo " max(workinfoid) as max_workinfoid"
	echo "  from marks where workinfoid >= $wi;"
	echo "\\echo 'count workmarkers'"
	echo "select count(*),min(workinfoidstart) as min_workinfoidstart,"
	echo " max(workinfoidend) as max_workinfoidend"
	echo "  from workmarkers where workinfoidend >= $wi;"
 fi
 if [ "$opt" = "-r" ] ; then
	echo "\\echo 'delete marks'"
	echo "delete from marks where workinfoid >= $wi;"
	echo "\\echo 'delete workmarkers'"
	echo "delete from workmarkers where workinfoidend >= $wi;"
 fi
 if [ "$opt" = "-e" -o "$opt" = "-m" ] ; then
	echo "\\echo 'delete/update marks'"
	echo "delete from marks where $oldex and workinfoid >= $wi;"
	echo "update marks set $ex where $unex and workinfoid >= $wi;"
	echo "\\echo 'delete/update workmarkers'"
	echo "delete from workmarkers where $oldex and workinfoidend >= $wi;"
	echo "update workmarkers set $ex where $unex and workinfoidend >= $wi;"
 fi
 #
 if [ "$opt" = "-c" ] ; then
	echo "\\echo 'count blocks'"
	echo "select count(*),min(height) as min_height,max(height) as max_height,"
	echo " min(workinfoid) as min_workinfoid,max(workinfoid) as max_workinfoid"
	echo "  from blocks where workinfoid >= $wi;"
	echo "\\echo 'count workinfo'"
	echo "select count(*),min(workinfoid) as min_workinfoid,"
	echo " max(workinfoid) as max_workinfoid,min(reward) as min_reward,"
	echo " max(reward) as max_reward,max(length(transactiontree)) as max_tree,"
	echo " min(createdate) as min_createdate,max(createdate) as max_createdate"
	echo "  from workinfo where workinfoid >= $wi;"
 fi
 if [ "$opt" = "-r" ] ; then
	if [ "$deblk" ] ; then
		echo "\\echo 'delete blocks'"
		echo "delete from blocks where workinfoid >= $wi;"
	fi
	echo "\\echo 'delete workinfo'"
	echo "delete from workinfo where workinfoid >= $wi;"
 fi
 if [ "$opt" = "-e" -o "$opt" = "-m" ] ; then
	if [ "$deblk" ] ; then
		echo "\\echo 'delete/update blocks'"
		echo "delete from blocks where $oldex and workinfoid >= $wi;"
		echo "update blocks set $ex where $unex and workinfoid >= $wi;"
	fi
	echo "\\echo 'delete/update workinfo'"
	echo "delete from workinfo where $oldex and workinfoid >= $wi;"
	echo "update workinfo set $ex where $unex and workinfoid >= $wi;"
 fi
 #
 if [ "$opt" = "-c" ] ; then
	echo "\\echo 'count miningpayouts'"
	echo "select count(*),min(payoutid) as min_payoutid,"
	echo " max(payoutid) as max_payoutid"
	echo "  from miningpayouts where payoutid in"
	echo "   (select distinct payoutid from payouts where workinfoidend >= $wi);"
	echo "\\echo 'count payments'"
	echo "select count(*),min(payoutid) as min_payoutid,"
	echo " max(payoutid) as max_payoutid"
	echo "  from payments where payoutid in"
	echo "   (select distinct payoutid from payouts where workinfoidend >= $wi);"
	echo "\\echo 'count payouts'"
	echo "select count(*),min(workinfoidstart) as min_workinfoidstart,"
	echo " max(workinfoidend) as max_workinfoidend"
	echo "  from payouts where workinfoidend >= $wi;"
 fi
 if [ "$opt" = "-r" ] ; then
	echo "\\echo 'delete miningpayouts'"
	echo "delete from miningpayouts where payoutid in"
	echo " (select distinct payoutid from payouts where workinfoidend >= $wi);"
	echo "\\echo 'delete payments'"
	echo "delete from payments where payoutid in"
	echo " (select distinct payoutid from payouts where workinfoidend >= $wi);"
	echo "\\echo 'delete payouts'"
	echo "delete from payouts where workinfoidend >= $wi;"
 fi
 if [ "$opt" = "-e" -o "$opt" = "-m" ] ; then
	echo "\\echo 'delete/update miningpayouts'"
	echo "delete from miningpayouts where $oldex and payoutid in"
	echo " (select distinct payoutid from payouts where workinfoidend >= $wi);"
	echo "update miningpayouts set $ex where $unex and payoutid in"
	echo " (select distinct payoutid from payouts where workinfoidend >= $wi);"
	echo "\\echo 'delete/update payments'"
	echo "delete from payments where $oldex and payoutid in"
	echo " (select distinct payoutid from payouts where workinfoidend >= $wi);"
	echo "update payments set $ex where $unex and payoutid in"
	echo " (select distinct payoutid from payouts where workinfoidend >= $wi);"
	echo "\\echo 'delete/update payouts'"
	echo "delete from payouts where $oldex and workinfoidend >= $wi;"
	echo "update payouts set $ex where workinfoidend >= $wi and $unex;"
 fi
 #
 if [ "$opt" = "-e" -o "$opt" = "-m" -o "$opt" = "-r" ] ; then
	idctl markerid workmarkers
	idctl paymentid payments
	idctl payoutid payouts
	# this makes sure the worker data is consistent - don't remove this
	idctl workerid workers
 fi
}
#
if [ -z "$1" ] ; then
 usAge
fi
#
if [ "$1" = "-?" -o "$1" = "-h" -o "$1" = "-help" -o "$1" = "--help" ] ; then
 usAge
fi
#
deblk=""
if [ "$1" = "-b" ] ; then
 deblk="y"
 shift
fi
#
usenow=""
if [ "$1" = "-n" ] ; then
 usenow="y"
 shift
fi
#
if [ "$1" != "-c" -a "$1" != "-e" -a "$1" != "-r" -a "$1" != "-m" ] ; then
 echo "ERR: Unknown p1='$1'"
 usAge
fi
#
opt="$1"
shift
#
if [ -z "$1" ] ; then
 echo "ERR: missing workinfoid"
 usAge
fi
#
wi="$1"
#
process
