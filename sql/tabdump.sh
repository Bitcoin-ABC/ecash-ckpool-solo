#!/bin/bash
#
# idcontrol is updated after the rows are loaded
#  for users, paymentaddresses and workers
#
# note that this doesn't save idcontrol since it
#  would cause a consistency problem with the reload
# Instead it generates it based on the current DB
#
# Obviously ... don't run the output file when CKDB is running
#
# initid.sh would also be useful to create any missing idcontrol
#  records, before using this to update them
#
t0="optioncontrol paymentaddresses useratts users workers version"
#
usAge()
{
 echo "usAge: `basename $0` -r > log.sql"
 echo " -r = do it"
 echo " dump tables not part of the reload"
 exit 1
}
#
idctl()
{
 echo "
update idcontrol
set lastid=(select max($1) from $2),
modifydate=now(),modifyby='$idn',
modifycode='$mc',modifyinet='$mi'
where idname='$1';"
}
#
process()
{
 t=""
 for i in $t0 ; do
	t="$t -t $i"
	echo "delete from $i;"
 done
 pg_dump -a $t ckdb
 #
 idn="tabdump-`date "+%Y%m%d%H%M%S"`"
 mc="`basename $0`"
 mi="127.0.0.1"
 #
 idctl userid users
 idctl workerid workers
 idctl paymentaddressid paymentaddresses

 # these below are just to make sure the DB is consistent
 idctl markerid workmarkers
 idctl paymentid payments
 idctl payoutid payouts
}
#
if [ "$1" != "-r" ] ; then
 echo "Missing -r"
 usAge
fi
#
process
