#!/bin/bash
#
tmp="/tmp/`basename $0`-$$"
tmp0="$tmp.0.sql"
tmp1="$tmp.1.sql"
tmp2="$tmp.2.sql"
tmp3="$tmp.3.sql"
tmp4="$tmp.4.sql"
tmp5="$tmp.5.sql"
msdd="1,000,000,000"
msd="`echo "$msdd" | tr -d ,`"
#
usAge()
{
 echo "usAge: `basename $0` [-s sdiffX] [w] 0|[b startblock]|[s shift] endblock|z"
 echo " run as root or change dosql1()"
 echo
 echo " -s sdiffX = all shares must have minsdiff <= sdiffX - if not then abort"
 echo "    any commas are removed with \"tr -d ,\""
 echo "    shares with sdiff below sdiffX are ignored. Default $msdd"
 echo " w = worker stats - without w = user stats"
 echo " 0 = from the first hi share"
 echo " b startblock = start after the workinfoid of startblock (instead of 0)"
 echo "                i.e. this only includes data AFTER 'startblock'"
 echo "                'startblock' is the lowest block >= 'startblock'"
 echo " s shift = start from the shift with the starting 5 char code 'shift'"
 echo "           if there ever is a duplicate, it will use the lowest one"
 echo " endblock = finish at the workinfoid of endblock (instead of z)"
 echo "            this includes all of 'endblock'"
 echo "            'endblock' is the highest block <= 'endblock'"
 echo " z = to the last high share"
 echo
 echo " Basically would be '0 z' for all available share history or"
 echo "  e.g. 'b NNN MMM' for a block range after NNN up to (including) MMM or"
 echo "  e.g. 'b NNN z' starting after block NNN up to now"
 echo " Put a 'w' in front, to get worker instead of user summarisation"
 echo
 echo " The share history determines the limits used"
 echo " i.e. markersummaries before the first share, or after the last share,"
 echo "  are not included since that would invalidate the results"
 echo " Missing shares within the share data would invalidate the results"
 exit 1
}
#
dosql1()
{
 su - postgres << EOF
echo "$sql" | psql ckdb
EOF
}
#
procsql()
{
 got=""
 fin=""
 prev=""
 while true ; do
	read line
	if [ "$?" != "0" ] ; then
		break
	fi
	if [ "$got" ] ; then
		if [ -z "$fin" ] ; then
			echo "$line"
			if [ "${line:0:1}" = "(" ] ;then
				fin="y"
			fi
		fi
	else
		if [ "${line:0:5}" = "-----" ] ; then
			got="y"
			echo "$prev"
			echo "$line"
		else
			prev="$line"
		fi
	fi
 done
}
#
dosql()
{
 dosql1 2>&1 | procsql
}
#
# reduce a large, 9 or more digit, comma number with 2 decimal places to nnG
toG()
{
 sed -e "s/,\([0-9][0-9]\)[0-9],[0-9][0-9][0-9],[0-9][0-9][0-9]\.[0-9][0-9]*/.\1G/g" -e "s/\(\.[0-9][0-9]G\)   *|/\1 |/g" -e "s/  *$//"
}
#
dedup()
{
 cut -d '|' -f 1-5,7-10,12-
}
#
dedupw()
{
 cut -d '|' -f 1-4,6-9,11-
}
#
debar()
{
 sed -e "s/[ |]*$//" -e "s/|[ |]*|/|/g"
}
#
p1="$((0x1d))"
p1v="`echo "$p1 3 - 8 * p" | dc`"
#
# calculate the diff ratio for each diffacc, given bits
diff1()
{
 read line
 read line
 while true ; do
	read line
	if [ "$?" != "0" ] ; then
		break
	fi
	if [ "${line:0:1}" = "(" ] ; then
		break
	fi
	bits="`echo "$line" | cut -d '|' -f2 | tr -d ' '`"
	diffacc="`echo "$line" | cut -d '|' -f3 | tr -d ' '`"
	po="$((0x${bits:0:2}))"
	bi="$((0x${bits:2:6}))"
	pd="`echo "$p1v $po 3 - 8 * - p" | dc`"
	if [ "$pd" -lt "8" ] ; then
		pd="8"
	fi
	per="`echo "8 k $diffacc 2 $pd ^ 65535 * $bi / / p" | dc`"
	echo "$line | ${per}"
 done
}
#
diffvals()
{
 grep "^$uorw  *|" "$tmp4" | cut -d '|' -f4 | tr "\n" "+" | sed -e "s/+/ +/g"
}
#
getdiff()
{
 echo "4 k 0 `diffvals` p" | dc
}
#
# blocks are appended 3rd since if blocks exist, then at least 1 share must
proc()
{
 read line
 read line
 while true ; do
	read line
	if [ "$?" != "0" ] ; then
		break
	fi
	if [ "${line:0:1}" = "(" ] ; then
		echo "$line"
		break
	fi
	uorw="`echo "$line" | cut -d'|' -f1 | tr -d ' '`"
	uws="`echo "$uorw" | sed -e "s/\(^[^_\.]*\)[_\.].*$/\1/"`"
	diffs="`getdiff` BDR"
	if [ "${diffs:0:1}" = "." ] ; then
		diffs="  0$diffs"
	elif [ "${diffs:1:1}" = "." ] ; then
		diffs="  $diffs"
	elif [ "${diffs:2:1}" = "." ] ; then
		diffs=" $diffs"
	fi
	stats="`grep "^$uorw  *|" "$tmp2"`"
	bstats="`grep "^$uorw  *|" "$tmp3"`"
	hstats="`grep "^$uws  *|" "$tmp5" | cut -d'|' -f2 | sed -e "s/6666-06-06 //"`"
	if [ "$stats" ] ; then
		s=" | $stats"
	else
		s=" | | | | | "
	fi
	if [ "$bstats" ] ; then
		b=" | $bstats"
	else
		b=" | |"
	fi
	echo "$line | $diffs$s$b |$hstats"
 done
}
#
procblk()
{
 while true ; do
	read line
	if [ "$?" != "0" ] ; then
		break
	fi
	if [ "${line:0:1}" = "(" ] ; then
		echo "$line"
		break
	fi
	uorw="`echo "$line" | cut -d'|' -f1 | tr -d ' '`"
	bstats="`grep "^$uorw  *|" "$tmp3"`"
	echo "$line | $bstats"
 done
}
#
if [ "$1" = "-s" ] ; then
 shift
 msd="`echo "$1" | tr -d ,`"
 shift
fi
#
if [ -z "$1" ] ; then
 usAge
fi
#
if [ "$1" = "-?" -o "$1" = "-h" -o "$1" = "-help" -o "$1" = "--help" ] ; then
 usAge
fi
#
work=""
if [ "$1" = "w" ] ; then
 work="w"
 shift
fi
#
valsh="sdiff>=$msd"
# Orphans included, Rejects not - since they can be below diff, or invalid, or too late or ...
valblk="expirydate>'5555-05-05' and confirmed!='R'"
#
# START
if [ "$1" = "0" ] ; then
 shift
 selwm1="ms.markerid>=(select min(markerid) from workmarkers where workinfoidstart>=(select min(workinfoid) from shares))"
 selsh1=""
 selblk1="and b.workinfoid>=(select min(workinfoid) from shares)"
else
 if [ "$1" = "s" ] ; then
	shift
	selwm1="ms.markerid>=(select min(markerid) from workmarkers where description like 'Shift fin: $1 %')"
	selsh1="and workinfoid>=(select min(workinfoidstart) from workmarkers where description like 'Shift fin: $1 %')"
	selblk1="$selsh1"
	shift
 else
	if [ "$1" = "b" ] ; then
		shift
		selwm1="ms.markerid>=(select min(markerid) from workmarkers where workinfoidstart>(select min(workinfoid) from blocks where height>=$1))"
		selsh1="and s.workinfoid>=(select min(workinfoid) from blocks where height>=$1)"
		selblk1="and b.height>$1"
		shift
	else
		echo "ERR: Unknown first option '$1'"
		usAge
	fi
 fi
fi
#
# END
if [ "$1" = "z" ] ; then
 selwm2=""
 selsh2=""
 selblk2=""
else
 if [ -z "$1" ] ; then
	echo "ERR: missing ending block|z"
	usAge
 else
	selwm2="and wm.markerid<=(select max(markerid) from workmarkers where workinfoidend<=(select max(workinfoid) from blocks where height<=$1))"
	selsh2="and s.workinfoid<=(select max(workinfoid) from blocks where height<=$1)"
	selblk2="and b.height<=$1"
 fi
fi
#
# check all shares have minsdiff > $msd
sql="select count(*) from shares s where s.minsdiff>$msd $selsh1 $selsh2 ;"
#
dosql > "$tmp0"
count="`head -n 3 "$tmp0" | tail -n 1`"
if [ "$count" != "0" ] ; then
 count
 echo "ERROR: there were '$count' shares with minsdiff>$msd - that must be '0'"
 usAge
fi
#
# summarise markersummary into tmp1 for any user or worker with 'msd' diffacc or more
if [ -z "$work" ] ; then
 sql="select ms.userid,substring(max(ms.workername) from '(^[^\._]*)'),to_char(sum(ms.diffacc),'999G999G999G999G999.99'),to_char(sum(ms.sharecount),'999G999G999G999G999') from markersummary ms where $selwm1 $selwm2 group by ms.userid having sum(ms.diffacc)>$msd order by sum(ms.diffacc) desc;"
else
 sql="select ms.workername,to_char(sum(ms.diffacc),'999G999G999G999G999.99'),to_char(sum(ms.sharecount),'999G999G999G999G999.99') from markersummary ms where $selwm1 $selwm2 group by ms.workername having sum(ms.diffacc)>$msd order by sum(ms.diffacc) desc;"
fi
#
dosql > "$tmp1"
#
# summarise the shares into tmp2
if [ -z "$work" ] ; then
 sql="select s.userid,count(*),to_char(min(s.sdiff),'999G999G999G999G999.99'),to_char(max(s.sdiff),'999G999G999G999G999.99'),to_char(avg(s.sdiff),'999G999G999G999G999.99') from shares s where $valsh $selsh1 $selsh2 group by s.userid;"
else
 sql="select s.workername,count(*),to_char(min(s.sdiff),'999G999G999G999G999.99'),to_char(max(s.sdiff),'999G999G999G999G999.99'),to_char(avg(s.sdiff),'999G999G999G999G999.99') from shares s where $valsh $selsh1 $selsh2 group by s.workername;"
fi
#
dosql > "$tmp2"
#
# summarise the blocks into tmp3
if [ -z "$work" ] ; then
 sql="select b.userid,count(*)||' B' from blocks b where $valblk $selblk1 $selblk2 group by b.userid;"
else
 sql="select b.workername,count(*)||' B' from blocks b where $valblk $selblk1 $selblk2 group by b.workername;"
fi
#
dosql > "$tmp3"
#
# summarise diff% into tmp4 (all ids will have a value)
if [ -z "$work" ] ; then
 sql0="select ms.userid,wi.bits,sum(ms.diffacc)"
 sqlz="group by ms.userid,wi.bits;"
else
 sql0="select ms.workername,wi.bits,sum(ms.diffacc)"
 sqlz="group by ms.userid,ms.workername,wi.bits;"
fi
#
valwm="wm.status='p' and wm.expirydate>'5555-05-05'"
sql="$sql0 from markersummary ms join workmarkers wm on ms.markerid=wm.markerid join workinfo wi on wm.workinfoidend=wi.workinfoid where $valwm and $selwm1 $selwm2 $sqlz"
#
dosql | diff1 > "$tmp4"
#
if [ -z "$work" ] ; then
 sql0="select userid"
 sqlz="group by userid"
else
 sql0="select username"
 sqlz="group by username"
fi
#
sql="$sql0,substring(max(expirydate)::varchar from 1 for 10)||' Hold' from useratts where attname='HoldPayouts' $sqlz;"
#
dosql > "$tmp5"
#
# join (append) to each tmp1 row, the matching row/data in tmp4, tmp2 and tmp3
cat "$tmp1" | proc | toG | dedup$work | debar
#
shred -uz "$tmp0" "$tmp1" "$tmp2" "$tmp3" "$tmp4" "$tmp5" &> /dev/null
