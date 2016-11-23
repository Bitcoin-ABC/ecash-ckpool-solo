#!/bin/bash
#
tab="	"
#
cmd="
a genoff - turn off mark and payout generation (2 commands)
b genon - turn on mark and payout generation (2 commands)
c hold user - put a payout hold on user
d lock user reason - put a mining lock on user|  a blank reason unlocks user
e pay block - display payout info for block height
f opay payoutid - orphan payoutid
g unhold user - remove a payout hold on a user
h ban ip eventname - ban an ip eventname, forever until ckdb restart
i unban ip eventname - unban an ip eventname|  use 'exp' to clear it afterwards
j exp - remove all expired IP bans
k block height - show block details
l reject height blockhash - reject a block as unworthy|  when it wasn't actually a block, just a close share
m reject2 height blockhash type desc - reject a block with type and desc|  e.g. 'Stale' and 'Share was submitted after the block changed'
n terminate - I'll be back
"
#
msg="
a marks.1.action=genoff|payouts.1.action=genoff
b marks.1.action=genon|payouts.1.action=genon
c setatts.1.ua_HoldPayouts.str=Y${tab}username=@user@
d userstatus.1.username=@user@${tab}status=@reason@
e query.1.request=payout${tab}height=@block@
f payouts.1.action=orphan${tab}payoutid=@payoutid@
g expatts.1.attlist=HoldPayouts${tab}username=@user@
h events.1.action=ban${tab}ip=@ip@${tab}eventname=@eventname@
i events.1.action=unban${tab}ip=@ip@${tab}eventname=@eventname@
j events.1.action=expire
k query.1.request=block${tab}height=@height@
l blockstatus.1.action=reject${tab}height=@height@${tab}blockhash=@blockhash@${tab}info=
m blockstatus.1.action=reject${tab}height=@height@${tab}blockhash=@blockhash@${tab}info=@type@:@desc@
n terminate
"
# grep pattern matching the starting field used in cmd -> msg
letters="[a-n]"
# params allowed to be entered as blank (but will be prompted for if blank)
allowblank="|reason|"
#
cproc()
{
 echo "$cmd" | cut -d' ' -f2 | tr "\n" "|" | sed -e "s/|||*/|/g"
}
#
getex()
{
 let="`echo "$cmd" | grep "^$letters $1 " | cut -d' ' -f1`"
 echo "$msg" | grep "^$let " | cut -d' ' -f2-
}
#
dsp0()
{
 grep -v "^$" | cut -d' ' -f2- | tr "|" "\n" | sed -e "s/^/  /"
}
#
dsp()
{
 echo "$cmd" | grep "^$letters $1 " | dsp0
}
#
cmds="`cproc`"
#
cmdz()
{
 echo "$cmds" | tr '|' ' ' | sed -e "s/^ *//" -e "s/ *$//"
}
#
pars()
{
 echo "$cmd" | grep "^$letters $1" | cut -d'-' -f1 | cut -d' ' -f3-
}
#
show()
{
 echo "$1" | sed -e "s/$tab/'TAB'/g" -e "s/|/ and /g"
}
#
usAge()
{
 echo "usAge: `basename $0` [cmd [params...]]"
 echo " missing cmd or required params are prompted for"
 echo " it's easiest to just run `basename $0` with no cmd/params :)"
 echo " params can't contain TAB or '|'"
 echo " cmd [params...] is one of:"
 echo "$cmd" | dsp0
 exit 1
}
#
if [ "$1" = "-?" -o "$1" = "-h" -o "$1" = "-help" -o "$1" = "--help" ] ; then
 usAge
fi
#
if [ -z "$1" ] ; then
 echo "(`cmdz`)"
 read -p " or '?' for help: " cm
else
 cm="$1"
fi
#
ok="`echo "$cmds" | grep "|$cm|"`"
#
if [ -z "$ok" ] ; then
 usAge
fi
#
echo "`dsp $cm`"
ex0="`getex $cm`"
#
p="1"
for i in `pars $cm` ; do
 p="$[$p+1]"
 v="${@:$p:1}"
 if [ -z "$v" ] ; then
	read -p "$i: " v
 fi
 t="`echo "$v" | grep "$tab"`"
 if [ "$t" ] ; then
	echo "ERR: values can't contain TAB"
	usAge
 fi
 m="`echo "$v" | grep "|"`"
 if [ "$m" ] ; then
	echo "ERR: values can't contain '|'"
	usAge
 fi
 ab="`echo "$allowblank" | grep "|$i|"`"
 if [ -z "$ab" ] ; then
	if [ -z "$v" ] ; then
		echo "ERR: $i can't be blank"
		usAge
	fi
 fi
 ex="`echo "$ex0" | sed -e "s|@$i@|$v|g"`" # allow /
 ex0="$ex"
done
#
s=""
multi="`echo "$ex0" | grep '|'`"
if [ "$multi" ] ; then
 s="s"
fi
#
echo "Command$s: `show "$ex0"`"
read -p "ok? (y): " ok
if [ "${ok:0:1}" = "y" ] ; then
 echo "$ex0" | tr "|" "\n" | php ckdb.php
 echo "Done"
else
 echo "Aborted"
fi
