#!/bin/bash
#
fldsep="`echo -e '\x09'`"
#
dsp()
{
 cut -c4-
# echo
}
process()
{
 # <256
 len=${#1}
 oct="`printf '%03o' "$len"`"
 code="`printf "\\\\$oct"`"
 all="$code$zero$zero$zero$1"
 printf "$code\\0\\0\\000$1" | nc -U -w 1 /opt/ckdb/listener | dsp
}
#
addid()
{
 msg="newid.$1.idname=$1${fldsep}idvalue=$2"
 process "$msg"
}
#
# Default to yyyymmddXXXXXX
# thus on reinit it will always be above old values
# XXXXXX should allow enough per day to avoid overlap with other ids
#  but of course overlapping with another id doesn't technically matter
now="`date +%Y%m%d`"
#
addid workerid ${now}100000
addid paymentid ${now}200000
addid authid ${now}300000
addid userid ${now}400000
addid markerid ${now}500000
addid paymentaddressid ${now}600000
