#!/bin/bash
#
fldsep="`echo -e '\x09'`"
#
addid()
{
 msg="newid.$1.idname=$1${fldsep}idvalue=$2"
 echo "$msg"
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
addid payoutid ${now}700000
