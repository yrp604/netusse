#!/bin/sh
MODS="sctp rose sunrpc appletalk dccp ipv6 atm ax25 unix irda wimax caif ceph rfkill phonet nfc netrom llc ipx"

for mod in $MODS
do
    modprobe $mod
done
