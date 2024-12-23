#!/bin/bash
#Autoscript-Lite By praisedev
clear
data=($(find /var/log/ -name '*.log'))
for log in "${data[@]}"; do
	echo "$log clear"
	echo >$log
done
data=($(find /var/log/ -name '*.err'))
for log in "${data[@]}"; do
	echo "$log clear"
	echo >$log
done
data=($(find /var/log/ -name 'mail.*'))
for log in "${data[@]}"; do
	echo "$log clear"
	echo >$log
done
echo >/var/log/syslog
echo >/var/log/btmp
echo >/var/log/messages
echo >/var/log/debug
bcc=$(date)
echo ""
echo "Successfully clean log at $bcc"
sleep 0.5
clear
echo ""
