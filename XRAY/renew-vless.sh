#!/bin/bash
#Autoscript-Lite By praisedev
clear
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
NUMBER_OF_CLIENTS=$(grep -c -E "^### " "/usr/local/etc/xray/vless.json")
if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
	echo -e "\033[0;34m
\033[0m"
	echo -e "\\E[0;41;36m   Renew XRAY Vless WS Account    \E[0m"
	echo -e "\033[0;34m
\033[0m"
	echo ""
	echo "You have no existing clients!"
	echo ""
	exit 1
fi
echo -e "\033[0;34m
\033[0m"
echo -e "\\E[0;41;36m   Renew XRAY Vless WS Account    \E[0m"
echo -e "\033[0;34m
\033[0m"
echo "Select the existing client you want to renew"
echo " Press CTRL+C to return"
echo -e "\033[0;34m
\033[0m"
grep -E "^### " "/usr/local/etc/xray/vless.json" | cut -d ' ' -f 2-3 | nl -s ') '
until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
	if [[ ${CLIENT_NUMBER} == '1' ]]; then
		read -rp "Select one client [1]: " CLIENT_NUMBER
	else
		read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
	fi
done
read -p "Expired (days): " masaaktif
user=$(grep -E "^### " "/usr/local/etc/xray/vless.json" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p)
exp=$(grep -E "^### " "/usr/local/etc/xray/vless.json" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
now=$(date +%Y-%m-%d)
d1=$(date -d "$exp" +%s)
d2=$(date -d "$now" +%s)
exp2=$(((d1 - d2) / 86400))
exp3=$(($exp2 + $masaaktif))
exp4=$(date -d "$exp3 days" +"%Y-%m-%d")
sed -i "s/### $user $exp/### $user $exp4/g" /usr/local/etc/xray/vless.json
sed -i "s/### $user $exp/### $user $exp4/g" /usr/local/etc/xray/vnone.json
systemctl restart xray@vless.service
systemctl restart xray@vnone.service
service cron restart
clear
echo ""
echo " XRAY Vless WS Account Renewed"
echo -e "\033[0;34m
\033[0m"
echo " Client Name : $user"
echo " Expired On  : $exp4"
echo -e "\033[0;34m
\033[0m"
echo -e ""
echo -e "Autoscript By praisedev"
echo -e ""
