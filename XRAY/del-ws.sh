#!/bin/bash
#Autoscript-Lite By praisedev
clear
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
NUMBER_OF_CLIENTS=$(grep -c -E "^### " "/usr/local/etc/xray/config.json")
if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
	echo -e "\033[0;34m
\033[0m"
	echo -e "\\E[0;41;36m     Delete XRAY Vmess WS Account  \E[0m"
	echo -e "\033[0;34m
\033[0m"
	echo ""
	echo "You have no existing clients!"
	echo ""
	exit 1
fi
echo -e "\033[0;34m
\033[0m"
echo -e "\\E[0;41;36m   Delete XRAY Vmess WS Account    \E[0m"
echo -e "\033[0;34m
\033[0m"
echo " Select the existing client you want to remove"
echo " Press CTRL+C to return"
echo -e "\033[0;34m
\033[0m"
echo "     No  Expired   User"
grep -E "^### " "/usr/local/etc/xray/config.json" | cut -d ' ' -f 2-3 | nl -s ') '
until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
	if [[ ${CLIENT_NUMBER} == '1' ]]; then
		read -rp "Select one client [1]: " CLIENT_NUMBER
	else
		read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
	fi
done
user=$(grep -E "^### " "/usr/local/etc/xray/config.json" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p)
exp=$(grep -E "^### " "/usr/local/etc/xray/config.json" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
sed -i "/^### $user $exp/,/^},{/d" /usr/local/etc/xray/config.json
sed -i "/^### $user $exp/,/^},{/d" /usr/local/etc/xray/none.json
rm -f /usr/local/etc/xray/$user-tls.json /usr/local/etc/xray/$user-none.json /usr/local/etc/xray/$user-maxis.json /usr/local/etc/xray/$user-celcom.json /usr/local/etc/xray/$user-digi.json /usr/local/etc/xray/$user-yes.json
rm -f /home/vps/public_html/$user-VMESSTLS.yaml /home/vps/public_html/$user-VMESSNTLS.yaml
systemctl restart xray.service
systemctl restart xray@none.service
clear
echo " XRAY Vmess WS Account Deleted"
echo -e "\033[0;34m
\033[0m"
echo " Client Name : $user"
echo " Expired On  : $exp"
echo -e "\033[0;34m
\033[0m"
echo -e ""
echo -e "Autoscript By praisedev"
echo -e ""
