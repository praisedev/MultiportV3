#!/bin/bash
clear
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=$(date +"%Y-%m-%d" -d "$dateFromServer")
#########################
MYIP=$(curl -sS https://raw.githubusercontent.com/KhaiVpn767/MultiportV3/main/LICENSE/access | awk '{print $2}')
clear
red='\e[1;31m'
green='\e[0;32m'
yell='\e[1;33m'
tyblue='\e[1;36m'
purple='\e[0;35m'
NC='\e[0m'

purple() { echo -e "\\033[35;1m${*}\\033[0m"; }
tyblue() { echo -e "\\033[36;1m${*}\\033[0m"; }
yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }

cek=$(curl -sS https://raw.githubusercontent.com/KhaiVpn767/MultiportV3/main/LICENSE/access | awk '{print $2}' | grep $MYIP)
Name=$(curl -sS https://raw.githubusercontent.com/KhaiVpn767/MultiportV3/main/LICENSE/access | grep $MYIP | awk '{print $4}')
if [[ $cek = $MYIP ]]; then
	echo -e "${green}Permission Accepted...${NC}"
else
	echo -e "${red}Permission Denied!${NC}"
	echo ""
	echo -e "Your IP is ${red}NOT REGISTER${NC} @ ${red}EXPIRED${NC}"
	echo ""
	echo -e "Please Contact ${green}Admin${NC}"
	echo -e "Telegram : t.me/KhaiVpn767"
	exit 0
fi

clear
BURIQ() {
	curl -sS https://raw.githubusercontent.com/KhaiVpn767/MultiportV3/main/LICENSE/access >/root/tmp
	data=($(cat /root/tmp | grep -E "^### " | awk '{print $4}'))
	for user in "${data[@]}"; do
		exp=($(grep -E "^### $user" "/root/tmp" | awk '{print $3}'))
		d1=($(date -d "$exp" +%s))
		d2=($(date -d "$biji" +%s))
		exp2=$(((d1 - d2) / 86400))
		if [[ "$exp2" -le "0" ]]; then
			echo $user >/etc/.$user.ini
		else
			rm -f /etc/.$user.ini >/dev/null 2>&1
		fi
	done
	rm -f /root/tmp
}

MYIP=$(curl -sS https://raw.githubusercontent.com/KhaiVpn767/MultiportV3/main/LICENSE/access | awk '{print $2}')
Name=$(curl -sS https://raw.githubusercontent.com/KhaiVpn767/MultiportV3/main/LICENSE/access | grep $MYIP | awk '{print $4}')
echo $Name >/usr/local/etc/.$Name.ini
CekOne=$(cat /usr/local/etc/.$Name.ini)

Bloman() {
	if [[ -f "/etc/.$Name.ini" ]]; then
		CekTwo=$(cat /etc/.$Name.ini)
		if [[ "$CekOne" = "$CekTwo" ]]; then
			res="Expired"
		fi
	else
		res="Permission Accepted..."
	fi
}

PERMISSION() {
	MYIP=$(curl -sS https://raw.githubusercontent.com/KhaiVpn767/MultiportV3/main/LICENSE/access | awk '{print $2}')
	IZIN=$(curl -sS https://raw.githubusercontent.com/KhaiVpn767/MultiportV3/main/LICENSE/access | awk '{print $2}' | grep $MYIP)
	if [[ "$MYIP" = "$IZIN" ]]; then
		Bloman
	else
		res="Permission Denied!"
	fi
	BURIQ
}

red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'

green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }

PERMISSION

cekray=$(cat /root/log-install.txt | grep -ow "XRAY" | sort | uniq)

if [ "$cekray" = "XRAY" ]; then
	domen=$(cat /usr/local/etc/xray/domain)
else
	domen=$(cat /etc/v2ray/domain)
fi

portsshws=$(cat ~/log-install.txt | grep -w "SSH Websocket" | cut -d: -f2 | awk '{print $1}')
wsssl=$(cat /root/log-install.txt | grep -w "SSH SSL Websocket" | cut -d: -f2 | awk '{print $1}')
echo -e "\033[0;34m
\033[0m"
echo -e "\E[0;41;36m            SSH Account            \E[0m"
echo -e "\033[0;34m
\033[0m"
read -p " Username : " Login
read -p " Password : " Pass
read -p " Expired  : " masaaktif
IP=$(curl -sS ifconfig.me)
ossl=$(cat /root/log-install.txt | grep -w "OpenVPN" | cut -f2 -d: | awk '{print $6}')
opensh=$(cat /root/log-install.txt | grep -w "OpenSSH" | cut -f2 -d: | awk '{print $1}')
db=$(cat /root/log-install.txt | grep -w "Dropbear" | cut -f2 -d: | awk '{print $1,$2}')
ssl="$(cat ~/log-install.txt | grep -w "Stunnel4" | cut -d: -f2)"
sqd="$(cat ~/log-install.txt | grep -w "Squid" | cut -d: -f2)"
ovpn="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
ovpn2="$(netstat -nlpu | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
OhpSSH=$(cat /root/log-install.txt | grep -w "OHP SSH" | cut -d: -f2 | awk '{print $1}')
OhpDB=$(cat /root/log-install.txt | grep -w "OHP DBear" | cut -d: -f2 | awk '{print $1}')
OhpOVPN=$(cat /root/log-install.txt | grep -w "OHP OpenVPN" | cut -d: -f2 | awk '{print $1}')
nsdomain1=$(cat /root/nsdomain)
pubkey1=$(cat /etc/slowdns/server.pub)
sleep 1
clear
useradd -e $(date -d "$masaaktif days" +"%Y-%m-%d") -s /bin/false -M $Login
exp="$(chage -l $Login | grep "Account expires" | awk -F": " '{print $2}')"
echo -e "$Pass\n$Pass\n" | passwd $Login &>/dev/null
PID=$(ps -ef | grep -v grep | grep sshws | awk '{print $2}')
if [[ ! -z "${PID}" ]]; then
echo -e ""
echo -e "\e[33m═══════════════════════════════════════════════════════\e[m"
echo -e " \E[1;47;30m         \e[30m[\e[$box Informasi Account SSH & OpenVPN\e[30m ]\e[1m           \e[m"
echo -e "\e[33m═══════════════════════════════════════════════════════\e[m"
echo -e "\e[33m══════════════════════\e[m"
echo -e "Username         : $Login" | tee -a /etc/log-create-user.log
echo -e "Password         : $Pass" | tee -a /etc/log-create-user.log
echo -e "Expired          : $exp1" | tee -a /etc/log-create-user.log
echo -e "\e[33m══════════════════════\e[m"
echo -e "Domain           : $domain" | tee -a /etc/log-create-user.log
echo -e "Name Server(NS)  : $nsdomain1" | tee -a /etc/log-create-user.log
echo -e "\e[33m══════════════════════\e[m"
echo -e "Pubkey           : $pubkey1" | tee -a /etc/log-create-user.log
echo -e "\e[33m══════════════════════\e[m"
echo -e "IP/Host          : $MYIP" | tee -a /etc/log-create-user.log
echo -e "OpenSSH          : 22" | tee -a /etc/log-create-user.log
echo -e "Dropbear         : 143, 109" | tee -a /etc/log-create-user.log
echo -e "SSL/TLS          :$ssl" | tee -a /etc/log-create-user.log
echo -e "SlowDNS          : 22,80,443,53,5300" | tee -a /etc/log-create-user.log
echo -e "SSH-UDP          : 1-65535" | tee -a /etc/log-create-user.log
echo -e "WS SSH(HTTP)     : $wsdropbear" | tee -a /etc/log-create-user.log
echo -e "WS SSL(HTTPS)    : $wsstunnel" | tee -a /etc/log-create-user.log
echo -e "WS OpenVPN(HTTP) : $wsovpn" | tee -a /etc/log-create-user.log
echo -e "OHP Dropbear     : $ohpdrop" | tee -a /etc/log-create-user.log
echo -e "OHP OpenSSH      : $ohpssh" | tee -a /etc/log-create-user.log
echo -e "OHP OpenVPN      : $ovpn3" | tee -a /etc/log-create-user.log
echo -e "Port Squid       :$sqd" | tee -a /etc/log-create-user.log
echo -e "Badvpn(UDPGW)    : 7100-7300" | tee -a /etc/log-create-user.log
echo -e "\e[33m══════════════════════\e[m"
""
echo -e "\e[33m══════════════════════\e[m"
echo -e "PAYLOAD WS       : GET / HTTP/1.1[crlf]Host: bug.com.$domain[crlf]Upgrade: websocket[crlf][crlf]" | tee -a /etc/log-create-user.log
echo -e "\e[33m══════════════════════\e[m"
echo -e "PAYLOAD WSS      : GET wss://$sni/ HTTP/1.1[crlf]Host: bug.com.$domain[crlf]Upgrade: websocket[crlf]Connection: Keep-Alive[crlf][crlf]" | tee -a /etc/log-create-user.log
echo -e "\e[33m══════════════════════\e[m"
echo -e "PAYLOAD WS OVPN  : GET wss://$sni/ HTTP/1.1[crlf]Host: bug.com.$domain[crlf]Upgrade: websocket[crlf]Connection: Keep-Alive[crlf][crlf]" | tee -a /etc/log-create-user.log
echo -e "\e[33m══════════════════════\e[m"
echo ""
echo ""
read -n 1 -s -r -p "Press any key to back on menu ssh"
ssh
else
	echo -e "$Pass\n$Pass\n"|passwd $Login &> /dev/null
echo -e ""
echo -e "\e[33m═══════════════════════════════════════════════════════\e[m"
echo -e " \E[1;47;30m         \e[30m[\e[$box Informasi Account SSH & OpenVPN\e[30m ]\e[1m           \e[m"
echo -e "\e[33m═══════════════════════════════════════════════════════\e[m"
echo -e "\e[33m══════════════════════\e[m"
echo -e "Username         : $Login" | tee -a /etc/log-create-user.log
echo -e "Password         : $Pass" | tee -a /etc/log-create-user.log
echo -e "Expired          : $exp1" | tee -a /etc/log-create-user.log
echo -e "\e[33m══════════════════════\e[m"
echo -e "Domain           : $domain" | tee -a /etc/log-create-user.log
echo -e "Name Server(NS)  : $nsdomain1" | tee -a /etc/log-create-user.log
echo -e "\e[33m══════════════════════\e[m"
echo -e "Pubkey           : $pubkey1" | tee -a /etc/log-create-user.log
echo -e "\e[33m══════════════════════\e[m"
echo -e "IP/Host          : $MYIP" | tee -a /etc/log-create-user.log
echo -e "OpenSSH          : 22" | tee -a /etc/log-create-user.log
echo -e "Dropbear         : 143, 109" | tee -a /etc/log-create-user.log
echo -e "SSL/TLS          :$ssl" | tee -a /etc/log-create-user.log
echo -e "SlowDNS          : 22,80,443,53,5300" | tee -a /etc/log-create-user.log
echo -e "SSH-UDP          : 1-65535" | tee -a /etc/log-create-user.log
echo -e "WS SSH(HTTP)     : $wsdropbear" | tee -a /etc/log-create-user.log
echo -e "WS SSL(HTTPS)    : $wsstunnel" | tee -a /etc/log-create-user.log
echo -e "WS OpenVPN(HTTP) : $wsovpn" | tee -a /etc/log-create-user.log
echo -e "OHP Dropbear     : $ohpdrop" | tee -a /etc/log-create-user.log
echo -e "OHP OpenSSH      : $ohpssh" | tee -a /etc/log-create-user.log
echo -e "OHP OpenVPN      : $ovpn3" | tee -a /etc/log-create-user.log
echo -e "Port Squid       :$sqd" | tee -a /etc/log-create-user.log
echo -e "Badvpn(UDPGW)    : 7100-7300" | tee -a /etc/log-create-user.log
echo -e "\e[33m══════════════════════\e[m"
echo -e "CONFIG SSH WS" | tee -a /etc/log-create-user.log
echo -e "--------------"
echo -e "SSH-22      : $(cat /usr/local/etc/xray/domain):22@$Login:$Pass" | tee -a /etc/log-create-user.log
echo -e "SSH-80      : $(cat /usr/local/etc/xray/domain):80@$Login:$Pass" | tee -a /etc/log-create-user.log
echo -e "SSH-443     : $(cat /usr/local/etc/xray/domain):443@$Login:$Pass" | tee -a /etc/log-create-user.log
echo -e "SSH-1-65535 : $MYIP:1-65535@$Login:$Pass" | tee -a /etc/log-create-user.log
echo -e "\e[33m══════════════════════\e[m"
""
echo -e "\e[33m══════════════════════\e[m"
echo -e "PAYLOAD WS       : GET / HTTP/1.1[crlf]Host: bug.com.$domain[crlf]Upgrade: websocket[crlf][crlf]" | tee -a /etc/log-create-user.log
echo -e "\e[33m══════════════════════\e[m"
echo -e "PAYLOAD WSS      : GET wss://$sni/ HTTP/1.1[crlf]Host: bug.com.$domain[crlf]Upgrade: websocket[crlf]Connection: Keep-Alive[crlf][crlf]" | tee -a /etc/log-create-user.log
echo -e "\e[33m══════════════════════\e[m"
echo -e "PAYLOAD WS OVPN  : GET wss://$sni/ HTTP/1.1[crlf]Host: bug.com.$domain[crlf]Upgrade: websocket[crlf]Connection: Keep-Alive[crlf][crlf]" | tee -a /etc/log-create-user.log
echo -e "\e[33m══════════════════════\e[m"
echo ""
echo ""
read -n 1 -s -r -p "Press any key to back on menu ssh"
ssh
