#!/bin/bash
#Autoscript-Lite By praisedev
clear
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=$(date +"%Y-%m-%d" -d "$dateFromServer")
#########################
MYIP=$(curl -sS https://raw.githubusercontent.com/praisedev/MultiportV3/main/LICENSE/access | awk '{print $2}')
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

cek=$(curl -sS https://raw.githubusercontent.com/praisedev/MultiportV3/main/LICENSE/access | awk '{print $2}' | grep $MYIP)
Name=$(curl -sS https://raw.githubusercontent.com/praisedev/MultiportV3/main/LICENSE/access | grep $MYIP | awk '{print $4}')
if [[ $cek = $MYIP ]]; then
	echo -e "${green}Permission Accepted...${NC}"
else
	echo -e "${red}Permission Denied!${NC}"
	echo ""
	echo -e "Your IP is ${red}NOT REGISTER${NC} @ ${red}EXPIRED${NC}"
	echo ""
	echo -e "Please Contact ${green}Admin${NC}"
	echo -e "Telegram : t.me/praisedev"
	exit 0
fi

clear

BURIQ() {
	curl -sS https://raw.githubusercontent.com/praisedev/MultiportV3/main/LICENSE/access >/root/tmp
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

MYIP=$(curl -sS https://raw.githubusercontent.com/praisedev/MultiportV3/main/LICENSE/access | awk '{print $2}')
Name=$(curl -sS https://raw.githubusercontent.com/praisedev/MultiportV3/main/LICENSE/access | grep $MYIP | awk '{print $4}')
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
	MYIP=$(curl -sS https://raw.githubusercontent.com/praisedev/MultiportV3/main/LICENSE/access | awk '{print $2}')
	IZIN=$(curl -sS https://raw.githubusercontent.com/praisedev/MultiportV3/main/LICENSE/access | awk '{print $3}' | grep $MYIP)
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
domain=$(cat /usr/local/etc/xray/domain)
MYIP2=$(wget -qO- ipv4.icanhazip.com)
tls="$(cat ~/log-install.txt | grep -w "VMESS WS TLS" | cut -d: -f2 | sed 's/ //g')"
none="$(cat ~/log-install.txt | grep -w "VMESS WS None TLS" | cut -d: -f2 | sed 's/ //g')"
until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${CLIENT_EXISTS} == '0' ]]; do
	echo -e "\033[0;34m
\033[0m"
	echo -e "\\E[0;41;36m     Add XRAY Vmess WS Account     \E[0m"
	echo -e "\033[0;34m
\033[0m"
	read -rp "Username : " -e user
	CLIENT_EXISTS=$(grep -w $user /usr/local/etc/xray/config.json | wc -l)
	if [[ ${CLIENT_EXISTS} == '1' ]]; then
		clear
		echo -e "\033[0;34m
\033[0m"
		echo -e "\\E[0;41;36m     Add XRAY Vmess WS Account     \E[0m"
		echo -e "\033[0;34m
\033[0m"
		echo ""
		echo "A client with the specified name was already created, please choose another name."
		echo ""
		echo -e "\033[0;34m
\033[0m"
		read -n 1 -s -r -p "Press any key to back on menu"
		menu
	fi
done
read -p "Bug Address (Example: www.google.com) : " address
read -p "Bug SNI/Host (Example : m.facebook.com) : " hst
read -p "Expired (days) : " masaaktif
bug_addr=${address}.
bug_addr2=${address}
if [[ $address == "" ]]; then
	sts=$bug_addr2
else
	sts=$bug_addr
fi
bug=${hst}
bug2=bug.com
if [[ $hst == "" ]]; then
	sni=$bug2
else
	sni=$bug
fi
uuid=$(cat /proc/sys/kernel/random/uuid)
exp=$(date -d "$masaaktif days" +"%Y-%m-%d")
hariini=$(date -d "0 days" +"%Y-%m-%d")
sed -i '/#tls$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'","alterId": '"0"',"email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#none$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'","alterId": '"0"',"email": "'""$user""'"' /usr/local/etc/xray/none.json

cat >/usr/local/etc/xray/$user-tls.json <<EOF
{
      "v": "2",
      "ps": "XRAY_VMESS_TLS_${user}",
      "add": "${sts}${domain}",
      "port": "${tls}",
      "id": "${uuid}",
      "aid": "0",
      "net": "ws",
      "path": "/vmess-tls",
      "type": "none",
      "host": "${domain}",
      "tls": "tls",
      "sni": "${sni}"
}
EOF

cat >/usr/local/etc/xray/$user-maxis.json <<EOF
{
      "v": "2",
      "ps": "XRAY_VMESS_MAXIS_${user}",
      "add": "104.22.39.195",
      "port": "${tls}",
      "id": "${uuid}",
      "aid": "0",
      "net": "ws",
      "path": "CF-VINS:http://ufuture.uitm.edu.my/vmess-tls",
      "type": "none",
      "host": "${domain}",
      "tls": "tls",
      "sni": "ufuture.uitm.edu.my"
}
EOF

cat >/usr/local/etc/xray/$user-celcom.json <<EOF
{
      "v": "2",
      "ps": "XRAY_VMESS_CELCOM_${user}",
      "add": "104.20.65.29",
      "port": "${tls}",
      "id": "${uuid}",
      "aid": "0",
      "net": "ws",
      "path": "CF-VINS:http://onlinepayment.celcom.com.my/vmess-tls",
      "type": "none",
      "host": "${domain}",
      "tls": "tls",
      "sni": "onlinepayment.celcom.com.my"
}
EOF

cat >/usr/local/etc/xray/$user-none.json <<EOF
{
      "v": "2",
      "ps": "XRAY_VMESS_NON_TLS_${user}",
      "add": "${sts}${domain}",
      "port": "${none}",
      "id": "${uuid}",
      "aid": "0",
      "net": "ws",
      "path": "/vmess-ntls",
      "type": "none",
      "host": "${domain}",
      "tls": "none"
}
EOF

cat >/usr/local/etc/xray/$user-digi.json <<EOF
{
      "v": "2",
      "ps": "XRAY_VMESS_DIGI_${user}",
      "add": "162.159.134.61",
      "port": "${none}",
      "id": "${uuid}",
      "aid": "0",
      "net": "ws",
      "path": "/vmess-ntls",
      "type": "none",
      "host": "${domain}",
      "tls": "none"
}
EOF

cat >/usr/local/etc/xray/$user-yes.json <<EOF
{
      "v": "2",
      "ps": "XRAY_VMESS_YES_${user}",
      "add": "104.17.112.188",
      "port": "${none}",
      "id": "${uuid}",
      "aid": "0",
      "net": "ws",
      "path": "CF-VINS:http://cdn.who.int/vmess-ntls",
      "type": "none",
      "host": "${domain}",
      "tls": "none"
}
EOF

vmess_base641=$(base64 -w 0 <<<$vmess_json1)
vmess_base642=$(base64 -w 0 <<<$vmess_json2)
vmess_base643=$(base64 -w 0 <<<$vmess_json3)
vmess_base644=$(base64 -w 0 <<<$vmess_json4)
vmess_base645=$(base64 -w 0 <<<$vmess_json5)
vmess_base646=$(base64 -w 0 <<<$vmess_json5)
vmesslink1="vmess://$(base64 -w 0 /usr/local/etc/xray/$user-tls.json)"
vmesslink2="vmess://$(base64 -w 0 /usr/local/etc/xray/$user-none.json)"
vmesslink3="vmess://$(base64 -w 0 /usr/local/etc/xray/$user-maxis.json)"
vmesslink4="vmess://$(base64 -w 0 /usr/local/etc/xray/$user-digi.json)"
vmesslink5="vmess://$(base64 -w 0 /usr/local/etc/xray/$user-celcom.json)"
vmesslink6="vmess://$(base64 -w 0 /usr/local/etc/xray/$user-yes.json)"
systemctl restart xray.service
systemctl restart xray@none.service
service cron restart

cat >/home/vps/public_html/$user-VMESSTLS.yaml <<EOF
port: 7890
socks-port: 7891
redir-port: 7892
mixed-port: 7893
tproxy-port: 7895
ipv6: false
mode: rule
log-level: silent
allow-lan: true
external-controller: 0.0.0.0:9090
secret: ""
bind-address: "*"
unified-delay: true
profile:
  store-selected: true
  store-fake-ip: true
dns:
  enable: true
  ipv6: false
  use-host: true
  enhanced-mode: fake-ip
  listen: 0.0.0.0:7874
  nameserver:
    - 8.8.8.8
    - 1.0.0.1
    - https://dns.google/dns-query
  fallback:
    - 1.1.1.1
    - 8.8.4.4
    - https://cloudflare-dns.com/dns-query
    - 112.215.203.254
  default-nameserver:
    - 8.8.8.8
    - 1.1.1.1
    - 112.215.203.254
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*.lan"
    - "*.localdomain"
    - "*.example"
    - "*.invalid"
    - "*.localhost"
    - "*.test"
    - "*.local"
    - "*.home.arpa"
    - time.*.com
    - time.*.gov
    - time.*.edu.cn
    - time.*.apple.com
    - time1.*.com
    - time2.*.com
    - time3.*.com
    - time4.*.com
    - time5.*.com
    - time6.*.com
    - time7.*.com
    - ntp.*.com
    - ntp1.*.com
    - ntp2.*.com
    - ntp3.*.com
    - ntp4.*.com
    - ntp5.*.com
    - ntp6.*.com
    - ntp7.*.com
    - "*.time.edu.cn"
    - "*.ntp.org.cn"
    - +.pool.ntp.org
    - time1.cloud.tencent.com
    - music.163.com
    - "*.music.163.com"
    - "*.126.net"
    - musicapi.taihe.com
    - music.taihe.com
    - songsearch.kugou.com
    - trackercdn.kugou.com
    - "*.kuwo.cn"
    - api-jooxtt.sanook.com
    - api.joox.com
    - joox.com
    - y.qq.com
    - "*.y.qq.com"
    - streamoc.music.tc.qq.com
    - mobileoc.music.tc.qq.com
    - isure.stream.qqmusic.qq.com
    - dl.stream.qqmusic.qq.com
    - aqqmusic.tc.qq.com
    - amobile.music.tc.qq.com
    - "*.xiami.com"
    - "*.music.migu.cn"
    - music.migu.cn
    - "*.msftconnecttest.com"
    - "*.msftncsi.com"
    - msftconnecttest.com
    - msftncsi.com
    - localhost.ptlogin2.qq.com
    - localhost.sec.qq.com
    - +.srv.nintendo.net
    - +.stun.playstation.net
    - xbox.*.microsoft.com
    - xnotify.xboxlive.com
    - +.battlenet.com.cn
    - +.wotgame.cn
    - +.wggames.cn
    - +.wowsgame.cn
    - +.wargaming.net
    - proxy.golang.org
    - stun.*.*
    - stun.*.*.*
    - +.stun.*.*
    - +.stun.*.*.*
    - +.stun.*.*.*.*
    - heartbeat.belkin.com
    - "*.linksys.com"
    - "*.linksyssmartwifi.com"
    - "*.router.asus.com"
    - mesu.apple.com
    - swscan.apple.com
    - swquery.apple.com
    - swdownload.apple.com
    - swcdn.apple.com
    - swdist.apple.com
    - lens.l.google.com
    - stun.l.google.com
    - +.nflxvideo.net
    - "*.square-enix.com"
    - "*.finalfantasyxiv.com"
    - "*.ffxiv.com"
    - "*.mcdn.bilivideo.cn"
    - +.media.dssott.com
proxies:
  - name: XRAY_VMESS_TLS_${user}
    server: ${sts}${domain}
    port: ${tls}
    type: vmess
    uuid: ${uuid}
    alterId: 0
    cipher: auto
    tls: true
    skip-cert-verify: true
    servername: ${sni}
    network: ws
    ws-opts:
      path: /vmess-tls
      headers:
        Host: ${domain}
    udp: true
proxy-groups:
  - name: praisedev-Autoscript
    type: select
    proxies:
      - XRAY_VMESS_TLS_${user}
      - DIRECT
rules:
  - MATCH,praisedev-Autoscript
EOF

cat >/home/vps/public_html/$user-VMESSNTLS.yaml <<EOF
port: 7890
socks-port: 7891
redir-port: 7892
mixed-port: 7893
tproxy-port: 7895
ipv6: false
mode: rule
log-level: silent
allow-lan: true
external-controller: 0.0.0.0:9090
secret: ""
bind-address: "*"
unified-delay: true
profile:
  store-selected: true
  store-fake-ip: true
dns:
  enable: true
  ipv6: false
  use-host: true
  enhanced-mode: fake-ip
  listen: 0.0.0.0:7874
  nameserver:
    - 8.8.8.8
    - 1.0.0.1
    - https://dns.google/dns-query
  fallback:
    - 1.1.1.1
    - 8.8.4.4
    - https://cloudflare-dns.com/dns-query
    - 112.215.203.254
  default-nameserver:
    - 8.8.8.8
    - 1.1.1.1
    - 112.215.203.254
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*.lan"
    - "*.localdomain"
    - "*.example"
    - "*.invalid"
    - "*.localhost"
    - "*.test"
    - "*.local"
    - "*.home.arpa"
    - time.*.com
    - time.*.gov
    - time.*.edu.cn
    - time.*.apple.com
    - time1.*.com
    - time2.*.com
    - time3.*.com
    - time4.*.com
    - time5.*.com
    - time6.*.com
    - time7.*.com
    - ntp.*.com
    - ntp1.*.com
    - ntp2.*.com
    - ntp3.*.com
    - ntp4.*.com
    - ntp5.*.com
    - ntp6.*.com
    - ntp7.*.com
    - "*.time.edu.cn"
    - "*.ntp.org.cn"
    - +.pool.ntp.org
    - time1.cloud.tencent.com
    - music.163.com
    - "*.music.163.com"
    - "*.126.net"
    - musicapi.taihe.com
    - music.taihe.com
    - songsearch.kugou.com
    - trackercdn.kugou.com
    - "*.kuwo.cn"
    - api-jooxtt.sanook.com
    - api.joox.com
    - joox.com
    - y.qq.com
    - "*.y.qq.com"
    - streamoc.music.tc.qq.com
    - mobileoc.music.tc.qq.com
    - isure.stream.qqmusic.qq.com
    - dl.stream.qqmusic.qq.com
    - aqqmusic.tc.qq.com
    - amobile.music.tc.qq.com
    - "*.xiami.com"
    - "*.music.migu.cn"
    - music.migu.cn
    - "*.msftconnecttest.com"
    - "*.msftncsi.com"
    - msftconnecttest.com
    - msftncsi.com
    - localhost.ptlogin2.qq.com
    - localhost.sec.qq.com
    - +.srv.nintendo.net
    - +.stun.playstation.net
    - xbox.*.microsoft.com
    - xnotify.xboxlive.com
    - +.battlenet.com.cn
    - +.wotgame.cn
    - +.wggames.cn
    - +.wowsgame.cn
    - +.wargaming.net
    - proxy.golang.org
    - stun.*.*
    - stun.*.*.*
    - +.stun.*.*
    - +.stun.*.*.*
    - +.stun.*.*.*.*
    - heartbeat.belkin.com
    - "*.linksys.com"
    - "*.linksyssmartwifi.com"
    - "*.router.asus.com"
    - mesu.apple.com
    - swscan.apple.com
    - swquery.apple.com
    - swdownload.apple.com
    - swcdn.apple.com
    - swdist.apple.com
    - lens.l.google.com
    - stun.l.google.com
    - +.nflxvideo.net
    - "*.square-enix.com"
    - "*.finalfantasyxiv.com"
    - "*.ffxiv.com"
    - "*.mcdn.bilivideo.cn"
    - +.media.dssott.com
proxies:
  - name: XRAY_VMESS_NON_TLS_${user}
    server: ${sts}${domain}
    port: ${none}
    type: vmess
    uuid: ${uuid}
    alterId: 0
    cipher: auto
    tls: false
    skip-cert-verify: true
    servername: ${domain}
    network: ws
    ws-opts:
      path: /vmess-ntls
      headers:
        Host: ${domain}
    udp: true
proxy-groups:
  - name: praisedev-Autoscript
    type: select
    proxies:
      - XRAY_VMESS_NON_TLS_${user}
      - DIRECT
rules:
  - MATCH,praisedev-Autoscript
EOF

clear
echo -e "\e[33m╒════════════════════════════════════════════╕\033[0m"
echo -e " \E[1;48;39m                [XRAY VMESS WS]                 \E[0m"
echo -e "\e[33m╘════════════════════════════════════════════╛\033[0m"
echo -e "Remarks           : ${user}"
echo -e "Domain            : ${domain}"
echo -e "Port TLS          : ${tls}"
echo -e "Port None TLS     : ${none}"
echo -e "ID                : ${uuid}"
echo -e "AlterId           : 0"
echo -e "Security          : Auto"
echo -e "Network           : WS"
echo -e "Path TLS          : /vmess-tls"
echo -e "Path NTLS         : /vmess-ntls"
echo -e "\e[33m═════════════════════════════════\e[m"
echo -e "Link WS TLS       : ${vmesslink1}"
echo -e "\e[33m═════════════════════════════════\e[m"
echo -e "Link WS None TLS  : ${vmesslink2}"
echo -e "\e[33m═════════════════════════════════\e[m"
echo -e "Link (MAXIS)      : ${vmesslink3}"
echo -e "\e[33m═════════════════════════════════\e[m"
echo -e "Link (DIGI)       : ${vmesslink4}"
echo -e "\e[33m═════════════════════════════════\e[m"
echo -e "Link (CELCOM)     : ${vmesslink5}"
echo -e "\e[33m═════════════════════════════════\e[m"
echo -e "Link (YES)        : ${vmesslink6}"
echo -e "\e[33m═════════════════════════════════\e[m"
echo -e "YAML WS TLS       : http://${MYIP2}:81/$user-VMESSTLS.yaml"
echo -e "\e[33m═════════════════════════════════\e[m"
echo -e "YAML WS None TLS  : http://${MYIP2}:81/$user-VMESSNTLS.yaml"
echo -e "\e[33m══════════════════════\e[m"
echo -e "nama              : ${user}"
echo -e "Created On        : $hariini"
echo -e "Expired On        : $exp"
echo -e "server            : $User"
echo -e "\e[33m══════════════════════\e[m"
echo -e ""
echo -e ""
echo -e "Autoscript By praisedev"
read -n 1 -s -r -p "Press any key to back on menu"
menu
