#!/bin/sh
adgb=`nvram get adg_enable`
D="/etc/storage/cron/crontabs"
F="$D/`nvram get http_username`"
#adgip=`nvram get adg_ipaddr`
change_dns() {
if [ "$(nvram get adg_redirect)" = 1 ]; then
sed -i '/no-resolv/d' /etc/storage/dnsmasq/dnsmasq.conf
sed -i '/server=127.0.0.1/d' /etc/storage/dnsmasq/dnsmasq.conf
cat >> /etc/storage/dnsmasq/dnsmasq.conf << EOF
no-resolv
server=127.0.0.1#5335
EOF
/sbin/restart_dhcpd
logger -t "AdGuardHome" "添加DNS转发到5335端口"
fi
}

del_dns() {
sed -i '/no-resolv/d' /etc/storage/dnsmasq/dnsmasq.conf
sed -i '/server=127.0.0.1#5335/d' /etc/storage/dnsmasq/dnsmasq.conf
/sbin/restart_dhcpd
}

set_iptable() {
    if [ "$(nvram get adg_redirect)" = 2 ]; then
  IPS="`ifconfig | grep "inet addr" | grep -v ":127" | grep "Bcast" | awk '{print $2}' | awk -F : '{print $2}'`"
  for IP in $IPS
  do
    iptables -t nat -A PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports 5335 >/dev/null 2>&1
    iptables -t nat -A PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports 5335 >/dev/null 2>&1
  done

  IPS="`ifconfig | grep "inet6 addr" | grep -v " fe80::" | grep -v " ::1" | grep "Global" | awk '{print $3}'`"
  for IP in $IPS
  do
    ip6tables -t nat -A PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports 5335 >/dev/null 2>&1
    ip6tables -t nat -A PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports 5335 >/dev/null 2>&1
  done
    logger -t "AdGuardHome" "重定向53端口"
    fi
}

clear_iptable() {
  OLD_PORT="5335"
  IPS="`ifconfig | grep "inet addr" | grep -v ":127" | grep "Bcast" | awk '{print $2}' | awk -F : '{print $2}'`"
  for IP in $IPS
  do
    iptables -t nat -D PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
    iptables -t nat -D PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
  done

  IPS="`ifconfig | grep "inet6 addr" | grep -v " fe80::" | grep -v " ::1" | grep "Global" | awk '{print $3}'`"
  for IP in $IPS
  do
    ip6tables -t nat -D PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
    ip6tables -t nat -D PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
  done

}

getconfig() {
adg_file="/etc/storage/adg.sh"
if [ ! -f "$adg_file" ] || [ ! -s "$adg_file" ] ; then
  cat > "$adg_file" <<-\EEE
bind_host: 0.0.0.0
bind_port: 3000
auth_name: adguardhome
auth_pass: adguardhome
language: zh-cn
rlimit_nofile: 0
dns:
  bind_host: 0.0.0.0
  port: 5335
  protection_enabled: true
  filtering_enabled: true
  blocking_mode: nxdomain
  blocked_response_ttl: 10
  querylog_enabled: true
  ratelimit: 20
  ratelimit_whitelist: []
  refuse_any: true
  bootstrap_dns:
  - 223.5.5.5
  - 119.29.29.29
  all_servers: true
  allowed_clients: []
  disallowed_clients: []
  blocked_hosts: []
  parental_sensitivity: 0
  parental_enabled: false
  safesearch_enabled: false
  safebrowsing_enabled: false
  resolveraddress: ""
  upstream_dns:
  - quic://i.passcloud.xyz:784
  - tls://i.passcloud.xyz:5432
  - quic://a.passcloud.xyz:784
  - tls://a.passcloud.xyz:5432
tls:
  enabled: false
  server_name: ""
  force_https: false
  port_https: 443
  port_dns_over_tls: 853
  certificate_chain: ""
  private_key: ""
filters:
- enabled: true
  url: https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
  name: AdGuard Simplified Domain Names filter
  id: 1
- enabled: true
  url: https://adaway.org/hosts.txt
  name: AdAway
  id: 2
- enabled: true
  url: https://www.malwaredomainlist.com/hostslist/hosts.txt
  name: MalwareDomainList.com Hosts List
  id: 3
user_rules: []
dhcp:
  enabled: false
  interface_name: ""
  gateway_ip: ""
  subnet_mask: ""
  range_start: ""
  range_end: ""
  lease_duration: 86400
  icmp_timeout_msec: 1000

log_file: ""
verbose: false
schema_version: 3

EEE
  chmod 755 "$adg_file"
fi
}

start_adg() {
sed -Ei '/AdGuardHome守护进程|^$/d' "$F"
  logger -t "AdGuardHome" "正在启动..."
  AdGuardHome="/tmp/AdGuardHome/AdGuardHome"
  [ -f /etc/storage/bin/AdGuardHome ] && AdGuardHome="/etc/storage/bin/AdGuardHome"
	if [ ! -s "$AdGuardHome" ] ; then
	logger -t "AdGuardHome" "找不到 $AdGuardHome ，开始下载 AdGuardHome 程序"
	tag=$(curl -k --silent "https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
	[ -z "$tag" ] && tag="$( curl -k -L --connect-timeout 20 --silent https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/latest | grep 'tag_name' | cut -d\" -f4 )"
	[ -z "$tag" ] && tag="$( curl -k --connect-timeout 20 --silent https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/latest | grep 'tag_name' | cut -d\" -f4 )"
	[ -z "$tag" ] && tag="$( curl -k --connect-timeout 20 -s https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/latest | grep 'tag_name' | cut -d\" -f4 )"
		if [ ! -z "$tag" ] ; then
			logger -t "AdGuardHome" "自动下载最新版本 $tag,下载较慢，耐心等待"
			curl -L -k -S -o "/tmp/AdGuardHome.tar.gz" --connect-timeout 10 --retry 3 "https://github.com/AdguardTeam/AdGuardHome/releases/download/$tag/AdGuardHome_linux_mipsle_softfloat.tar.gz"
			tar -xzvf /tmp/AdGuardHome.tar.gz -C /tmp
		else
			static_adguard="https://fastly.jsdelivr.net/gh/AdguardTeam/AdGuardHome@releases/download/v0.107.35/AdGuardHome_linux_mipsle_softfloat.tar.gz"
			logger -t "AdGuardHome" "获取最新版本失败,下载$static_adguard"
			curl -L -k -S -o "/tmp/AdGuardHome.tar.gz" --connect-timeout 10 --retry 3 "$static_adguard"
			tar -xzvf /tmp/AdGuardHome.tar.gz -C /tmp ; cd /tmp/AdGuardHome
		fi
		 cd /tmp/AdGuardHome ; rm -f ./AdGuardHome.tar.gz ./LICENSE.txt./README.md ./CHANGELOG.md ./AdGuardHome.sig
		if [ ! -s "$AdGuardHome" ] && [ -d "/tmp/AdGuardHome" ] ; then
			logger -t "AdGuardHome" "AdGuardHome下载失败,重新下载"
                if [ ! -z "$tag" ] ; then
			logger -t "AdGuardHome" "下载最新版本 $tag"
			curl -L -k -S -o "/tmp/AdGuardHome.tar.gz" --connect-timeout 10 --retry 3 "https://fastly.jsdelivr.net/gh/AdguardTeam/AdGuardHome@releases/download/$tag/AdGuardHome_linux_mipsle_softfloat.tar.gz"
			tar -xzvf /tmp/AdGuardHome.tar.gz -C /tmp
		else
			static_adguard="https://fastly.jsdelivr.net/gh/AdguardTeam/AdGuardHome@releases/download/v0.107.35/AdGuardHome_linux_mipsle_softfloat.tar.gz"
			logger -t "AdGuardHome" "下载AdGuardHome_v0.107.35"
			curl -L -k -S -o "/tmp/AdGuardHome.tar.gz" --connect-timeout 10 --retry 3 "$static_adguard"
			tar -xzvf /tmp/AdGuardHome.tar.gz -C /tmp ; cd /tmp/AdGuardHome
		fi
		 cd /tmp/AdGuardHome ; rm -f ./LICENSE.txt./README.md ./CHANGELOG.md ./AdGuardHome.sig
	        fi
     fi
              chmod 777 "$AdGuardHome"
	      adgver=$($AdGuardHome --version | awk '{print $4}')
       [ -z "$adgver" ] && logger -t "AdGuardHome" "程序不完整，重新下载" && rm -rf $AdGuardHome && adg_re
                if [ -f "/tmp/AdGuardHome/AdGuardHome" ]; then
                logger -t "AdGuardHome" "AdGuardHome_$adgver下载成功！"
                fi
  adgenable=$(nvram get adg_enable)
  if [ "$adgb" = "1" ] ;then
  getconfig
  change_dns
  set_iptable
  logger -t "AdGuardHome" "运行AdGuardHome_$adgver"
  eval "$AdGuardHome -c $adg_file -w /tmp/AdGuardHome -v" &
  sleep 10
  [ ! -z "`pidof AdGuardHome`" ] && logger -t "AdGuardHome" "启动成功"
  [ -z "`pidof AdGuardHome`" ] && logger -t "AdGuardHome" "启动失败，20秒后尝试重新启动" && sleep 20 && adg_re
  adgip=$(cat /etc/storage/adg.sh | grep "address:" | awk -F ':' '{print $3}' | tr -d ' ' )
  [ -z "$adgip" ] && adgip=$(cat /etc/storage/adg.sh | grep "bind_port" | awk -F ':' '{print $2}' | tr -d ' ' )
  [ -z "$adgip" ] && adgip=3030
  lanip=`nvram get lan_ipaddr`
  nvram set adg_ipaddr="http://${lanip}:${adgip}"
logger -t "AdGuardHome" "守护进程启动" 
sed -Ei '/AdGuardHome守护进程|^$/d' "$F"
cat >> "$F" <<-OSC
*/1 * * * * test -z \"\$(pidof AdGuardHome\" && [ \"\$(nvram get adg_enable)\" = "1" ] &&  adguardhome.sh start #AdGuardHome守护进程"
OSC
fi
exit 0
}

adg_re(){
        adg_enable=`nvram get adg_enable`
	if [ -z "`pidof AdGuardHome`" ] && [ "$adg_enable" = "1" ];then
	 sleep 20
	start_adg
	fi
 [ "$adgb" != "1" ] && stop_adg
	exit 0
}

stop_adg() {
sed -Ei '/AdGuardHome守护进程|^$/d' "$F"
killall -9 AdGuardHome
killall AdGuardHome
del_dns
clear_iptable
[ -z "`pidof AdGuardHome`" ] && logger -t "AdGuardHome" "关闭AdGuardHome"
}

case $1 in
start)
  start_adg &
  ;;
stop)
  stop_adg &
  ;;
*)
  start_adg &
  ;;
esac
