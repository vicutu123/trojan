#!/usr/bin/env bash
#
#一键脚本
#version=v1.1
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#check root
[ $(id -u) != "0" ] && { echo "错误: 您必须以root用户运行此脚本"; exit 1; }
rm -rf all
rm -rf $0
mkdir -p -m 777 /usr/local/xrayr
#
# 设置字体颜色函数
function blue(){
    echo -e "\033[34m\033[01m $1 \033[0m"
}
function green(){
    echo -e "\033[32m\033[01m $1 \033[0m"
}
function greenbg(){
    echo -e "\033[43;42m\033[01m $1 \033[0m"
}
function red(){
    echo -e "\033[31m\033[01m $1 \033[0m"
}
function redbg(){
    echo -e "\033[37;41m\033[01m $1 \033[0m"
}
function yellow(){
    echo -e "\033[33m\033[01m $1 \033[0m"
}
function white(){
    echo -e "\033[37m\033[01m $1 \033[0m"
}


#            
# @安装docker
install_docker() {
    docker version > /dev/null || curl -fsSL get.docker.com | bash 
    service docker restart 
    systemctl enable docker  
    echo "30 4 * * * systemctl restart docker >/dev/null 2>&1" > /var/spool/cron/root && sysctl -w vm.panic_on_oom=1
}

# 单独检测docker是否安装，否则执行安装docker。
check_docker() {
	if [ -x "$(command -v docker)" ]; then
		blue "docker is installed"
		# command
	else
		echo "Install docker"
		# command
		install_docker
	fi
}

#工具安装
install_tool() {
    echo "===> Start to install tool"    
    if [ -x "$(command -v yum)" ]; then
        command -v curl > /dev/null || yum install -y curl
    elif [ -x "$(command -v apt)" ]; then
        command -v curl > /dev/null || apt install -y curl
    else
        echo "Package manager is not support this OS. Only support to use yum/apt."
        exit -1
    fi 
    
}
#写入xrayr配置文件
xrayr_file(){
    cat > /usr/local/xrayr/config.yml << EOF
Log:
  Level: none # Log level: none, error, warning, info, debug 
  AccessPath: # /etc/XrayR/access.Log
  ErrorPath: # /etc/XrayR/error.log
DnsConfigPath: # /etc/XrayR/dns.json # Path to dns config, check https://xtls.github.io/config/base/dns/ for help
RouteConfigPath: # /etc/XrayR/route.json # Path to route config, check https://xtls.github.io/config/base/route/ for help
OutboundConfigPath: # /etc/XrayR/custom_outbound.json # Path to custom outbound config, check https://xtls.github.io/config/base/outbound/ for help
ConnetionConfig:
  Handshake: 10 # Handshake time limit, Second
  ConnIdle: 300 # Connection idle time limit, Second
  UplinkOnly: 60 # Time limit when the connection downstream is closed, Second
  DownlinkOnly: 120 # Time limit when the connection is closed after the uplink is closed, Second
  BufferSize: 128 # The internal cache size of each connection, kB 
Nodes:
  -
    PanelType: "SSpanel" # Panel type: SSpanel, V2board, PMpanel, , Proxypanel
    ApiConfig:
      ApiHost: "https://qwword.xyz"
      ApiKey: "vicutu123"
      NodeID: $node_id
      NodeType: Trojan # Node type: V2ray, Shadowsocks, Trojan, Shadowsocks-Plugin
      Timeout: 30 # Timeout for the api request
      EnableVless: false # Enable Vless for V2ray Type
      EnableXTLS: true # Enable XTLS for V2ray and Trojan
      SpeedLimit: 0 # Mbps, Local settings will replace remote settings, 0 means disable
      DeviceLimit: 0 # Local settings will replace remote settings, 0 means disable
      RuleListPath: # ./rulelist Path to local rulelist file
    ControllerConfig:
      ListenIP: 0.0.0.0 # IP address you want to listen
      SendIP: 0.0.0.0 # IP address you want to send pacakage
      UpdatePeriodic: 60 # Time to update the nodeinfo, how many sec.
      EnableDNS: false # Use custom DNS config, Please ensure that you set the dns.json well
      DNSType: AsIs # AsIs, UseIP, UseIPv4, UseIPv6, DNS strategy
      EnableProxyProtocol: false # Only works for WebSocket and TCP
      EnableFallback: false # Only support for Trojan and Vless
      FallBackConfigs:  # Support multiple fallbacks
        -
          SNI: # TLS SNI(Server Name Indication), Empty for any
          Path: # HTTP PATH, Empty for any
          Dest: 80 # Required, Destination of fallback, check https://xtls.github.io/config/fallback/ for details.
          ProxyProtocolVer: 0 # Send PROXY protocol version, 0 for dsable
      CertConfig:
        CertMode: file # Option about how to get certificate: none, file, http, dns. Choose "none" will forcedly disable the tls config.
        CertDomain: "111.111" # Domain to cert
        CertFile: /etc/XrayR/certificate.crt # Provided if the CertMode is file
        KeyFile: /etc/XrayR/private.key
        Provider: alidns # DNS cert provider, Get the full support list here: https://go-acme.github.io/lego/dns/
        Email: test@me.com
        DNSEnv: # DNS ENV option used by DNS provider
          ALICLOUD_ACCESS_KEY: aaa
          ALICLOUD_SECRET_KEY: bbb
  # -
  #   PanelType: "V2board" # Panel type: SSpanel, V2board
  #   ApiConfig:
  #     ApiHost: "http://127.0.0.1:668"
  #     ApiKey: "123"
  #     NodeID: 4
  #     NodeType: Shadowsocks # Node type: V2ray, Shadowsocks, Trojan
  #     Timeout: 30 # Timeout for the api request
  #     EnableVless: false # Enable Vless for V2ray Type
  #     EnableXTLS: true # Enable XTLS for V2ray and Trojan
  #     SpeedLimit: 0 # Mbps, Local settings will replace remote settings
  #     DeviceLimit: 0 # Local settings will replace remote settings
  #   ControllerConfig:
  #     ListenIP: 0.0.0.0 # IP address you want to listen
  #     UpdatePeriodic: 10 # Time to update the nodeinfo, how many sec.
  #     EnableDNS: false # Use custom DNS config, Please ensure that you set the dns.json well
  #     CertConfig:
  #       CertMode: dns # Option about how to get certificate: none, file, http, dns
  #       CertDomain: "node1.test.com" # Domain to cert
  #       CertFile: ./cert/node1.test.com.cert # Provided if the CertMode is file
  #       KeyFile: ./cert/node1.test.com.pem
  #       Provider: alidns # DNS cert provider, Get the full support list here: https://go-acme.github.io/lego/dns/
  #       Email: test@me.com
  #       DNSEnv: # DNS ENV option used by DNS provider
  #         ALICLOUD_ACCESS_KEY: aaa
  #         ALICLOUD_SECRET_KEY: bbb

EOF
}

#写入证书文件
crt_file(){
    cat > /usr/local/xrayr/certificate.crt << EOF
-----BEGIN CERTIFICATE-----
MIIEFTCCAv2gAwIBAgIUTfDBwIYqBAiiA5RPaHyI9PD35howDQYJKoZIhvcNAQEL
BQAwgagxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH
Ew1TYW4gRnJhbmNpc2NvMRkwFwYDVQQKExBDbG91ZGZsYXJlLCBJbmMuMRswGQYD
VQQLExJ3d3cuY2xvdWRmbGFyZS5jb20xNDAyBgNVBAMTK01hbmFnZWQgQ0EgMDA1
MmIzYThhZDk4ZmE5N2Y4ZWE2MzJhMGQzNTA0ZTMwHhcNMjUwNDIxMDMxNDAwWhcN
MzUwNDE5MDMxNDAwWjAiMQswCQYDVQQGEwJVUzETMBEGA1UEAxMKQ2xvdWRmbGFy
ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK7oFpm1GNmnxhZFGZoM
5s7432u03fBewoH/H+i2DrwwhveiHuRIQD1kYARrzDTehj0Keao48vbHPCE020cG
lNUvm+BeWmZMmLyTR/QN1j0l5u7Aq3LjulpOANbBz5E7hswr9SAr5X7dmHHgz/77
t7gJufX8sijUzPA88gXx2GERvEdKkrfxxDxqD0Y7wVlMp5V9dmmLP7jn9kuk0Kzp
t3CWFhVsub7IDwjxlUp7GeimGJR3q8mtP2tm78LqwS9Dov540rz2zGc5Zu1qsRJZ
YOOOEY5Vy78HBJ2pZehXGcNx4HbMOWo63wTHZUIL4Q12JwSjuKaHxVVlmuJESQsZ
KdsCAwEAAaOBuzCBuDATBgNVHSUEDDAKBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAA
MB0GA1UdDgQWBBQZNElCFbNkHBpwOjVQyHAYuy/pvTAfBgNVHSMEGDAWgBRYBfkh
bk/zecwAuQI/bNwwjmjKxjBTBgNVHR8ETDBKMEigRqBEhkJodHRwOi8vY3JsLmNs
b3VkZmxhcmUuY29tLzZlNDMwYzNmLTA1Y2YtNDM3Ni1iYzFkLTNiNWRkZGQ4ZWVl
Ny5jcmwwDQYJKoZIhvcNAQELBQADggEBAEWoXFCTRRq0ce5KVvvOfo4QOEh/gXXf
tkgqFtpvCraXZrfwiwEayoeDuZWMwq4eOnSG+NyMXMdazv+ovfP36j2oEaq5PZUO
qqaJ5pBMINvwtXV75ITZcfprMjZ+d5n6R/ijtOVT2j3t8XGY4viCdA0+ak/ioEAh
HfgenE9RATx8KsuItfjrs/5mFizKR462m7Tj/umHU8HZHnKk1gMW1pUiLYVFhOuu
27EU+RP8bVAr9kuTaNCsce9Lk1Ny32KZ4Mw/RLGjUYGWQg59Mp4kkMbz6W3UOeYl
0tIpBOlNGE7CJq4Un//NjkT6wSbaivLlfs590DnLYXgUmyWWyKcDQ2E=
-----END CERTIFICATE-----
EOF
cat > /usr/local/xrayr/private.key << EOF
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCu6BaZtRjZp8YW
RRmaDObO+N9rtN3wXsKB/x/otg68MIb3oh7kSEA9ZGAEa8w03oY9CnmqOPL2xzwh
NNtHBpTVL5vgXlpmTJi8k0f0DdY9JebuwKty47paTgDWwc+RO4bMK/UgK+V+3Zhx
4M/++7e4Cbn1/LIo1MzwPPIF8dhhEbxHSpK38cQ8ag9GO8FZTKeVfXZpiz+45/ZL
pNCs6bdwlhYVbLm+yA8I8ZVKexnophiUd6vJrT9rZu/C6sEvQ6L+eNK89sxnOWbt
arESWWDjjhGOVcu/BwSdqWXoVxnDceB2zDlqOt8Ex2VCC+ENdicEo7imh8VVZZri
REkLGSnbAgMBAAECggEAEet4aU4bGi2sx1pUCar5uMnZxiS1OmvS/NOhNsv0TYah
RVzIUnYukrumdL2AoggMc9OPbIfCKNN3zyUltCyx8febPk0ccO+3FFb4n8INKZ2o
/9wglLhNPvRP9LDNreEN6fw09JNaw3k7pas1VDgA9iuU8GVv8WwABTsRRtek5ijq
IseZhKZPIldzvqICQQFRXsgYHZp1AJrKKaMTZFUxFrnwNdonI0Ff5b+dwfin1s2L
urik+xgCXMwrtwIJSjcY3vBV51noKuJ4q2f5IGyQleCpwcobLpD/0E0dPtsE1GgB
YIgrcOaC6Bgf5rNZMse6DmBkwMUhLc7SFrVdSLrSKQKBgQDaCJjb83Pgug2B+Td8
YY4fvctSF5LKSfRB2FOkcPcJtQ5YDoTmr7odUXqVy70HLPIWpFdxkG7P1IeLmvk/
BQWWjZTI1zo9I+moWyDjHKqI1DlayZt2iQto6KDQg4kgJd4PTjFwIVJEXykA2b3w
NwJOGrA+nVxaqqgk/MBNPMUviQKBgQDNXP7om729W6QOCBMMN0xdof8COkWuB55A
2pevwTwc+DUbC18fWnL0Utk/6Agt3JxUbvVT1eMCpoDRcEw879ZD4B3my35kzEtl
XDg1OqV7y8ysdQK8bn+WZWjBeBYkL8KuxGMy7jUmeL4h9a/Vkoh63v3ceNivKdqJ
L/pxWKCxQwKBgAGR/kfXQQZlUKOW/+dNbJCd9VDqCoyaa7/tpuyQQ7c2LpxDvoFK
0rRTWeaqSPo8QKIZHOgcei/VAATpYNIrXxbufhvUMP8vuwcTYPFBy5igrqkQuqXn
5sUip8XYrKwmmarSjViZZNZJOSpgZxXLz6BwYMSSrY+ZmwxpJZlozqLBAoGAZfwC
0z1Uks8Jv7Yez3g+wlkKrO6HYA+EdayYm72YvsI8jTuud4GRiOgD34q5VR0zvXKE
/qc/XzeUzW25TqHEhFyuPMld8WzLHIEZoMWJHNtuv040l6NAVU3zIfEi/cGCKwx4
PvixCHP56B98vNFSWcKXy39wDDz6vBpJgzSCSMUCgYB/zza++DDHlBVAkQnlFYLK
hnuDO5vKvKxtb+faxjLAzxTT9KnUi5a+VxmZy/YiveR5diLYBI23KJDwX7GtReag
su8k4t39gGHK+spXWMkCFZpkO1GzWds8kz7rFt9hBlkCkMJwSFewMF/0wGv88eUh
mwq3wEa9e8jBC2pg14RRKg==
-----END PRIVATE KEY-----

EOF
}
          

# 以上步骤完成基础环境配置。
echo "恭喜，您已完成基础环境安装，可执行安装程序。"

backend_docking_set(){
    white "本脚本支持 green "webapi"的对接方式"
    green "请选择对接方式"
    yellow "1.trojan对接"
    echo
    read -e -p "请输入数字[1~2](默认1)：" vnum
    [[ -z "${vnum}" ]] && vnum="1" 
	if [[ "${vnum}" == "1" ]]; then
        greenbg "当前对接模式：webapi"
        greenbg "使用前请准备好 redbg "节点ID""
        green "节点ID,示例: 6"
        read -p "请输入节点ID:" node_id
        yellow "配置已完成，正在部署后端。。。。"
        start=$(date "+%s")
        install_tool
        check_docker
        xrayr_file
        crt_file
        docker run --restart=always --name xrayr -d -v /usr/local/xrayr/config.yml:/etc/XrayR/config.yml -v /usr/local/xrayr/certificate.crt:/etc/XrayR/certificate.crt -v /usr/local/xrayr/private.key:/etc/XrayR/private.key --network=host crackair/xrayr:latest
        greenbg "恭喜您，后端节点已搭建成功"
        end=$(date "+%s")
        echo 安装总耗时:$[$end-$start]"秒"           
	fi       
    }



#开始菜单
start_menu(){
    clear
    greenbg "==============================================================="
    greenbg "程序：sspanel后端对接 v1.0                          "
    greenbg "系统：Centos7.x、Ubuntu、Debian等                              "
    greenbg "==============================================================="
    echo
    echo
    green "-------------程序安装-------------"
    green "1.SSPANEL后端对接（默认：支持v2ray,trojan）"
    green "2.节点bbrplus加速"
    green "3.移除旧docker和证书配置文件夹"
    green "4.安装aapanel宝塔"
    green "5.禁用ipv6"
    blue "0.退出脚本"
    echo
    echo
    read -p "请输入数字:" num

    case "$num" in
    1)
    greenbg "您选择了默认对接方式"
    backend_docking_set
	;;
	2)
    yellow "bbr加速脚本"
    wget -O tcp.sh "https://github.com/cx9208/Linux-NetSpeed/raw/master/tcp.sh" && chmod +x tcp.sh && ./tcp.sh
	;;            
	3)
    yellow "移除旧docker和证书配置文件夹"
    docker rm -f xrayr
    systemctl restart docker
    rm -rf /usr/local/xrayr/
	;;    
	4)
    yellow "安装aapanel宝塔"
    yum install -y wget && wget -O install.sh http://www.aapanel.com/script/install_6.0_en.sh && bash install.sh
	;;  
	5)
    yellow "禁用ipv6"
    clear
    sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
    sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
    sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
    sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.conf
    sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.conf
    sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.conf

    echo "net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1" >>/etc/sysctl.d/99-sysctl.conf
    sysctl --system
    echo -e "${Info}禁用IPv6结束，可能需要重启！"
	;;  
	0)
	exit 1
	;;
	*)
	clear
	echo "请输入正确数字[0~2],退出请按0"
	sleep 3s
	start_menu
	;;
    esac
}

start_menu
