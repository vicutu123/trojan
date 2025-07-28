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
MIIFFzCCA/+gAwIBAgISBT7UPqXnr5Zd4FjHLZkzj1l6MA0GCSqGSIb3DQEBCwUA
MDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQwwCgYDVQQD
EwNSMTEwHhcNMjUwNzI4MTE1ODI3WhcNMjUxMDI2MTE1ODI2WjAfMR0wGwYDVQQD
DBQqLnhuLS1tOHN2NDBkd2ViLnh5ejCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAKan2m66jRYDYTOojoiTiZGAVzJ2uozyDsIv97ykZ0NMQlFxDdK5kX00
VPoP0LtvWDCzNX1lVihFaA1d3AaqTz51N/EAGkXrUz9hqcI7PLfnAAVsaw7zrxwq
Z2OM79ixlTW/qkpVvYMHsC4fCNMOaSO9y6c+QU8GjpSfL+QRi9hl/MeQv97bAXmg
qLwP4wvdba3gRRYz4ZpHq8le15PjfL9PBAaLS65CQKCT9jVTdqR5Df8iP8uSx+/C
PbO8pqMmeG2/8T+nE49cpzXVHoNRV1ZBnv+AdmLLq9P+V1bJSFiW94D++E8iaLcx
5gKNsjzA1SmUvkmN8rIrfu6K25dSDT8CAwEAAaOCAjcwggIzMA4GA1UdDwEB/wQE
AwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIw
ADAdBgNVHQ4EFgQUpPRxJaqeHmazbZf1mAnLZtzXrQ8wHwYDVR0jBBgwFoAUxc9G
pOr0w8B6bJXELbBeki8m47kwMwYIKwYBBQUHAQEEJzAlMCMGCCsGAQUFBzAChhdo
dHRwOi8vcjExLmkubGVuY3Iub3JnLzAzBgNVHREELDAqghQqLnhuLS1tOHN2NDBk
d2ViLnh5eoISeG4tLW04c3Y0MGR3ZWIueHl6MBMGA1UdIAQMMAowCAYGZ4EMAQIB
MC8GA1UdHwQoMCYwJKAioCCGHmh0dHA6Ly9yMTEuYy5sZW5jci5vcmcvMTIzLmNy
bDCCAQIGCisGAQQB1nkCBAIEgfMEgfAA7gB1ABLxTjS9U3JMhAYZw48/ehP457Vi
h4icbTAFhOvlhiY6AAABmFEbjqkAAAQDAEYwRAIgJLGGyEpwOr2owOyz3NE/6g0V
MN+FG9jSv3oF+pln0UICICjYLdkr8+Ev+VjrLZwmmy0RtuQ0WsfPLoTgYMTnQkIM
AHUAGgT/SdBUHUCv9qDDv/HYxGcvTuzuI0BomGsXQC7ciX0AAAGYURuO4wAABAMA
RjBEAiBUB4Uok9TAVwBIgSqt6PW5QNOb5bQCk2dXLa5BHRwg5QIgO8s3eZiJneh6
fYGt1AeFa5D0VUiXA4kOsFUE7Gl+IV8wDQYJKoZIhvcNAQELBQADggEBALYVYfEm
2YXpU6CgXD1qlZdnMGWtwyJ5Px0NQ95H35EzRrr92eYD8QSGp1h7+RDCiWBArnGY
SrSGRCsdNVrGBEJgMrQwE/aE0JW9ZpHyeJLo1XTVab2ElwKMAAOsuS+qslkDgI0Y
wdNn3fKrVrLOKjsYVmFtWL4V6qExonlz/Kv2Kgzybl3zmKgAEQF3Voy8ysWDScl6
PR6iWdPbUkHFMYU3caBj5Rv+zTDoyVDKckBYaQ3XWDLPQJATozvkMu7f/rGZhp6l
VST8I1+w2YdGg6dqS8Rovk8zuolmHQ0iZSvamZMRJty3GhnTRcc0s+svxZ3Diyez
PhhqCGL1VlX0laU=
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIFBjCCAu6gAwIBAgIRAIp9PhPWLzDvI4a9KQdrNPgwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjQwMzEzMDAwMDAw
WhcNMjcwMzEyMjM1OTU5WjAzMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDEMMAoGA1UEAxMDUjExMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAuoe8XBsAOcvKCs3UZxD5ATylTqVhyybKUvsVAbe5KPUoHu0nsyQYOWcJ
DAjs4DqwO3cOvfPlOVRBDE6uQdaZdN5R2+97/1i9qLcT9t4x1fJyyXJqC4N0lZxG
AGQUmfOx2SLZzaiSqhwmej/+71gFewiVgdtxD4774zEJuwm+UE1fj5F2PVqdnoPy
6cRms+EGZkNIGIBloDcYmpuEMpexsr3E+BUAnSeI++JjF5ZsmydnS8TbKF5pwnnw
SVzgJFDhxLyhBax7QG0AtMJBP6dYuC/FXJuluwme8f7rsIU5/agK70XEeOtlKsLP
Xzze41xNG/cLJyuqC0J3U095ah2H2QIDAQABo4H4MIH1MA4GA1UdDwEB/wQEAwIB
hjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwEgYDVR0TAQH/BAgwBgEB
/wIBADAdBgNVHQ4EFgQUxc9GpOr0w8B6bJXELbBeki8m47kwHwYDVR0jBBgwFoAU
ebRZ5nu25eQBc4AIiMgaWPbpm24wMgYIKwYBBQUHAQEEJjAkMCIGCCsGAQUFBzAC
hhZodHRwOi8veDEuaS5sZW5jci5vcmcvMBMGA1UdIAQMMAowCAYGZ4EMAQIBMCcG
A1UdHwQgMB4wHKAaoBiGFmh0dHA6Ly94MS5jLmxlbmNyLm9yZy8wDQYJKoZIhvcN
AQELBQADggIBAE7iiV0KAxyQOND1H/lxXPjDj7I3iHpvsCUf7b632IYGjukJhM1y
v4Hz/MrPU0jtvfZpQtSlET41yBOykh0FX+ou1Nj4ScOt9ZmWnO8m2OG0JAtIIE38
01S0qcYhyOE2G/93ZCkXufBL713qzXnQv5C/viOykNpKqUgxdKlEC+Hi9i2DcaR1
e9KUwQUZRhy5j/PEdEglKg3l9dtD4tuTm7kZtB8v32oOjzHTYw+7KdzdZiw/sBtn
UfhBPORNuay4pJxmY/WrhSMdzFO2q3Gu3MUBcdo27goYKjL9CTF8j/Zz55yctUoV
aneCWs/ajUX+HypkBTA+c8LGDLnWO2NKq0YD/pnARkAnYGPfUDoHR9gVSp/qRx+Z
WghiDLZsMwhN1zjtSC0uBWiugF3vTNzYIEFfaPG7Ws3jDrAMMYebQ95JQ+HIBD/R
PBuHRTBpqKlyDnkSHDHYPiNX3adPoPAcgdF3H2/W0rmoswMWgTlLn1Wu0mrks7/q
pdWfS6PJ1jty80r2VKsM/Dj3YIDfbjXKdaFU5C+8bhfJGqU3taKauuz0wHVGT3eo
6FlWkWYtbt4pgdamlwVeZEW+LM7qZEJEsMNPrfC03APKmZsJgpWCDWOKZvkZcvjV
uYkQ4omYCTX5ohy+knMjdOmdH9c7SpqEWBDC86fiNex+O0XOMEZSa8DA
-----END CERTIFICATE-----
EOF
cat > /usr/local/xrayr/private.key << EOF
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCmp9puuo0WA2Ez
qI6Ik4mRgFcydrqM8g7CL/e8pGdDTEJRcQ3SuZF9NFT6D9C7b1gwszV9ZVYoRWgN
XdwGqk8+dTfxABpF61M/YanCOzy35wAFbGsO868cKmdjjO/YsZU1v6pKVb2DB7Au
HwjTDmkjvcunPkFPBo6Uny/kEYvYZfzHkL/e2wF5oKi8D+ML3W2t4EUWM+GaR6vJ
XteT43y/TwQGi0uuQkCgk/Y1U3akeQ3/Ij/Lksfvwj2zvKajJnhtv/E/pxOPXKc1
1R6DUVdWQZ7/gHZiy6vT/ldWyUhYlveA/vhPImi3MeYCjbI8wNUplL5JjfKyK37u
ituXUg0/AgMBAAECggEAUNrXCynPEYMKQbnhjTmnYMRXidA4qfE2X9hN5WQOBYSW
GFU1U6tcftZI9BmAN6/JpbcMmI31wwwJc5K6ETHHyJGuVmqqVInblcCYT/fVeZPF
WtxDBLoNlyiriIz0QLnHnpAi2nXGwC+WtomwClXPhNusVrPJk8Gmo0yoO4qXwqDP
1A3N+4ItHA9p724kKyuSQf2HvS+f8WbHJSaA5dE/gMn3JK5bCqYjKgkWwKig4cSH
gcunCMuvIOORG8BqIwFlG6I4i+zB03DSwhrfEefFV6UuKSw7S2MTdginxyh3Oas4
CNTeURz5/ZNym9UQJ93/c/MMHEiGOFwUUMyTGDZNwQKBgQDZpf/AwX3MGgjlFy3b
mg7g3I6kdT9cyqP6tPubTcFiDCDZ8mHMsuz1XRGylkgvUne4EyX5kiqB3kX4zdYZ
3vdkXzdXDyjQ95tpORyrPPYh1KzBSys+nx8+03R1KKhoajl8QZC46nPMv+3zc2te
ES/jnJcvyeFGxvvQeHColSwdiQKBgQDEBZlagLdYnsaCoYAxTQfMs04ipuLUOJtY
nLtM6+ir7fF1OYIYVdpRzMxMPPvfPuVnQwLOKMR6ZbZ68azrW6Y0cnCbnxNjiYfu
YmEqGR3+JmNR2Zt8bdwI1awiqB7DH1RrBBGqCpPKGHUfnsGdyLXz81GcrKkDH6FU
Hk2yRwYqhwKBgH8SSvLIRWD/pkfSs6RuGtewDdv41GihqwF53xh6Wjibaia1O+Je
aLiMgQOqeDSgymL/UwGWFBlEo8eyrZjnM7s3WEENCcCPf/38KT/U1MNFvyMPdw0V
rBFrNagdd82Wjz97rDo6MCfPuuaTcZE3KaWTTDXLgSpojKbXWrcieOI5AoGAZc1S
m4IFtmyfQ/CEFxaeWl000yJA416Sry6Wx5gtOj1VDUBUpDbSL3FhGKcDWCneEgbn
ShI6GCcC4k7pM0JhyxM0EF5JP4SJp/BH7gklXnypUDTnX3PetmfiAg22DDgVK47t
bZYYsviIu2dDvqIifRN86xVwoUKoEnu6dkAUn7kCgYBBPcGhC8PTUNxgtCjM+UZL
bgix0MDJiO8ot9o47IVpjMZrNgA4u81SU2+7DYo1JfzeHVWq8eT0kq77By3zq+e6
/0btIu3CgUd/M5L3Sj6hRQD3USXI80t3Mt5HDrZdssQXpgl2FiLI+kj1IjcMT37+
OcImw45NTXlkhUZwhNnjsA==
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
