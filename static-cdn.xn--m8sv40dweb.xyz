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
MIIFGzCCBAOgAwIBAgISBndX2LM2JXZJ24/6k7QxsSh0MA0GCSqGSIb3DQEBCwUA
MDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQwwCgYDVQQD
EwNSMTMwHhcNMjYwMTIwMDAwMDU1WhcNMjYwNDIwMDAwMDU0WjAfMR0wGwYDVQQD
DBQqLnhuLS1tOHN2NDBkd2ViLnh5ejCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAKi/Ijb0zQBA37ntFX2f0VgVDax9DIFsPusDtGiuVzqr8W49WomlfBbe
vO2uWLWEVS9dFVBJio6bd+uR4KUxQ98dsB+CEWTXukLBL2MpbQMlBk9ZRpqXJa/5
trrnmiEmTpHxON2atmJBuEFiNutUV6OEAtkMcQqDsVYyoHAXA9rXd1LnOs4ptawB
SFL2+01rVlPQ+XJXIXeJyiiQcLBiThkACgs1H+STEiun9lhMO498h4iIbIDXYSq+
z6KmrCqPQgRAcq5wF4RDQescwstk+jwadSJnS094ZabVFYn8hIoXa6xTZC8DX/jP
9V15z1+QPlqccl2uJrqQSoXfBkJGzDUCAwEAAaOCAjswggI3MA4GA1UdDwEB/wQE
AwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIw
ADAdBgNVHQ4EFgQUwN3OjzPSyBfQUqQVtaS73xTtVgwwHwYDVR0jBBgwFoAU56uf
DywzoFPTXk94yLKEDjvWkjMwMwYIKwYBBQUHAQEEJzAlMCMGCCsGAQUFBzAChhdo
dHRwOi8vcjEzLmkubGVuY3Iub3JnLzAzBgNVHREELDAqghQqLnhuLS1tOHN2NDBk
d2ViLnh5eoISeG4tLW04c3Y0MGR3ZWIueHl6MBMGA1UdIAQMMAowCAYGZ4EMAQIB
MC8GA1UdHwQoMCYwJKAioCCGHmh0dHA6Ly9yMTMuYy5sZW5jci5vcmcvMTE3LmNy
bDCCAQYGCisGAQQB1nkCBAIEgfcEgfQA8gB3AJaXZL9VWJet90OHaDcIQnfp8DrV
9qTzNm5GpD8PyqnGAAABm9jp47QAAAQDAEgwRgIhAJ+5uPteD8o029oOmDczdpSb
MPjzHVYNoo+e60jAtIjCAiEA4xExQMwJXgTwQWcAfsx/93NKW35WuV/PmVI8oU7l
0fsAdwDLOPcViXyEoURfW8Hd+8lu8ppZzUcKaQWFsMsUwxRY5wAAAZvY6etBAAAE
AwBIMEYCIQDHX5oI9yvzXP7sku4KWsHfS60aTX0pgwDlIsTXODjAnAIhAJI4kWsy
xafJYsRZr2dC63Dwdg5yqSAQtlHTlzRqZIc/MA0GCSqGSIb3DQEBCwUAA4IBAQAQ
wiL+rPTI8bT6QyFntdv9wl9SoIGfmc4B+w6B9G4B7IRs83XqQMnyplrpc2Deefby
i/QOxiAfw+Qaw98QlSAjssMTRmvvyCW4Jt3xjOHKyAaJRdwFD6sHsYUVLyHL4cTj
lz934jP+4dc2uhgY+haTM6LPifKJxdynIFEjkUWHzNpgPGTWVAruwYaiIRnV/quc
tpQlLTHHxhYM0UbSP/T2sKkNBLwdTRfzCcRt7ISBZaRnzQb5YvLern3Vqb1iNQi9
CMyZXobVRT1L5Zlm33TDoS/JpvntOSl5hpbnNXvi/Jvo+VOUTB2ZM4KlUrF7OLm6
bh3pAOMJK1t2EKkCUiMf
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIFBTCCAu2gAwIBAgIQWgDyEtjUtIDzkkFX6imDBTANBgkqhkiG9w0BAQsFADBP
MQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFy
Y2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMTAeFw0yNDAzMTMwMDAwMDBa
Fw0yNzAzMTIyMzU5NTlaMDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBF
bmNyeXB0MQwwCgYDVQQDEwNSMTMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQClZ3CN0FaBZBUXYc25BtStGZCMJlA3mBZjklTb2cyEBZPs0+wIG6BgUUNI
fSvHSJaetC3ancgnO1ehn6vw1g7UDjDKb5ux0daknTI+WE41b0VYaHEX/D7YXYKg
L7JRbLAaXbhZzjVlyIuhrxA3/+OcXcJJFzT/jCuLjfC8cSyTDB0FxLrHzarJXnzR
yQH3nAP2/Apd9Np75tt2QnDr9E0i2gB3b9bJXxf92nUupVcM9upctuBzpWjPoXTi
dYJ+EJ/B9aLrAek4sQpEzNPCifVJNYIKNLMc6YjCR06CDgo28EdPivEpBHXazeGa
XP9enZiVuppD0EqiFwUBBDDTMrOPAgMBAAGjgfgwgfUwDgYDVR0PAQH/BAQDAgGG
MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATASBgNVHRMBAf8ECDAGAQH/
AgEAMB0GA1UdDgQWBBTnq58PLDOgU9NeT3jIsoQOO9aSMzAfBgNVHSMEGDAWgBR5
tFnme7bl5AFzgAiIyBpY9umbbjAyBggrBgEFBQcBAQQmMCQwIgYIKwYBBQUHMAKG
Fmh0dHA6Ly94MS5pLmxlbmNyLm9yZy8wEwYDVR0gBAwwCjAIBgZngQwBAgEwJwYD
VR0fBCAwHjAcoBqgGIYWaHR0cDovL3gxLmMubGVuY3Iub3JnLzANBgkqhkiG9w0B
AQsFAAOCAgEAUTdYUqEimzW7TbrOypLqCfL7VOwYf/Q79OH5cHLCZeggfQhDconl
k7Kgh8b0vi+/XuWu7CN8n/UPeg1vo3G+taXirrytthQinAHGwc/UdbOygJa9zuBc
VyqoH3CXTXDInT+8a+c3aEVMJ2St+pSn4ed+WkDp8ijsijvEyFwE47hulW0Ltzjg
9fOV5Pmrg/zxWbRuL+k0DBDHEJennCsAen7c35Pmx7jpmJ/HtgRhcnz0yjSBvyIw
6L1QIupkCv2SBODT/xDD3gfQQyKv6roV4G2EhfEyAsWpmojxjCUCGiyg97FvDtm/
NK2LSc9lybKxB73I2+P2G3CaWpvvpAiHCVu30jW8GCxKdfhsXtnIy2imskQqVZ2m
0Pmxobb28Tucr7xBK7CtwvPrb79os7u2XP3O5f9b/H66GNyRrglRXlrYjI1oGYL/
f4I1n/Sgusda6WvA6C190kxjU15Y12mHU4+BxyR9cx2hhGS9fAjMZKJss28qxvz6
Axu4CaDmRNZpK/pQrXF17yXCXkmEWgvSOEZy6Z9pcbLIVEGckV/iVeq0AOo2pkg9
p4QRIy0tK2diRENLSF2KysFwbY6B26BFeFs3v1sYVRhFW9nLkOrQVporCS0KyZmf
wVD89qSTlnctLcZnIavjKsKUu1nA1iU0yYMdYepKR7lWbnwhdx3ewok=
-----END CERTIFICATE-----
EOF
cat > /usr/local/xrayr/private.key << EOF
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCovyI29M0AQN+5
7RV9n9FYFQ2sfQyBbD7rA7Rorlc6q/FuPVqJpXwW3rztrli1hFUvXRVQSYqOm3fr
keClMUPfHbAfghFk17pCwS9jKW0DJQZPWUaalyWv+ba655ohJk6R8TjdmrZiQbhB
YjbrVFejhALZDHEKg7FWMqBwFwPa13dS5zrOKbWsAUhS9vtNa1ZT0PlyVyF3icoo
kHCwYk4ZAAoLNR/kkxIrp/ZYTDuPfIeIiGyA12Eqvs+ipqwqj0IEQHKucBeEQ0Hr
HMLLZPo8GnUiZ0tPeGWm1RWJ/ISKF2usU2QvA1/4z/Vdec9fkD5anHJdria6kEqF
3wZCRsw1AgMBAAECggEAQQyZFGVO51OayvHtUGV8zj8ja8Qyv2tqX68oaxgV0Sy6
H3xwO9J6oNhRLTCBystOCTmRP0dyLaIZ2sn7tsJkfwxTOfoqWVzd1ODisw+jkcxC
f/ESygINCaax/Z/NJw08yX6bJLYAq6TY8f9520LCm+qGLIRiySJWCLvwY/VDS6cV
w1d7n4DSoCT8e3kjejVYIoTpX6sdC7b8pyoA04/7aW+1ZIWYbLOYtx6MaO+4flBf
r8FNz+hYO5j2QTu2U0M/dTBRq4eGufb8EPBgFEHOODQM48r4NUI1BnP4uiWX9N8u
iH0EiFglhr7jujyK+NEZxq4L4+HkorG7AlXhUqVD6wKBgQDkrARAh/u8Vkb9JkA3
u8Yc4rCnYBUP0uGHWJYxZrNhxFqRAH/2Ec2OwGYlRiz06+LVZDYeQBpuIQ3qILwh
G5gP6oXobTbiBjGG6ihWG4CvwLyS7QZ7gxi2QQhu/16fo6aOsy/GT8bnf1qgcenI
qiTGzinxWRCyAP1guTTdF72eewKBgQC86cNjQ6rHNhsewErlhZGFn+kmyBAdewJu
vQBkog/Y8lkcXHzdJw3eyvpH9WsnbbAkEW7uZ+lThtgZKNNRO88wB2ZlOsgmeaOP
40PeXrx1JH9G0Un4stv3Rp6eYg97LQHN50YW8JUaFwKWuAMlt7lvmKZCMWQKhJqc
yVjhfmmZDwKBgQCwpPj76I/cI0HfWGcPJqyZr7wK77wVZy/038fWDaHQil/z11EC
AyqpdZLyhE1CPd4SPcFYiOhh3oLjM7pgUPKciOw8afGVlHc54zSZn9E+80I4tYTm
cJTsZTxgkkDETSTi4ySqqwHZ3pVhj92qt1SFhsj7uXOeLgmNaESf7jD6dQKBgQCZ
LxzGoxoaC1+WYerZjqNfrTmLvvKCVTq1vQBSma8sBegIPV7qnT58CC9GplTLVgBc
Xt6K5yumFVOpoxcnac4pbfaz4yRlPoFIrcpcyIkcnAmwzQikZ7RCILuCRpWzFd2+
ruiAtXjR/RKWUIQM05vESA2Y4x/x/3C37fTqdG0ANQKBgQCaBCIJKTlxpnlurx3n
WtGawqiJUPBKZT5F+B3mEs8TCx6Ly96bPm66dzyDMK41/YMWM8y764INY8LH/rne
2T+Qsv6FSOggT4JB+2/ex/X98rtNC0+phE4h6CKmAvNpUqj8mgfjMHaAWIUZIzgS
TdUnr07zu5JA2MgUDFI745V5lQ==
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
