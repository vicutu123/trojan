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
MIIFFzCCA/+gAwIBAgISBrRLfQT/67QIRWximlQwctDQMA0GCSqGSIb3DQEBCwUA
MDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQwwCgYDVQQD
EwNSMTIwHhcNMjUxMDI1MTMxMjE5WhcNMjYwMTIzMTMxMjE4WjAfMR0wGwYDVQQD
DBQqLnhuLS1tOHN2NDBkd2ViLnh5ejCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAJy77Osx5yAz3C16bFW5M4BihHZP+vIYnR0r2Y2Ts/qtkVEz01S8iuD3
IFnW86DtWLncPajxOXi6MzmUZ16XdPASRFOcFoAXw/bEzSwEOc4pqP1xY+a2ASsG
8fcEd8ZHglpV6UqK6TYQ+88kDv/X2Mm2vELiSzsrKSyYYGW76ujCjn7KErHC9V2R
oDekjFJ/YzgaY9hSW6BTTlL19LKtcxWUTvrY2UYoxMP3nLaodqdahpy6fhbNQUOi
dfB/eeScVu1KiNnHdyPLm92vVmt07dQgjJpgk8PvJi3k0WNsqmhsYzR5BoIJfFdO
n90ccXHpMYB8mzKakzkOGM+NzECdaOECAwEAAaOCAjcwggIzMA4GA1UdDwEB/wQE
AwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIw
ADAdBgNVHQ4EFgQUw2vIw4kohy7ZH1Kqx/zHcX+3f3cwHwYDVR0jBBgwFoAUALUp
8i2ObzHom0yteD763OkM0dIwMwYIKwYBBQUHAQEEJzAlMCMGCCsGAQUFBzAChhdo
dHRwOi8vcjEyLmkubGVuY3Iub3JnLzAzBgNVHREELDAqghQqLnhuLS1tOHN2NDBk
d2ViLnh5eoISeG4tLW04c3Y0MGR3ZWIueHl6MBMGA1UdIAQMMAowCAYGZ4EMAQIB
MC4GA1UdHwQnMCUwI6AhoB+GHWh0dHA6Ly9yMTIuYy5sZW5jci5vcmcvODEuY3Js
MIIBAwYKKwYBBAHWeQIEAgSB9ASB8QDvAHYAyzj3FYl8hKFEX1vB3fvJbvKaWc1H
CmkFhbDLFMMUWOcAAAGaG7Us6AAABAMARzBFAiAuWhqxrFAsT7LueetqOruRgm0y
F/CQoU0ytVBkDXiyhwIhAON+J63GxoJfvwhPXNOvOEAKKw9o/zkBFcdjTdPoE8W9
AHUAGYbUxyiqb/66A294Kk0BkarOLXIxD67OXXBBLSVMx9QAAAGaG7Us1wAABAMA
RjBEAiAgW7YF8yKCJTL4fLyTyWiPQKeJSZ6ZZdYYKUotBAvt3AIgWwlv9wHoawMW
QgsabTltmMCBZV1/8Ia/iM+yHg8llzkwDQYJKoZIhvcNAQELBQADggEBAH1bKaOH
Bqmllxp4/hkgIkQ3basmoci/LdWnCMWjoIrgzY8QqLZY+KW9WRJl0k+iZthZ7y3W
oKxvLef/BwHQowXw3CWwMMCPawQVkx6UxrRZ7+bFMZZ4KiVHo5oPSnv87QPhJHoj
z6H/E0qzQxB4RzJHI7lansph+WM0cciwaH83MFna7Tl22FCui21ac5b+kxWtacrG
S5vW7PyhUFU3slAPLe7lSOcRUNEsV+CSeCy/2TVZ+h/g4TqrN65Ek+4P8oYo7a6Y
EXnnPFmFQFvmjsPEBc9jNR9HjIyNh1WU+lL2dj34uCoxUV6r8jfSdOihd9jQbahB
ixsqsULYV2SqR7Y=
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIFBjCCAu6gAwIBAgIRAMISMktwqbSRcdxA9+KFJjwwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjQwMzEzMDAwMDAw
WhcNMjcwMzEyMjM1OTU5WjAzMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDEMMAoGA1UEAxMDUjEyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA2pgodK2+lP474B7i5Ut1qywSf+2nAzJ+Npfs6DGPpRONC5kuHs0BUT1M
5ShuCVUxqqUiXXL0LQfCTUA83wEjuXg39RplMjTmhnGdBO+ECFu9AhqZ66YBAJpz
kG2Pogeg0JfT2kVhgTU9FPnEwF9q3AuWGrCf4yrqvSrWmMebcas7dA8827JgvlpL
Thjp2ypzXIlhZZ7+7Tymy05v5J75AEaz/xlNKmOzjmbGGIVwx1Blbzt05UiDDwhY
XS0jnV6j/ujbAKHS9OMZTfLuevYnnuXNnC2i8n+cF63vEzc50bTILEHWhsDp7CH4
WRt/uTp8n1wBnWIEwii9Cq08yhDsGwIDAQABo4H4MIH1MA4GA1UdDwEB/wQEAwIB
hjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwEgYDVR0TAQH/BAgwBgEB
/wIBADAdBgNVHQ4EFgQUALUp8i2ObzHom0yteD763OkM0dIwHwYDVR0jBBgwFoAU
ebRZ5nu25eQBc4AIiMgaWPbpm24wMgYIKwYBBQUHAQEEJjAkMCIGCCsGAQUFBzAC
hhZodHRwOi8veDEuaS5sZW5jci5vcmcvMBMGA1UdIAQMMAowCAYGZ4EMAQIBMCcG
A1UdHwQgMB4wHKAaoBiGFmh0dHA6Ly94MS5jLmxlbmNyLm9yZy8wDQYJKoZIhvcN
AQELBQADggIBAI910AnPanZIZTKS3rVEyIV29BWEjAK/duuz8eL5boSoVpHhkkv3
4eoAeEiPdZLj5EZ7G2ArIK+gzhTlRQ1q4FKGpPPaFBSpqV/xbUb5UlAXQOnkHn3m
FVj+qYv87/WeY+Bm4sN3Ox8BhyaU7UAQ3LeZ7N1X01xxQe4wIAAE3JVLUCiHmZL+
qoCUtgYIFPgcg350QMUIWgxPXNGEncT921ne7nluI02V8pLUmClqXOsCwULw+PVO
ZCB7qOMxxMBoCUeL2Ll4oMpOSr5pJCpLN3tRA2s6P1KLs9TSrVhOk+7LX28NMUlI
usQ/nxLJID0RhAeFtPjyOCOscQBA53+NRjSCak7P4A5jX7ppmkcJECL+S0i3kXVU
y5Me5BbrU8973jZNv/ax6+ZK6TM8jWmimL6of6OrX7ZU6E2WqazzsFrLG3o2kySb
zlhSgJ81Cl4tv3SbYiYXnJExKQvzf83DYotox3f0fwv7xln1A2ZLplCb0O+l/AK0
YE0DS2FPxSAHi0iwMfW2nNHJrXcY3LLHD77gRgje4Eveubi2xxa+Nmk/hmhLdIET
iVDFanoCrMVIpQ59XWHkzdFmoHXHBV7oibVjGSO7ULSQ7MJ1Nz51phuDJSgAIU7A
0zrLnOrAj/dfrlEWRhCvAgbuwLZX1A2sjNjXoPOHbsPiy+lO1KF8/XY7
-----END CERTIFICATE-----
EOF
cat > /usr/local/xrayr/private.key << EOF
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCcu+zrMecgM9wt
emxVuTOAYoR2T/ryGJ0dK9mNk7P6rZFRM9NUvIrg9yBZ1vOg7Vi53D2o8Tl4ujM5
lGdel3TwEkRTnBaAF8P2xM0sBDnOKaj9cWPmtgErBvH3BHfGR4JaVelKiuk2EPvP
JA7/19jJtrxC4ks7KyksmGBlu+rowo5+yhKxwvVdkaA3pIxSf2M4GmPYUlugU05S
9fSyrXMVlE762NlGKMTD95y2qHanWoacun4WzUFDonXwf3nknFbtSojZx3cjy5vd
r1ZrdO3UIIyaYJPD7yYt5NFjbKpobGM0eQaCCXxXTp/dHHFx6TGAfJsympM5DhjP
jcxAnWjhAgMBAAECggEASH20sP1mOGM0EUa/p5BejSFDwdLxLpsKw+y9lPk9M5Km
lQei1VzU4QL70AGWshZExMXkMOjNG5UHTzjf7IShnc3dE0ysrXcQeGiCurqDn+Jt
2jbhLVp9xNBUBltnKGp3lF+K5KLGBW8qgB5d36AOERG3FjpC8G1ggFNDtpoJJrjn
ubCYhFDk38RiEQTQwAHmVMM/ExgDQtJDzRBQz9w9AH2BlR5sPPyEIHV06CUgRQ53
px3tvcmcRMnyGXwMwYpppUVRfXPc76InqA8L77Geh0NOgsFuqyaEupn7cE+ZUPB8
B0A7YD0lh4NYPYt5Z4Q2OxcoOtwYp6CWfNv9t9wSHwKBgQDZFNhqNiD76bvus4Nd
UZRyt3lR05Io4E0psy7IRh7dgTVQ4lUAFo23QHncIW1Mgs4GlOcn+aN/TwlgXuJH
AALC0TcnF6zHCQ5Vl0w4qkjgz4k6Sp5IXq0iN1YIjPVDE0m4aGpm4z97+i7NfeN3
+HpVZ1a9KQKhKv4ihkfL7sOblwKBgQC41WHpXxzPd8SrHXt5QlcycL8avXKeKcNg
AcJV0aE2WmIbv1ISLHY1LcWA2wI6o8jb/X3ZzyXUdwWt4dz+wMfRHX2b4g8/zYUl
hV1V0aUTMmj7cpfujDY438CzvxwUclz9Ish/kKneIu9WYekiU3O318ADsknH8Fk6
HRTxsF0ORwKBgEKfDB/khtDpFb0XKJyuGcHvHvOG29dhpyzCCfx60KQoMEWngHCr
e0ifKAbv10xg5HvOnPZ+vbenePgzhnxFu5MwhB2iPWtEEzsfWMwXLpCYAMR7/AG3
1KiolOXA5NB2DezjVqxG18fjqxNzrCi4gErPkSYyfNUbjazoywYCO9P3AoGAWW0D
/kFCUy6DPLb68mQihAkArRNTzSovmNfBCnxuHzoDlaEvOBPC7V/D2uAbZ/uuRqGS
rjsG9pDPcp2AqtDi3E4EY9MvxZLOBKVNzyOrVmphWKbM02GLKmE3fr/L+iiKzP5z
OyTmys7kNUsR3MW7iwsbn642/EFRKki/xV+q5ikCgYAQzO6+6XN8FUgW0oswzpuG
VSIloN9Cdwf0wXwB1nwCbxYFP0vT88fF3IJxkhIT4fZBaJFSqEA+Psw5uWYeYbce
W0TDAHl0e0TOZjMnQAV/VDvCxOOA9EexOnp3ijB5tWOTpL6dUgLDxjsnYQuLMOOz
9Q6d466wUO/Pse213nmoAQ==
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
