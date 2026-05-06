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
      ListenIP: "::" # IP address you want to listen
      SendIP: "::" # IP address you want to send pacakage
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
MIIFFzCCA/+gAwIBAgISBiMjFTWTS7ki5WX5IR/QTJTbMA0GCSqGSIb3DQEBCwUA
MDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQwwCgYDVQQD
EwNSMTIwHhcNMjYwNDE4MTExOTM4WhcNMjYwNzE3MTExOTM3WjAfMR0wGwYDVQQD
DBQqLnhuLS1tOHN2NDBkd2ViLnh5ejCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAMVMgjc/MPeYVdNHijUvC23OrH9l92dEH3YNmEbADh4PKMdpQJapq9SR
X5Ks04tUOFEmVCJvq44miljZrBYPztAdCDU2JPjpwaQ9cnQh0icsr5L2dW3nh4jY
A49ivY+pJey7hJhApUYmUaQWEuxcxPTV/cb1Rc7FTtTguhnvQVGnx0lIbpQK1Qn7
nM1EkNJWhgqXFtytXgz8EdLdXR7X3+U4uPOnpnQAXf8xY7R0fIGcfgTlSS1H2ZHL
7Wab1wjORU/51w6mXqpqIUSYYdaVrl40VoCvyLf+XO5LrDknTdtavg3I5xfsf8qh
s3O2Xi0KdceMTrqPu3zGRaKmAk3R420CAwEAAaOCAjcwggIzMA4GA1UdDwEB/wQE
AwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQW
BBRKxb0J+Y0HSop4YzeUHNocNUKRKjAfBgNVHSMEGDAWgBQAtSnyLY5vMeibTK14
Pvrc6QzR0jAzBggrBgEFBQcBAQQnMCUwIwYIKwYBBQUHMAKGF2h0dHA6Ly9yMTIu
aS5sZW5jci5vcmcvMDMGA1UdEQQsMCqCFCoueG4tLW04c3Y0MGR3ZWIueHl6ghJ4
bi0tbThzdjQwZHdlYi54eXowEwYDVR0gBAwwCjAIBgZngQwBAgEwLgYDVR0fBCcw
JTAjoCGgH4YdaHR0cDovL3IxMi5jLmxlbmNyLm9yZy85Mi5jcmwwggENBgorBgEE
AdZ5AgQCBIH+BIH7APkAdwDLOPcViXyEoURfW8Hd+8lu8ppZzUcKaQWFsMsUwxRY
5wAAAZ2ghudxAAAEAwBIMEYCIQCJ1P/UU5HgpOS9ezDlW58sczBqD6FbQNRYKt/e
UZuDnwIhAKXrOCzJPUl2yYqKChhnCPBrGTZLsOGbs5hy7KLybtWEAH4AJuNkblhp
ISO8ND9HJDWbN5LNJFqI2BXTkzP9mRirRyMAAAGdoIbnjAAIAAAFAAgx3wcEAwBH
MEUCIBOMhPR7sZ8li8QikFI4CXzUydenoQZzq4iqvdIBbXstAiEA3x4U7sjf2kby
c5B577nZRAxMDJ2eMmfofv8TRnFvr8QwDQYJKoZIhvcNAQELBQADggEBAAVlQBUt
wAtA32hlFwSath8vLhqlzum18xs2mHgBOaht8AUtX3aFt2j8cRmrZ3rI1RDPPHYg
LGn7zLqb0+7MongWcSz57o3gdXtJbuQVgnsj4jnInSc/u+yHdRe2z+7J4kMZgwWQ
2g1QLTbv8eGHbC8I37c2wFeycuIZckxo/4hV6VVPmxSqLhOkH1n8iNJCj3xPwenf
KbJvygcTVm1zRcfEgsWE4EGWQRoQFTJJazm+tNx+3HwhbJ0ea9GXFhs+LBAtu7zP
eokqebE5cZC8LD2kfDIHIbQmHAmuFDMNMv3X83/imDOV98UFd8LLrmfMTCZYLmSp
VbfauYzqaABLsdc=
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
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDFTII3PzD3mFXT
R4o1Lwttzqx/ZfdnRB92DZhGwA4eDyjHaUCWqavUkV+SrNOLVDhRJlQib6uOJopY
2awWD87QHQg1NiT46cGkPXJ0IdInLK+S9nVt54eI2AOPYr2PqSXsu4SYQKVGJlGk
FhLsXMT01f3G9UXOxU7U4LoZ70FRp8dJSG6UCtUJ+5zNRJDSVoYKlxbcrV4M/BHS
3V0e19/lOLjzp6Z0AF3/MWO0dHyBnH4E5UktR9mRy+1mm9cIzkVP+dcOpl6qaiFE
mGHWla5eNFaAr8i3/lzuS6w5J03bWr4NyOcX7H/KobNztl4tCnXHjE66j7t8xkWi
pgJN0eNtAgMBAAECggEAI8QlXO+LKG9Iq7bt0otXNo4/Tg8FhQZf764yOy0owgE8
gr3NVCKpAC1kVnoXFUxssyVQHjgBMRFChi3bmNo/wxFoQgExPaBelq/+9heFec2L
fIhKLGTK+J80MgOT2p2uvtYViOY7L9bVePn5bzi4CaxbR3yCLaQuEMA2bGonfK4s
nJtkzc31zlxIZSqOFbfmGMiZdj/bgsqh52OmRyfCDn1xgb4L2u4XbHiN5AXbMyeu
W//8EtBK/M7q48QDIM6bYxkuL3leSjB8QrYB8agKhCaPrcCIfqQwULYHh3nxdZ1B
Z1fvlG/aO1s4Cl94WTq6BcUcdGZAzbp50LaTbTdY8QKBgQDmAKSl3TGwIU1cnhrk
9VfNuzQIpUFu32a2aYzmzHra8kCmQjKSIp5tVNNJQ82TI7+BYDDjQIoNPwUXvk0G
f4UzyZeOQhu3v7mMqQquQ8iLk8eN97bLgfAwiEKkFvt92XZV1siwFk2lkn1LrS0i
B5wAOGOHPDK5oypwFdXMFKLntQKBgQDbmY1VQZmu5RSLP1triW664ZMUnpYOCtAS
KKXaXLSg6xfguDYixCtiSUtyHenYa0IA0dyYHTzkW50HAk4KiVALuWAn4Ze/WdE0
gq5zcX0SJs9Y4LYOU8QXtvj78rDfTh/FbdJ7J4OUdBQr1okBAPA/ZgsBiF4qm7pV
lWyPerRv2QKBgH+qUbnDKmZiRcen9rOpvv/x7jLyT3yUQjX0JoKhc3v+RYZDbkCR
OLDlCZY8LWqDyDOuydQKKdaqaVBBkA2QUMZrGlWbOjlnET4TQltyQmm/MGAL5InX
aRP3Pk5Id3Xmc/m3i5O5/YVu519PE6M06BFzO0OAVYOXHuIyLIbn2XiVAoGAM/2a
tICffgTGZGFPp5oWGTCmvc79/70XnfT5r0Ubjq2aLZ3vUzPWgaKQtifW4WIjckY9
T9Y8QGRgPPSSvXPc+6mb1lVWs/rzyNbXroVD8zQ1CvnIoIO8fVDYie3faj74zqk9
l+K3CEKjM+3K6e3q81eZa3d5s+TCrNh/p0iJx6ECgYBln6y1q/WSeAREix53xT8s
VGQIyrl8d3TjkYt31jJIRFgbcqzBlb8ferOsB02wel4LVbBjjoQphXjL3ziz8SCE
JmgfNCfisyg14hWJL+Fkv88OhlbMCqK7ktIBY7RCYqEFmLmea665ai/T3hkIQYKk
G8oW9qA+ZpHFIFnxmsFeyg==
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
