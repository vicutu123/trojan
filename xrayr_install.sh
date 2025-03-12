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

# 工具安装
install_tool() {
    echo "===> 开始安装必要工具"    
    if [ -x "$(command -v yum)" ]; then
        yum install -y curl fail2ban iptables-services
        systemctl enable iptables
        systemctl restart iptables
    elif [ -x "$(command -v apt)" ]; then
        apt update && apt install -y curl fail2ban iptables
    else
        echo "不支持的系统，仅支持 yum/apt 包管理器"
        exit 1
    fi 
}

# 自动检测 SSH 日志路径
detect_ssh_logpath() {
    if [[ -f "/var/log/auth.log" ]]; then
        SSH_LOG="/var/log/auth.log"
    else
        SSH_LOG="/var/log/secure"
    fi
}

# Fail2Ban 防火墙保护 XrayR & SSH
configure_fail2ban() {
    echo "===> 配置 Fail2Ban 进行防护"

    detect_ssh_logpath  # 自动检测 SSH 日志路径

    # Fail2Ban 配置
    cat > /etc/fail2ban/jail.local << EOF
[xrayr]
enabled = true
port = 443,8443,2087
filter = xrayr
logpath = /var/log/xrayr.log
maxretry = 3
findtime = 600 # 在10分钟内发生maxretry次就封禁
bantime = 86400 # 封禁时间1天
action = iptables-allports  # 确保封禁所有端口
ignoreip = 127.0.0.1 192.168.1.1  # 你的服务器IP，防止误封
bantime.increment = true  # 每次被封禁，时间加倍

[sshd]
enabled = true
port = 22
filter = sshd
logpath = $SSH_LOG
maxretry = 5
findtime = 600
bantime = 86400
action = iptables-allports
EOF

    # 重新启动 Fail2Ban
    systemctl restart fail2ban
    systemctl enable fail2ban
    echo "✅ Fail2Ban 配置完成"
}

# 创建 XrayR 过滤规则
setup_xrayr_filter() {
    echo "===> 配置 XrayR 过滤规则"
    cat > /etc/fail2ban/filter.d/xrayr.conf << EOF
[Definition]
failregex = .* \[Warning\] \[Trojan\] client \[<HOST>\] authentication failed.*
            .* \[Warning\] \[V2ray\] client \[<HOST>\] authentication failed.*
            .* \[Warning\] \[Shadowsocks\] client \[<HOST>\] authentication failed.*

ignoreregex =
EOF
    echo "✅ XrayR 过滤规则已设置"
}

# 确保 fail2ban 规则正常生效
check_fail2ban() {
    echo "===> 检查 Fail2Ban 运行状态"
    systemctl status fail2ban | grep "Active: active (running)"
    if [[ $? -eq 0 ]]; then
        echo "✅ Fail2Ban 运行正常"
    else
        echo "❌ Fail2Ban 运行失败，尝试重启"
        systemctl restart fail2ban
    fi

    echo "➡  当前 XrayR 规则状态："
    fail2ban-client status xrayr || echo "❌ XrayR 规则未生效"

    echo "➡  当前 SSH 规则状态："
    fail2ban-client status sshd || echo "❌ SSH 规则未生效"
}

# 执行所有步骤
install_tool
setup_xrayr_filter
configure_fail2ban
check_fail2ban

echo "🎉 安装 & 配置 Fail2Ban 完成！"

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
      EnableXTLS: false # Enable XTLS for V2ray and Trojan
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
      EnableFallback: true # Only support for Trojan and Vless
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
  #     EnableXTLS: false # Enable XTLS for V2ray and Trojan
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
MIIFrjCCBJagAwIBAgIMNBnJFpFORBRkaX3HMA0GCSqGSIb3DQEBCwUAMFUxCzAJ
BgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSswKQYDVQQDEyJH
bG9iYWxTaWduIEdDQyBSNiBBbHBoYVNTTCBDQSAyMDIzMB4XDTI0MDMyODA1NDYw
NloXDTI1MDQyOTA1NDYwNVowIjEgMB4GA1UEAwwXKi54bi0tbWVzcjVoZDFtYjdz
LnNob3AwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR0uz4OQ8sw1iIwDjwgTTRp
nZoXyI+gqUQw4wELyji3Fm9da5XpmkG2EHG/oFOugqvetCMvwhvfAjXramB0jW34
o4IDejCCA3YwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwgZkGCCsGAQUF
BwEBBIGMMIGJMEkGCCsGAQUFBzAChj1odHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24u
Y29tL2NhY2VydC9nc2djY3I2YWxwaGFzc2xjYTIwMjMuY3J0MDwGCCsGAQUFBzAB
hjBodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9nc2djY3I2YWxwaGFzc2xjYTIw
MjMwVwYDVR0gBFAwTjAIBgZngQwBAgEwQgYKKwYBBAGgMgoBAzA0MDIGCCsGAQUF
BwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzBEBgNV
HR8EPTA7MDmgN6A1hjNodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjZh
bHBoYXNzbGNhMjAyMy5jcmwwOQYDVR0RBDIwMIIXKi54bi0tbWVzcjVoZDFtYjdz
LnNob3CCFXhuLS1tZXNyNWhkMW1iN3Muc2hvcDAdBgNVHSUEFjAUBggrBgEFBQcD
AQYIKwYBBQUHAwIwHwYDVR0jBBgwFoAUvQW384qTPHPLefoPhRKhd5YYkXQwHQYD
VR0OBBYEFH6hEQR2OlYxgD/802rPMznQKvcvMIIBfwYKKwYBBAHWeQIEAgSCAW8E
ggFrAWkAdgCi4wrkRe+9rZt+OO1HZ3dT14JbhJTXK14bLMS5UKRH5wAAAY6DmB2L
AAAEAwBHMEUCIQCzO1yHSezspNS3qMygOfOumf9iYg/uRwTJNj3X4nH+iQIgBsST
848a/PWctU3ELpwGgCiZKBVwMRkUTwe3PuSEbgkAdwBOdaMnXJoQwzhbbNTfP1Lr
HfDgjhuNacCx+mSxYpo53wAAAY6DmB6tAAAEAwBIMEYCIQCU9a/OUPU5aas6KJ1I
T10/bqCtXMEnN1KSSjLh2YEtmQIhAMCUOqlRr0deP9UHG2xbrvKE+yW6lNrET8ae
YiiLG04aAHYA4JKz/AwdyOdoNh/eYbmWTQpSeBmKctZyxLBNpW1vVAQAAAGOg5gd
2gAABAMARzBFAiBKaytvRddIw/h3mW7g/Ias3WYUvUbobcvqbBVy1AYbygIhAOgi
WaI+afB9q8kyc1cv4eEHWpkbqBOgQg8n3o/7vmunMA0GCSqGSIb3DQEBCwUAA4IB
AQAcOwIIDTDIJ9c0kBFwNgXemCQCK3hfV5s0rVlmzZvOepJLGHTU/QDxOigGEmUt
KRDDb34zB81QQ5szwMURqhQJVStot2/Lh/KBl7QbqRdmRrg01leRWrS1+IWY4/cM
svuG3yx/Tt4v9tAIowioj0uxRsf9k3Smii8pZPIxE68FOt1JRLPSnaeP1mfVkope
5v5skLWSnIPusD1PdwSzsAEvB0B+pAcB+K106xKTFDdUNmEYuOWq/xS9gWFlx9J9
efsYuibWmk1ZM9VO8mOxzd9QmR5dvA6p2usRk9qO84O8CJsNmM0Q1ALQXqQNTfLh
Xc0wvnu+X1ip+xja+4OP7NLi
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFjDCCA3SgAwIBAgIQfx8skC6D0OO2+zvuR4tegDANBgkqhkiG9w0BAQsFADBM
MSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xv
YmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0yMzA3MTkwMzQzMjVaFw0y
NjA3MTkwMDAwMDBaMFUxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
IG52LXNhMSswKQYDVQQDEyJHbG9iYWxTaWduIEdDQyBSNiBBbHBoYVNTTCBDQSAy
MDIzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA00Jvk5ADppO0rgDn
j1M14XIb032Aas409JJFAb8cUjipFOth7ySLdaWLe3s63oSs5x3eWwzTpX4BFkzZ
bxT1eoJSHfT2M0wZ5QOPcCIjsr+YB8TAvV2yJSyq+emRrN/FtgCSTaWXSJ5jipW8
SJ/VAuXPMzuAP2yYpuPcjjQ5GyrssDXgu+FhtYxqyFP7BSvx9jQhh5QV5zhLycua
n8n+J0Uw09WRQK6JGQ5HzDZQinkNel+fZZNRG1gE9Qeh+tHBplrkalB1g85qJkPO
J7SoEvKsmDkajggk/sSq7NPyzFaa/VBGZiRRG+FkxCBniGD5618PQ4trcwHyMojS
FObOHQIDAQABo4IBXzCCAVswDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsG
AQUFBwMBBggrBgEFBQcDAjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBS9
BbfzipM8c8t5+g+FEqF3lhiRdDAfBgNVHSMEGDAWgBSubAWjkxPioufi1xzWx/B/
yGdToDB7BggrBgEFBQcBAQRvMG0wLgYIKwYBBQUHMAGGImh0dHA6Ly9vY3NwMi5n
bG9iYWxzaWduLmNvbS9yb290cjYwOwYIKwYBBQUHMAKGL2h0dHA6Ly9zZWN1cmUu
Z2xvYmFsc2lnbi5jb20vY2FjZXJ0L3Jvb3QtcjYuY3J0MDYGA1UdHwQvMC0wK6Ap
oCeGJWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vcm9vdC1yNi5jcmwwIQYDVR0g
BBowGDAIBgZngQwBAgEwDAYKKwYBBAGgMgoBAzANBgkqhkiG9w0BAQsFAAOCAgEA
fMkkMo5g4mn1ft4d4xR2kHzYpDukhC1XYPwfSZN3A9nEBadjdKZMH7iuS1vF8uSc
g26/30DRPen2fFRsr662ECyUCR4OfeiiGNdoQvcesM9Xpew3HLQP4qHg+s774hNL
vGRD4aKSKwFqLMrcqCw6tEAfX99tFWsD4jzbC6k8tjSLzEl0fTUlfkJaWpvLVkpg
9et8tD8d51bymCg5J6J6wcXpmsSGnksBobac1+nXmgB7jQC9edU8Z41FFo87BV3k
CtrWWsdkQavObMsXUPl/AO8y/jOuAWz0wyvPnKom+o6W4vKDY6/6XPypNdebOJ6m
jyaILp0quoQvhjx87BzENh5s57AIOyIGpS0sDEChVDPzLEfRsH2FJ8/W5woF0nvs
BTqfYSCqblQbHeDDtCj7Mlf8JfqaMuqcbE4rMSyfeHyCdZQwnc/r9ujnth691AJh
xyYeCM04metJIe7cB6d4dFm+Pd5ervY4x32r0uQ1Q0spy1VjNqUJjussYuXNyMmF
HSuLQQ6PrePmH5lcSMQpYKzPoD/RiNVD/PK0O3vuO5vh3o7oKb1FfzoanDsFFTrw
0aLOdRW/tmLPWVNVlAb8ad+B80YJsL4HXYnQG8wYAFb8LhwSDyT9v+C1C1lcIHE7
nE0AAp9JSHxDYsma9pi4g0Phg3BgOm2euTRzw7R0SzU=
-----END CERTIFICATE-----

EOF
cat > /usr/local/xrayr/private.key << EOF
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBA2C1mgozdHrXETI+1q3oyj5Vng2xuodjtZ1GBOMLPNoAoGCCqGSM49
AwEHoUQDQgAEdLs+DkPLMNYiMA48IE00aZ2aF8iPoKlEMOMBC8o4txZvXWuV6ZpB
thBxv6BTroKr3rQjL8Ib3wI162pgdI1t+A==
-----END EC PRIVATE KEY-----

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
	configure_dns
        configure_fail2ban
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
