#!/usr/bin/env bash
#
# 一键脚本（优化版）
# version=v1.2
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# 检查 root 权限
[ $(id -u) != "0" ] && { echo "错误: 您必须以 root 用户运行此脚本"; exit 1; }

rm -rf all
rm -rf $0
mkdir -p -m 777 /usr/local/xrayr

# 设置字体颜色函数
function blue(){ echo -e "\033[34m\033[01m $1 \033[0m"; }
function green(){ echo -e "\033[32m\033[01m $1 \033[0m"; }
function yellow(){ echo -e "\033[33m\033[01m $1 \033[0m"; }
function red(){ echo -e "\033[31m\033[01m $1 \033[0m"; }
function white(){ echo -e "\033[37m\033[01m $1 \033[0m"; }

# 安装 Docker
install_docker() {
    docker version > /dev/null || curl -fsSL get.docker.com | bash 
    systemctl restart docker 
    systemctl enable docker  
    echo "30 4 * * * systemctl restart docker >/dev/null 2>&1" > /var/spool/cron/root
    sysctl -w vm.panic_on_oom=1
}

# 检测 Docker 是否安装
check_docker() {
    if [ -x "$(command -v docker)" ]; then
        blue "Docker 已安装"
    else
        echo "正在安装 Docker..."
        install_docker
    fi
}

# 工具安装
install_tool() {
    echo "===> 开始安装必要工具"    
    if [ -x "$(command -v yum)" ]; then
        command -v curl > /dev/null || yum install -y curl
    elif [ -x "$(command -v apt)" ]; then
        command -v curl > /dev/null || apt install -y curl
    else
        echo "不支持的系统，仅支持 yum/apt 包管理器"
        exit 1
    fi 
}

# 写入 XrayR 配置文件
xrayr_file(){
    cat > /usr/local/xrayr/config.yml << EOF
Log:
  Level: none
  AccessPath: # /etc/XrayR/access.log
  ErrorPath: # /etc/XrayR/error.log

ConnetionConfig:
  Handshake: 5 # 调整握手时间，降低连接失败率
  ConnIdle: 300 # 降低空闲时间，减少 GFW 识别风险
  UplinkOnly: 30
  DownlinkOnly: 60
  BufferSize: 128

Nodes:
  -
    PanelType: "SSpanel"
    ApiConfig:
      ApiHost: "https://qwword.xyz"
      ApiKey: "vicutu123"
      NodeID: \$node_id
      NodeType: Trojan
      Timeout: 30
      EnableVless: false
      EnableXTLS: false
      SpeedLimit: 0
      DeviceLimit: 0
    ControllerConfig:
      ListenIP: 0.0.0.0
      ListenPort: 443, 8443, 2087 # 监听多个端口，防止单点封锁
      UpdatePeriodic: 60
      EnableFallback: true
      FallBackConfigs:
        - Dest: 80
      EnableWebSocket: true
      WebSocketPath: "/chat"
      WebSocketHost: "your-domain.com"
      EnableUTLS: true
      Fingerprint: chrome
      CertConfig:
        CertMode: file
        CertDomain: "your-domain.com"
        CertFile: /etc/XrayR/fullchain.pem
        KeyFile: /etc/XrayR/privkey.pem
EOF
}

# 写入证书文件
crt_file(){
    cat > /usr/local/xrayr/fullchain.pem << EOF
-----BEGIN CERTIFICATE-----
（你的完整证书内容）
-----END CERTIFICATE-----
EOF

    cat > /usr/local/xrayr/privkey.pem << EOF
-----BEGIN PRIVATE KEY-----
（你的私钥内容）
-----END PRIVATE KEY-----
EOF
}

# 开始安装并部署 XrayR
backend_docking_set(){
    green "正在配置 WebAPI 对接..."
    read -p "请输入节点 ID:" node_id
    yellow "配置完成，开始部署..."
    install_tool
    check_docker
    xrayr_file
    crt_file
    docker run --restart=always --name xrayr -d -v /usr/local/xrayr/config.yml:/etc/XrayR/config.yml -v /usr/local/xrayr/fullchain.pem:/etc/XrayR/fullchain.pem -v /usr/local/xrayr/privkey.pem:/etc/XrayR/privkey.pem --network=host crackair/xrayr:latest
    green "XrayR 部署完成！"
}

# 开始菜单
start_menu(){
    clear
    green "=================================================="
    green "SSPanel 后端对接 v1.2"
    green "支持系统：CentOS7+ / Ubuntu / Debian"
    green "=================================================="
    echo
    green "1. 安装 XrayR 并对接 SSPanel"
    green "2. 启用 BBRPlus 加速"
    green "3. 清理旧 Docker 和配置文件"
    green "4. 安装 aaPanel（宝塔）"
    green "5. 禁用 IPv6"
    blue "0. 退出"
    echo
    read -p "请输入选项 [0-5]: " num
    case "$num" in
    1) backend_docking_set;;
    2) wget -O tcp.sh "https://github.com/cx9208/Linux-NetSpeed/raw/master/tcp.sh" && chmod +x tcp.sh && ./tcp.sh;;
    3) docker rm -f xrayr && systemctl restart docker && rm -rf /usr/local/xrayr/;;
    4) yum install -y wget && wget -O install.sh http://www.aapanel.com/script/install_6.0_en.sh && bash install.sh;;
    5) sysctl -w net.ipv6.conf.all.disable_ipv6=1;;
    0) exit 1;;
    *) echo "无效选项，请重新输入！"; sleep 2; start_menu;;
    esac
}

start_menu
