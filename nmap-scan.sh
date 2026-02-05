#!/bin/bash

# ============================================================================
# 网络安全扫描脚本 - Network Security Scanner
# 功能: 全面扫描TCP/UDP端口，检测不安全服务和漏洞
# 作者: Security Team
# 版本: v2.0
# ============================================================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 全局变量
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE}")" && pwd)"
SCAN_DIR="${SCRIPT_DIR}/scan_results_$(date +%Y%m%d_%H%M%S)"
TARGET=""
SCAN_TYPE="full"
THREADS=100
TIMEOUT=30

# 常见不安全端口定义
UNSAFE_TCP_PORTS="21,22,23,25,53,69,79,80,110,111,135,139,143,161,389,443,445,512,513,514,515,993,995,1433,1521,2049,3306,3389,5432,5900,6000,8080,8443"
UNSAFE_UDP_PORTS="53,69,111,123,135,137,138,161,162,445,500,514,520,1900,4500,5353"

# 显示帮助信息
show_help() {
    cat << EOF
${CYAN}网络安全扫描工具${NC}

用法: \$0 [选项] <目标>

${YELLOW}选项:${NC}
    -h, --help          显示帮助信息
    -t, --target        扫描目标 (IP地址或域名或网段)
    -s, --scan-type     扫描类型 [quick|full|vuln|custom]
    -p, --ports         自定义端口范围 (如: 1-1000 或 80,443,8080)
    -T, --threads       线程数 (默认: 100)
    -o, --output        输出目录 (默认: ./scan_results_timestamp)
    --tcp-only          仅扫描TCP端口
    --udp-only          仅扫描UDP端口
    --no-ping           跳过主机发现
    --stealth           隐蔽扫描模式

${YELLOW}扫描类型:${NC}
    quick    - 快速扫描常用端口
    full     - 全面扫描所有端口 (默认)
    vuln     - 漏洞扫描
    custom   - 自定义端口扫描

${YELLOW}示例:${NC}
    \$0 -t 192.168.1.1                    # 全面扫描单个主机
    \$0 -t 192.168.1.0/24 -s quick        # 快速扫描网段
    \$0 -t example.com -s vuln            # 漏洞扫描
    \$0 -t 10.0.0.1 --tcp-only            # 仅TCP扫描
    \$0 -t 192.168.1.1 -p 1-1000          # 自定义端口范围

EOF
}

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - \$1" | tee -a "${SCAN_DIR}/scan.log"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - \$1" | tee -a "${SCAN_DIR}/scan.log"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - \$1" | tee -a "${SCAN_DIR}/scan.log"
}

log_critical() {
    echo -e "${RED}[CRITICAL]${NC} $(date '+%Y-%m-%d %H:%M:%S') - \$1" | tee -a "${SCAN_DIR}/scan.log"
}

# 检查依赖
check_dependencies() {
    local deps=("nmap" "netstat" "ss")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        log_error "缺少依赖: ${missing[*]}"
        echo "请安装缺少的依赖:"
        echo "Ubuntu/Debian: sudo apt-get install nmap net-tools iproute2"
        echo "CentOS/RHEL: sudo yum install nmap net-tools iproute"
        exit 1
    fi
}

# 创建输出目录
setup_output_dir() {
    mkdir -p "$SCAN_DIR"
    log_info "扫描结果将保存到: $SCAN_DIR"
}

# 主机发现
host_discovery() {
    local target="\$1"
    log_info "开始主机发现: $target"
    
    nmap -sn "$target" -oN "${SCAN_DIR}/host_discovery.txt" -oX "${SCAN_DIR}/host_discovery.xml" 2>/dev/null
    
    # 提取活跃主机
    grep "Nmap scan report for" "${SCAN_DIR}/host_discovery.txt" | awk '{print \$5}' > "${SCAN_DIR}/live_hosts.txt"
    
    local host_count=$(wc -l < "${SCAN_DIR}/live_hosts.txt")
    log_info "发现 $host_count 个活跃主机"
}

# TCP端口扫描
tcp_port_scan() {
    local target="\$1"
    local ports="\$2"
    local scan_name="\$3"
    
    log_info "开始TCP端口扫描: $target (端口: $ports)"
    
    # SYN扫描
    nmap -sS -p "$ports" "$target" \
        --max-retries 2 \
        --host-timeout "${TIMEOUT}m" \
        --max-parallelism "$THREADS" \
        -oN "${SCAN_DIR}/tcp_${scan_name}.txt" \
        -oX "${SCAN_DIR}/tcp_${scan_name}.xml" \
        -oG "${SCAN_DIR}/tcp_${scan_name}.grep" 2>/dev/null
    
    # 提取开放端口
    grep "open" "${SCAN_DIR}/tcp_${scan_name}.txt" | grep -E "^[0-9]+" > "${SCAN_DIR}/tcp_open_ports_${scan_name}.txt"
}

# UDP端口扫描
udp_port_scan() {
    local target="\$1"
    local ports="\$2"
    local scan_name="\$3"
    
    log_info "开始UDP端口扫描: $target (端口: $ports)"
    
    # UDP扫描 (较慢，使用较少线程)
    nmap -sU -p "$ports" "$target" \
        --max-retries 1 \
        --host-timeout "${TIMEOUT}m" \
        --max-parallelism $((THREADS/4)) \
        -oN "${SCAN_DIR}/udp_${scan_name}.txt" \
        -oX "${SCAN_DIR}/udp_${scan_name}.xml" \
        -oG "${SCAN_DIR}/udp_${scan_name}.grep" 2>/dev/null
    
    # 提取开放端口
    grep -E "(open|open\|filtered)" "${SCAN_DIR}/udp_${scan_name}.txt" | grep -E "^[0-9]+" > "${SCAN_DIR}/udp_open_ports_${scan_name}.txt"
}

# 服务版本检测
service_detection() {
    local target="\$1"
    log_info "开始服务版本检测: $target"
    
    # 从之前的扫描结果中获取开放端口
    local tcp_ports=""
    local udp_ports=""
    
    if [ -f "${SCAN_DIR}/tcp_open_ports_scan.txt" ]; then
        tcp_ports=$(awk '{print \$1}' "${SCAN_DIR}/tcp_open_ports_scan.txt" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
    fi
    
    if [ -f "${SCAN_DIR}/udp_open_ports_scan.txt" ]; then
        udp_ports=$(awk '{print \$1}' "${SCAN_DIR}/udp_open_ports_scan.txt" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
    fi
    
    # TCP服务检测
    if [ -n "$tcp_ports" ]; then
        nmap -sV -sC -p "$tcp_ports" "$target" \
            --version-all \
            -oN "${SCAN_DIR}/service_detection_tcp.txt" \
            -oX "${SCAN_DIR}/service_detection_tcp.xml" 2>/dev/null
    fi
    
    # UDP服务检测
    if [ -n "$udp_ports" ]; then
        nmap -sUV -p "$udp_ports" "$target" \
            --version-all \
            -oN "${SCAN_DIR}/service_detection_udp.txt" \
            -oX "${SCAN_DIR}/service_detection_udp.xml" 2>/dev/null
    fi
}

# 漏洞扫描
vulnerability_scan() {
    local target="\$1"
    log_info "开始漏洞扫描: $target"
    
    # 通用漏洞扫描
    nmap --script vuln "$target" \
        --script-timeout 10m \
        -oN "${SCAN_DIR}/vulnerability_scan.txt" \
        -oX "${SCAN_DIR}/vulnerability_scan.xml" 2>/dev/null
    
    # SSL/TLS漏洞扫描
    nmap --script ssl-enum-ciphers,ssl-cert,ssl-date,ssl-heartbleed,ssl-poodle,ssl-ccs-injection "$target" \
        -p 443,993,995,8443 \
        -oN "${SCAN_DIR}/ssl_vulnerabilities.txt" 2>/dev/null
    
    # Web应用漏洞扫描
    nmap --script http-enum,http-vuln-*,http-slowloris-check "$target" \
        -p 80,443,8080,8443,8000,8888 \
        -oN "${SCAN_DIR}/web_vulnerabilities.txt" 2>/dev/null
    
    # 数据库漏洞扫描
    nmap --script mysql-*,mssql-*,oracle-*,postgresql-* "$target" \
        -p 1433,1521,3306,5432 \
        -oN "${SCAN_DIR}/database_vulnerabilities.txt" 2>/dev/null
    
    # SMB漏洞扫描
    nmap --script smb-vuln-*,smb-os-discovery,smb-security-mode "$target" \
        -p 139,445 \
        -oN "${SCAN_DIR}/smb_vulnerabilities.txt" 2>/dev/null
}

# 不安全服务检测
unsafe_service_scan() {
    local target="\$1"
    log_info "开始不安全服务检测: $target"
    
    # FTP匿名登录
    nmap --script ftp-anon,ftp-bounce "$target" -p 21 \
        -oN "${SCAN_DIR}/ftp_security.txt" 2>/dev/null
    
    # Telnet检测
    nmap --script telnet-encryption "$target" -p 23 \
        -oN "${SCAN_DIR}/telnet_security.txt" 2>/dev/null
    
    # SSH安全检测
    nmap --script ssh-hostkey,ssh-auth-methods "$target" -p 22 \
        -oN "${SCAN_DIR}/ssh_security.txt" 2>/dev/null
    
    # SNMP检测
    nmap --script snmp-info,snmp-brute "$target" -p 161 \
        -oN "${SCAN_DIR}/snmp_security.txt" 2>/dev/null
    
    # RDP检测
    nmap --script rdp-enum-encryption,rdp-vuln-ms12-020 "$target" -p 3389 \
        -oN "${SCAN_DIR}/rdp_security.txt" 2>/dev/null
}

# 本地端口检测
local_port_scan() {
    log_info "扫描本地监听端口"
    
    # 使用netstat检测本地端口
    if command -v netstat &> /dev/null; then
        netstat -tuln > "${SCAN_DIR}/local_netstat.txt"
    fi
    
    # 使用ss检测本地端口
    if command -v ss &> /dev/null; then
        ss -tuln > "${SCAN_DIR}/local_ss.txt"
    fi
    
    # 分析本地监听端口
    cat > "${SCAN_DIR}/analyze_local_ports.py" << 'EOF'
#!/usr/bin/env python3
import re
import sys

def analyze_ports(filename):
    unsafe_ports = {
        21: 'FTP - 明文传输',
        23: 'Telnet - 明文传输',
        25: 'SMTP - 可能未加密',
        53: 'DNS - 可能被利用进行DDoS',
        69: 'TFTP - 无认证',
        79: 'Finger - 信息泄露',
        135: 'RPC - Windows服务',
        139: 'NetBIOS - 信息泄露',
        161: 'SNMP - 弱认证',
        445: 'SMB - 多个漏洞',
        512: 'rexec - 无加密',
        513: 'rlogin - 无加密',
        514: 'rsh - 无加密',
        1433: 'SQL Server - 数据库',
        1521: 'Oracle - 数据库',
        2049: 'NFS - 文件共享',
        3306: 'MySQL - 数据库',
        3389: 'RDP - 远程桌面',
        5432: 'PostgreSQL - 数据库',
        5900: 'VNC - 远程桌面'
    }
    
    try:
        with open(filename, 'r') as f:
            content = f.read()
            
        # 提取端口信息
        ports = re.findall(r':(\d+)\s', content)
        
        print("发现的潜在不安全端口:")
        for port in set(ports):
            port_num = int(port)
            if port_num in unsafe_ports:
                print(f"  端口 {port}: {unsafe_ports[port_num]}")
                
    except FileNotFoundError:
        print(f"文件 {filename} 不存在")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        analyze_ports(sys.argv)
EOF
    
    python3 "${SCAN_DIR}/analyze_local_ports.py" "${SCAN_DIR}/local_netstat.txt" > "${SCAN_DIR}/local_unsafe_analysis.txt"
}

# 生成报告
generate_report() {
    local target="\$1"
    log_info "生成扫描报告"
    
    cat > "${SCAN_DIR}/security_report.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>网络安全扫描报告</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .critical { background-color: #ffebee; border-color: #f44336; }
        .warning { background-color: #fff3e0; border-color: #ff9800; }
        .info { background-color: #e3f2fd; border-color: #2196f3; }
        pre { background-color: #f5f5f5; padding: 10px; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>网络安全扫描报告</h1>
        <p><strong>扫描目标:</strong> $target</p>
        <p><strong>扫描时间:</strong> $(date)</p>
        <p><strong>报告生成:</strong> $(hostname)</p>
    </div>
EOF

    # 添加TCP端口扫描结果
    if [ -f "${SCAN_DIR}/tcp_scan.txt" ]; then
        echo '<div class="section info"><h2>TCP端口扫描结果</h2><pre>' >> "${SCAN_DIR}/security_report.html"
        grep "open" "${SCAN_DIR}/tcp_scan.txt" >> "${SCAN_DIR}/security_report.html"
        echo '</pre></div>' >> "${SCAN_DIR}/security_report.html"
    fi
    
    # 添加UDP端口扫描结果
    if [ -f "${SCAN_DIR}/udp_scan.txt" ]; then
        echo '<div class="section info"><h2>UDP端口扫描结果</h2><pre>' >> "${SCAN_DIR}/security_report.html"
        grep -E "(open|open\|filtered)" "${SCAN_DIR}/udp_scan.txt" >> "${SCAN_DIR}/security_report.html"
        echo '</pre></div>' >> "${SCAN_DIR}/security_report.html"
    fi
    
    # 添加漏洞扫描结果
    if [ -f "${SCAN_DIR}/vulnerability_scan.txt" ]; then
        echo '<div class="section critical"><h2>漏洞扫描结果</h2><pre>' >> "${SCAN_DIR}/security_report.html"
        cat "${SCAN_DIR}/vulnerability_scan.txt" >> "${SCAN_DIR}/security_report.html"
        echo '</pre></div>' >> "${SCAN_DIR}/security_report.html"
    fi
    
    # 添加不安全服务
    echo '<div class="section warning"><h2>潜在不安全服务</h2>' >> "${SCAN_DIR}/security_report.html"
    for file in "${SCAN_DIR}"/*_security.txt; do
        if [ -f "$file" ]; then
            echo "<h3>$(basename "$file" .txt)</h3><pre>" >> "${SCAN_DIR}/security_report.html"
            cat "$file" >> "${SCAN_DIR}/security_report.html"
            echo '</pre>' >> "${SCAN_DIR}/security_report.html"
        fi
    done
    echo '</div>' >> "${SCAN_DIR}/security_report.html"
    
    echo '</body></html>' >> "${SCAN_DIR}/security_report.html"
    
    # 生成文本摘要报告
    cat > "${SCAN_DIR}/summary_report.txt" << EOF
================================================================================
                           网络安全扫描摘要报告
================================================================================
扫描目标: $target
扫描时间: $(date)
扫描类型: $SCAN_TYPE

EOF

    # 统计开放端口
    local tcp_count=0
    local udp_count=0
    
    if [ -f "${SCAN_DIR}/tcp_open_ports_scan.txt" ]; then
        tcp_count=$(wc -l < "${SCAN_DIR}/tcp_open_ports_scan.txt")
    fi
    
    if [ -f "${SCAN_DIR}/udp_open_ports_scan.txt" ]; then
        udp_count=$(wc -l < "${SCAN_DIR}/udp_open_ports_scan.txt")
    fi
    
    cat >> "${SCAN_DIR}/summary_report.txt" << EOF
端口扫描结果:
- TCP开放端口: $tcp_count
- UDP开放端口: $udp_count

主要发现:
EOF

    # 分析关键发现
    if [ -f "${SCAN_DIR}/vulnerability_scan.txt" ]; then
        local vuln_count=$(grep -c "VULNERABLE" "${SCAN_DIR}/vulnerability_scan.txt" 2>/dev/null || echo "0")
        echo "- 发现漏洞: $vuln_count" >> "${SCAN_DIR}/summary_report.txt"
    fi
    
    echo "" >> "${SCAN_DIR}/summary_report.txt"
    echo "详细报告文件:" >> "${SCAN_DIR}/summary_report.txt"
    ls -la "${SCAN_DIR}"/*.txt "${SCAN_DIR}"/*.xml 2>/dev/null >> "${SCAN_DIR}/summary_report.txt"
}

# 主扫描函数
run_scan() {
    local target="\$1"
    
    case "$SCAN_TYPE" in
        "quick")
            log_info "执行快速扫描模式"
            tcp_port_scan "$target" "$UNSAFE_TCP_PORTS" "scan"
            udp_port_scan "$target" "$UNSAFE_UDP_PORTS" "scan"
            unsafe_service_scan "$target"
            ;;
        "full")
            log_info "执行全面扫描模式"
            tcp_port_scan "$target" "1-65535" "scan"
            udp_port_scan "$target" "1-1000" "scan"
            service_detection "$target"
            vulnerability_scan "$target"
            unsafe_service_scan "$target"
            ;;
        "vuln")
            log_info "执行漏洞扫描模式"
            tcp_port_scan "$target" "$UNSAFE_TCP_PORTS" "scan"
            vulnerability_scan "$target"
            unsafe_service_scan "$target"
            ;;
        "custom")
            log_info "执行自定义扫描模式"
            if [ -n "$CUSTOM_PORTS" ]; then
                tcp_port_scan "$target" "$CUSTOM_PORTS" "scan"
                udp_port_scan "$target" "$CUSTOM_PORTS" "scan"
            else
                log_error "自定义扫描需要指定端口范围"
                exit 1
            fi
            ;;
    esac
    
    # 如果是本地扫描，添加本地端口检测
    if [[ "$target" == "localhost" || "$target" == "127.0.0.1" || "$target" == "$(hostname -I | awk '{print \$1}')" ]]; then
        local_port_scan
    fi
}

# 参数解析
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case \$1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -t|--target)
                TARGET="\$2"
                shift 2
                ;;
            -s|--scan-type)
                SCAN_TYPE="\$2"
                shift 2
                ;;
            -p|--ports)
                CUSTOM_PORTS="\$2"
                shift 2
                ;;
            -T|--threads)
                THREADS="\$2"
                shift 2
                ;;
            -o|--output)
                SCAN_DIR="\$2"
                shift 2
                ;;
            --tcp-only)
                TCP_ONLY=true
                shift
                ;;
            --udp-only)
                UDP_ONLY=true
                shift
                ;;
            --no-ping)
                NO_PING=true
                shift
                ;;
            --stealth)
                STEALTH=true
                shift
                ;;
            *)
                if [ -z "$TARGET" ]; then
                    TARGET="\$1"
                else
                    log_error "未知参数: \$1"
                    show_help
                    exit 1
                fi
                shift
                ;;
        esac
    done
}

# 主函数
main() {
    echo -e "${CYAN}"
    cat << "EOF"
    ███╗   ██╗███████╗████████╗███████╗███████╗ ██████╗
    ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔════╝
    ██╔██╗ ██║█████╗     ██║   ███████╗█████╗  ██║     
    ██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██║     
    ██║ ╚████║███████╗   ██║   ███████║███████╗╚██████╗
    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝ ╚═════╝
                    Network Security Scanner v2.0
EOF
    echo -e "${NC}"
    
    # 检查是否以root权限运行
    if [[ $EUID -ne 0 ]]; then
        log_warn "建议以root权限运行以获得最佳扫描效果"
    fi
    
    # 解析参数
    parse_arguments "$@"
    
    # 检查必要参数
    if [ -z "$TARGET" ]; then
        log_error "请指定扫描目标"
        show_help
        exit 1
    fi
    
    # 检查依赖
    check_dependencies
    
    # 设置输出目录
    setup_output_dir
    
    # 开始扫描
    log_info "开始安全扫描: $TARGET"
    log_info "扫描类型: $SCAN_TYPE"
    log_info "线程数: $THREADS"
    
    # 主机发现
    if [ "$NO_PING" != true ]; then
        host_discovery "$TARGET"
    fi
    
    # 执行扫描
    run_scan "$TARGET"
    
    # 生成报告
    generate_report "$TARGET"
    
    # 扫描完成
    log_info "扫描完成!"
    echo -e "${GREEN}扫描结果保存在: $SCAN_DIR${NC}"
    echo -e "${YELLOW}主要报告文件:${NC}"
    echo "  - 摘要报告: $SCAN_DIR/summary_report.txt"
    echo "  - HTML报告: $SCAN_DIR/security_report.html"
    echo "  - 详细日志: $SCAN_DIR/scan.log"
    
    # 显示关键发现
    if [ -f "${SCAN_DIR}/tcp_open_ports_scan.txt" ] && [ -s "${SCAN_DIR}/tcp_open_ports_scan.txt" ]; then
        echo -e "${RED}发现开放的TCP端口:${NC}"
        head -10 "${SCAN_DIR}/tcp_open_ports_scan.txt"
    fi
    
    if [ -f "${SCAN_DIR}/udp_open_ports_scan.txt" ] && [ -s "${SCAN_DIR}/udp_open_ports_scan.txt" ]; then
        echo -e "${RED}发现开放的UDP端口:${NC}"
        head -10 "${SCAN_DIR}/udp_open_ports_scan.txt"
    fi
}

# 信号处理
trap 'log_warn "扫描被中断"; exit 1' INT TERM

# 执行主函数
main "$@"