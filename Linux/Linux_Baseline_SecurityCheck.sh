#!/bin/bash
# Linux基线安全检查脚本
set -o nounset   # 使用未定义变量时报错
set -o pipefail  # 管道中任一命令失败则整体失败

readonly TIMESTAMP=$(date +"%Z.%m月.%d日.%A")
readonly REPORT_DIR="/var/legendsec" && mkdir -p "$REPORT_DIR"
readonly IP_ADDR=$(ip addr show | awk '/inet / && $2!~/127.0.0.1/{sub(/\/.*/,"",$2);print $2;exit}')
readonly REPORT_FILE="${REPORT_DIR}/report.${IP_ADDR:-unknown}.${TIMESTAMP}"

# ---------- 通用结果输出函数（简化核心） ----------
# 用法：_result "合格|不合格|待确认" "检查项名" "描述"
_result() {
    local level=$1 name=$2 msg=$3
    case "$level" in
        合格)   echo "[合格]   ${name} — ${msg}" >> "$REPORT_FILE" ;;
        不合格) echo "[不合格] ${name} — ${msg}" >> "$REPORT_FILE" ;;
        待确认) echo "[待确认] ${name} — ${msg}" >> "$REPORT_FILE" ;;
    esac
}

{
echo "===== Linux基线安全检查报告 ====="
echo "评估时间：$(date '+%F %T')"
echo "检查主机IP：${IP_ADDR:-获取失败}"
echo "=============================="
} > "$REPORT_FILE"

# ---------- 1. 账号安全 ----------
echo -e "\n### 一、账号安全基线检查 ###" >> "$REPORT_FILE"

empty=$(awk -F: '$2==""{print $1}' /etc/shadow 2>/dev/null)
[ -z "$empty" ] && _result 合格 "空口令账号" "未发现空口令账号" || _result 不合格 "空口令账号" "存在: $empty"

uid0=$(awk -F: '$3==0{print $1}' /etc/passwd)
[ "$uid0" = "root" ] && _result 合格 "UID=0账号" "仅root" || _result 不合格 "UID=0账号" "非root也UID=0: $(echo $uid0|tr '\n' ' ')"

shared=$(awk -F: '$1~/^(admin|test|temp)$/' /etc/passwd)
[ -z "$shared" ] && _result 合格 "共享账号" "未发现特征账号" || _result 待确认 "共享账号" "疑似: $(echo $shared|cut -d: -f1)"

grep -qE "pam_tally2.so|pam_faillock.so" /etc/pam.d/system-auth 2>/dev/null && _result 合格 "账号锁定策略" "已配置PAM锁定" || _result 不合格 "账号锁定策略" "未配置，存在暴破风险"

risk_files=$(find /etc/hosts.equiv 2>/dev/null; getent passwd | cut -d: -f6 | sort -u | while read h; do find "$h" -maxdepth 1 -name ".rhosts" -o -name ".netrc" 2>/dev/null; done)
[ -z "$risk_files" ] && _result 合格 "rhosts/netrc" "未发现hosts.equiv/.rhosts/.netrc" || _result 不合格 "rhosts/netrc" "存在信任文件，需清理: $(echo $risk_files | tr '\n' ' ')"

unlocked=$(awk -F: '$2!~/^(\!|\*)/ && $2!="" && $1!~/^(root|halt|sync|shutdown)/{print $1}' /etc/shadow 2>/dev/null)
[ -z "$unlocked" ] && _result 合格 "账号锁定状态" "无长期未锁定可登录账号" || _result 待确认 "账号锁定状态" "可登录账号: $unlocked，请确认是否应锁定"

# ---------- 2. 口令策略 ----------
echo -e "\n### 二、口令策略基线检查 ###" >> "$REPORT_FILE"

_get_login_defs() { grep "^$1" /etc/login.defs | awk '{print $2}' | head -1; }

maxd=$(_get_login_defs PASS_MAX_DAYS)
[[ "$maxd" =~ ^[0-9]+$ ]] && [ "$maxd" -le 90 ] && [ "$maxd" -gt 0 ] && _result 合格 "口令最长生存期" "${maxd}天" || _result 不合格 "口令最长生存期" "${maxd:-未设置}天，应≤90"

mind=$(_get_login_defs PASS_MIN_LEN)
[[ "$mind" =~ ^[0-9]+$ ]] && [ "$mind" -ge 8 ] && _result 合格 "口令最小长度" "${mind}位" || _result 不合格 "口令最小长度" "${mind:-未设置}位，应≥8"

grep -qE "pam_cracklib.so|pam_pwquality.so" /etc/pam.d/system-auth 2>/dev/null && _result 合格 "口令复杂度" "PAM已配置" || _result 不合格 "口令复杂度" "未配置，存在弱口令风险"

# ---------- 3. 访问控制 ----------
echo -e "\n### 三、访问控制基线检查 ###" >> "$REPORT_FILE"

_sshd() { grep -E "^$1\s" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | tail -1; }

[ "$(_sshd PermitRootLogin)" = "no" ] && _result 合格 "Root远程登录" "已禁止" || _result 不合格 "Root远程登录" "PermitRootLogin=$(_sshd PermitRootLogin)，应no"

[ "$(_sshd PermitEmptyPasswords)" = "no" ] && _result 合格 "空密码登录" "已禁止" || _result 待确认 "空密码登录" "PermitEmptyPasswords未显式no"

[ "$(_sshd MaxAuthTries)" -le 6 ] 2>/dev/null && _result 合格 "SSH最大重试" "$(_sshd MaxAuthTries)" || _result 待确认 "SSH最大重试" "建议≤6，当前: $(_sshd MaxAuthTries)"

[[ "$(umask)" =~ ^(0022|0027)$ ]] && _result 合格 "缺省umask" "$(umask)" || _result 不合格 "缺省umask" "$(umask)，应022/027"

systemctl is-enabled ctrl-alt-del.target 2>/dev/null | grep -q "disabled\|masked" && _result 合格 "Ctrl+Alt+Del" "已禁用" || _result 不合格 "Ctrl+Alt+Del" "未禁用"

grep -q HISTTIMEFORMAT /etc/profile /etc/bashrc 2>/dev/null && _result 合格 "History时间戳" "已配置" || _result 不合格 "History时间戳" "未配置"

[ -f /etc/securetty ] && _result 合格 "/etc/securetty" "存在，限制root登录终端" || _result 待确认 "/etc/securetty" "缺失，root可从任意tty登录"

# ---------- 4. 内核安全 ----------
echo -e "\n### 四、内核安全基线检查 ###" >> "$REPORT_FILE"

_sys() { cat /proc/sys/$1 2>/dev/null; }

[ "$(_sys net/ipv4/conf/all/accept_redirects)" -eq 0 ] && _result 合格 "ICMP重定向" "已禁用" || _result 不合格 "ICMP重定向" "未禁用"

[ "$(_sys net/ipv4/tcp_syncookies)" -eq 1 ] && _result 合格 "SYN Cookies" "已启用" || _result 不合格 "SYN Cookies" "未启用"

[ "$(_sys net/ipv4/conf/all/accept_source_route)" -eq 0 ] && _result 合格 "源路由" "已禁用" || _result 不合格 "源路由" "未禁用"

[ "$(_sys net/ipv4/ip_forward)" -eq 0 ] && _result 合格 "IP转发" "已禁用(非路由设备)" || _result 待确认 "IP转发" "已启用，如非路由设备建议关"

[ "$(_sys net/ipv4/conf/all/rp_filter)" -eq 1 ] && _result 合格 "反向路径过滤" "已启用" || _result 待确认 "反向路径过滤" "未启用，建议开"

# ---------- 5. 服务与端口 ----------
echo -e "\n### 五、服务与端口基线检查 ###" >> "$REPORT_FILE"

server=(telnet vsftpd nfs-server rpcbind ypserv)

for svc in ${server[*]};do systemctl is-active --quiet ${svc}.service 2>/dev/null && _result 不合格 "服务-${svc}" "运行中" || _result 合格 "服务-${svc}" "未运行";done

# ---------- 6. 日志审计 ----------
echo -e "\n### 六、日志审计基线检查 ###" >> "$REPORT_FILE"

[ -f /var/log/secure ] && _result 合格 "安全日志" "/var/log/secure存在" || _result 不合格 "安全日志" "缺失"

grep -qE "@@|@" /etc/rsyslog.conf 2>/dev/null && _result 合格 "远程日志" "已配置" || _result 待确认 "远程日志" "未配置，建议集中存储"

systemctl is-active --quiet auditd 2>/dev/null && _result 合格 "auditd审计" "运行中" || _result 待确认 "auditd审计" "未运行，建议开启"

# ---------- 7. 补丁与文件系统 ----------
echo -e "\n### 七、补丁与文件系统基线检查 ###" >> "$REPORT_FILE"

cnt=$((command -v yum>/dev/null&&yum check-update --security -q 2>/dev/null|wc -l)||(command -v apt>/dev/null&&apt list --upgradable 2>/dev/null|grep -ci security)||echo "?")
case "$cnt" in 0)_result 合格 "安全补丁" "已最新";;"?")_result 待确认 "安全补丁" "无法判断包管理器";;*)_result 待确认 "安全补丁" "约${cnt}个安全更新待装";;esac

grep -qE "nosuid|noexec|nodev" /etc/fstab && _result 合格 "tmp/shm挂载" "已加限制选项" || _result 不合格 "tmp/shm挂载" "未限制，建议nosuid,noexec"

suid=$(find /usr -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l) && _result 待确认 "SUID/SGID文件" "共${suid}个，建议人工复核/usr下特权文件"

ww=$(find /etc /var /usr -type f -perm -0002 2>/dev/null | grep -v '/proc' | head -5)
[ -z "$ww" ] && _result 合格 "全局可写文件" "未发现" || _result 待确认 "全局可写文件" "示例: $(echo $ww|tr '\n' ' ')... 建议复核"

# ---------- 8. 网络安全 ----------
echo -e "\n### 八、网络安全基线检查 ###" >> "$REPORT_FILE"

if command -v firewall-cmd &>/dev/null; then
    fw_state=$(firewall-cmd --state 2>/dev/null)
    [ "$fw_state" = "running" ] && _result 合格 "Firewalld" "运行中" || _result 不合格 "Firewalld" "未运行"
elif command -v ufw &>/dev/null; then
    ufw status | grep -qi active && _result 合格 "UFW" "运行中" || _result 不合格 "UFW" "未运行"
elif command -v iptables &>/dev/null; then
    iptables -L -n 2>/dev/null | grep -q "Chain INPUT" && _result 合格 "iptables" "规则存在" || _result 不合格 "iptables" "无规则"
else
    _result 待确认 "防火墙" "无法检测防火墙状态"
fi

if command -v getenforce &>/dev/null; then
    se_status=$(getenforce 2>/dev/null)
    [ "$se_status" = "Enforcing" ] && _result 合格 "SELinux" "强制模式" || _result 不合格 "SELinux" "当前模式: ${se_status:-未知}，建议 Enforcing"
else
    _result 待确认 "SELinux" "未安装或不可用"
fi

ssh_proto=$(grep -E "^Protocol\s+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
[ "$ssh_proto" = "2" ] && _result 合格 "SSH协议版本" "仅允许SSHv2" || _result 不合格 "SSH协议版本" "Protocol=${ssh_proto:-未设置}，建议仅允许2"

weak_ciphers=$(grep -i "Ciphers" /etc/ssh/sshd_config 2>/dev/null | grep -iE "aes128-cbc|3des-cbc|blowfish-cbc" || true)
[ -z "$weak_ciphers" ] && _result 合格 "SSH加密算法" "未使用弱算法" || _result 不合格 "SSH加密算法" "使用了弱算法: $weak_ciphers"

danger_ports=$(ss -tlnp 2>/dev/null | awk '{print $4}' | grep -E ":23$|:111$|:2049$|:512$|:513$|:514$" | head -5)
[ -z "$danger_ports" ] && _result 合格 "高危端口" "未发现 telnet/rpc/nfs 等监听" || _result 不合格 "高危端口" "发现高危端口: $(echo $danger_ports|tr '\n' ' ')"

tcp_ts=$(_sys net/ipv4/tcp_timestamps 2>/dev/null)
[ "$tcp_ts" = "0" ] && _result 合格 "TCP时间戳" "已禁用" || _result 待确认 "TCP时间戳" "tcp_timestamps=${tcp_ts:-未设置}，建议关闭"

tcp_sack=$(_sys net/ipv4/tcp_sack 2>/dev/null)
[ "$tcp_sack" = "0" ] && _result 合格 "TCP SACK" "已禁用" || _result 待确认 "TCP SACK" "tcp_sack=${tcp_sack:-未设置}，建议关闭"

arp_ignore=$(_sys net/ipv4/conf/all/arp_ignore 2>/dev/null)
arp_announce=$(_sys net/ipv4/conf/all/arp_announce 2>/dev/null)
[ "$arp_ignore" = "1" ] && [ "$arp_announce" = "2" ] && _result 合格 "ARP防护" "arp_ignore=1, arp_announce=2" || _result 待确认 "ARP防护" "建议设置 arp_ignore=1, arp_announce=2"

rp_loose=$(_sys net/ipv4/conf/all/arp_filter 2>/dev/null)
[ "$rp_loose" = "0" ] && _result 合格 "IP伪装防护" "arp_filter=0" || _result 待确认 "IP伪装防护" "arp_filter=${rp_loose:-未设置}，建议保持0"

if [ -f /etc/hosts.allow ]; then
    allow_rules=$(grep -v "^#" /etc/hosts.allow | grep -v "^$" | wc -l)
    [ "$allow_rules" -gt 0 ] && _result 合格 "hosts.allow" "已配置 ${allow_rules} 条规则" || _result 待确认 "hosts.allow" "文件存在但无有效规则"
else
    _result 待确认 "hosts.allow" "不存在，如使用 firewalld 可忽略"
fi

# ---------- 9. 其他安全配置 ----------
echo -e "\n### 九、其他安全基线检查 ###" >> "$REPORT_FILE"

sudo_nopasswd=$(grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | head -3)
[ -z "$sudo_nopasswd" ] && _result 合格 "sudo免密" "未配置 NOPASSWD" || _result 不合格 "sudo免密" "存在免密配置: $(echo $sudo_nopasswd|tr '\n' ' ')"

if [ -f /etc/cron.allow ]; then
    _result 合格 "cron.allow" "存在，限制 crontab 使用"
elif [ -f /etc/cron.deny ]; then
    _result 待确认 "cron.deny" "仅使用 deny 文件，建议改用 allow"
else
    _result 待确认 "cron控制" "既无 allow 也无 deny，所有用户均可使用 crontab"
fi

for tool in aide rkhunter clamav; do
    if command -v $tool &>/dev/null; then
        _result 合格 "安全工具-${tool}" "已安装"
    else
        _result 待确认 "安全工具-${tool}" "未安装，建议部署"
    fi
done

core_limit=$(ulimit -c 2>/dev/null)
[ "$core_limit" = "0" ] && _result 合格 "Core Dump" "已限制 (ulimit -c 0)" || _result 不合格 "Core Dump" "ulimit -c=${core_limit:-未限制}，建议限制为0"

mount | grep -q " /tmp " && _result 合格 "/tmp独立分区" "已独立挂载" || _result 待确认 "/tmp独立分区" "建议将 /tmp 单独分区并加挂载选项"

echo -e "\n===== 基线检查完成：$(date '+%F %T') =====" >> "$REPORT_FILE"
clear && echo "报告路径：$REPORT_FILE" && cat "$REPORT_FILE"