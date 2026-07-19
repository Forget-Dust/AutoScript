#!/usr/bin/env python3
import os, sys, platform, socket, subprocess, re, pathlib, calendar
from datetime import datetime

# ==================== 元数据 ====================
class Level:
    PASS = "合格"; FAIL = "不合格"; WARN = "待确认"

def _script_dir() -> pathlib.Path:
    """脚本/ exe 所在目录，PyInstaller --onefile 也稳"""
    p = pathlib.Path(__file__).resolve()
    if getattr(sys, 'frozen', False):          # PyInstaller 标记
        p = pathlib.Path(sys.executable).resolve()
    return p.parent

def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "unknown"

def get_sysname():
    system = platform.system()
    if system == "Windows":
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            build, _ = winreg.QueryValueEx(key, "CurrentBuildNumber")
            ubr, _ = winreg.QueryValueEx(key, "UBR")
            win_ver = f"Windows_{platform.release()}_{build}"
            if ubr is not None and str(ubr).strip():
                win_ver += f".{ubr}"
            winreg.CloseKey(key)
            return win_ver
        except Exception:
            ver = platform.version().split('.')
            b = ver[2] if len(ver) > 2 else "19045"
            ext = f".{ver[3]}" if len(ver) > 3 and ver[3] else ""
            return f"Windows_{ver[0] if ver else '10'}_{b}{ext}"
    elif system == "Linux":
        distro_id, distro_ver = "linux", ""
        try:
            if hasattr(platform, 'freedesktop_os_release'):
                o = platform.freedesktop_os_release()
                distro_id = o.get('ID', 'linux').lower()
                distro_ver = o.get('VERSION_ID', '')
            else:
                with open("/etc/os-release", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("ID="):
                            distro_id = line.split("=",1)[1].strip().strip('"').lower()
                        elif line.startswith("VERSION_ID="):
                            distro_ver = line.split("=",1)[1].strip().strip('"')
        except Exception:
            pass
        kernel = platform.release()
        if distro_ver.startswith(distro_id):
            distro_ver = distro_ver.replace(distro_id, '') or distro_ver  # 防空
        return f"{distro_id}_{distro_ver}_{kernel}" if distro_ver else f"{distro_id}_{kernel}"
    else:
        return platform.system()

SYS_NAME = get_sysname()
IP_ADDR = get_ip()
NOW = datetime.now()
TIMESTAMP = NOW.strftime("%Y%m%d_%H%M%S")
WEEKDAY = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"][NOW.weekday()]  # 强制英文，不受 locale 影响

REPORT_DIR = _script_dir() / "legendsec"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

REPORT_FILE = REPORT_DIR / f"report.{SYS_NAME}.{IP_ADDR}.{TIMESTAMP}_{WEEKDAY}.txt"


# ==================== 工具 ====================
def _result(level: str, name: str, msg: str):
    tag = {Level.PASS: "[合格]", Level.FAIL: "[不合格]", Level.WARN: "[待确认]"}
    with open(REPORT_FILE, "a", encoding="utf-8") as f:
        f.write(f"{tag.get(level, '[?]')}   {name} — {msg}\n")

def _run(cmd, shell=False, timeout=15):
    try:
        r = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except Exception:
        return "", 1

def _reg(key, val):
    ps = f'(Get-ItemProperty "{key}" -Name "{val}" -EA SilentlyContinue).{val}'
    out, _ = _run(["powershell", "-NoProfile", "-Command", ps])
    return out.strip() or None

def _append(section):
    with open(REPORT_FILE, "a", encoding="utf-8") as f:
        f.write(f"\n### {section} ###\n")


# 报告头
with open(REPORT_FILE, "w", encoding="utf-8") as f:
    f.write("===== 基线安全检查报告 =====\n")
    f.write(f"评估时间：{NOW.strftime('%F %T')}\n")
    f.write(f"主机IP：{IP_ADDR}\n")
    f.write(f"系统：{SYS_NAME}\n")
    f.write("==============================\n")


# ================================================================
#  Linux 检查（↓ 你原版，一字不改 ↓）
# ================================================================
def linux_checks():
    import pwd
    _append("一、账号安全基线检查")
    pw_entries = {p.pw_name: p for p in pwd.getpwall()}
    shad_lines = {}
    try:
        with open("/etc/shadow", "r", errors="ignore") as sf:
            for ln in sf:
                ln = ln.strip()
                if not ln or ln.startswith("#"): continue
                parts = ln.split(":")
                if len(parts) >= 2: shad_lines[parts[0]] = parts[1]
    except PermissionError:
        _result("不合格", "脚本权限", "需 root 读取 /etc/shadow，sudo 重跑"); return

    pa = pathlib.Path("/etc/pam.d/system-auth")
    pa_txt = pa.read_text(errors="ignore") if pa.exists() else ""

    empty = []
    for name, sp_pwd in shad_lines.items():
        pw = pw_entries.get(name)
        if pw and sp_pwd in ("", "!!", "!*", "*"):
            if pw.pw_uid < 1000 and ("nologin" in (pw.pw_shell or "") or "false" in (pw.pw_shell or "")): continue
            if sp_pwd == "": empty.append(name)
    _result("合格" if not empty else "不合格", "空口令账号", "未发现空口令账号" if not empty else f"存在: {empty}")

    uid0 = [p.pw_name for p in pwd.getpwall() if p.pw_uid == 0]
    _result("合格" if uid0 == ["root"] else "不合格", "UID=0账号", "仅root" if uid0 == ["root"] else f"非root也UID=0: {uid0}")

    shared = [p.pw_name for p in pwd.getpwall() if p.pw_name in ("admin","test","temp")]
    _result("合格" if not shared else "待确认", "共享账号", "未发现特征账号" if not shared else f"疑似: {shared}")

    ok_lock = any(x in pa_txt for x in ("pam_tally2.so","pam_faillock.so"))
    _result("合格" if ok_lock else "不合格", "账号锁定策略", "已配置PAM锁定" if ok_lock else "未配置pam_tally2/pam_faillock，存在暴破风险")

    risk = []
    if pathlib.Path("/etc/hosts.equiv").exists(): risk.append("/etc/hosts.equiv")
    for p in pwd.getpwall():
        h = pathlib.Path(p.pw_dir)
        for ff in (h/".rhosts", h/".netrc"):
            if ff.exists(): risk.append(str(ff))
    _result("合格" if not risk else "不合格", "rhosts/netrc", "未发现" if not risk else f"存在信任文件，需清理: {risk}")

    unlocked = []
    for name, sp_pwd in shad_lines.items():
        pw = pw_entries.get(name)
        if not sp_pwd or sp_pwd.startswith(("!","*")): continue
        if name in ("root","halt","sync","shutdown"): continue
        if pw and pw.pw_uid < 1000: continue
        unlocked.append(name)
    _result("合格" if not unlocked else "待确认", "账号锁定状态", "无长期未锁定可登录账号" if not unlocked else f"可登录账号: {unlocked}")

    # 二、口令策略
    _append("二、口令策略基线检查")
    la = pathlib.Path("/etc/login.defs").read_text(errors="ignore")
    m = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", la, re.M)
    md = int(m.group(1)) if m else 99999
    _result("合格" if 0 < md <= 90 else "不合格", "口令最长生存期", f"{md}天")
    m = re.search(r"^\s*PASS_MIN_LEN\s+(\d+)", la, re.M)
    ml = int(m.group(1)) if m else 0
    _result("合格" if ml >= 8 else "不合格", "口令最小长度", f"{ml}位")
    ok_pw = any(x in pa_txt for x in ("pam_cracklib.so","pam_pwquality.so"))
    _result("合格" if ok_pw else "不合格", "口令复杂度", "PAM已配置pam_cracklib/pwquality" if ok_pw else "未配置口令复杂度模块，存在弱口令风险")

    # 三、访问控制
    _append("三、访问控制基线检查")
    def _sshd(k):
        out,_ = _run(f"grep -Ei '^{k}\\s' /etc/ssh/sshd_config 2>/dev/null | awk '{{print $2}}' | tail -1", shell=True)
        return out.strip()
    pr = _sshd("PermitRootLogin")
    _result("合格" if pr == "no" else "不合格", "Root远程登录", f"PermitRootLogin={pr or '未设'}，应no")
    pe = _sshd("PermitEmptyPasswords")
    _result("合格" if pe == "no" else "待确认", "空密码登录", f"PermitEmptyPasswords={pe or '未显式no'}")
    mat = _sshd("MaxAuthTries")
    _result("合格" if mat and mat.isdigit() and int(mat) <= 6 else "待确认", "SSH最大重试", f"建议≤6，当前: {mat or '未设'}")
    um = _run("umask", shell=True)[0]
    _result("合格" if um in ("0022","0027") else "不合格", "缺省umask", f"{um}，应0022/0027")
    out,_ = _run("systemctl is-enabled ctrl-alt-del.target 2>/dev/null", shell=True)
    _result("合格" if "disabled" in out or "masked" in out else "不合格", "Ctrl+Alt+Del", "已禁用" if "disabled" in out else "未禁用")
    _result("合格" if _run("grep -q HISTTIMEFORMAT /etc/profile /etc/bashrc 2>/dev/null", shell=True)[1] == 0 else "不合格", "History时间戳", "已配置")
    _result("合格" if pathlib.Path("/etc/securetty").exists() else "待确认", "/etc/securetty", "存在，限制root登录终端" if pathlib.Path("/etc/securetty").exists() else "缺失，root可从任意tty登录")

    # 四、内核安全
    _append("四、内核安全基线检查")
    def _sys(p):
        f = pathlib.Path(f"/proc/sys/{p}")
        return f.read_text(errors="ignore").strip() if f.exists() else ""
    _result("合格" if _sys("net/ipv4/conf/all/accept_redirects")=="0" else "不合格", "ICMP重定向", "已禁用")
    _result("合格" if _sys("net/ipv4/tcp_syncookies")=="1" else "不合格", "SYN Cookies", "已启用")
    _result("合格" if _sys("net/ipv4/conf/all/accept_source_route")=="0" else "不合格", "源路由", "已禁用")
    _result("合格" if _sys("net/ipv4/ip_forward")=="0" else "待确认", "IP转发", "已禁用(非路由设备)" if _sys("net/ipv4/ip_forward")=="0" else "已启用，如非路由设备建议关")
    _result("合格" if _sys("net/ipv4/conf/all/rp_filter")=="1" else "待确认", "反向路径过滤", "未启用，建议开" if _sys("net/ipv4/conf/all/rp_filter")!="1" else "已启用")

    # 五、服务与端口
    _append("五、服务与端口基线检查")
    svc_map = {"telnet":["telnet.service","telnet.socket"],"vsftpd":["vsftpd.service"],"nfs-server":["nfs-server.service"],"rpcbind":["rpcbind.service"],"ypserv":["ypserv.service"]}
    for nm,units in svc_map.items():
        inst=False; act=False
        for u in units:
            uf,_ = _run(f"systemctl list-unit-files '{u}' 2>/dev/null | grep -c '{u}'", shell=True)
            if uf.strip()!="0":
                inst=True
                ao,_ = _run(f"systemctl is-active '{u}' 2>/dev/null", shell=True)
                if "active" in ao: act=True; break
        if not inst: _result("合格",f"服务-{nm}","未安装")
        elif act: _result("不合格",f"服务-{nm}","运行中")
        else: _result("合格",f"服务-{nm}","已安装但未运行")

    # 六、日志审计
    _append("六、日志审计基线检查")
    _result("合格" if pathlib.Path("/var/log/secure").exists() else "不合格", "安全日志", "/var/log/secure存在")
    _result("合格" if _run("grep -qE '@@|@' /etc/rsyslog.conf 2>/dev/null", shell=True)[1]==0 else "待确认", "远程日志", "已配置，建议集中存储")
    out,_ = _run("systemctl is-active auditd 2>/dev/null", shell=True)
    _result("合格" if "active" in out else "待确认", "auditd审计", "运行中" if "active" in out else "未运行，建议开启")

    # 七、补丁与文件系统
    _append("七、补丁与文件系统基线检查")
    cnt="?"
    if _run("command -v yum",shell=True)[1]==0:
        out,_=_run("yum check-update --security -q 2>/dev/null | wc -l",shell=True); cnt=out or "0"
    elif _run("command -v apt-get",shell=True)[1]==0:
        out,_=_run("apt list --upgradable 2>/dev/null | grep -ci security",shell=True); cnt=out or "0"
    if cnt=="0": _result("合格","安全补丁","已最新")
    elif cnt=="?": _result("待确认","安全补丁","无法判断包管理器")
    else: _result("待确认","安全补丁",f"约{cnt}个安全更新待装")
    _result("合格" if _run("grep -qE 'nosuid|noexec|nodev' /etc/fstab",shell=True)[1]==0 else "不合格","tmp/shm挂载","已加限制选项")
    suid=_run("find /usr -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null | wc -l",shell=True)[0] or "0"
    _result("待确认","SUID/SGID文件",f"共{suid}个，建议人工复核/usr下特权文件")
    ww=_run("find /etc /var /usr -type f -perm -0002 2>/dev/null | grep -v '/proc' | head -5",shell=True)[0]
    _result("合格" if not ww else "待确认","全局可写文件","未发现" if not ww else f"示例: {ww}... 建议复核")

    # 八、网络安全
    _append("八、网络安全基线检查")
    fw_ok=False
    if _run("command -v firewall-cmd",shell=True)[1]==0:
        out,_=_run("firewall-cmd --state 2>/dev/null",shell=True); fw_ok=(out=="running")
    elif _run("command -v ufw",shell=True)[1]==0:
        out,_=_run("ufw status",shell=True); fw_ok=("active" in out.lower())
    elif _run("command -v iptables",shell=True)[1]==0:
        out,_=_run("iptables -L -n 2>/dev/null",shell=True); fw_ok=("Chain INPUT" in out)
    _result("合格" if fw_ok else "不合格","防火墙","运行中" if fw_ok else "未运行")
    if _run("command -v getenforce",shell=True)[1]==0:
        se=_run("getenforce",shell=True)[0]
        _result("合格" if se=="Enforcing" else "不合格","SELinux",f"当前模式: {se}，建议Enforcing")
    else: _result("待确认","SELinux","未安装或不可用")
    proto=_sshd("Protocol")
    _result("合格" if proto=="2" else "不合格","SSH协议版本",f"Protocol={proto or '未设置'}，建议仅允许2")
    weak=_run("grep -i 'Ciphers' /etc/ssh/sshd_config 2>/dev/null | grep -iE 'aes128-cbc|3des-cbc|blowfish-cbc'",shell=True)[0]
    _result("合格" if not weak else "不合格","SSH加密算法",f"使用了弱算法: {weak}" if weak else "未使用弱算法")
    dp=_run("ss -tlnp 2>/dev/null | awk '{print $4}' | grep -E ':23$|:111$|:2049$|:512$|:513$|:514$' | head -5",shell=True)[0]
    _result("合格" if not dp else "不合格","高危端口",f"发现: {dp}" if dp else "未发现 telnet/rpc/nfs 等监听")
    _result("合格" if _sys("net/ipv4/tcp_timestamps")=="0" else "待确认","TCP时间戳",f"tcp_timestamps={_sys('net/ipv4/tcp_timestamps')}，建议关闭")
    _result("合格" if _sys("net/ipv4/tcp_sack")=="0" else "待确认","TCP SACK",f"tcp_sack={_sys('net/ipv4/tcp_sack')}，建议关闭")
    ai=_sys("net/ipv4/conf/all/arp_ignore"); aa=_sys("net/ipv4/conf/all/arp_announce")
    _result("合格" if ai=="1" and aa=="2" else "待确认","ARP防护",f"建议 arp_ignore=1, arp_announce=2，当前 {ai}/{aa}")
    rp=_sys("net/ipv4/conf/all/arp_filter")
    _result("合格" if rp=="0" else "待确认","IP伪装防护",f"arp_filter={rp}，建议保持0")
    if pathlib.Path("/etc/hosts.allow").exists():
        al=_run("grep -v '^#' /etc/hosts.allow | grep -v '^$' | wc -l",shell=True)[0] or "0"
        _result("合格" if int(al)>0 else "待确认","hosts.allow",f"已配置{al}条规则" if int(al)>0 else "文件存在但无有效规则")
    else: _result("待确认","hosts.allow","不存在，如使用 firewalld 可忽略")

    # 九、其他
    _append("九、其他安全基线检查")
    np,_=_run("grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^[[:space:]]*#' | head -3",shell=True)
    np_lines=[l for l in np.splitlines() if l.strip() and not l.strip().startswith("#")]
    _result("合格" if not np_lines else "不合格","sudo免密","未配置 NOPASSWD" if not np_lines else f"存在免密配置: {' | '.join(np_lines[:2])}")
    if pathlib.Path("/etc/cron.allow").exists(): _result("合格","cron.allow","存在，限制 crontab 使用")
    elif pathlib.Path("/etc/cron.deny").exists(): _result("待确认","cron.deny","仅使用 deny 文件，建议改用 allow")
    else: _result("待确认","cron控制","既无 allow 也无 deny，所有用户均可使用 crontab")
    for tool in ("aide","rkhunter","clamscan"):
        ok=_run(f"command -v {tool}",shell=True)[1]==0
        _result("合格" if ok else "待确认",f"安全工具-{tool}","已安装" if ok else "未安装，建议部署")
    core=_run("ulimit -c",shell=True)[0]
    _result("合格" if core=="0" else "不合格","Core Dump",f"ulimit -c={core}，建议限制为0")
    mt=_run("mount | grep ' /tmp '",shell=True)[0]
    _result("合格" if mt else "待确认","/tmp独立分区","已独立挂载" if mt else "建议将 /tmp 单独分区并加挂载选项")


# ================================================================
#  Windows 检查（你原版，不动）
# ================================================================
def windows_checks():
    _append("一、账号安全")
    gs,_=_run(["powershell","-NoProfile","-Command","(Get-LocalUser -Name Guest).Enabled"])
    _result("合格" if gs.strip()=="False" else "不合格","Guest账户","已禁用" if gs.strip()=="False" else "仍启用")
    adm_out,_=_run(["powershell","-NoProfile","-Command","Get-LocalGroupMember -Name 'Administrators' | Select-Object -ExpandProperty Name"])
    _result("待确认","管理员组成员",adm_out.replace("\n"," ") if adm_out else "无法获取")
    lp=_reg(r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa","LimitBlankPasswordUse")
    _result("合格" if lp=="1" else "不合格","空密码登录",f"已禁止(LimitBlankPasswordUse=1)" if lp=="1" else f"LimitBlankPasswordUse={lp}，建议1")

    _append("二、口令策略")
    ml=_reg(r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa","MinimumPasswordLength")
    cp=_reg(r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa","PasswordComplexity")
    _result("合格" if ml and int(ml)>=8 else "不合格","口令最小长度",f"{ml or '?'}位")
    _result("合格" if cp=="1" else "不合格","口令复杂度","已启用" if cp=="1" else "未启用")

    _append("三、访问控制")
    rdp=_reg(r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server","fDenyTSConnections")
    _result("合格" if rdp=="1" else "待确认","RDP服务","已禁用" if rdp=="1" else ("已开启" if rdp=="0" else f"值={rdp}"))
    nla=_reg(r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp","UserAuthentication")
    _result("合格" if nla=="1" else "不合格","RDP-NLA","已启用" if nla=="1" else "未启用")
    ra=_reg(r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa","RestrictAnonymous")
    _result("合格" if ra=="1" else "待确认","匿名SAM枚举限制",f"RestrictAnonymous={ra or '未设'}，建议1")

    _append("四、内核与安全服务")
    uac=_reg(r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System","EnableLUA")
    _result("合格" if uac=="1" else "不合格","UAC","已启用" if uac=="1" else "未启用")
    lsa=_reg(r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa","RunAsPPL")
    _result("合格" if lsa=="1" else "待确认","LSA Protection",f"RunAsPPL={lsa or '未设'}，建议1")

    _append("五、服务与端口")
    for svc in ("TlntSvr","FTPSVC","SNMP"):
        out,_=_run(["sc","query",svc])
        if "RUNNING" in out: _result("不合格",f"服务-{svc}","运行中")
        elif "1060" in out or "does not exist" in out.lower(): _result("合格",f"服务-{svc}","未安装")
        else: _result("合格",f"服务-{svc}","已安装但未运行")

    _append("六、防火墙与安全组件")
    fw,_=_run(["netsh","advfirewall","show","allprofiles","state"])
    _result("合格" if "State                                 ON" in fw else "不合格","Windows防火墙","各Profile均已开启" if "ON" in fw else "有Profile未开")
    mp,_=_run(["powershell","-NoProfile","-Command","(Get-MpComputerStatus).RealTimeProtectionEnabled"])
    _result("合格" if mp.strip()=="True" else "不合格","Defender实时防护",mp.strip())
    smb1,_=_run(["powershell","-NoProfile","-Command","(Get-SmbServerConfiguration).EnableSMB1Protocol"])
    _result("合格" if smb1.strip()=="False" else "不合格","SMBv1","已禁用" if smb1.strip()=="False" else "仍启用(高危)")

    _append("七、补丁")
    hf,_=_run(["powershell","-NoProfile","-Command",'(Get-HotFix|Sort-Object InstalledOn -Desc|Select -First 3).HotFixID'])
    _result("待确认","最近补丁",hf.replace("\n"," ") or "无法获取")

    _append("八、日志审计")
    out,_=_run(["powershell","-NoProfile","-Command",'(Get-WinEvent -ListLog Application,System,Security|Select LogName,IsEnabled).LogName'])
    _result("待确认","Windows事件日志","Application/System/Security 可用" if out else "无法获取")

    _append("九、其他")
    smb_sig=_reg(r"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters","RequireSecuritySignature")
    _result("合格" if smb_sig=="1" else "待确认","SMB签名",f"RequireSecuritySignature={smb_sig or '未设'}，建议1")


# ==================== 入口 ====================
if __name__ == "__main__":
    ps = platform.system()
    if ps == "Linux":
        try:
            linux_checks()
        except PermissionError:
            _result("不合格", "脚本权限", "需 sudo 运行以读取 /etc/shadow")
        except Exception as e:
            _result("待确认", "Linux检查异常", str(e))
    elif ps == "Windows":
        try:
            windows_checks()
        except Exception as e:
            _result("待确认", "Windows检查异常", str(e))
    else:
        _result("待确认", "系统类型", f"未知: {ps}")

    with open(REPORT_FILE, "a", encoding="utf-8") as f:
        f.write(f"\n===== 基线检查完成：{datetime.now().strftime('%F %T')} =====\n")

    print(f"\n报告路径：{REPORT_FILE}")
    try:
        print(REPORT_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"读取报告内容失败: {e}")

    # ★ 等一下再退，避免双击 exe 时窗口秒关
    #    CMD / PowerShell 里手动跑的，按回车就走；双击的也能看到输出
    try:
        input("\n按 Enter 退出...")
    except (EOFError, KeyboardInterrupt):
        pass