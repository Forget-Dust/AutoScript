#!/bin/bash
set -euo pipefail

# ========== 全局 ==========
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# 解开 Ctrl+Q（XON）占用，方便以后扩展字符级捕获；非 TTY 时忽略
stty -ixon 2>/dev/null || true

# 全局 INT：主菜单态下 Ctrl+C → 退出
global_int() { echo -e "\n${GREEN}已取消，退出。${NC}"; exit 0; }
trap global_int SIGINT

need() { command -v "$1" &>/dev/null || { echo -e "${RED}缺少: $1${NC}"; exit 1; }; }
need curl; need bash

pause() { echo -e "${YELLOW}按 Enter 返回...${NC}"; read -r; }

run() {
    local name="$1" cmd="$2"

    echo -e "\n${BLUE}▶ $name${NC}"
    echo -e "${YELLOW}   $cmd${NC}"
    echo -e "${YELLOW}   [运行中: Ctrl+C 终止并返回主菜单]${NC}\n"

    # ---- 进入 run：把 INT 改成"杀子进程 + 返主菜单" ----
    # 注意：eval 跑的命令如果是 bash <(curl ...) 本身会再启子 shell，
    # Ctrl+C 会打到整个前台进程组，父 bash 的 trap 先触发 return，
    # 子进程也被 SIGINT 带走，正好。
    trap 'echo -e "\n${YELLOW}⏹ 已终止「${name}」，返回主菜单...${NC}"; return 0' SIGINT

    ( set +e; eval "$cmd"; exit $? )
    local rc=$?

    # ---- 离开 run：恢复全局 INT trap ----
    trap global_int SIGINT

    if (( rc == 0 )); then
        echo -e "${GREEN}✓ 执行完成${NC}"
    else
        # rc 非 0 可能是 Ctrl+C(return 已接管) 或真失败
        # Ctrl+C 路径已经 return 了，走到这里的非 0 是真失败
        echo -e "${RED}✗ 执行异常 (rc=$rc)${NC}"
    fi
    pause
}

# ========== 1. 系统安全 ==========
menu_security() {
    local ITEMS=("返回主菜单" "基线检查 (Forget-Dust)")
    local CMDS=('' 'bash <(curl -sfSL "https://raw.githubusercontent.com/Forget-Dust/AutoScript/main/Linux/Linux_Baseline_SecurityCheck.sh")')

    while true; do
        clear
        echo -e "${GREEN}===== 系统安全 =====${NC}"
        for i in "${!ITEMS[@]}"; do printf "%2d. %s\n" "$i" "${ITEMS[$i]}"; done
        echo -e "${GREEN}==================${NC}"
        read -p "选择 [0-$((${#ITEMS[@]}-1))]: " c
        [[ "$c" =~ ^[0-9]+$ ]] && (( c>=0 && c<${#ITEMS[@]} )) || { sleep 0.5; continue; }
        (( c == 0 )) && return
        run "${ITEMS[$c]}" "${CMDS[$c]}"
    done
}

# ========== 2. 第三方脚本 ==========
menu_thirdparty() {
    local ITEMS=(
        "返回主菜单"
        "换源 (LinuxMirrors)" "Docker (LinuxMirrors)"
        "雷池 WAF (长亭)" "1Panel" "LinuxEnvConfig（适用apt系列）"
    )
    local CMDS=(
        ''
        'bash <(curl -sfSL "https://linuxmirrors.cn/main.sh")'
        'bash <(curl -sfSL "https://linuxmirrors.cn/docker.sh")'
        'bash <(curl -sfSL "https://waf-ce.chaitin.cn/release/latest/manager.sh")'
        'bash <(curl -sfSL "https://resource.fit2cloud.com/1panel/package/quick_start.sh")'
        'bash <(curl -sfSL "https://gitee.com/yijingsec/LinuxEnvConfig/raw/master/install.sh")'
    )

    while true; do
        clear
        echo -e "${GREEN}===== 第三方脚本 =====${NC}"
        for i in "${!ITEMS[@]}"; do printf "%2d. %s\n" "$i" "${ITEMS[$i]}"; done
        echo -e "${GREEN}====================${NC}"
        read -p "选择 [0-$((${#ITEMS[@]}-1))]: " c
        [[ "$c" =~ ^[0-9]+$ ]] && (( c>=0 && c<${#ITEMS[@]} )) || { sleep 0.5; continue; }
        (( c == 0 )) && return
        run "${ITEMS[$c]}" "${CMDS[$c]}"
    done
}

# ========== 主菜单 ==========
MAIN=("退出" "系统安全" "第三方脚本")

while true; do
    clear
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}      Linux 常用工具一键安装菜单       ${NC}"
    echo -e "${GREEN}========================================${NC}"
    for i in "${!MAIN[@]}"; do printf "%2d. %s\n" "$i" "${MAIN[$i]}"; done
    echo -e "${GREEN}========================================${NC}"
    echo -e "${YELLOW}  提示: 主菜单 Ctrl+C 退出 | 执行中 Ctrl+C 终止返回${NC}"
    read -p "选择 [0-$((${#MAIN[@]}-1))]: " c
    [[ "$c" =~ ^[0-9]+$ ]] || { sleep 0.5; continue; }
    (( c == 0 )) && { echo -e "${GREEN}再见。${NC}"; exit 0; }
    (( c == 1 )) && { menu_security; continue; }
    (( c == 2 )) && { menu_thirdparty; continue; }
done