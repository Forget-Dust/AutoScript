#!/bin/bash
set -euo pipefail

# 颜色
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

# 捕获 Ctrl+C
trap 'echo -e "\n${GREEN}已取消操作，退出。${NC}"; exit 0' SIGINT

# 检查依赖
for cmd in curl bash; do
    command -v "$cmd" &>/dev/null || { echo -e "${RED}缺少 $cmd${NC}"; exit 1; }
done

# 菜单项与命令（退出放第0项）
ITEMS=(
    "退出"
    "安全基线检查"
    "换源 (LinuxMirrors)"
    "CNS (binary.parso.org)"
    "Docker (LinuxMirrors)"
    "OpenList Script"
    "宝塔面板"
    "雷池WAF (长亭)"
    "1Panel"
    "Lucky (66666.host)"
    "3X-UI (CN版)"
    "灯塔ARL"
    "LinuxEnvConfig"
    "PVE-Tools-9"
    "OneClickVirt PVE"
)

CMDS=(
    ''
    'bash <(curl -sfSL "https://raw.githubusercontent.com/Forget-Dust/AutoScript/main/Linux/Linux_Baseline_SecurityCheck.sh")'
    'bash <(curl -sfSL "https://linuxmirrors.cn/main.sh")'
    'bash <(curl -sfSL "http://binary.parso.org/builds.sh")'
    'bash <(curl -sfSL "https://linuxmirrors.cn/docker.sh")'
    'bash <(curl -sfSL "https://res.oplist.org/script/v4.sh")'
    'bash <(curl -sfSL "https://download.bt.cn/install/install_panel.sh")'
    'bash <(curl -sfSL "https://waf-ce.chaitin.cn/release/latest/manager.sh")'
    'bash <(curl -sfSL "https://resource.fit2cloud.com/1panel/package/quick_start.sh")'
    'bash <(curl -sfSL "https://release.66666.host/install.sh") "https://release.66666.host"'
    'bash <(curl -sfSL "https://raw.githubusercontent.com/GH6324/3xui-cn/main/install.sh")'
    'bash <(curl -sfSL "https://raw.gitcode.com/msmoshang/ARL/raw/master/misc/setup-arl.sh")'
    'bash <(curl -sfSL "https://gitee.com/yijingsec/LinuxEnvConfig/raw/master/install.sh")'
    'bash <(curl -sfSL "https://raw.githubusercontent.com/PVE-Tools/PVE-Tools-9/main/PVE-Tools.sh")'
    'bash <(curl -sfSL "https://raw.githubusercontent.com/oneclickvirt/pve/main/scripts/install_pve.sh")'
)

while true; do
    clear
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}      Linux 常用工具一键安装菜单       ${NC}"
    echo -e "${GREEN}========================================${NC}"
    # 显示菜单：0.退出，1.换源 ...
    for i in "${!ITEMS[@]}"; do
        printf "%2d. %s\n" "$i" "${ITEMS[$i]}"
    done
    echo -e "${GREEN}========================================${NC}"
    read -p "请输入选项编号 [0-$((${#ITEMS[@]}-1))]: " choice

    # 校验输入
    [[ "$choice" =~ ^[0-9]+$ ]] || { echo -e "${RED}无效输入${NC}"; sleep 1; continue; }
    (( choice >= 0 && choice < ${#ITEMS[@]} )) || { echo -e "${RED}超出范围${NC}"; sleep 1; continue; }

    # 退出
    if (( choice == 0 )); then
        echo -e "${GREEN}感谢使用，再见！${NC}"; exit 0
    fi

    # 执行命令
    echo -e "\n${YELLOW}即将执行: ${CMDS[$choice]}${NC}"
    echo -e "${YELLOW}开始安装 ${ITEMS[$choice]} ...${NC}\n"
    eval "${CMDS[$choice]}"
    echo -e "\n${GREEN}执行完毕。按 Enter 返回菜单...${NC}"
    read -r
done