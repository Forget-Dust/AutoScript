#!/bin/bash

while true; do
	clear && trap 'echo -e "\n⛔收到中断信号，退出脚本";kill -9 $(jobs -p) 2>/dev/null;rm -f $t;exit 0' SIGINT
	echo -e "\n======= 菜单 ======="
	echo -e "\n0. 退出"
	echo -e "\n1. 循环 ping 网段"
	echo -e "\n2. 打印三角形"
	echo -e "\n3. 打印乘法表"
	echo -e "\n4. 计算 奇(偶) 的和、乘"
	echo -e "\n5. 猜数字小游戏"
	echo -e "\n==================="
	read -p "请输入对应数值: " choice

	case "$choice" in
		1)	while true; do
			read -p "输入需要测试的网段（回车默认 192.168.1）: " lan && lan="${lan:-192.168.1}"
			if [[ "$lan" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]];then a=${BASH_REMATCH[1]};b=${BASH_REMATCH[2]};c=${BASH_REMATCH[3]}
			if (( a<=254 && b<=254 && c<=254 ));then break;fi;fi;echo "❌：格式不合法，请按 x.x.x 输入前三段（每段 0-254），重新输入...";done
			t=$(mktemp);for ip in {1..254};do(ping -c1 -w1 "${lan}.${ip}"&>/dev/null&&echo "${lan}.${ip} ✅"||echo "${lan}.${ip} ⛔")|tee -a ${t}&done;wait;echo "✅ $(grep -c "✅$" ${t}) ⛔ $(grep -c "⛔$" ${t})"
		read;;
		2)	read -p "请输入三角形行数（回车默认 12）: " a && a="${a:-12}";read -p "请输入以什么显示内容（回车默认 *）: " b && b="${b:-*}"
			for (( i=1; i<=a; i++ )); do for (( c=1; c<=a-i; c++ )); do echo -n " ";done;for (( d=1; d<=i; d++ ));do echo -n "${b} ";done;echo;done
		read;;
		3)	while true; do
			read -p "请输入需要开始数值（回车默认 1）：" a && a="${a:-1}";read -p "请输入结束数值（回车默认 9）：" b && b="${b:-9}"
			if ! [[ "${a}" =~ ^[1-9][0-9]*$ && "${b}" =~ ^[1-9][0-9]*$ && ${a} -le ${b} ]];then echo "❌ 输入不合法：请输入正整数，且起始值 ≤ 结束值";continue;fi
			echo -e "\n✅ 生成 ${a}~${b} 乘法表：";for (( c=a; c<=b; c++ ));do for (( d=c; d<=b; d++));do echo -en "${c}*${d}=$((c*d))\t";done;echo;done;break;done
		read;;
		4)	while true; do
			read -p "请输入起始数值: " start;read -p "请输入结束数值: " end
			if ! [[ "${start}" =~ ^[1-9][0-9]*$ && "${end}" =~ ^[1-9][0-9]*$ && "${start}" -le "${end}" ]];then echo -e "❌ 输入不合法：请输入正整数，且起始值 ≤ 结束值\n🔄 请重新输入...\n";continue;fi
			sum_odd=0;sum_even=0;mul_odd=1;mul_even=1;for (( a=start; a<=end; a++ ));do if (( a%2==1 ));then (( sum_odd += a ));(( mul_odd *= a ));else (( sum_even += a ));(( mul_even *= a ));fi;done
			echo -e "\n✅ ${start}~${end} 的计算结果：\n奇数和: ${sum_odd}\n偶数和: ${sum_even}\n奇数乘积: ${mul_odd}\n偶数乘积: ${mul_even}";break;done
		read;;
		5)	while true;do 
			clear&&ans=$((RANDOM%101));echo -e "\n===== 新游戏（0-100，5次机会）=====";c=0;ok=0;while((c<5));do ((c++));read -p "第$c次猜:" g
			if ! [[ "$g" =~ ^[0-9]+$ ]]||((g<0||g>100));then echo "无效";((c--));continue;fi;if((g==ans));then echo "对！$ans";ok=1;break;elif((g>ans));then echo "大";else echo "小";fi;done;[ $ok -eq 0 ]&&echo "答案是$ans";read -p "q退出，任意继续：" q;[[ "$q" =~ ^[qQ]$ ]]&&exit 0;done
		read;;
		0)	echo "退出脚本，bye~" && exit 0;;
		*)	read -p "无效选择，请正确输入数值";;
	esac
done