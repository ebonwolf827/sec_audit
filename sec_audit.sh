#!/bin/bash
#=============================================================
# AWS Linux 安全检测脚本 v7.1
# 特性: 检测 + 告警 + 响应(L1-L5) + eBPF 阻断 | 模块化 | YARA
# 用法: sudo bash sec_audit.sh [选项]
#=============================================================

set -uo pipefail

# ============================================================
# 目录与文件
# ============================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/lib"
CONF_DIR="${SCRIPT_DIR}/conf"
RULES_DIR="${SCRIPT_DIR}/rules"
EBPF_DIR="${SCRIPT_DIR}/ebpf"

REPORT_BASE_DIR="/var/log/sec_audit"
BASELINE_BASE_DIR="/var/lib/sec_audit"
TOOLS_DIR="/opt/sec_audit/tools"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

REPORT_FILE="${REPORT_BASE_DIR}/audit_${TIMESTAMP}.log"
SUMMARY_FILE="${REPORT_BASE_DIR}/summary_${TIMESTAMP}.txt"
VERSION_FILE="${REPORT_BASE_DIR}/sysinfo_${TIMESTAMP}.txt"
JSON_FILE="${REPORT_BASE_DIR}/report_${TIMESTAMP}.json"
INSTALL_LOG="${REPORT_BASE_DIR}/install_${TIMESTAMP}.log"
BASELINE_FILE="${BASELINE_BASE_DIR}/baseline.sha256"
SUID_BASELINE_FILE="${BASELINE_BASE_DIR}/suid_baseline.txt"
WHITELIST_FILE="${CONF_DIR}/whitelist.conf"
REMEDIATION_FILE="${CONF_DIR}/remediation.conf"

# ============================================================
# 参数解析
# ============================================================
OUTPUT_JSON=false
SETUP_SCHEDULE=false
SKIP_INSTALL=false
FIX_MODE=false
RESPONSE_LEVEL=1
DRY_RUN=false
ROLLBACK_ONLY=false
CHECK_EBPF=false

for arg in "$@"; do
    case "$arg" in
        # --- 基础选项 ---
        --json)           OUTPUT_JSON=true ;;
        --schedule)       SETUP_SCHEDULE=true ;;
        --no-install)     SKIP_INSTALL=true ;;
        --fix)            FIX_MODE=true ;;

        # --- 响应引擎选项 ---
        --response-level=*)
            RESPONSE_LEVEL="${arg#*=}"
            if ! [[ "$RESPONSE_LEVEL" =~ ^[1-5]$ ]]; then
                echo "错误: --response-level 必须是 1-5 之间的整数"
                exit 1
            fi
            ;;
        --dry-run)        DRY_RUN=true ;;
        --rollback)       ROLLBACK_ONLY=true ;;

        # --- 诊断选项 ---
        --check-ebpf)     CHECK_EBPF=true ;;

        # --- 帮助 ---
        -h|--help)
            cat <<'EOF'
用法: sudo bash sec_audit.sh [选项]

基础选项:
  --json                    生成 JSON 格式报告
  --schedule                配置定时任务（每日 03:00 + 每周日 04:00）
  --no-install              跳过工具安装（日常运行必选）
  --fix                     自动修复低风险基线项（文件权限、sysctl）

响应引擎选项:
  --response-level=N        响应级别 (1-5，默认 1)
                              1 = 仅记录（默认，安全）
                              2 = 记录 + 告警
                              3 = + 低风险处置（文件隔离、权限修复、持久化移除）
                              4 = + 高风险处置（终止进程、封禁 IP、锁定账户）
                                   + eBPF 进程执行阻断（如内核支持）
                              5 = + 主机隔离（仅保留管理 IP 的 SSH）
  --dry-run                 干跑模式，仅展示将要执行的动作，不实际执行
  --rollback                仅显示可回滚的动作信息

诊断选项:
  --check-ebpf              检查 eBPF 环境是否就绪，不执行检测

其他:
  -h, --help                显示此帮助

示例:
  # 日常巡检（只检测，不动系统）
  sudo sec_audit.sh --json --no-install

  # 检查 eBPF 环境
  sudo sec_audit.sh --check-ebpf

  # 验证响应策略（干跑 L4，看会做什么）
  sudo sec_audit.sh --response-level=4 --dry-run --no-install

  # 低风险自动处置（隔离 Webshell、修复权限）
  sudo sec_audit.sh --response-level=3 --no-install

  # 应急响应（终止进程、封禁 IP、eBPF 阻断）
  sudo sec_audit.sh --response-level=4 --json --no-install

  # 主机隔离（保留管理 IP 的 SSH）
  sudo sec_audit.sh --response-level=5 --no-install

  # 查看历史响应动作的回滚方法
  sudo sec_audit.sh --rollback
EOF
            exit 0
            ;;
        *)
            echo "未知参数: $arg"
            echo "使用 --help 查看支持的选项"
            exit 1
            ;;
    esac
done

export RESPONSE_LEVEL DRY_RUN

# ============================================================
# rollback 独占模式
# ============================================================
if $ROLLBACK_ONLY; then
    source "${LIB_DIR}/response.sh"
    response_rollback
    exit 0
fi

# ============================================================
# root 检查
# ============================================================
[[ $EUID -ne 0 ]] && { echo "请使用 sudo 运行"; exit 1; }

# ============================================================
# 并发锁
# ============================================================
LOCK_FILE="/var/run/sec_audit.lock"
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    echo "另一个 sec_audit 实例正在运行，退出"
    exit 2
fi

# ============================================================
# 创建目录
# ============================================================
mkdir -p "$REPORT_BASE_DIR" "$BASELINE_BASE_DIR" "$TOOLS_DIR"

# ============================================================
# 加载模块（顺序重要）
# ============================================================
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/response.sh"
source "${LIB_DIR}/detect_os.sh"
source "${LIB_DIR}/install_tools.sh"
source "${LIB_DIR}/check_yara.sh"
source "${LIB_DIR}/check_memshell.sh"
source "${LIB_DIR}/check_rootkit.sh"
source "${LIB_DIR}/check_integrity.sh"
source "${LIB_DIR}/check_system.sh"
source "${LIB_DIR}/check_backdoor.sh"
source "${LIB_DIR}/check_webshell.sh"
source "${LIB_DIR}/check_nacos.sh"
source "${LIB_DIR}/check_log_audit.sh"
source "${LIB_DIR}/check_web_log.sh"
source "${LIB_DIR}/check_baseline.sh"
source "${LIB_DIR}/check_container.sh"
source "${LIB_DIR}/check_falco.sh"
source "${LIB_DIR}/report.sh"

# ============================================================
# 初始化
# ============================================================
init_report
log "AWS Linux 安全检测报告 — $(date '+%Y-%m-%d %H:%M:%S')"
log "主机名: $(hostname)  内核: $(uname -r)"
log "响应级别: L${RESPONSE_LEVEL}$($DRY_RUN && echo ' [干跑模式]' || echo '')"

init_imds_token

# ============================================================
# eBPF 环境诊断（独立模式）
# ============================================================
if $CHECK_EBPF; then
    section "eBPF 环境诊断"

    # 1. 内核版本
    local_kernel_major=$(uname -r | cut -d. -f1)
    local_kernel_minor=$(uname -r | cut -d. -f2)

    if [[ "$local_kernel_major" -gt 5 ]] || \
       [[ "$local_kernel_major" -eq 5 && "$local_kernel_minor" -ge 7 ]]; then
        pass "内核版本 $(uname -r)（≥ 5.7，支持 BPF LSM）"
    else
        fail "内核版本 $(uname -r) < 5.7，不支持 BPF LSM"
    fi

    # 2. BPF LSM 启用
    if grep -q "bpf" /sys/kernel/security/lsm 2>/dev/null; then
        pass "BPF LSM 已启用: $(cat /sys/kernel/security/lsm)"
    else
        fail "BPF LSM 未启用"
        info "启用方法:"
        info "  1. 编辑 /etc/default/grub"
        info "  2. 在 GRUB_CMDLINE_LINUX 中添加 lsm=lockdown,capability,landlock,yama,bpf"
        info "  3. sudo update-grub && sudo reboot"
    fi

    # 3. bpftool 可用
    if command -v bpftool &>/dev/null; then
        pass "bpftool 已安装: $(bpftool version 2>/dev/null | head -1)"
    else
        fail "bpftool 未安装"
        info "安装: apt install linux-tools-common linux-tools-generic"
    fi

    # 4. clang 可用
    if command -v clang &>/dev/null; then
        pass "clang 已安装: $(clang --version 2>/dev/null | head -1)"
    else
        warn "clang 未安装（编译 eBPF 程序需要）"
        info "安装: apt install clang llvm"
    fi

    # 5. 控制工具
    if [[ -x "${TOOLS_DIR}/block_exec_ctl" ]]; then
        pass "block_exec_ctl 已编译"
    else
        warn "block_exec_ctl 未编译"
        info "编译: cd ${SCRIPT_DIR} && gcc -O2 -o ${TOOLS_DIR}/block_exec_ctl ebpf/block_exec_ctl.c -lbpf -lelf -lz"
    fi

    # 6. eBPF 程序
    if [[ -f "${EBPF_DIR}/block_exec.bpf.o" ]]; then
        pass "eBPF 程序已编译"
    else
        warn "eBPF 程序未编译"
        info "编译: cd ${SCRIPT_DIR} && bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h"
        info "      clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I./ebpf -c ebpf/block_exec.bpf.c -o ebpf/block_exec.bpf.o"
    fi

    # 7. 程序是否已加载
    if [[ -f "/sys/fs/bpf/block_exec/procs" ]]; then
        pass "eBPF 阻断程序已加载"
        if [[ -x "${TOOLS_DIR}/block_exec_ctl" ]]; then
            info "当前阻断统计:"
            "${TOOLS_DIR}/block_exec_ctl" stats 2>/dev/null | while read -r line; do
                log "  $line"
            done
        fi
    else
        info "eBPF 阻断程序未加载（会在 --response-level=4 时自动加载）"
    fi

    exit 0
fi

# ============================================================
# 主流程
# ============================================================
main() {
    # 初始化响应引擎（含 eBPF 阻断模块）
    init_response_engine

    # 检测阶段
    phase_detect_os
    phase_install_tools
    phase_install_yara
    phase_check_memshell
    phase_check_rootkit
    phase_check_integrity
    phase_check_system
    phase_check_backdoor
    phase_check_webshell
    phase_check_nacos
    phase_check_log_audit
    phase_check_web_log
    phase_check_baseline
    phase_check_container
    phase_check_falco

    # 汇总报告
    phase_report
    response_summary

    # 定时任务配置
    $SETUP_SCHEDULE && setup_schedule
}

main

# ============================================================
# 退出码
# ============================================================
# 0 = 无 FAIL
# 1 = 有 FAIL 但响应动作未失败
# 2 = 响应动作执行失败
if [[ "$RESPONSE_ACTIONS_FAILED" -gt 0 ]]; then
    log "部分响应动作执行失败: $RESPONSE_ACTIONS_FAILED 项"
    log "详情见: $RESPONSE_LOG"
    exit 2
elif [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi

log "摘要文件: $SUMMARY_FILE"
exit 0