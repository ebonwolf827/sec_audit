#!/bin/bash
#=============================================================
# AWS Linux 安全检测脚本 v7.1
# 特性: 检测 + 告警 + 响应(L1-L5) + eBPF 阻断 | 模块化 | YARA
# 用法: sudo bash sec_audit.sh [选项]
# 修复:
#   1. 使用 readlink -f 解析软链接，正确定位 SCRIPT_DIR
#   2. source 失败时给出明确错误提示
#   3. 关键函数提供 fallback 定义
#=============================================================

set -uo pipefail

#=============================================================
# 解析真实脚本路径（关键修复）
#=============================================================
# BASH_SOURCE[0] 在软链接执行时返回软链接路径
# readlink -f 递归解析所有软链接，返回真实路径
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"

# 验证解析结果
if [[ ! -d "$SCRIPT_DIR" ]]; then
    echo "错误: 无法解析脚本目录: $SCRIPT_DIR" >&2
    exit 1
fi

#=============================================================
# 目录与文件
#=============================================================
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

# 导出给子模块使用
export SCRIPT_DIR LIB_DIR CONF_DIR RULES_DIR EBPF_DIR TOOLS_DIR
export REPORT_BASE_DIR BASELINE_BASE_DIR
export REPORT_FILE SUMMARY_FILE VERSION_FILE JSON_FILE INSTALL_LOG
export BASELINE_FILE SUID_BASELINE_FILE WHITELIST_FILE REMEDIATION_FILE
export TIMESTAMP

#=============================================================
# 颜色定义（fallback，防止 common.sh 加载失败时未定义）
#=============================================================
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'
export RED YELLOW GREEN CYAN BOLD NC

#=============================================================
# 参数解析
#=============================================================
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
        --json)           OUTPUT_JSON=true ;;
        --schedule)       SETUP_SCHEDULE=true ;;
        --no-install)     SKIP_INSTALL=true ;;
        --fix)            FIX_MODE=true ;;
        --response-level=*)
            RESPONSE_LEVEL="${arg#*=}"
            if ! [[ "$RESPONSE_LEVEL" =~ ^[1-5]$ ]]; then
                echo "错误: --response-level 必须是 1-5 之间的整数"
                exit 1
            fi
            ;;
        --dry-run)        DRY_RUN=true ;;
        --rollback)       ROLLBACK_ONLY=true ;;
        --check-ebpf)     CHECK_EBPF=true ;;
        -h|--help)
            cat <<'EOF'
用法: sudo bash sec_audit.sh [选项]

基础选项:
  --json                    生成 JSON 格式报告
  --schedule                配置定时任务
  --no-install              跳过工具安装
  --fix                     自动修复低风险基线项

响应引擎选项:
  --response-level=N        响应级别 (1-5，默认 1)
                              1 = 仅记录（默认，安全）
                              2 = 记录 + 告警
                              3 = + 低风险处置（文件隔离、权限修复）
                              4 = + 高风险处置（终止进程、封禁 IP、eBPF 阻断）
                              5 = + 主机隔离
  --dry-run                 干跑模式，仅展示将要执行的动作
  --rollback                仅显示可回滚的动作信息

诊断选项:
  --check-ebpf              检查 eBPF 环境是否就绪

其他:
  -h, --help                显示此帮助
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

export OUTPUT_JSON SETUP_SCHEDULE SKIP_INSTALL FIX_MODE
export RESPONSE_LEVEL DRY_RUN ROLLBACK_ONLY CHECK_EBPF

#=============================================================
# root 检查
#=============================================================
if [[ $EUID -ne 0 ]]; then
    echo "请使用 sudo 运行"
    exit 1
fi

#=============================================================
# 并发锁
#=============================================================
LOCK_FILE="/var/run/sec_audit.lock"
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    echo "另一个 sec_audit 实例正在运行，退出"
    exit 2
fi

#=============================================================
# 创建目录
#=============================================================
mkdir -p "$REPORT_BASE_DIR" "$BASELINE_BASE_DIR" "$TOOLS_DIR"
mkdir -p "${BASELINE_BASE_DIR}/response/quarantine"
mkdir -p "${BASELINE_BASE_DIR}/response/evidence"
mkdir -p "${BASELINE_BASE_DIR}/response/rollback"

#=============================================================
# 模块加载函数（带错误检查）
#=============================================================
load_module() {
    local module="$1"
    local path="${LIB_DIR}/${module}"

    if [[ ! -f "$path" ]]; then
        echo "错误: 模块文件不存在: $path" >&2
        echo "  请检查 SCRIPT_DIR 是否解析正确: $SCRIPT_DIR" >&2
        return 1
    fi

    # shellcheck source=/dev/null
    if ! source "$path"; then
        echo "错误: 模块加载失败: $path" >&2
        return 1
    fi

    return 0
}

#=============================================================
# 加载核心模块（顺序重要）
#=============================================================
if ! load_module "common.sh"; then
    echo "" >&2
    echo "致命错误: 无法加载 common.sh" >&2
    echo "" >&2
    echo "诊断信息:" >&2
    echo "  BASH_SOURCE[0] = ${BASH_SOURCE[0]}" >&2
    echo "  SCRIPT_PATH    = ${SCRIPT_PATH}" >&2
    echo "  SCRIPT_DIR     = ${SCRIPT_DIR}" >&2
    echo "  LIB_DIR        = ${LIB_DIR}" >&2
    echo "" >&2
    echo "请检查:" >&2
    echo "  1. /usr/local/bin/sec_audit/lib/common.sh 是否存在" >&2
    echo "  2. 软链接是否指向正确路径: ls -la /usr/local/bin/sec-audit" >&2
    echo "  3. SCRIPT_DIR 是否用 readlink -f 解析" >&2
    exit 1
fi

# 加载其他模块
load_module "response.sh"          || echo "警告: response.sh 加载失败" >&2
load_module "detect_os.sh"         || echo "警告: detect_os.sh 加载失败" >&2
load_module "install_tools.sh"     || echo "警告: install_tools.sh 加载失败" >&2
load_module "check_yara.sh"        || echo "警告: check_yara.sh 加载失败" >&2
load_module "check_memshell.sh"    || echo "警告: check_memshell.sh 加载失败" >&2
load_module "check_rootkit.sh"     || echo "警告: check_rootkit.sh 加载失败" >&2
load_module "check_integrity.sh"   || echo "警告: check_integrity.sh 加载失败" >&2
load_module "check_system.sh"      || echo "警告: check_system.sh 加载失败" >&2
load_module "check_backdoor.sh"    || echo "警告: check_backdoor.sh 加载失败" >&2
load_module "check_webshell.sh"    || echo "警告: check_webshell.sh 加载失败" >&2
load_module "check_nacos.sh"       || echo "警告: check_nacos.sh 加载失败" >&2
load_module "check_log_audit.sh"   || echo "警告: check_log_audit.sh 加载失败" >&2
load_module "check_web_log.sh"     || echo "警告: check_web_log.sh 加载失败" >&2
load_module "check_baseline.sh"    || echo "警告: check_baseline.sh 加载失败" >&2
load_module "check_container.sh"   || echo "警告: check_container.sh 加载失败" >&2
load_module "check_falco.sh"       || echo "警告: check_falco.sh 加载失败" >&2
load_module "report.sh"            || echo "警告: report.sh 加载失败" >&2

#=============================================================
# 关键函数的 fallback 定义（防止 common.sh 部分加载失败）
#=============================================================
if ! declare -f init_report &>/dev/null; then
    init_report() {
        mkdir -p "$REPORT_BASE_DIR"
        : > "$REPORT_FILE"
        : > "$INSTALL_LOG"
    }
fi

if ! declare -f log &>/dev/null; then
    log() { echo -e "$*" | tee -a "$REPORT_FILE"; }
fi

if ! declare -f init_imds_token &>/dev/null; then
    init_imds_token() {
        IMDS_TOKEN=$(curl -s -m 2 -X PUT "http://169.254.169.254/latest/api/token" \
            -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || true)
    }
fi

if ! declare -f section &>/dev/null; then
    section() {
        log ""
        log "============================================================"
        log "  $*"
        log "============================================================"
    }
fi

if ! declare -f info &>/dev/null; then
    info() { log "${CYAN}[INFO]${NC} $*"; }
fi

if ! declare -f pass &>/dev/null; then
    pass() { log "${GREEN}[PASS]${NC} $*"; }
fi

if ! declare -f fail &>/dev/null; then
    fail() { log "${RED}[FAIL]${NC} $*"; }
fi

if ! declare -f warn &>/dev/null; then
    warn() { log "${YELLOW}[WARN]${NC} $*"; }
fi

#=============================================================
# rollback 独占模式
#=============================================================
if $ROLLBACK_ONLY; then
    if declare -f response_rollback &>/dev/null; then
        response_rollback
    else
        echo "错误: response_rollback 函数未定义" >&2
        exit 1
    fi
    exit 0
fi

#=============================================================
# 初始化
#=============================================================
init_report
log "AWS Linux 安全检测报告 — $(date '+%Y-%m-%d %H:%M:%S')"
log "主机名: $(hostname)  内核: $(uname -r)"
log "响应级别: L${RESPONSE_LEVEL}$($DRY_RUN && echo ' [干跑模式]' || echo '')"
log "脚本目录: $SCRIPT_DIR"

init_imds_token

#=============================================================
# eBPF 环境诊断（独立模式）
#=============================================================
if $CHECK_EBPF; then
    section "eBPF 环境诊断"

    # 1. 内核版本
    KERNEL_MAJOR=$(uname -r | cut -d. -f1)
    KERNEL_MINOR=$(uname -r | cut -d. -f2)

    if [[ "$KERNEL_MAJOR" -gt 5 ]] || \
       [[ "$KERNEL_MAJOR" -eq 5 && "$KERNEL_MINOR" -ge 7 ]]; then
        pass "内核版本 $(uname -r)（≥ 5.7，支持 BPF LSM）"
    else
        fail "内核版本 $(uname -r) < 5.7，不支持 BPF LSM"
    fi

    # 2. BPF LSM
    if grep -q "bpf" /sys/kernel/security/lsm 2>/dev/null; then
        pass "BPF LSM 已启用: $(cat /sys/kernel/security/lsm)"
    else
        fail "BPF LSM 未启用"
        info "启用方法: 在 GRUB_CMDLINE_LINUX 中添加 lsm=lockdown,capability,landlock,yama,bpf"
    fi

    # 3. bpftool
    if command -v bpftool &>/dev/null; then
        pass "bpftool 已安装: $(bpftool version 2>/dev/null | head -1)"
    else
        fail "bpftool 未安装"
    fi

    # 4. clang
    if command -v clang &>/dev/null; then
        pass "clang 已安装: $(clang --version 2>/dev/null | head -1)"
    else
        warn "clang 未安装"
    fi

    # 5. 控制工具
    if [[ -x "${TOOLS_DIR}/block_exec_ctl" ]]; then
        pass "block_exec_ctl 已编译"
    else
        warn "block_exec_ctl 未编译"
    fi

    # 6. eBPF 程序
    if [[ -f "${EBPF_DIR}/block_exec.bpf.o" ]]; then
        pass "eBPF 程序已编译"
    else
        warn "eBPF 程序未编译"
    fi

    # 7. 程序加载状态
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

#=============================================================
# 主流程
#=============================================================
main() {
    # 初始化响应引擎
    if declare -f init_response_engine &>/dev/null; then
        init_response_engine
    fi

    # 检测阶段
    for phase in \
        phase_detect_os \
        phase_install_tools \
        phase_install_yara \
        phase_check_memshell \
        phase_check_rootkit \
        phase_check_integrity \
        phase_check_system \
        phase_check_backdoor \
        phase_check_webshell \
        phase_check_nacos \
        phase_check_log_audit \
        phase_check_web_log \
        phase_check_baseline \
        phase_check_container \
        phase_check_falco \
        phase_report
    do
        if declare -f "$phase" &>/dev/null; then
            "$phase" || warn "阶段 $phase 执行异常"
        else
            warn "阶段函数 $phase 未定义，跳过"
        fi
    done

    # 响应汇总
    if declare -f response_summary &>/dev/null; then
        response_summary
    fi

    # 定时任务配置
    if $SETUP_SCHEDULE && declare -f setup_schedule &>/dev/null; then
        setup_schedule
    fi
}

main

#=============================================================
# 退出码
#=============================================================
if [[ "${RESPONSE_ACTIONS_FAILED:-0}" -gt 0 ]]; then
    log "部分响应动作执行失败: $RESPONSE_ACTIONS_FAILED 项"
    exit 2
elif [[ "${FAIL_COUNT:-0}" -gt 0 ]]; then
    exit 1
fi

log "摘要文件: $SUMMARY_FILE"
exit 0