#!/bin/bash
#=============================================================
# lib/common.sh — 公共函数与全局状态
# 功能: 颜色 | 计数器 | 数组 | 日志 | JSON | 判定 | 白名单
#       | 修复建议 | IMDS | 包安装 | 安全计数工具
# 修复:
#   1. 全局数组显式初始化为空（避免 set -u 报错）
#   2. 外部依赖变量提供默认值
#   3. 新增 to_number/count_matches/count_matches_stdin/count_lines
#      解决 grep -c ... || echo 0 输出 "0\n0" 的语法陷阱
#=============================================================

#=============================================================
# 一、颜色定义
#=============================================================
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

#=============================================================
# 二、全局计数器
#=============================================================
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
INFO_COUNT=0

#=============================================================
# 三、全局数组：显式初始化为空
#=============================================================
declare -ga FAIL_MESSAGES=()
declare -ga WARN_MESSAGES=()
declare -ga FINDINGS_ARRAY=()

FINDINGS_JSON="[]"

#=============================================================
# 四、工具可用性标记
#=============================================================
HAS_MEMSHELL_DETECTOR=false
HAS_KMBA=false
HAS_RKHUNTER=false
HAS_CHKROOTKIT=false
HAS_UNHIDE=false
HAS_AIDE=false
HAS_LYNIS=false
HAS_YARA=false
HAS_DOCKER=false
HAS_FALCO=false
HAS_AUDITD=false

#=============================================================
# 五、系统探测结果
#=============================================================
DISTRO_ID="unknown"
DISTRO_VER="unknown"
DISTRO_CODENAME="unknown"
DISTRO_FAMILY="unknown"
OS_PRETTY="unknown"
PKG_MGR=""
EPEL_NEEDED=false
PKG_JDK=""
PKG_RKHUNTER=""
PKG_CHKROOTKIT=""
PKG_UNHIDE=""
PKG_AIDE=""
PKG_LYNIS=""
IMDS_TOKEN=""

#=============================================================
# 六、外部依赖变量默认值
#=============================================================
: "${SCRIPT_DIR:=/usr/local/bin/sec_audit}"
: "${LIB_DIR:=${SCRIPT_DIR}/lib}"
: "${CONF_DIR:=${SCRIPT_DIR}/conf}"
: "${RULES_DIR:=${SCRIPT_DIR}/rules}"
: "${EBPF_DIR:=${SCRIPT_DIR}/ebpf}"
: "${TOOLS_DIR:=/opt/sec_audit/tools}"
: "${REPORT_BASE_DIR:=/var/log/sec_audit}"
: "${BASELINE_BASE_DIR:=/var/lib/sec_audit}"
: "${WHITELIST_FILE:=${CONF_DIR}/whitelist.conf}"
: "${REMEDIATION_FILE:=${CONF_DIR}/remediation.conf}"

#=============================================================
# 七、日志函数
#=============================================================
init_report() {
    : "${REPORT_FILE:=${REPORT_BASE_DIR}/audit_$(date +%Y%m%d_%H%M%S).log}"
    : "${INSTALL_LOG:=${REPORT_BASE_DIR}/install_$(date +%Y%m%d_%H%M%S).log}"

    mkdir -p "$REPORT_BASE_DIR"
    : > "$REPORT_FILE"
    : > "$INSTALL_LOG"
}

log()    { echo -e "$*" | tee -a "$REPORT_FILE"; }
plog()   { echo -e "$*" | tee -a "$INSTALL_LOG"; }
info()   { INFO_COUNT=$((INFO_COUNT+1)); log "${CYAN}[INFO]${NC} $*"; }
section(){ log ""; log "============================================================"; log "  $*"; log "============================================================"; }

#=============================================================
# 八、JSON 生成
#=============================================================
add_finding() {
    local severity="$1"
    local message="$2"

    message=${message//\\/\\\\}
    message=${message//\"/\\\"}
    message=${message//$'\n'/ }
    message=${message//$'\t'/ }
    message=${message//$'\r'/}

    if [[ "$FINDINGS_JSON" == "[]" ]]; then
        FINDINGS_JSON="[{\"severity\":\"${severity}\",\"message\":\"${message}\"}]"
    else
        FINDINGS_JSON="${FINDINGS_JSON%]},{\"severity\":\"${severity}\",\"message\":\"${message}\"}]"
    fi
}

#=============================================================
# 九、判定函数
#=============================================================
pass() {
    PASS_COUNT=$((PASS_COUNT+1))
    log "${GREEN}[PASS]${NC} $*"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT+1))
    log "${RED}[FAIL]${NC} $*"
    add_finding "HIGH" "$1"
    FAIL_MESSAGES+=("$1")
}

warn() {
    WARN_COUNT=$((WARN_COUNT+1))
    log "${YELLOW}[WARN]${NC} $*"
    add_finding "MEDIUM" "$1"
    WARN_MESSAGES+=("$1")
}

#=============================================================
# 十、工具函数
#=============================================================
silent() { "$@" >/dev/null 2>&1; }

is_whitelisted() {
    [[ -f "$WHITELIST_FILE" ]] && grep -qF "$1" "$WHITELIST_FILE" 2>/dev/null
}

get_remediation() {
    local key="$1"
    [[ -f "$REMEDIATION_FILE" ]] || return
    grep "^${key}=" "$REMEDIATION_FILE" 2>/dev/null | head -1 | cut -d= -f2-
}

show_remediation() {
    local key="$1"
    local cmd
    cmd=$(get_remediation "$key")
    [[ -n "$cmd" ]] && log "       ${BOLD}修复:${NC} $cmd"
}

#=============================================================
# 十一、AWS IMDS
#=============================================================
init_imds_token() {
    IMDS_TOKEN=$(curl -s -m 2 -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || true)
}

imds_get() {
    [[ -z "$IMDS_TOKEN" ]] && return
    curl -s -m 2 -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" \
        "http://169.254.169.254/latest/meta-data/$1" 2>/dev/null
}

#=============================================================
# 十二、包管理器工具函数
#=============================================================
pkg_install() {
    local pkg="$1"
    local verify_cmd="${2:-$1}"
    plog "安装 $pkg ..."

    case "${PKG_MGR:-}" in
        apt-get)
            apt-get update >> "$INSTALL_LOG" 2>&1 || true
            DEBIAN_FRONTEND=noninteractive apt-get install -y \
                -o Dpkg::Options::="--force-confdef" \
                -o Dpkg::Options::="--force-confold" \
                -o Acquire::http::Timeout=30 \
                -o Acquire::https::Timeout=30 \
                -o Acquire::Retries=2 \
                "$pkg" >> "$INSTALL_LOG" 2>&1
            ;;
        dnf|yum)
            $PKG_MGR install -y --setopt=timeout=30 --setopt=retries=2 \
                "$pkg" >> "$INSTALL_LOG" 2>&1
            ;;
        *)
            plog "错误: 无可用包管理器"
            return 1
            ;;
    esac

    if command -v "$verify_cmd" &>/dev/null; then
        return 0
    fi
    case "${PKG_MGR:-}" in
        apt-get) dpkg -s "$pkg" &>/dev/null ;;
        dnf|yum) rpm -q "$pkg" &>/dev/null ;;
    esac
}

fix_dpkg_state() {
    [[ "${PKG_MGR:-}" != "apt-get" ]] && return 0
    if dpkg --audit 2>/dev/null | grep -q .; then
        plog "检测到 dpkg 未完成事务，正在修复..."
        DEBIAN_FRONTEND=noninteractive dpkg --configure -a >> "$INSTALL_LOG" 2>&1 || true
        apt-get install -f -y >> "$INSTALL_LOG" 2>&1 || true
    fi
}

preset_debconf() {
    [[ "${PKG_MGR:-}" != "apt-get" ]] && return 0
    echo "rkhunter rkhunter/apt_autogen boolean true"  | debconf-set-selections 2>/dev/null || true
    echo "rkhunter rkhunter/cron_daily_run boolean true" | debconf-set-selections 2>/dev/null || true
}

get_latest_github_tag() {
    local repo="$1"
    local tag
    tag=$(curl -sL --max-time 15 \
        "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null \
        | grep -oP '"tag_name":\s*"\K[^"]+' | head -1 || true)
    [[ -z "$tag" ]] && tag=$(curl -sL --max-time 15 \
        "https://api.github.com/repos/${repo}/tags" 2>/dev/null \
        | grep -oP '"name":\s*"\K[^"]+' | head -1 || true)
    echo "$tag"
}

#=============================================================
# 十三、安全计数工具函数（核心修复）
#=============================================================
# 说明:
#   grep -c 在无匹配时输出 "0" 且退出码 1，导致 `|| echo 0` 输出 "0\n0"
#   在 [[ "$VAR" -gt 0 ]] 中触发语法错误
#   以下函数保证返回纯数字
#=============================================================

# 将任意值转为纯数字（只取第一行，去除空白，非法值转 0）
to_number() {
    local val="${1:-0}"
    val=$(echo "$val" | head -1 | tr -d '[:space:]')
    [[ "$val" =~ ^[0-9]+$ ]] || val=0
    echo "$val"
}

# 安全统计文件中匹配 PATTERN 的行数
# 用法: count=$(count_matches "PATTERN" "FILE")
count_matches() {
    local pattern="$1"
    local file="$2"

    if [[ ! -f "$file" ]]; then
        echo "0"
        return 0
    fi

    local count
    count=$(grep -c "$pattern" "$file" 2>/dev/null || true)
    to_number "$count"
}

# 安全统计管道输入中匹配 PATTERN 的行数
# 用法: echo "$data" | count_matches_stdin "PATTERN"
count_matches_stdin() {
    local pattern="$1"
    local count
    count=$(grep -c "$pattern" 2>/dev/null || true)
    to_number "$count"
}

# 安全统计文件行数
# 用法: lines=$(count_lines "FILE")
count_lines() {
    local file="$1"

    if [[ ! -f "$file" ]]; then
        echo "0"
        return 0
    fi

    local count
    count=$(wc -l < "$file" 2>/dev/null || true)
    to_number "$count"
}

# 安全统计管道输入的行数
# 用法: echo "$data" | count_lines_stdin
count_lines_stdin() {
    local count
    count=$(wc -l 2>/dev/null || true)
    to_number "$count"
}

#=============================================================
# 十四、兼容性函数
#=============================================================
reset_counters() {
    PASS_COUNT=0
    FAIL_COUNT=0
    WARN_COUNT=0
    INFO_COUNT=0
    FAIL_MESSAGES=()
    WARN_MESSAGES=()
    FINDINGS_JSON="[]"
}