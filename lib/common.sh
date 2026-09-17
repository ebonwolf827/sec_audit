#!/bin/bash
#=============================================================
# lib/common.sh — 公共函数与全局状态
#=============================================================

# ---------- 颜色 ----------
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ---------- 计数器 ----------
PASS_COUNT=0; FAIL_COUNT=0; WARN_COUNT=0; INFO_COUNT=0
FINDINGS_JSON="[]"

# ---------- 工具可用性 ----------
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

# ---------- 系统探测结果 ----------
DISTRO_ID="unknown"
DISTRO_VER="unknown"
DISTRO_CODENAME="unknown"
DISTRO_FAMILY="unknown"
OS_PRETTY="unknown"
PKG_MGR=""
EPEL_NEEDED=false
PKG_JDK=""
IMDS_TOKEN=""

# ---------- 日志 ----------
init_report() {
    : > "$REPORT_FILE"
    : > "$INSTALL_LOG"
}

log()    { echo -e "$*" | tee -a "$REPORT_FILE"; }
plog()   { echo -e "$*" | tee -a "$INSTALL_LOG"; }
info()   { INFO_COUNT=$((INFO_COUNT+1)); log "${CYAN}[INFO]${NC} $*"; }
section(){ log ""; log "============================================================"; log "  $*"; log "============================================================"; }

# ---------- JSON 生成 ----------
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

# ---------- 判定 ----------
pass()   { PASS_COUNT=$((PASS_COUNT+1)); log "${GREEN}[PASS]${NC} $*"; }
fail()   { FAIL_COUNT=$((FAIL_COUNT+1)); log "${RED}[FAIL]${NC} $*"; add_finding "HIGH" "$1"; }
warn()   { WARN_COUNT=$((WARN_COUNT+1)); log "${YELLOW}[WARN]${NC} $*"; add_finding "MEDIUM" "$1"; }

# ---------- 工具函数 ----------
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

# ---------- IMDS ----------
init_imds_token() {
    IMDS_TOKEN=$(curl -s -m 2 -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || true)
}

imds_get() {
    [[ -z "$IMDS_TOKEN" ]] && return
    curl -s -m 2 -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" \
        "http://169.254.169.254/latest/meta-data/$1" 2>/dev/null
}

# ---------- 包安装 ----------
pkg_install() {
    local pkg="$1"
    local verify_cmd="${2:-$1}"
    plog "安装 $pkg ..."

    case "$PKG_MGR" in
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
        *) plog "错误: 无可用包管理器"; return 1 ;;
    esac

    command -v "$verify_cmd" &>/dev/null && return 0
    case "$PKG_MGR" in
        apt-get) dpkg -s "$pkg" &>/dev/null ;;
        dnf|yum) rpm -q "$pkg" &>/dev/null ;;
    esac
}

fix_dpkg_state() {
    [[ "$PKG_MGR" != "apt-get" ]] && return 0
    if dpkg --audit 2>/dev/null | grep -q .; then
        plog "修复 dpkg 未完成事务..."
        DEBIAN_FRONTEND=noninteractive dpkg --configure -a >> "$INSTALL_LOG" 2>&1 || true
        apt-get install -f -y >> "$INSTALL_LOG" 2>&1 || true
    fi
}

preset_debconf() {
    [[ "$PKG_MGR" != "apt-get" ]] && return 0
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