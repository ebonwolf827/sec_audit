#!/bin/bash
#=============================================================
# lib/response.sh — 响应动作引擎
# 分级响应 | 取证优先 | 白名单保护 | 干跑验证 | 审计日志
# 动作: 文件隔离 | 进程终止 | IP 封禁 | 账户锁定 | 主机隔离
#       | eBPF 进程执行阻断 (BLOCK_EXEC)
#=============================================================

RESPONSE_LEVEL="${RESPONSE_LEVEL:-1}"
DRY_RUN="${DRY_RUN:-false}"

# ---------- 目录 ----------
RESPONSE_BASE_DIR="/var/lib/sec_audit/response"
RESPONSE_QUARANTINE_DIR="${RESPONSE_BASE_DIR}/quarantine"
RESPONSE_EVIDENCE_DIR="${RESPONSE_BASE_DIR}/evidence"
RESPONSE_LOG="${RESPONSE_BASE_DIR}/response_actions.log"
RESPONSE_ROLLBACK_DIR="${RESPONSE_BASE_DIR}/rollback"
RESPONSE_WHITELIST="${CONF_DIR}/response_whitelist.conf"

# ---------- 动作类型 ----------
ACTION_QUARANTINE_FILE="QUARANTINE_FILE"
ACTION_KILL_PROCESS="KILL_PROCESS"
ACTION_BLOCK_IP="BLOCK_IP"
ACTION_LOCK_ACCOUNT="LOCK_ACCOUNT"
ACTION_REMOVE_PERSISTENCE="REMOVE_PERSISTENCE"
ACTION_DISABLE_SERVICE="DISABLE_SERVICE"
ACTION_ISOLATE_HOST="ISOLATE_HOST"
ACTION_FIX_PERMISSION="FIX_PERMISSION"
ACTION_BLOCK_EXEC="BLOCK_EXEC"

# ---------- 硬编码保护名单 ----------
PROTECTED_PIDS=(1)
PROTECTED_PROCESSES=("systemd" "sshd" "init" "kernel" "kthreadd" "kworker" "migration" "containerd" "docker")
PROTECTED_USERS=("root" "systemd-network" "systemd-resolve" "messagebus" "daemon")
PROTECTED_IPS=("127.0.0.1" "::1" "169.254.169.254")

# ---------- eBPF 阻断相关 ----------
EBPF_CTL="${TOOLS_DIR}/block_exec_ctl"
EBPF_PIN_DIR="/sys/fs/bpf/block_exec"
EBPF_PROG_OBJ="${SCRIPT_DIR}/ebpf/block_exec.bpf.o"

# ---------- 响应统计 ----------
RESPONSE_ACTIONS_TAKEN=0
RESPONSE_ACTIONS_DRY=0
RESPONSE_ACTIONS_SKIPPED=0
RESPONSE_ACTIONS_FAILED=0

#=============================================================
# 初始化
#=============================================================
init_response_engine() {
    mkdir -p "$RESPONSE_QUARANTINE_DIR" "$RESPONSE_EVIDENCE_DIR" "$RESPONSE_ROLLBACK_DIR"
    : > "$RESPONSE_LOG"

    if [[ "$RESPONSE_LEVEL" -ge 4 ]] && ! $DRY_RUN; then
        warn "响应引擎已启用 L${RESPONSE_LEVEL} 高风险处置能力"
        warn "所有动作将先取证再执行，详见 $RESPONSE_LOG"
    fi

    # 尝试初始化 eBPF 阻断模块（仅 L4+ 且非干跑时）
    if [[ "$RESPONSE_LEVEL" -ge 4 ]] && ! $DRY_RUN; then
        init_block_exec
    fi
}

#=============================================================
# 审计日志
#=============================================================
response_audit() {
    local action="$1" target="$2" reason="$3" result="$4" details="${5:-}"
    local ts mode
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    mode=$($DRY_RUN && echo "DRY_RUN" || echo "EXECUTE")

    printf '[%s] [L%s] [%s] action=%s target=%s reason=%s result=%s %s\n' \
        "$ts" "$RESPONSE_LEVEL" "$mode" "$action" "$target" "$reason" "$result" "$details" \
        >> "$RESPONSE_LOG"
}

#=============================================================
# 白名单检查
#=============================================================
is_protected_pid() {
    local pid="$1"
    for p in "${PROTECTED_PIDS[@]}"; do [[ "$pid" == "$p" ]] && return 0; done
    local comm
    comm=$(cat "/proc/$pid/comm" 2>/dev/null || true)
    for name in "${PROTECTED_PROCESSES[@]}"; do [[ "$comm" == "$name" ]] && return 0; done
    return 1
}

is_protected_user() {
    local user="$1"
    for u in "${PROTECTED_USERS[@]}"; do [[ "$user" == "$u" ]] && return 0; done
    return 1
}

is_protected_ip() {
    local ip="$1"
    for p in "${PROTECTED_IPS[@]}"; do [[ "$ip" == "$p" ]] && return 0; done
    [[ "$ip" =~ ^(10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168\.|169\.254\.) ]] && return 0
    return 1
}

is_protected_path() {
    local path="$1"
    [[ -f "$RESPONSE_WHITELIST" ]] || return 1
    grep -qF "$path" "$RESPONSE_WHITELIST" 2>/dev/null
}

is_protected_container() {
    local name="$1"
    [[ -f "$RESPONSE_WHITELIST" ]] || return 1
    grep -qF "container:$name" "$RESPONSE_WHITELIST" 2>/dev/null
}

#=============================================================
# 通用响应动作包装
#=============================================================
response_execute() {
    local action="$1" target="$2" reason="$3" min_level="$4" exec_func="$5"
    shift 5

    if [[ "$RESPONSE_LEVEL" -lt "$min_level" ]]; then
        RESPONSE_ACTIONS_SKIPPED=$((RESPONSE_ACTIONS_SKIPPED+1))
        response_audit "$action" "$target" "$reason" "SKIP_LEVEL" "need=L${min_level}"
        return 0
    fi

    if $DRY_RUN; then
        RESPONSE_ACTIONS_DRY=$((RESPONSE_ACTIONS_DRY+1))
        response_audit "$action" "$target" "$reason" "DRY_RUN" "func=$exec_func args=$*"
        log "       ${YELLOW}[DRY_RUN]${NC} 将执行 $action: $target"
        return 0
    fi

    if "$exec_func" "$target" "$reason" "$@"; then
        RESPONSE_ACTIONS_TAKEN=$((RESPONSE_ACTIONS_TAKEN+1))
        response_audit "$action" "$target" "$reason" "SUCCESS"
        return 0
    else
        RESPONSE_ACTIONS_FAILED=$((RESPONSE_ACTIONS_FAILED+1))
        response_audit "$action" "$target" "$reason" "FAILED"
        return 1
    fi
}

#=============================================================
# 动作 1: 隔离文件（L3）
#=============================================================
respond_quarantine_file() {
    local file="$1" reason="$2"
    [[ -f "$file" ]] || return 1
    is_protected_path "$file" && {
        response_audit "$ACTION_QUARANTINE_FILE" "$file" "$reason" "SKIP_WHITELIST"
        return 1
    }

    local ts evidence quarantine_path
    ts=$(date +%s)
    evidence="${RESPONSE_EVIDENCE_DIR}/${ts}_$(basename "$file").meta"
    {
        echo "original_path: $file"
        echo "size: $(stat -c '%s' "$file" 2>/dev/null)"
        echo "owner: $(stat -c '%U:%G' "$file" 2>/dev/null)"
        echo "perm: $(stat -c '%a' "$file" 2>/dev/null)"
        echo "mtime: $(stat -c '%y' "$file" 2>/dev/null)"
        echo "sha256: $(sha256sum "$file" 2>/dev/null | awk '{print $1}')"
        echo "quarantine_time: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "reason: $reason"
    } > "$evidence"

    quarantine_path="${RESPONSE_QUARANTINE_DIR}/${ts}_$(basename "$file")"
    cp -a "$file" "$quarantine_path" 2>/dev/null

    if command -v chattr &>/dev/null; then
        chattr +i "$file" 2>/dev/null || chmod 000 "$file" 2>/dev/null
    else
        chmod 000 "$file" 2>/dev/null
    fi

    log "       ${RED}[响应]${NC} 已隔离文件: $file → $quarantine_path"
    log "              证据: $evidence"
    echo "quarantine $file $quarantine_path $ts" >> "${RESPONSE_ROLLBACK_DIR}/actions.log"
    return 0
}

#=============================================================
# 动作 2: 终止进程（L4）
#=============================================================
respond_kill_process() {
    local pid="$1" reason="$2"
    [[ -d "/proc/$pid" ]] || return 1
    is_protected_pid "$pid" && {
        response_audit "$ACTION_KILL_PROCESS" "$pid" "$reason" "SKIP_PROTECTED"
        return 1
    }

    local ts evidence_dir
    ts=$(date +%s)
    evidence_dir="${RESPONSE_EVIDENCE_DIR}/proc_${pid}_${ts}"
    mkdir -p "$evidence_dir"

    {
        echo "=== cmdline ==="
        tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null; echo ""
        echo "=== status ==="
        cat "/proc/$pid/status" 2>/dev/null
        echo "=== environ ==="
        tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null
        echo "=== cwd ==="
        readlink "/proc/$pid/cwd" 2>/dev/null
        echo "=== exe ==="
        readlink "/proc/$pid/exe" 2>/dev/null
        echo "=== network ==="
        ss -tnp 2>/dev/null | grep "pid=$pid"
    } > "${evidence_dir}/process_info.txt"

    [[ -r "/proc/$pid/exe" ]] && cp "/proc/$pid/exe" "${evidence_dir}/exe" 2>/dev/null || true

    kill -STOP "$pid" 2>/dev/null
    sleep 1
    kill -TERM "$pid" 2>/dev/null
    sleep 2
    kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null

    if ! kill -0 "$pid" 2>/dev/null; then
        log "       ${RED}[响应]${NC} 已终止进程: PID=$pid ($reason)"
        log "              证据: $evidence_dir"
        echo "kill $pid $ts" >> "${RESPONSE_ROLLBACK_DIR}/actions.log"
        return 0
    fi
    return 1
}

#=============================================================
# 动作 3: 封禁 IP（L4）
#=============================================================
respond_block_ip() {
    local ip="$1" reason="$2"
    [[ -z "$ip" ]] && return 1
    is_protected_ip "$ip" && {
        response_audit "$ACTION_BLOCK_IP" "$ip" "$reason" "SKIP_PROTECTED"
        return 1
    }
    iptables -C INPUT -s "$ip" -j DROP 2>/dev/null && return 0

    local ts evidence
    ts=$(date +%s)
    evidence="${RESPONSE_EVIDENCE_DIR}/ip_${ip//\//_}_${ts}.log"
    {
        echo "ip: $ip"
        echo "block_time: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "reason: $reason"
        echo "=== connections ==="
        ss -tnp 2>/dev/null | grep "$ip"
    } > "$evidence"

    iptables -I INPUT 1 -s "$ip" -j DROP 2>/dev/null
    iptables -I OUTPUT 1 -d "$ip" -j DROP 2>/dev/null

    command -v iptables-save &>/dev/null && [[ -d /etc/iptables ]] && \
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true

    log "       ${RED}[响应]${NC} 已封禁 IP: $ip ($reason)"
    echo "block_ip $ip $ts" >> "${RESPONSE_ROLLBACK_DIR}/actions.log"
    return 0
}

#=============================================================
# 动作 4: 锁定账户（L4）
#=============================================================
respond_lock_account() {
    local user="$1" reason="$2"
    is_protected_user "$user" && {
        response_audit "$ACTION_LOCK_ACCOUNT" "$user" "$reason" "SKIP_PROTECTED"
        return 1
    }
    id "$user" &>/dev/null || return 1

    local ts evidence
    ts=$(date +%s)
    evidence="${RESPONSE_EVIDENCE_DIR}/user_${user}_${ts}.log"
    {
        echo "user: $user"
        echo "lock_time: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "reason: $reason"
        echo "=== passwd entry ==="
        grep "^${user}:" /etc/passwd
        echo "=== groups ==="
        groups "$user" 2>/dev/null
    } > "$evidence"

    usermod -L "$user" 2>/dev/null
    usermod -s /sbin/nologin "$user" 2>/dev/null

    while IFS= read -r pid; do
        [[ -z "$pid" ]] && continue
        kill -TERM "$pid" 2>/dev/null
    done < <(pgrep -u "$user" 2>/dev/null || true)

    log "       ${RED}[响应]${NC} 已锁定账户: $user ($reason)"
    echo "lock_user $user $ts" >> "${RESPONSE_ROLLBACK_DIR}/actions.log"
    return 0
}

#=============================================================
# 动作 5: 移除持久化（L3）
#=============================================================
respond_remove_persistence() {
    local target="$1" reason="$2"
    local type="${target%%:*}"
    local value="${target##*:}"
    is_protected_path "$value" && return 1

    local ts evidence
    ts=$(date +%s)
    evidence="${RESPONSE_EVIDENCE_DIR}/persistence_${type}_$(basename "$value")_${ts}.log"
    {
        echo "type: $type"
        echo "target: $value"
        echo "reason: $reason"
        case "$type" in
            crontab) cat "$value" 2>/dev/null ;;
            systemd) cat "/etc/systemd/system/${value}.service" 2>/dev/null ;;
        esac
    } > "$evidence"

    case "$type" in
        crontab)
            cp "$value" "${RESPONSE_QUARANTINE_DIR}/${ts}_$(basename "$value")" 2>/dev/null
            rm -f "$value" 2>/dev/null
            ;;
        systemd)
            systemctl stop "$value" 2>/dev/null
            systemctl disable "$value" 2>/dev/null
            ;;
    esac

    log "       ${RED}[响应]${NC} 已移除持久化: $target ($reason)"
    echo "remove_persistence $target $ts" >> "${RESPONSE_ROLLBACK_DIR}/actions.log"
    return 0
}

#=============================================================
# 动作 6: 禁用服务（L3）
#=============================================================
respond_disable_service() {
    local service="$1" reason="$2"
    systemctl list-unit-files "${service}.service" &>/dev/null || return 1
    systemctl stop "$service" 2>/dev/null
    systemctl disable "$service" 2>/dev/null
    log "       ${RED}[响应]${NC} 已禁用服务: $service ($reason)"
    echo "disable_service $service $(date +%s)" >> "${RESPONSE_ROLLBACK_DIR}/actions.log"
    return 0
}

#=============================================================
# 动作 7: 修复文件权限（L3）
#=============================================================
respond_fix_permission() {
    local target="$1" reason="$2"
    local expected_perm="${3:-}"
    [[ -z "$expected_perm" ]] && return 1
    local file="${target##*:}"
    [[ -f "$file" ]] || return 1
    is_protected_path "$file" && return 1
    chmod "$expected_perm" "$file" 2>/dev/null
    chown root:root "$file" 2>/dev/null
    log "       ${GREEN}[响应]${NC} 已修复权限: $file → $expected_perm"
    return 0
}

#=============================================================
# 动作 8: 主机隔离（L5）
#=============================================================
respond_isolate_host() {
    local reason="$1"
    [[ "$RESPONSE_LEVEL" -lt 5 ]] && return 1
    log "       ${RED}[响应]${NC} 执行主机隔离（保留 SSH 管理通道）"
    local mgmt_ips="${MGMT_IPS:-}"
    for ip in $mgmt_ips; do
        iptables -I INPUT 1 -s "$ip" -p tcp --dport 22 -j ACCEPT 2>/dev/null
    done
    iptables -I INPUT 2 -j DROP 2>/dev/null
    log "              恢复命令: iptables -F INPUT"
    echo "isolate_host $(date +%s)" >> "${RESPONSE_ROLLBACK_DIR}/actions.log"
    return 0
}

#=============================================================
# 动作 9: eBPF 进程执行阻断（L4）
#=============================================================
init_block_exec() {
    # 内核版本检查（需 5.7+ 支持 BPF LSM）
    local kernel_major kernel_minor
    kernel_major=$(uname -r | cut -d. -f1)
    kernel_minor=$(uname -r | cut -d. -f2)

    if [[ "$kernel_major" -lt 5 ]] || \
       [[ "$kernel_major" -eq 5 && "$kernel_minor" -lt 7 ]]; then
        log "       ${YELLOW}[INFO]${NC} 内核版本过低（需 5.7+），BLOCK_EXEC 不可用"
        return 1
    fi

    # BPF LSM 检查
    if ! grep -q "bpf" /sys/kernel/security/lsm 2>/dev/null; then
        log "       ${YELLOW}[INFO]${NC} BPF LSM 未启用，BLOCK_EXEC 不可用"
        log "              启用: 在 /etc/default/grub 的 GRUB_CMDLINE_LINUX 中添加 lsm=...,bpf"
        return 1
    fi

    # 控制工具检查
    if [[ ! -x "$EBPF_CTL" ]]; then
        log "       ${YELLOW}[INFO]${NC} block_exec_ctl 未安装，BLOCK_EXEC 不可用"
        return 1
    fi

    # 程序文件检查
    if [[ ! -f "$EBPF_PROG_OBJ" ]]; then
        log "       ${YELLOW}[INFO]${NC} eBPF 程序未编译: $EBPF_PROG_OBJ"
        return 1
    fi

    mkdir -p "$EBPF_PIN_DIR" 2>/dev/null

    # 加载 eBPF 程序
    if [[ ! -f "${EBPF_PIN_DIR}/procs" ]]; then
        log "       ${CYAN}[INFO]${NC} 正在加载 eBPF 阻断程序..."
        if ! bpftool prog loadall "$EBPF_PROG_OBJ" "$EBPF_PIN_DIR" 2>/dev/null; then
            log "       ${YELLOW}[INFO]${NC} eBPF 程序加载失败"
            return 1
        fi
        bpftool prog attach pinned "${EBPF_PIN_DIR}/block_exec_hook" \
            lsm bprm_check_security 2>/dev/null || true
    fi

    log "       ${GREEN}[INFO]${NC} BLOCK_EXEC 已就绪"
    return 0
}

respond_block_exec() {
    local target="$1" reason="$2"

    if [[ ! -x "$EBPF_CTL" ]]; then
        response_audit "$ACTION_BLOCK_EXEC" "$target" "$reason" "SKIP_UNAVAILABLE"
        return 1
    fi

    local type="${target%%:*}"
    local value="${target##*:}"

    if [[ -z "$value" || "$value" == "$target" ]]; then
        response_audit "$ACTION_BLOCK_EXEC" "$target" "$reason" "SKIP_INVALID_FORMAT"
        return 1
    fi

    # 白名单检查
    if [[ "$type" == "proc" ]]; then
        for name in "${PROTECTED_PROCESSES[@]}"; do
            [[ "$value" == "$name" ]] && {
                response_audit "$ACTION_BLOCK_EXEC" "$target" "$reason" "SKIP_PROTECTED"
                return 1
            }
        done
    fi

    # 取证
    local ts evidence
    ts=$(date +%s)
    evidence="${RESPONSE_EVIDENCE_DIR}/block_exec_${ts}.log"
    {
        echo "type: $type"
        echo "value: $value"
        echo "reason: $reason"
        echo "block_time: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "kernel: $(uname -r)"
        echo "bpf_lsm: $(cat /sys/kernel/security/lsm 2>/dev/null)"
    } > "$evidence"

    # 下发规则
    local result
    case "$type" in
        proc)
            result=$("$EBPF_CTL" add-proc "$value" 2>&1)
            ;;
        pattern)
            result=$("$EBPF_CTL" add-pattern "$value" 2>&1)
            ;;
        *)
            response_audit "$ACTION_BLOCK_EXEC" "$target" "$reason" "SKIP_UNKNOWN_TYPE"
            return 1
            ;;
    esac

    if echo "$result" | grep -q "已添加"; then
        log "       ${RED}[响应]${NC} 已阻断进程执行: $target ($reason)"
        echo "block_exec $target $ts" >> "${RESPONSE_ROLLBACK_DIR}/actions.log"
        return 0
    else
        log "       ${YELLOW}[响应]${NC} 阻断失败: $result"
        response_audit "$ACTION_BLOCK_EXEC" "$target" "$reason" "FAILED" "$result"
        return 1
    fi
}

respond_unblock_exec() {
    local target="$1"
    local type="${target%%:*}"
    local value="${target##*:}"

    case "$type" in
        proc)    "$EBPF_CTL" del-proc "$value" 2>/dev/null ;;
        pattern) "$EBPF_CTL" del-pattern "$value" 2>/dev/null ;;
    esac
    log "       ${GREEN}[响应]${NC} 已解除阻断: $target"
}

#=============================================================
# 批量响应接口
#=============================================================
act_quarantine() {
    local file="$1" reason="$2" severity="${3:-HIGH}"
    case "$severity" in
        CRITICAL|HIGH) response_execute "$ACTION_QUARANTINE_FILE" "$file" "$reason" 3 respond_quarantine_file ;;
        *) info "低风险项，仅记录: $file" ;;
    esac
}

act_kill() {
    local pid="$1" reason="$2" severity="${3:-HIGH}"
    [[ "$severity" == "CRITICAL" || "$severity" == "HIGH" ]] && \
        response_execute "$ACTION_KILL_PROCESS" "$pid" "$reason" 4 respond_kill_process || \
        info "低风险进程，仅记录: PID=$pid"
}

act_block_ip() {
    local ip="$1" reason="$2" severity="${3:-HIGH}"
    [[ "$severity" == "CRITICAL" || "$severity" == "HIGH" ]] && \
        response_execute "$ACTION_BLOCK_IP" "$ip" "$reason" 4 respond_block_ip || \
        info "低风险 IP，仅记录: $ip"
}

act_lock_account() {
    local user="$1" reason="$2" severity="${3:-HIGH}"
    [[ "$severity" == "CRITICAL" ]] && \
        response_execute "$ACTION_LOCK_ACCOUNT" "$user" "$reason" 4 respond_lock_account || \
        warn "账户 $user 需人工确认: $reason"
}

act_remove_persistence() {
    local target="$1" reason="$2"
    response_execute "$ACTION_REMOVE_PERSISTENCE" "$target" "$reason" 3 respond_remove_persistence
}

act_fix_permission() {
    local file="$1" expected="$2" reason="$3"
    response_execute "$ACTION_FIX_PERMISSION" "file:$file" "$reason" 3 respond_fix_permission "$expected"
}

act_block_exec() {
    local target="$1" reason="$2" severity="${3:-CRITICAL}"
    if [[ "$severity" != "CRITICAL" ]]; then
        info "非 CRITICAL 级别，仅记录: $target"
        return 0
    fi
    response_execute "$ACTION_BLOCK_EXEC" "$target" "$reason" 4 respond_block_exec
}

#=============================================================
# 汇总与回滚
#=============================================================
response_summary() {
    section "响应动作汇总"

    log ""
    log "  响应级别: L${RESPONSE_LEVEL}$($DRY_RUN && echo ' [干跑模式]' || echo '')"
    log "  已执行动作: $RESPONSE_ACTIONS_TAKEN 项"
    log "  干跑预览:   $RESPONSE_ACTIONS_DRY 项"
    log "  跳过:       $RESPONSE_ACTIONS_SKIPPED 项"
    log "  执行失败:   $RESPONSE_ACTIONS_FAILED 项"

    # 组合响应统计
    if [[ -f "$RESPONSE_LOG" ]]; then
        local reverse_count
        reverse_count=$(grep -c "REVERSE_SHELL_RESPONSE" "$RESPONSE_LOG" 2>/dev/null || echo 0)
        [[ "$reverse_count" -gt 0 ]] && \
            log "  反弹 Shell 组合响应: $reverse_count 次"
    fi

    # eBPF 阻断统计
    if [[ -x "$EBPF_CTL" ]]; then
        log ""
        log "  --- eBPF 阻断统计 ---"
        "$EBPF_CTL" stats 2>/dev/null | while read -r line; do
            log "  $line"
        done
    fi

    log ""
    log "  审计日志:   $RESPONSE_LOG"
    log "  隔离目录:   $RESPONSE_QUARANTINE_DIR"
    log "  证据目录:   $RESPONSE_EVIDENCE_DIR"
    [[ -f "${RESPONSE_ROLLBACK_DIR}/actions.log" ]] && \
        log "  回滚记录:   ${RESPONSE_ROLLBACK_DIR}/actions.log"
}

response_rollback() {
    local action_log="${RESPONSE_ROLLBACK_DIR}/actions.log"
    [[ -f "$action_log" ]] || { echo "无回滚记录"; return 1; }
    echo "=== 可回滚的动作 ==="
    cat "$action_log"
    echo ""
    echo "回滚命令:"
    echo "  解除文件隔离: chattr -i <文件> && chmod 644 <文件>"
    echo "  解除 IP 封禁: iptables -D INPUT -s <IP> -j DROP && iptables -D OUTPUT -d <IP> -j DROP"
    echo "  解除账户锁定: usermod -U <用户> && usermod -s /bin/bash <用户>"
    echo "  解除主机隔离: iptables -F INPUT"
    echo "  解除进程阻断: ${EBPF_CTL} del-proc <进程名>"
    echo "  解除特征阻断: ${EBPF_CTL} del-pattern <特征>"
}