#!/bin/bash
#=============================================================
# lib/check_log_audit.sh — 阶段 7: 系统日志审计（内核级）
# 功能:
#   - SSH 成功/失败登录统计（Top10）
#   - auditd 规则基线检查（CIS 4.1.x）
#   - 日志完整性检测（权限/不可变属性/FSS）
#   - 内核日志异常检测（dmesg/Oops/taint）
#   - 反取证行为检测（history -c/dmesg -c/日志清空）
#   - 跨日志源关联分析
# 修复:
#   1. auditd 规则匹配改用正则，支持多 syscall 变体
#   2. 空数组访问使用 :- 保护
#   3. 外部依赖变量提供默认值
#=============================================================

#=============================================================
# 外部依赖变量默认值
#=============================================================
: "${REPORT_BASE_DIR:=/var/log/sec_audit}"
: "${REPORT_FILE:=${REPORT_BASE_DIR}/audit_$(date +%Y%m%d_%H%M%S).log}"
: "${CONF_DIR:=/usr/local/bin/sec_audit/conf}"
: "${WHITELIST_FILE:=${CONF_DIR}/whitelist.conf}"
: "${REMEDIATION_FILE:=${CONF_DIR}/remediation.conf}"

#=============================================================
# 日志源（运行时由 detect_log_source 填充）
#=============================================================
AUTH_LOG_FILE=""
LOG_SOURCE=""

#=============================================================
# auditd 状态
#=============================================================
HAS_AUDITD=false
AUDIT_LOG_FILE="/var/log/audit/audit.log"

#=============================================================
# 危险行为检测模式（应用层）
# 格式: "标签|严重级别|正则表达式"
#=============================================================
DANGEROUS_PATTERNS=(
    "SSH暴力破解|HIGH|Failed password.*from"
    "SSH无效用户|MEDIUM|Invalid user.*from"
    "sudo未授权|HIGH|NOT in sudoers"
    "sudo命令拒绝|MEDIUM|command not allowed"
    "sudo认证失败|MEDIUM|sudo:.*authentication failure"
    "用户创建|MEDIUM|useradd.*new user"
    "用户删除|MEDIUM|userdel.*delete user"
    "用户组变更|MEDIUM|groupadd|groupmod|groupdel"
    "密码修改|MEDIUM|passwd.*password changed"
    "权限提升|HIGH|su:.*session opened for user root"
    "SSH密钥添加|HIGH|Accepted publickey.*new key"
    "systemd服务变更|MEDIUM|Started.*\.service"
    "cron任务变更|MEDIUM|CRON.*CMD"
    "PAM认证失败|MEDIUM|pam_unix.*authentication failure"
    "可能的反向Shell|CRITICAL|/dev/tcp|bash -i|nc -e"
)

#=============================================================
# auditd 关键规则基线（CIS 4.1.x）
# 格式: "描述|正则模式"
# 使用正则支持多 syscall 变体，避免误报
#=============================================================
AUDITD_EXPECTED_RULES=(
    "passwd 文件监控|-w /etc/passwd -p wa"
    "shadow 文件监控|-w /etc/shadow -p wa"
    "group 文件监控|-w /etc/group -p wa"
    "gshadow 文件监控|-w /etc/gshadow -p wa"
    "sudoers 监控|-w /etc/sudoers -p wa"
    "sudoers.d 监控|-w /etc/sudoers.d/ -p wa"
    "sshd_config 监控|-w /etc/ssh/sshd_config -p wa"
    "PAM 配置监控|-w /etc/pam.d/ -p wa"
    "登录记录监控|-w /var/log/(lastlog|faillog|tallylog)"
    "内核模块加载|-a always,exit -F arch=b64.*-S (init_module|delete_module)"
    "execve 命令执行|-a always,exit -F arch=b64.*-S execve"
    "unlink 文件删除|-a always,exit -F arch=b64.*-S (unlink|unlinkat|rename)"
    "mount 挂载|-a always,exit -F arch=b64.*-S (mount|umount2?)"
    "chmod 权限变更|-a always,exit -F arch=b64.*-S (chmod|fchmod|fchmodat)"
    "chown 所有者变更|-a always,exit -F arch=b64.*-S (chown|fchown|fchownat|lchown)"
    "时间修改|-a always,exit -F arch=b64.*-S (adjtimex|settimeofday|clock_settime)"
)

#=============================================================
# 反取证行为模式
# 格式: "标签|严重级别|正则表达式"
#=============================================================
ANTI_FORENSICS_PATTERNS=(
    "历史命令清空|HIGH|history\\s+-c|unset\\s+HISTFILE|HISTFILE=/dev/null"
    "历史文件删除|HIGH|rm\\s+.*\\.bash_history|>\\s*.*\\.bash_history|shred\\s+.*history"
    "日志清空|CRITICAL|journalctl\\s+--vacuum|rm\\s+.*/var/log"
    "审计日志清空|CRITICAL|>\\s*/var/log/audit/audit\\.log|rm\\s+.*audit\\.log"
    "内核缓冲区清空|CRITICAL|dmesg\\s+-c|dmesg\\s+--clear"
    "防火墙清空|HIGH|iptables\\s+-F|iptables\\s+-X|nft\\s+flush"
)

#=============================================================
# 主入口
#=============================================================
phase_check_log_audit() {
    section "阶段 7: 系统日志审计（内核级）"

    detect_log_source
    detect_auditd

    if [[ -z "$LOG_SOURCE" && "$HAS_AUDITD" != "true" ]]; then
        warn "未找到可用的日志源或 auditd，跳过日志审计"
        return
    fi

    [[ -n "$LOG_SOURCE" ]] && info "应用日志源: $LOG_SOURCE"
    [[ "$HAS_AUDITD" == "true" ]] && info "auditd 日志: $AUDIT_LOG_FILE"

    # --- 应用层检测 ---
    audit_ssh_successful_logins
    audit_ssh_failed_logins
    audit_dangerous_activities

    # --- 内核级检测 ---
    check_auditd_rules
    check_log_integrity
    check_kernel_logs
    detect_anti_forensics

    # --- 跨日志关联 ---
    correlate_logs
}

#=============================================================
# 日志源探测
#=============================================================
detect_log_source() {
    for logfile in /var/log/auth.log /var/log/secure; do
        if [[ -f "$logfile" && -r "$logfile" ]]; then
            AUTH_LOG_FILE="$logfile"
            LOG_SOURCE="file:$logfile"
            return
        fi
    done
    if command -v journalctl &>/dev/null; then
        LOG_SOURCE="journalctl"
        return
    fi
    LOG_SOURCE=""
}

#=============================================================
# 探测 auditd
#=============================================================
detect_auditd() {
    if command -v auditctl &>/dev/null && [[ -f "$AUDIT_LOG_FILE" ]]; then
        HAS_AUDITD=true
    elif systemctl is-active --quiet auditd 2>/dev/null; then
        HAS_AUDITD=true
    fi
}

#=============================================================
# 读取日志的统一接口
#=============================================================
read_auth_log() {
    local since="${1:-30 days ago}"
    local pattern="${2:-}"

    if [[ "$LOG_SOURCE" == file:* ]]; then
        if [[ -n "$pattern" ]]; then
            grep -iE "$pattern" "$AUTH_LOG_FILE" 2>/dev/null || true
        else
            cat "$AUTH_LOG_FILE" 2>/dev/null || true
        fi
    elif [[ "$LOG_SOURCE" == "journalctl" ]]; then
        if [[ -n "$pattern" ]]; then
            journalctl _COMM=sshd --since "$since" --no-pager -o short-iso 2>/dev/null | \
                grep -iE "$pattern" || true
        else
            journalctl _COMM=sshd --since "$since" --no-pager -o short-iso 2>/dev/null || true
        fi
    fi
}

#=============================================================
# 应用层: SSH 成功登录 IP Top10
#=============================================================
audit_ssh_successful_logins() {
    info "--- SSH 成功登录 IP 统计 ---"

    local raw_data
    raw_data=$(read_auth_log "30 days ago" "Accepted (password|publickey|keyboard-interactive)")

    if [[ -z "$raw_data" ]]; then
        info "近 30 天内无 SSH 成功登录记录"
        return
    fi

    local total_count
    total_count=$(echo "$raw_data" | wc -l)
    info "近 30 天 SSH 成功登录总次数: $total_count"

    info "最近 10 条 SSH 成功登录明细:"
    echo "$raw_data" | tail -10 | while IFS= read -r line; do
        local date_str ip user
        date_str=$(echo "$line" | grep -oP '^\S+\s+\d+\s+\d{2}:\d{2}:\d{2}|^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' | head -1)
        ip=$(echo "$line" | grep -oP 'from \K[0-9a-fA-F:.]+' | head -1)
        user=$(echo "$line" | grep -oP 'for \K\S+' | head -1)
        log "       └─ ${date_str:-未知时间} | 用户: ${user:-未知} | 来源: ${ip:-未知}"
    done

    log ""
    log "       ${BOLD}SSH 成功登录 IP Top10（近 30 天）:${NC}"

    echo "$raw_data" | \
        grep -oP 'from \K[0-9a-fA-F:.]+' | \
        sort | uniq -c | sort -rn | head -10 | \
        while read -r count ip; do
            local last_date
            last_date=$(echo "$raw_data" | grep "$ip" | tail -1 | \
                grep -oP '^\S+\s+\d+\s+\d{2}:\d{2}:\d{2}|^\d{4}-\d{2}-\d{2}' | head -1)
            printf "       %-5s %-45s 最后登录: %s\n" "$count" "$ip" "${last_date:-未知}" | \
                tee -a "$REPORT_FILE"
        done

    # 内网 IP 登录检查
    check_internal_ip_logins "$raw_data"
}

check_internal_ip_logins() {
    local raw_data="$1"
    local internal_ips
    internal_ips=$(echo "$raw_data" | grep -oP 'from \K[0-9a-fA-F:.]+' | \
        grep -E '^(10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168\.|127\.)' | \
        sort -u || true)

    if [[ -n "$internal_ips" ]]; then
        info "内网 IP 登录记录（需确认是否正常运维）:"
        echo "$internal_ips" | while read -r ip; do
            log "       └─ $ip"
        done
    fi
}

#=============================================================
# 应用层: SSH 失败登录统计
#=============================================================
audit_ssh_failed_logins() {
    info "--- SSH 失败登录统计 ---"

    local raw_data
    raw_data=$(read_auth_log "30 days ago" "Failed password|Invalid user")

    if [[ -z "$raw_data" ]]; then
        pass "近 30 天内无 SSH 失败登录记录"
        return
    fi

    local total
    total=$(echo "$raw_data" | wc -l)
    info "近 30 天 SSH 失败登录总次数: $total"

    local top_attackers
    top_attackers=$(echo "$raw_data" | \
        grep -oP 'from \K[0-9a-fA-F:.]+' | \
        sort | uniq -c | sort -rn | head -10)

    if [[ -n "$top_attackers" ]]; then
        log "       ${BOLD}SSH 失败登录来源 IP Top10:${NC}"
        echo "$top_attackers" | while read -r count ip; do
            if [[ "$count" -gt 100 ]]; then
                fail "暴力破解来源 IP: $ip ($count 次失败)"
                show_remediation "ssh_bruteforce"
                if declare -f act_block_ip &>/dev/null; then
                    act_block_ip "$ip" "SSH 暴力破解 $count 次" "HIGH"
                fi
            else
                printf "       %-5s %s\n" "$count" "$ip" | tee -a "$REPORT_FILE"
            fi
        done
    fi

    audit_failed_then_success "$raw_data"
}

audit_failed_then_success() {
    local failed_data="$1"

    local failed_ips
    failed_ips=$(echo "$failed_data" | grep -oP 'from \K[0-9a-fA-F:.]+' | sort -u)

    local success_data
    success_data=$(read_auth_log "30 days ago" "Accepted")

    local suspicious=false
    for ip in $failed_ips; do
        local fail_count success_count

        # 修复版：使用 count_matches_stdin 工具函数
        if declare -f count_matches_stdin &>/dev/null; then
            fail_count=$(echo "$failed_data" | count_matches_stdin "$ip")
            success_count=$(echo "$success_data" | count_matches_stdin "$ip")
        else
            # 降级：手动处理
            fail_count=$(echo "$failed_data" | grep -c "$ip" 2>/dev/null || true)
            fail_count=$(echo "${fail_count:-0}" | head -1 | tr -d '[:space:]')
            [[ "$fail_count" =~ ^[0-9]+$ ]] || fail_count=0

            success_count=$(echo "$success_data" | grep -c "$ip" 2>/dev/null || true)
            success_count=$(echo "${success_count:-0}" | head -1 | tr -d '[:space:]')
            [[ "$success_count" =~ ^[0-9]+$ ]] || success_count=0
        fi

        if [[ "$fail_count" -ge 10 && "$success_count" -ge 1 ]]; then
            suspicious=true
            fail "IP $ip 在 $fail_count 次失败后成功登录 $success_count 次（疑似密码猜测成功）"
            show_remediation "ssh_compromised"
        fi
    done

    $suspicious || pass "未发现失败后成功的可疑登录"
}

#=============================================================
# 应用层: 危险行为日志检测
#=============================================================
audit_dangerous_activities() {
    info "--- 危险行为日志检测 ---"

    local total_findings=0

    for pattern_entry in "${DANGEROUS_PATTERNS[@]:-}"; do
        local label="${pattern_entry%%|*}"
        local rest="${pattern_entry#*|}"
        local severity="${rest%%|*}"
        local regex="${rest#*|}"

        local hits
        hits=$(read_auth_log "30 days ago" "$regex")

        if [[ -z "$hits" ]]; then
            continue
        fi

        local count
        count=$(echo "$hits" | wc -l)
        total_findings=$((total_findings + count))

        case "$severity" in
            CRITICAL|HIGH)
                fail "日志审计发现 [$label] ($count 条)"
                echo "$hits" | tail -3 | while IFS= read -r line; do
                    log "       └─ ${line:0:200}"
                done
                show_remediation "log_$label"
                ;;
            MEDIUM)
                warn "日志审计发现 [$label] ($count 条)"
                echo "$hits" | tail -2 | while IFS= read -r line; do
                    log "       └─ ${line:0:200}"
                done
                ;;
        esac
    done

    if [[ "$total_findings" -eq 0 ]]; then
        pass "日志中未发现明显危险行为"
    else
        info "危险行为日志总命中数: $total_findings"
    fi
}

#=============================================================
# 内核级: auditd 规则基线检查（正则匹配版）
#=============================================================
check_auditd_rules() {
    info "--- auditd 规则基线检查（CIS 4.1.x）---"

    if [[ "$HAS_AUDITD" != "true" ]]; then
        warn "auditd 未安装或未运行，无法进行内核级审计"
        info "建议安装: apt install auditd（Ubuntu）或 dnf install audit（RHEL）"
        show_remediation "install_auditd"
        return
    fi

    # 1. auditd 服务状态
    if systemctl is-active --quiet auditd 2>/dev/null; then
        pass "auditd 服务运行中"
    else
        fail "auditd 服务未运行"
        show_remediation "start_auditd"
    fi

    # 2. 审计缓冲区配置
    local backlog_limit
    backlog_limit=$(auditctl -s 2>/dev/null | grep -oP 'backlog_limit\s+\K[0-9]+' | head -1 || echo "0")
    if [[ "$backlog_limit" -ge 8192 ]]; then
        pass "审计缓冲区大小: $backlog_limit"
    else
        warn "审计缓冲区大小为 $backlog_limit（建议 ≥ 8192，避免高负载时丢事件）"
        show_remediation "auditd_backlog"
    fi

    # 3. 获取当前规则
    local current_rules
    current_rules=$(auditctl -l 2>/dev/null || true)

    if [[ -z "$current_rules" ]]; then
        fail "auditd 无任何审计规则，内核级行为不可见"
        show_remediation "auditd_rules_missing"
        return
    fi

    # 4. 检查关键规则（使用正则，支持多 syscall 变体）
    local missing_count=0
    local total_rules=${#AUDITD_EXPECTED_RULES[@]}

    for entry in "${AUDITD_EXPECTED_RULES[@]:-}"; do
        local desc="${entry%%|*}"
        local pattern="${entry##*|}"

        if echo "$current_rules" | grep -qE "$pattern"; then
            pass "auditd 规则已配置: $desc"
        else
            missing_count=$((missing_count+1))
            fail "auditd 缺失规则: $desc"
            log "       期望模式: $pattern"
        fi
    done

    if [[ "$missing_count" -gt 0 ]]; then
        fail "缺失 $missing_count/$total_rules 条关键审计规则，内核级可见性不足"
        show_remediation "auditd_rules_missing"
    else
        pass "所有关键审计规则已配置（$total_rules/$total_rules）"
    fi

    # 5. 检查 auditd 日志大小限制
    if [[ -f /etc/audit/auditd.conf ]]; then
        local max_log_size
        max_log_size=$(grep -oP '^\s*max_log_file\s*=\s*\K[0-9]+' /etc/audit/auditd.conf 2>/dev/null | head -1 || echo "0")
        if [[ "$max_log_size" -ge 50 ]]; then
            pass "审计日志大小限制: ${max_log_size}MB"
        else
            warn "审计日志大小限制为 ${max_log_size}MB（建议 ≥ 50MB）"
        fi

        local space_left_action
        space_left_action=$(grep -oP '^\s*space_left_action\s*=\s*\K\w+' /etc/audit/auditd.conf 2>/dev/null | head -1 || true)
        if [[ "$space_left_action" == "email" || "$space_left_action" == "exec" || "$space_left_action" == "suspend" ]]; then
            pass "磁盘空间不足时的审计行为: $space_left_action"
        elif [[ -n "$space_left_action" ]]; then
            warn "磁盘空间不足时的审计行为: $space_left_action（建议 email 或 exec）"
        fi
    fi
}

#=============================================================
# 内核级: 日志完整性检测
#=============================================================
check_log_integrity() {
    info "--- 日志完整性检测 ---"

    # 1. 关键日志文件权限
    local log_files=(
        "/var/log/auth.log:640"
        "/var/log/secure:600"
        "/var/log/audit/audit.log:600"
        "/var/log/syslog:640"
        "/var/log/messages:640"
        "/var/log/wtmp:664"
        "/var/log/btmp:600"
        "/var/log/lastlog:664"
    )

    for entry in "${log_files[@]}"; do
        local file="${entry%%:*}"
        local expected="${entry##*:}"
        [[ -f "$file" ]] || continue

        local actual owner
        actual=$(stat -c '%a' "$file" 2>/dev/null)
        owner=$(stat -c '%U' "$file" 2>/dev/null)

        if [[ "$owner" != "root" && "$owner" != "syslog" && "$owner" != "systemd-journal" ]]; then
            fail "日志文件 $file 所有者为 $owner（应为 root 或 syslog）"
            show_remediation "log_file_owner"
        elif [[ "$actual" == "$expected" || "$actual" -lt "$expected" ]]; then
            pass "日志文件 $file 权限正确 ($actual, $owner)"
        else
            warn "日志文件 $file 权限过宽 ($actual, 建议 $expected)"
            show_remediation "log_file_perm"
        fi
    done

    # 2. 不可变属性检查
    local immutable_checked=false
    if command -v lsattr &>/dev/null; then
        for logfile in /var/log/auth.log /var/log/secure /var/log/audit/audit.log; do
            [[ -f "$logfile" ]] || continue
            local attrs
            attrs=$(lsattr -d "$logfile" 2>/dev/null | awk '{print $1}' | head -1 || true)
            if echo "$attrs" | grep -q 'i'; then
                pass "日志文件 $logfile 已设置不可变属性 (+i)"
                immutable_checked=true
            elif echo "$attrs" | grep -q 'a'; then
                pass "日志文件 $logfile 已设置追加属性 (+a)"
                immutable_checked=true
            fi
        done
    fi
    if ! $immutable_checked; then
        warn "关键日志文件未设置不可变/追加属性（攻击者可删除日志掩盖痕迹）"
        show_remediation "log_immutable"
    fi

    # 3. journald FSS 校验
    if command -v journalctl &>/dev/null; then
        local seal_state
        seal_state=$(grep -oP '^\s*Seal\s*=\s*\K\w+' /etc/systemd/journald.conf 2>/dev/null | head -1 || true)
        if [[ "$seal_state" == "yes" ]]; then
            pass "journald FSS 前向安全密封已启用"
            local verify_result
            verify_result=$(journalctl --verify 2>&1 | tail -3 || true)
            if echo "$verify_result" | grep -qiE 'fail|error|missing'; then
                fail "journald 日志校验失败（可能被篡改）"
                echo "$verify_result" | while read -r l; do log "       └─ $l"; done
                show_remediation "journal_tampered"
            else
                pass "journald 日志校验通过"
            fi
        else
            warn "journald FSS 未启用（日志可被中途篡改）"
            show_remediation "journal_fss"
        fi

        local storage_mode
        storage_mode=$(grep -oP '^\s*Storage\s*=\s*\K\w+' /etc/systemd/journald.conf 2>/dev/null | head -1 || true)
        if [[ "$storage_mode" == "persistent" ]]; then
            pass "journald 使用持久化存储"
        else
            warn "journald 使用非持久化存储（重启后日志丢失）"
            show_remediation "journal_persistent"
        fi
    fi
}

#=============================================================
# 内核级: 内核日志异常检测
#=============================================================
check_kernel_logs() {
    info "--- 内核日志异常检测 ---"

    local found=false

    # 1. dmesg 内核污染消息
    local taint_msgs
    taint_msgs=$(dmesg 2>/dev/null | grep -iE 'taint|module verification failed|out-of-tree|unsigned module' | head -10 || true)
    if [[ -n "$taint_msgs" ]]; then
        found=true
        warn "内核日志中发现模块污染消息（可能加载了非官方内核模块）:"
        echo "$taint_msgs" | while read -r l; do log "       └─ ${l:0:180}"; done
        show_remediation "kernel_taint"
    fi

    # 2. 内核异常
    local kernel_errors
    kernel_errors=$(dmesg 2>/dev/null | \
        grep -iE 'Oops|panic|general protection fault|BUG:|segfault|kernel NULL' | head -10 || true)
    if [[ -n "$kernel_errors" ]]; then
        found=true
        fail "内核日志中发现异常（可能是漏洞利用的副作用）:"
        echo "$kernel_errors" | while read -r l; do log "       └─ ${l:0:180}"; done
        show_remediation "kernel_error"
    fi

    # 3. dmesg 缓冲区清空检测
    if command -v journalctl &>/dev/null; then
        local dmesg_clear
        dmesg_clear=$(journalctl -k --since "7 days ago" --no-pager 2>/dev/null | \
            grep -iE 'dmesg.*clear|SYSLOG_ACTION_CLEAR|ring buffer' | head -5 || true)
        if [[ -n "$dmesg_clear" ]]; then
            found=true
            fail "检测到内核环形缓冲区被清空的记录（反取证行为）:"
            echo "$dmesg_clear" | while read -r l; do log "       └─ ${l:0:180}"; done
            show_remediation "dmesg_clear"
        fi
    fi

    # 4. dmesg_restrict 配置
    local dmesg_restrict
    dmesg_restrict=$(sysctl -n kernel.dmesg_restrict 2>/dev/null || echo "0")
    if [[ "$dmesg_restrict" == "1" ]]; then
        pass "kernel.dmesg_restrict=1（非特权用户无法读取内核日志）"
    else
        warn "kernel.dmesg_restrict=0（非特权用户可读取内核日志）"
        show_remediation "dmesg_restrict"
    fi

    # 5. 可疑内核模块
    local suspect_mods
    suspect_mods=$(lsmod 2>/dev/null | \
        grep -iE 'hide|rootkit|knark|adore|diamorphine|azazel|beurk|suterusu|reptile' | head -5 || true)
    if [[ -n "$suspect_mods" ]]; then
        found=true
        fail "发现可疑内核模块:"
        echo "$suspect_mods" | while read -r l; do log "       └─ ${l:0:180}"; done
        show_remediation "kernel_module"
    fi

    $found || pass "内核日志未发现异常"
}

#=============================================================
# 内核级: 反取证行为检测
#=============================================================
detect_anti_forensics() {
    info "--- 反取证行为检测 ---"

    local found=false

    # 1. 从 auditd 或 auth.log 检测反取证命令
    for pattern_entry in "${ANTI_FORENSICS_PATTERNS[@]:-}"; do
        local label="${pattern_entry%%|*}"
        local rest="${pattern_entry#*|}"
        local severity="${rest%%|*}"
        local regex="${rest#*|}"

        local hits
        if [[ "$HAS_AUDITD" == "true" ]] && command -v ausearch &>/dev/null; then
            hits=$(ausearch -ts recent -k exec_commands 2>/dev/null | \
                grep -iE "$regex" | head -5 || true)
        fi

        if [[ -z "$hits" ]]; then
            hits=$(read_auth_log "7 days ago" "$regex")
        fi

        if [[ -n "$hits" ]]; then
            found=true
            local count
            count=$(echo "$hits" | wc -l)
            if [[ "$severity" == "CRITICAL" ]]; then
                fail "反取证行为 [$label] ($count 条)"
            else
                warn "反取证行为 [$label] ($count 条)"
            fi
            echo "$hits" | tail -3 | while read -r l; do log "       └─ ${l:0:180}"; done
            show_remediation "anti_forensics"
        fi
    done

    # 2. 检测 HISTFILE 环境变量被禁用
    for user_home in /root /home/*; do
        [[ -d "$user_home" ]] || continue
        for rcfile in "$user_home/.bashrc" "$user_home/.bash_profile" "$user_home/.profile"; do
            [[ -f "$rcfile" ]] || continue
            if grep -qE '^\s*(unset|export)\s+HISTFILE|HISTFILE=/dev/null|HISTSIZE=0|HISTFILESIZE=0' "$rcfile" 2>/dev/null; then
                found=true
                fail "用户 $user_home 的 $rcfile 禁用了历史记录（反取证配置）"
                show_remediation "history_disabled"
            fi
        done
    done

    # 3. 检测历史文件被清空
    for user_home in /root /home/*; do
        [[ -d "$user_home" ]] || continue
        for hist_file in "$user_home/.bash_history" "$user_home/.zsh_history" "$user_home/.sh_history"; do
            [[ -f "$hist_file" ]] || continue
            local size
            size=$(stat -c '%s' "$hist_file" 2>/dev/null || echo 0)
            if [[ "$size" -lt 50 ]]; then
                warn "用户 $user_home 的历史文件仅 ${size} 字节，可能被清空"
            fi
        done
    done

    # 4. 检测 auditd 服务被停止
    if [[ "$HAS_AUDITD" == "true" ]] && command -v ausearch &>/dev/null; then
        local auditd_stop
        auditd_stop=$(ausearch -ts recent -m SERVICE_START,SERVICE_STOP 2>/dev/null | \
            grep -i 'auditd' | grep -i 'stop' | head -3 || true)
        if [[ -n "$auditd_stop" ]]; then
            found=true
            fail "检测到 auditd 服务被停止的记录:"
            echo "$auditd_stop" | while read -r l; do log "       └─ ${l:0:180}"; done
        fi
    fi

    $found || pass "未发现明显的反取证行为"
}

#=============================================================
# 内核级: 跨日志源关联分析
#=============================================================
correlate_logs() {
    info "--- 跨日志源关联分析 ---"

    if [[ "$HAS_AUDITD" != "true" ]] || ! command -v ausearch &>/dev/null; then
        info "auditd 不可用，跳过关联分析"
        return
    fi

    local found=false

    # 1. SSH 失败后触发命令执行的 IP 关联
    local failed_ips
    failed_ips=$(read_auth_log "7 days ago" "Failed password|Invalid user" | \
        grep -oP 'from \K[0-9a-fA-F:.]+' | sort -u | head -20 || true)

    for ip in $failed_ips; do
        local exec_count

        # 修复版：使用 count_matches_stdin 工具函数
        if declare -f count_matches_stdin &>/dev/null; then
            exec_count=$(ausearch -ts recent -k exec_commands 2>/dev/null | \
                count_matches_stdin "$ip")
        else
            # 降级：手动处理
            exec_count=$(ausearch -ts recent -k exec_commands 2>/dev/null | \
                grep -c "$ip" 2>/dev/null || true)
            exec_count=$(echo "${exec_count:-0}" | head -1 | tr -d '[:space:]')
            [[ "$exec_count" =~ ^[0-9]+$ ]] || exec_count=0
        fi

        if [[ "$exec_count" -gt 0 ]]; then
            found=true
            fail "IP $ip 在 SSH 失败后触发 $exec_count 次命令执行（疑似入侵成功）"
            show_remediation "intrusion_confirmed"
        fi
    done

    # 2. 提权事件与命令执行的关联
    local priv_esc_pids
    priv_esc_pids=$(ausearch -ts recent -k privilege_escalation 2>/dev/null | \
        grep -oP 'pid=\K[0-9]+' | sort -u | head -10 || true)

    for pid in $priv_esc_pids; do
        local cmd_hit
        cmd_hit=$(ausearch -ts recent -k exec_commands 2>/dev/null | \
            grep "pid=$pid" | grep -iE 'wget|curl|nc |ncat|bash -i|/dev/tcp' | head -1 || true)

        if [[ -n "$cmd_hit" ]]; then
            found=true
            fail "提权进程 PID=$pid 执行了可疑命令:"
            log "       └─ ${cmd_hit:0:180}"
            show_remediation "privilege_escalation_chain"
        fi
    done

    $found || pass "跨日志关联分析未发现异常"
}