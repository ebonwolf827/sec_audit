#!/bin/bash
#=============================================================
# lib/check_log_audit.sh — 阶段 7: 系统日志审计（内核级）
# 功能: SSH 登录审计 | auditd 规则 | 日志完整性 | 内核日志 | 反取证
#=============================================================

AUTH_LOG_FILE=""
LOG_SOURCE=""
HAS_AUDITD=false
AUDIT_LOG_FILE="/var/log/audit/audit.log"

AUDITD_EXPECTED_RULES=(
    "-w /etc/passwd -p wa"
    "-w /etc/shadow -p wa"
    "-w /etc/sudoers -p wa"
    "-w /etc/ssh/sshd_config -p wa"
    "-a always,exit -F arch=b64 -S execve"
    "-a always,exit -F arch=b64 -S unlink"
)

ANTI_FORENSICS_PATTERNS=(
    "历史命令清空|HIGH|history\\s+-c|unset\\s+HISTFILE|HISTFILE=/dev/null"
    "日志清空|CRITICAL|journalctl\\s+--vacuum|rm\\s+.*/var/log"
    "审计日志清空|CRITICAL|>\\s*/var/log/audit/audit.log"
    "内核缓冲区清空|CRITICAL|dmesg\\s+-c"
    "防火墙清空|HIGH|iptables\\s+-F|iptables\\s+-X"
)

phase_check_log_audit() {
    section "阶段 7: 系统日志审计（内核级）"

    detect_log_source
    detect_auditd

    if [[ -z "$LOG_SOURCE" && ! $HAS_AUDITD ]]; then
        warn "未找到可用日志源，跳过"
        return
    fi

    audit_ssh_successful_logins
    audit_ssh_failed_logins
    check_auditd_rules
    check_log_integrity
    check_kernel_logs
    detect_anti_forensics
    correlate_logs
}

detect_log_source() {
    for logfile in /var/log/auth.log /var/log/secure; do
        if [[ -f "$logfile" && -r "$logfile" ]]; then
            AUTH_LOG_FILE="$logfile"
            LOG_SOURCE="file:$logfile"
            return
        fi
    done
    command -v journalctl &>/dev/null && LOG_SOURCE="journalctl"
}

detect_auditd() {
    if command -v auditctl &>/dev/null && [[ -f "$AUDIT_LOG_FILE" ]]; then
        HAS_AUDITD=true
    elif systemctl is-active --quiet auditd 2>/dev/null; then
        HAS_AUDITD=true
    fi
}

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
            journalctl _COMM=sshd --since "$since" --no-pager -o short-iso 2>/dev/null | grep -iE "$pattern" || true
        else
            journalctl _COMM=sshd --since "$since" --no-pager -o short-iso 2>/dev/null || true
        fi
    fi
}

audit_ssh_successful_logins() {
    info "--- SSH 成功登录 IP 统计 ---"

    local raw
    raw=$(read_auth_log "30 days ago" "Accepted (password|publickey|keyboard-interactive)")
    [[ -z "$raw" ]] && { info "近 30 天无 SSH 成功登录"; return; }

    info "近 30 天成功登录总次数: $(echo "$raw" | wc -l)"
    info "最近 10 条成功登录明细:"

    echo "$raw" | tail -10 | while IFS= read -r line; do
        local date_str ip user
        date_str=$(echo "$line" | grep -oP '^\S+\s+\d+\s+\d{2}:\d{2}:\d{2}|^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' | head -1)
        ip=$(echo "$line" | grep -oP 'from \K[0-9a-fA-F:.]+' | head -1)
        user=$(echo "$line" | grep -oP 'for \K\S+' | head -1)
        log "       └─ $date_str | 用户: ${user:-未知} | 来源: ${ip:-未知}"
    done

    log ""
    log "       ${BOLD}SSH 成功登录 IP Top10:${NC}"

    echo "$raw" | grep -oP 'from \K[0-9a-fA-F:.]+' | \
        sort | uniq -c | sort -rn | head -10 | \
        while read -r count ip; do
            local last_date
            last_date=$(echo "$raw" | grep "$ip" | tail -1 | \
                grep -oP '^\S+\s+\d+\s+\d{2}:\d{2}:\d{2}|^\d{4}-\d{2}-\d{2}' | head -1)
            printf "       %-5s %-45s 最后登录: %s\n" "$count" "$ip" "${last_date:-未知}" | tee -a "$REPORT_FILE"
        done
}

audit_ssh_failed_logins() {
    info "--- SSH 失败登录统计 ---"

    local raw
    raw=$(read_auth_log "30 days ago" "Failed password|Invalid user")
    [[ -z "$raw" ]] && { pass "近 30 天无 SSH 失败登录"; return; }

    info "近 30 天失败登录总次数: $(echo "$raw" | wc -l)"

    local top
    top=$(echo "$raw" | grep -oP 'from \K[0-9a-fA-F:.]+' | \
        sort | uniq -c | sort -rn | head -10)

    if [[ -n "$top" ]]; then
        log "       ${BOLD}SSH 失败登录来源 IP Top10:${NC}"
        echo "$top" | while read -r count ip; do
            if [[ "$count" -gt 100 ]]; then
                fail "暴力破解来源 IP: $ip ($count 次失败)"
                show_remediation "ssh_bruteforce"
                act_block_ip "$ip" "SSH 暴力破解 $count 次" "HIGH"
            else
                printf "       %-5s %s\n" "$count" "$ip" | tee -a "$REPORT_FILE"
            fi
        done
    fi

    # 失败后成功检测
    local success
    success=$(read_auth_log "30 days ago" "Accepted")
    for ip in $(echo "$raw" | grep -oP 'from \K[0-9a-fA-F:.]+' | sort -u); do
        local fc sc
        fc=$(echo "$raw" | grep -c "$ip" || echo 0)
        sc=$(echo "$success" | grep -c "$ip" || echo 0)
        if [[ "$fc" -ge 10 && "$sc" -ge 1 ]]; then
            fail "IP $ip 在 $fc 次失败后成功登录 $sc 次（疑似密码猜测成功）"
            show_remediation "ssh_compromised"
        fi
    done
}

check_auditd_rules() {
    info "--- auditd 规则基线检查（CIS 4.1.x）---"

    if ! $HAS_AUDITD; then
        warn "auditd 未安装或未运行"
        show_remediation "install_auditd"
        return
    fi

    systemctl is-active --quiet auditd 2>/dev/null && \
        pass "auditd 服务运行中" || fail "auditd 服务未运行"

    local backlog
    backlog=$(auditctl -s 2>/dev/null | grep -oP 'backlog_limit\s+\K[0-9]+' | head -1 || echo "0")
    [[ "$backlog" -ge 8192 ]] && pass "审计缓冲区: $backlog" || \
        warn "审计缓冲区 $backlog（建议 ≥ 8192）"

    local current
    current=$(auditctl -l 2>/dev/null || true)
    [[ -z "$current" ]] && { fail "auditd 无任何规则"; return; }

    local missing=0
    for expected in "${AUDITD_EXPECTED_RULES[@]}"; do
        local key
        key=$(echo "$expected" | sed 's/ -k .*//')
        if echo "$current" | grep -qF "$key"; then
            pass "auditd 规则已配置: $key"
        else
            missing=$((missing+1))
            fail "auditd 缺失规则: $expected"
        fi
    done

    [[ "$missing" -gt 0 ]] && show_remediation "auditd_rules_missing"
}

check_log_integrity() {
    info "--- 日志完整性检测 ---"

    local files=(
        "/var/log/auth.log:640" "/var/log/secure:600"
        "/var/log/audit/audit.log:600"
        "/var/log/syslog:640" "/var/log/messages:640"
    )

    for entry in "${files[@]}"; do
        local file="${entry%%:*}" expected="${entry##*:}"
        [[ -f "$file" ]] || continue

        local perm owner
        perm=$(stat -c '%a' "$file" 2>/dev/null)
        owner=$(stat -c '%U' "$file" 2>/dev/null)

        if [[ "$owner" != "root" && "$owner" != "syslog" && "$owner" != "systemd-journal" ]]; then
            fail "日志文件 $file 所有者为 $owner（应为 root/syslog）"
        elif [[ "$perm" == "$expected" || "$perm" -lt "$expected" ]]; then
            pass "日志文件 $file 权限正确 ($perm, $owner)"
        else
            warn "日志文件 $file 权限过宽 ($perm, 建议 $expected)"
        fi
    done

    # 不可变属性
    if command -v lsattr &>/dev/null; then
        for lf in /var/log/auth.log /var/log/secure /var/log/audit/audit.log; do
            [[ -f "$lf" ]] || continue
            local attrs
            attrs=$(lsattr -d "$lf" 2>/dev/null | awk '{print $1}' | head -1)
            if echo "$attrs" | grep -q 'i\|a'; then
                pass "日志文件 $lf 有保护属性"
            fi
        done
    fi

    # journald FSS
    if command -v journalctl &>/dev/null; then
        local seal
        seal=$(grep -oP '^\s*Seal\s*=\s*\K\w+' /etc/systemd/journald.conf 2>/dev/null | head -1 || true)
        if [[ "$seal" == "yes" ]]; then
            pass "journald FSS 已启用"
            journalctl --verify 2>&1 | tail -3 | grep -qiE 'fail|error' && \
                fail "journald 日志校验失败" || pass "journald 日志校验通过"
        fi
    fi
}

check_kernel_logs() {
    info "--- 内核日志异常检测 ---"

    local found=false

    local taint
    taint=$(dmesg 2>/dev/null | grep -iE 'taint|module verification failed|out-of-tree' | head -5 || true)
    [[ -n "$taint" ]] && found=true && \
        warn "内核模块污染消息: $(echo "$taint" | head -1)"

    local errors
    errors=$(dmesg 2>/dev/null | grep -iE 'Oops|panic|general protection fault|BUG:' | head -5 || true)
    [[ -n "$errors" ]] && found=true && \
        fail "内核异常: $(echo "$errors" | head -1)"

    local dmesg_restrict
    dmesg_restrict=$(sysctl -n kernel.dmesg_restrict 2>/dev/null || echo "0")
    if [[ "$dmesg_restrict" == "1" ]]; then
        pass "kernel.dmesg_restrict=1"
    else
        warn "kernel.dmesg_restrict=0（非特权用户可读内核日志）"
    fi

    $found || pass "内核日志未发现异常"
}

detect_anti_forensics() {
    info "--- 反取证行为检测 ---"

    local found=false

    for entry in "${ANTI_FORENSICS_PATTERNS[@]}"; do
        local label="${entry%%|*}"
        local rest="${entry#*|}"
        local sev="${rest%%|*}"
        local regex="${rest#*|}"

        local hits
        hits=$(read_auth_log "7 days ago" "$regex")
        if [[ -z "$hits" && $HAS_AUDITD ]]; then
            hits=$(ausearch -ts recent -k exec_commands 2>/dev/null | \
                grep -iE "$regex" | head -5 || true)
        fi

        if [[ -n "$hits" ]]; then
            found=true
            [[ "$sev" == "CRITICAL" ]] && \
                fail "反取证行为 [$label] ($(echo "$hits" | wc -l) 条)" || \
                warn "反取证行为 [$label] ($(echo "$hits" | wc -l) 条)"
            echo "$hits" | tail -3 | while read -r l; do log "       └─ ${l:0:180}"; done
            show_remediation "anti_forensics"
        fi
    done

    # 历史文件篡改
    for uh in /root /home/*; do
        [[ -d "$uh" ]] || continue
        for rc in "$uh/.bashrc" "$uh/.bash_profile" "$uh/.profile"; do
            [[ -f "$rc" ]] || continue
            grep -qE '^\s*(unset|export)\s+HISTFILE|HISTFILE=/dev/null|HISTSIZE=0' "$rc" 2>/dev/null && \
                found=true && fail "用户 $uh 的 $rc 禁用了历史记录"
        done
    done

    $found || pass "未发现明显反取证行为"
}

correlate_logs() {
    info "--- 跨日志源关联分析 ---"

    $HAS_AUDITD || { info "auditd 不可用，跳过"; return; }

    local found=false

    local failed_ips
    failed_ips=$(read_auth_log "7 days ago" "Failed password|Invalid user" | \
        grep -oP 'from \K[0-9a-fA-F:.]+' | sort -u | head -20 || true)

    for ip in $failed_ips; do
        local exec_count
        exec_count=$(ausearch -ts recent -k exec_commands 2>/dev/null | \
            grep -c "$ip" 2>/dev/null || echo 0)
        if [[ "$exec_count" -gt 0 ]]; then
            found=true
            fail "IP $ip 在 SSH 失败后触发 $exec_count 次命令执行（疑似入侵）"
        fi
    done

    $found || pass "跨日志关联未发现异常"
}