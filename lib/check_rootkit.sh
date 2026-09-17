#!/bin/bash
#=============================================================
# lib/check_rootkit.sh — 阶段 3: Rootkit 扫描
# 工具: rkhunter | chkrootkit | unhide | 内核模块 | LD_PRELOAD
#=============================================================

phase_check_rootkit() {
    section "阶段 3: Rootkit 扫描"

    run_rkhunter
    run_chkrootkit
    run_unhide
    check_kernel_modules
    check_startup_scripts
    check_ld_preload
}

run_rkhunter() {
    if ! $HAS_RKHUNTER; then
        info "rkhunter 不可用"
        return
    fi

    info "执行 rkhunter..."
    local out
    out=$(rkhunter --check --skip-keypress --report-warnings-only 2>/dev/null | \
        grep -iE 'Warning|Infected|Suspicious' | head -20 || true)

    if [[ -n "$out" ]]; then
        warn "rkhunter 报告警告:"
        echo "$out" | while read -r l; do log "       └─ $l"; done
    else
        pass "rkhunter 未发现威胁"
    fi
}

run_chkrootkit() {
    if ! $HAS_CHKROOTKIT; then
        info "chkrootkit 不可用"
        return
    fi

    info "执行 chkrootkit..."
    local out
    out=$(chkrootkit 2>/dev/null | grep -iE 'INFECTED|Vulnerable|WARNING' | head -20 || true)

    if [[ -n "$out" ]]; then
        warn "chkrootkit: $(echo "$out" | head -3 | tr '\n' ' ')"
    else
        pass "chkrootkit 未发现威胁"
    fi
}

run_unhide() {
    if $HAS_UNHIDE; then
        info "执行 unhide..."
        local proc_out tcp_out
        proc_out=$(unhide proc 2>/dev/null | \
            grep -vE '^$|Unhide|Copyright|License|NOTE' | head -10 || true)

        if [[ -n "$proc_out" ]]; then
            fail "unhide 隐藏进程:"
            echo "$proc_out" | while read -r l; do log "       └─ $l"; done
            local hidden_pid
            hidden_pid=$(echo "$proc_out" | grep -oP 'PID[:\s]+\K[0-9]+' | head -1)
            [[ -n "$hidden_pid" ]] && act_kill "$hidden_pid" "隐藏进程" "CRITICAL"
        else
            pass "unhide 未发现隐藏进程"
        fi

        tcp_out=$(unhide-tcp 2>/dev/null | \
            grep -vE '^$|Unhide|Copyright|License|NOTE' | head -10 || true)
        [[ -n "$tcp_out" ]] && \
            fail "unhide-tcp 隐藏端口: $(echo "$tcp_out" | head -3 | tr '\n' ' ')" || \
            pass "unhide-tcp 未发现隐藏端口"
    else
        # 降级方案
        info "unhide 不可用，使用 /proc vs ps 降级方案"
        local proc_pids ps_pids hidden
        proc_pids=$(ls -d /proc/[0-9]* 2>/dev/null | awk -F/ '{print $3}' | sort -n)
        ps_pids=$(ps -eo pid --no-headers 2>/dev/null | tr -d ' ' | sort -n)
        hidden=$(comm -23 <(echo "$proc_pids") <(echo "$ps_pids") 2>/dev/null || true)

        if [[ -n "$hidden" ]]; then
            fail "隐藏进程 PID: $(echo $hidden | tr '\n' ' ')"
            echo "$hidden" | while read -r hp; do
                [[ -n "$hp" ]] && act_kill "$hp" "隐藏进程" "CRITICAL"
            done
        else
            pass "未发现隐藏进程（降级方案）"
        fi
    fi
}

check_kernel_modules() {
    local mods
    mods=$(grep -iE '^(hide|rootkit|knark|adore|diamorphine|azazel|beurk|suterusu)' \
        /proc/modules 2>/dev/null || true)

    if [[ -n "$mods" ]]; then
        fail "可疑内核模块: $mods"
        show_remediation "kernel_module"
    else
        pass "内核模块正常"
    fi
}

check_startup_scripts() {
    local suspect
    suspect=$(grep -rliE 'curl|wget|base64|/dev/tcp|nc -e' \
        /etc/init.d /etc/rc.d /etc/systemd/system 2>/dev/null | head -5 || true)

    if [[ -n "$suspect" ]]; then
        fail "启动脚本可疑: $suspect"
        echo "$suspect" | while read -r f; do
            local svc_name
            svc_name=$(basename "$f" .service)
            act_remove_persistence "systemd:$svc_name" "启动脚本后门"
        done
    else
        pass "启动脚本正常"
    fi
}

check_ld_preload() {
    if [[ -f /etc/ld.so.preload ]]; then
        fail "存在 /etc/ld.so.preload: $(cat /etc/ld.so.preload)"
        show_remediation "ld_preload"
        # 注意：/etc/ld.so.preload 在响应保护名单中，不会自动隔离
    else
        pass "/etc/ld.so.preload 不存在"
    fi
}