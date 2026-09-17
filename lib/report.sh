#!/bin/bash
#=============================================================
# lib/report.sh — 阶段 8: 汇总与报告生成
#=============================================================

phase_report() {
    section "阶段 8: 检测汇总"

    local risk_score=$(( FAIL_COUNT * 10 + WARN_COUNT * 3 ))
    local risk_level

    if [[ $risk_score -ge 50 ]]; then RISK_LEVEL="高危"
    elif [[ $risk_score -ge 20 ]]; then RISK_LEVEL="中危"
    elif [[ $risk_score -ge 5 ]]; then RISK_LEVEL="低危"
    else RISK_LEVEL="安全"; fi

    log ""
    log "  PASS : $PASS_COUNT 项"
    log "  WARN : $WARN_COUNT 项"
    log "  FAIL : $FAIL_COUNT 项"
    log "  INFO : $INFO_COUNT 项"
    log ""
    log "  风险评分: $risk_score  风险等级: $RISK_LEVEL"
    log ""
    log "完整报告: $REPORT_FILE"
    log "安装日志: $INSTALL_LOG"
    log "系统信息: $VERSION_FILE"

    generate_summary "$risk_score" "$RISK_LEVEL"

    if $OUTPUT_JSON; then
        generate_json "$risk_score" "$RISK_LEVEL"
    fi
}

# ---------- 摘要报告 ----------
generate_summary() {
    local score="$1" level="$2"

    {
        echo "============================================"
        echo "  安全检测摘要 — $(hostname) @ $(date)"
        echo "============================================"
        echo "系统        : ${OS_PRETTY}"
        echo "风险评分    : $score  风险等级: $level"
        echo "PASS: $PASS_COUNT | WARN: $WARN_COUNT | FAIL: $FAIL_COUNT"
        echo ""
        echo "--- FAIL 项 ---"
        grep '\[FAIL\]' "$REPORT_FILE" || echo "(无)"
        echo ""
        echo "--- WARN 项 ---"
        grep '\[WARN\]' "$REPORT_FILE" || echo "(无)"
        echo ""
        echo "--- 修复建议 ---"
        if [[ ${#FAIL_MESSAGES[@]} -eq 0 ]]; then
            echo "(无 FAIL 项)"
        else
            for msg in "${FAIL_MESSAGES[@]}"; do
                echo "  • $msg"
            done
        fi
    } > "$SUMMARY_FILE"
}

# ---------- JSON 报告 ----------
generate_json() {
    local score="$1" level="$2"

    cat > "$JSON_FILE" <<EOF
{
  "hostname": "$(hostname)",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "os": "${OS_PRETTY}",
  "distro_id": "${DISTRO_ID}",
  "distro_version": "${DISTRO_VER}",
  "risk_score": $score,
  "risk_level": "$level",
  "summary": {
    "pass": $PASS_COUNT,
    "warn": $WARN_COUNT,
    "fail": $FAIL_COUNT,
    "info": $INFO_COUNT
  },
  "findings": $FINDINGS_JSON
}
EOF
    log "JSON 报告: $JSON_FILE"
}

# ---------- 定时任务配置 ----------
setup_schedule() {
    section "阶段 9: 定时任务配置"

    local cron_file="/etc/cron.d/sec_audit"
    local script_path="${SCRIPT_DIR}/sec_audit.sh"

    cat > "$cron_file" <<EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
0 3 * * * root ${script_path} --json --no-install >/dev/null 2>&1
EOF
    chmod 644 "$cron_file"
    pass "定时任务已配置: 每日 03:00 执行"

    cat > "/etc/cron.d/sec_audit_update" <<EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
0 4 * * 0 root command -v rkhunter >/dev/null && rkhunter --update >/dev/null 2>&1
0 4 * * 0 root command -v rkhunter >/dev/null && rkhunter --propupd >/dev/null 2>&1
EOF
    chmod 644 "/etc/cron.d/sec_audit_update"
    pass "工具更新任务已配置: 每周日 04:00"
}