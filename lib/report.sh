#!/bin/bash
#=============================================================
# lib/report.sh — 阶段 12: 汇总与报告生成
# 功能: 风险评分 | 摘要 | JSON | 修复建议 | 定时任务配置
# 修复: FAIL_MESSAGES/WARN_MESSAGES 空数组在 set -u 下的报错
#=============================================================

#=============================================================
# 外部依赖变量默认值
#=============================================================
: "${REPORT_BASE_DIR:=/var/log/sec_audit}"
: "${SUMMARY_FILE:=${REPORT_BASE_DIR}/summary_$(date +%Y%m%d_%H%M%S).txt}"
: "${REPORT_FILE:=${REPORT_BASE_DIR}/audit_$(date +%Y%m%d_%H%M%S).log}"
: "${JSON_FILE:=${REPORT_BASE_DIR}/report_$(date +%Y%m%d_%H%M%S).json}"
: "${VERSION_FILE:=${REPORT_BASE_DIR}/sysinfo_$(date +%Y%m%d_%H%M%S).txt}"
: "${INSTALL_LOG:=${REPORT_BASE_DIR}/install_$(date +%Y%m%d_%H%M%S).log}"
: "${SCRIPT_DIR:=/usr/local/bin/sec_audit}"

#=============================================================
# 阶段 12: 检测汇总
#=============================================================
phase_report() {
    section "阶段 12: 检测汇总"

    local risk_score=$(( FAIL_COUNT * 10 + WARN_COUNT * 3 ))
    local risk_level

    if [[ $risk_score -ge 50 ]]; then
        RISK_LEVEL="高危"
    elif [[ $risk_score -ge 20 ]]; then
        RISK_LEVEL="中危"
    elif [[ $risk_score -ge 5 ]]; then
        RISK_LEVEL="低危"
    else
        RISK_LEVEL="安全"
    fi

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

    # 生成摘要
    generate_summary "$risk_score" "$RISK_LEVEL"

    # 生成 JSON（如果启用）
    if [[ "${OUTPUT_JSON:-false}" == "true" ]]; then
        generate_json "$risk_score" "$RISK_LEVEL"
    fi

    # 输出修复建议汇总
    generate_remediation_summary
}

#=============================================================
# 摘要报告
#=============================================================
generate_summary() {
    local score="$1" level="$2"

    {
        echo "============================================"
        echo "  安全检测摘要 — $(hostname) @ $(date)"
        echo "============================================"
        echo "系统        : ${OS_PRETTY:-未知}"
        echo "风险评分    : $score  风险等级: $level"
        echo "PASS: $PASS_COUNT | WARN: $WARN_COUNT | FAIL: $FAIL_COUNT"
        echo ""
        echo "--- FAIL 项 ---"
        if [[ -f "$REPORT_FILE" ]]; then
            grep '\[FAIL\]' "$REPORT_FILE" 2>/dev/null || echo "(无)"
        else
            echo "(无)"
        fi
        echo ""
        echo "--- WARN 项 ---"
        if [[ -f "$REPORT_FILE" ]]; then
            grep '\[WARN\]' "$REPORT_FILE" 2>/dev/null || echo "(无)"
        else
            echo "(无)"
        fi
        echo ""
        echo "--- 修复建议 ---"
        if [[ ${#FAIL_MESSAGES[@]} -eq 0 ]]; then
            echo "(无 FAIL 项)"
        else
            for msg in "${FAIL_MESSAGES[@]:-}"; do
                [[ -n "$msg" ]] && echo "  • $msg"
            done
        fi
    } > "$SUMMARY_FILE"
}

#=============================================================
# JSON 报告
#=============================================================
generate_json() {
    local score="$1" level="$2"

    cat > "$JSON_FILE" <<EOF
{
  "hostname": "$(hostname)",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "os": "${OS_PRETTY:-unknown}",
  "distro_id": "${DISTRO_ID:-unknown}",
  "distro_version": "${DISTRO_VER:-unknown}",
  "risk_score": $score,
  "risk_level": "$level",
  "summary": {
    "pass": $PASS_COUNT,
    "warn": $WARN_COUNT,
    "fail": $FAIL_COUNT,
    "info": $INFO_COUNT
  },
  "findings": ${FINDINGS_JSON:-[]}
}
EOF
    log "JSON 报告: $JSON_FILE"
}

#=============================================================
# 修复建议汇总
#=============================================================
generate_remediation_summary() {
    # 如果 FAIL 和 WARN 都为空，无需输出
    if [[ $FAIL_COUNT -eq 0 && $WARN_COUNT -eq 0 ]]; then
        return 0
    fi

    log ""
    log "============================================================"
    log "  修复建议汇总"
    log "============================================================"

    # FAIL 项的修复建议
    if [[ ${#FAIL_MESSAGES[@]} -gt 0 ]]; then
        log ""
        log "  ${RED}[FAIL] 需要立即处理的项:${NC}"
        local idx=0
        for msg in "${FAIL_MESSAGES[@]:-}"; do
            [[ -z "$msg" ]] && continue
            idx=$((idx+1))
            log "    $idx. $msg"
        done
    fi

    log ""
    log "  完整修复建议见: $SUMMARY_FILE"
    log "  或执行: grep -A2 '修复:' $REPORT_FILE"
}

#=============================================================
# 定时任务配置
#=============================================================
setup_schedule() {
    section "阶段 13: 定时任务配置"

    local cron_file="/etc/cron.d/sec_audit"
    local script_path
    script_path=$(readlink -f "${SCRIPT_DIR}/sec_audit.sh" 2>/dev/null || echo "${SCRIPT_DIR}/sec_audit.sh")

    # 确保脚本路径存在
    if [[ ! -x "$script_path" ]]; then
        warn "脚本路径不存在或不可执行: $script_path"
        return 1
    fi

    # 创建 cron 文件
    cat > "$cron_file" <<EOF
# sec_audit 自动检测任务
# 由 sec_audit.sh --schedule 自动生成于 $(date '+%Y-%m-%d %H:%M:%S')
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MAILTO=""
0 3 * * * root ${script_path} --json --no-install >> /var/log/sec_audit/cron_run.log 2>&1
EOF
    chmod 644 "$cron_file"
    pass "定时任务已配置: 每日 03:00 执行"

    # 工具更新任务
    local update_cron="/etc/cron.d/sec_audit_update"
    cat > "$update_cron" <<'EOF'
# sec_audit 工具更新任务
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MAILTO=""
0 4 * * 0 root command -v rkhunter >/dev/null && rkhunter --update >/dev/null 2>&1
0 4 * * 0 root command -v rkhunter >/dev/null && rkhunter --propupd >/dev/null 2>&1
EOF
    chmod 644 "$update_cron"
    pass "工具更新任务已配置: 每周日 04:00"

    # 确保日志目录存在
    mkdir -p /var/log/sec_audit

    info "查看任务: cat $cron_file"
    info "查看日志: tail -f /var/log/sec_audit/cron_run.log"
}