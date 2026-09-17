#!/bin/bash
#=============================================================
# lib/check_system.sh — 阶段 5: Lynis 系统审计
#=============================================================

phase_check_system() {
    section "阶段 5: Lynis 系统审计"

    if ! $HAS_LYNIS; then
        info "Lynis 不可用"
        return
    fi

    info "执行 Lynis（可能耗时 1-3 分钟）..."
    lynis audit system --quick --quiet 2>/dev/null || true

    if [[ ! -f /var/log/lynis-report.dat ]]; then
        warn "Lynis 报告文件未生成"
        return
    fi

    local hardening_index warnings suggestions
    hardening_index=$(grep '^hardening_index=' /var/log/lynis-report.dat 2>/dev/null | cut -d= -f2 || echo "N/A")
    warnings=$(grep '^warning\[\]=' /var/log/lynis-report.dat 2>/dev/null | wc -l || echo 0)
    suggestions=$(grep '^suggestion\[\]=' /var/log/lynis-report.dat 2>/dev/null | wc -l || echo 0)

    info "Lynis 加固指数: $hardening_index / 100  警告数: $warnings  建议数: $suggestions"

    if [[ "$hardening_index" != "N/A" && "$hardening_index" -lt 60 ]]; then
        fail "Lynis 加固指数偏低 ($hardening_index)"
        log "       详情见 /var/log/lynis-report.dat"
        show_remediation "lynis_hardening"
    fi

    if [[ "$warnings" -gt 0 ]]; then
        warn "Lynis 报告 $warnings 条警告"
    fi
}