#!/bin/bash
#=============================================================
# lib/check_integrity.sh — 阶段 4: 文件完整性检测
# 工具: AIDE | SHA256 基线 | SUID 基线
#=============================================================

phase_check_integrity() {
    section "阶段 4: 文件完整性检测"

    if $HAS_AIDE; then
        run_aide_check
    else
        run_sha256_baseline
    fi

    check_suid_baseline
}

run_aide_check() {
    if [[ ! -f /var/lib/aide/aide.db.gz ]]; then
        info "AIDE 数据库未初始化，正在初始化..."
        silent aide --init
        [[ -f /var/lib/aide/aide.db.new.gz ]] && \
            mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
        warn "AIDE 基线已建立"
        return
    fi

    info "执行 AIDE 检查..."
    local out
    out=$(aide --check 2>&1 | grep -vE '^$|AIDE.*started|AIDE.*finished' | head -30 || true)

    if echo "$out" | grep -qiE 'found differences|changed|added|removed'; then
        warn "AIDE 检测到文件差异"
        echo "$out" | head -10 | while read -r l; do log "       └─ $l"; done
    else
        pass "AIDE 检查通过"
    fi
}

run_sha256_baseline() {
    info "AIDE 不可用，使用 SHA256 基线降级方案"

    local critical_files=(
        /etc/passwd /etc/shadow /etc/group /etc/gshadow
        /etc/sudoers /etc/ssh/sshd_config /etc/crontab /etc/ld.so.preload
        /etc/pam.d/system-auth /etc/pam.d/sshd /etc/rc.local /etc/sysctl.conf
    )

    if [[ ! -f "$BASELINE_FILE" ]]; then
        : > "$BASELINE_FILE"
        for f in "${critical_files[@]}"; do
            [[ -f "$f" ]] && sha256sum "$f" >> "$BASELINE_FILE" 2>/dev/null
        done
        warn "SHA256 基线已生成 ($(wc -l < "$BASELINE_FILE") 文件)"
        return
    fi

    local changed=false
    while read -r old_hash file; do
        [[ -z "$file" ]] && continue
        if [[ ! -e "$file" ]]; then
            changed=true
            fail "文件被删除: $file"
            continue
        fi
        local new_hash
        new_hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
        if [[ "$old_hash" != "$new_hash" ]]; then
            changed=true
            fail "文件被篡改: $file"
            log "       原 hash: $old_hash"
            log "       新 hash: $new_hash"
            show_remediation "file_tampered"
        fi
    done < "$BASELINE_FILE"
    $changed || pass "SHA256 基线对比通过"
}

check_suid_baseline() {
    info "检查 SUID 文件变化..."

    local current="/tmp/suid_current_$$.txt"
    find / -perm -4000 -type f 2>/dev/null | sort > "$current"

    if [[ ! -f "$SUID_BASELINE_FILE" ]]; then
        cp "$current" "$SUID_BASELINE_FILE"
        warn "SUID 基线已建立 ($(wc -l < "$SUID_BASELINE_FILE") 个文件)"
        rm -f "$current"
        return
    fi

    local added
    added=$(diff "$SUID_BASELINE_FILE" "$current" 2>/dev/null | grep '^>' | sed 's/^> //' || true)

    if [[ -n "$added" ]]; then
        fail "发现新增 SUID 文件:"
        echo "$added" | while read -r f; do
            log "       └─ $f"
            show_remediation "suid_new"
        done
    else
        pass "SUID 文件无变化"
    fi
    rm -f "$current"
}