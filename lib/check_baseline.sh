#!/bin/bash
#=============================================================
# lib/check_baseline.sh — 阶段 9: 安全基线检查
#=============================================================

phase_check_baseline() {
    section "阶段 9: 安全基线检查"

    check_accounts
    check_sysctl_group
    check_file_perms_group
    check_ssh_config
    check_aws_env
}

check_accounts() {
    local extra_root
    extra_root=$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd 2>/dev/null || true)
    if [[ -n "$extra_root" ]]; then
        fail "UID=0 非 root 账户: $extra_root"
        show_remediation "extra_root"
    else
        pass "UID=0 仅 root"
    fi

    local empty_pw
    empty_pw=$(awk -F: '$2==""{print $1}' /etc/shadow 2>/dev/null | grep -vE '^(#|$)' || true)
    if [[ -n "$empty_pw" ]]; then
        fail "空密码账户: $empty_pw"
        show_remediation "empty_pw"
    else
        pass "无空密码账户"
    fi
}

check_sysctl() {
    local key="$1" expected="$2" desc="$3"
    local actual
    actual=$(sysctl -n "$key" 2>/dev/null || echo "N/A")

    if [[ "$actual" == "$expected" ]]; then
        pass "$desc ($key=$actual)"
    else
        warn "$desc — 当前 $key=$actual, 建议=$expected"
        show_remediation "sysctl:$key"
    fi
}

check_sysctl_group() {
    check_sysctl "net.ipv4.ip_forward" "0" "IP 转发已禁用"
    check_sysctl "kernel.randomize_va_space" "2" "ASLR 已启用"
    check_sysctl "kernel.dmesg_restrict" "1" "dmesg 限制已启用"
}

check_perm() {
    local file="$1" expected="$2" desc="$3"
    [[ -e "$file" ]] || return

    local actual
    actual=$(stat -c '%a' "$file" 2>/dev/null)

    if [[ "$actual" == "$expected" ]]; then
        pass "$desc ($file=$actual)"
    else
        warn "$desc ($file=$actual, 建议=$expected)"
        show_remediation "perm:$file:$expected"
        act_fix_permission "$file" "$expected" "文件权限过宽"
    fi
}

check_file_perms_group() {
    check_perm "/etc/passwd" "644" "/etc/passwd 权限"
    check_perm "/etc/shadow" "640" "/etc/shadow 权限"
    check_perm "/etc/ssh/sshd_config" "600" "sshd_config 权限"
    check_perm "/etc/crontab" "600" "/etc/crontab 权限"
}

check_ssh_config() {
    [[ -f /etc/ssh/sshd_config ]] || return

    if grep -qiE '^\s*PermitRootLogin\s+no' /etc/ssh/sshd_config; then
        pass "PermitRootLogin 已禁用"
    elif grep -qiE '^\s*PermitRootLogin' /etc/ssh/sshd_config; then
        warn "PermitRootLogin 未设为 no"
        show_remediation "ssh_permitrootlogin"
    else
        warn "PermitRootLogin 未显式设置"
        show_remediation "ssh_permitrootlogin"
    fi

    if grep -qiE '^\s*PasswordAuthentication\s+no' /etc/ssh/sshd_config; then
        pass "SSH 密码认证已关闭"
    else
        warn "SSH 密码认证未关闭"
    fi
}

check_aws_env() {
    if [[ -n "$IMDS_TOKEN" ]]; then
        pass "IMDSv2 可用"
        local imdsv1
        imdsv1=$(curl -s -m 2 "http://169.254.169.254/latest/meta-data/instance-id" 2>/dev/null || true)
        [[ -n "$imdsv1" ]] && \
            warn "IMDSv1 仍可访问，建议强制 IMDSv2" && \
            show_remediation "imdsv2"
    fi

    for cf in /root/.aws/credentials /home/*/.aws/credentials; do
        [[ -f "$cf" ]] || continue
        local perm
        perm=$(stat -c '%a' "$cf" 2>/dev/null)
        if [[ "$perm" == "600" ]]; then
            pass "$cf 权限正确"
        else
            fail "$cf 权限过宽 ($perm)"
            act_fix_permission "$cf" "600" "AWS 凭证权限过宽"
        fi
    done
}