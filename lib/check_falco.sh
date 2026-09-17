#!/bin/bash
#=============================================================
# lib/check_falco.sh — 阶段 X: Falco 实时运行时安全监控
# 功能: Falco 安装配置 | 自定义规则 | 告警解析 | 自动响应
# 数据源: 系统调用 (eBPF) | 容器运行时事件
#=============================================================

# Falco 状态标记
HAS_FALCO=false
FALCO_ALERT_FILE="/var/log/falco/alerts.json"
FALCO_CONFIG="/etc/falco/falco.yaml"
FALCO_CUSTOM_RULES="/etc/falco/rules.d/sec_audit_rules.yaml"

# Falco 优先级到安全级别的映射
# Falco 使用 Syslog 严重级别: Emergency > Alert > Critical > Error > Warning > Notice > Informational > Debug
declare -A FALCO_PRIORITY_MAP
FALCO_PRIORITY_MAP["Emergency"]="CRITICAL"
FALCO_PRIORITY_MAP["Alert"]="CRITICAL"
FALCO_PRIORITY_MAP["Critical"]="CRITICAL"
FALCO_PRIORITY_MAP["Error"]="HIGH"
FALCO_PRIORITY_MAP["Warning"]="MEDIUM"
FALCO_PRIORITY_MAP["Notice"]="MEDIUM"
FALCO_PRIORITY_MAP["Informational"]="LOW"
FALCO_PRIORITY_MAP["Debug"]="LOW"

#=============================================================
# 主入口
#=============================================================
phase_check_falco() {
    section "阶段 X: Falco 实时运行时安全监控"

    detect_falco

    if ! $HAS_FALCO; then
        info "Falco 未安装"
        if $SKIP_INSTALL; then
            warn "跳过 Falco 安装（--no-install），建议安装以增强实时监控能力"
            show_remediation "install_falco"
        else
            install_falco
        fi
    fi

    if $HAS_FALCO; then
        configure_falco
        deploy_custom_rules
        check_falco_status
        analyze_falco_alerts
        setup_falco_auto_response
    fi
}

#=============================================================
# 探测 Falco
#=============================================================
detect_falco() {
    if command -v falco &>/dev/null; then
        HAS_FALCO=true
        local ver
        ver=$(falco --version 2>/dev/null | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        info "Falco 已安装: $ver"

        # 检查服务状态
        if systemctl is-active --quiet falco 2>/dev/null; then
            info "Falco 服务运行中"
        else
            warn "Falco 已安装但服务未运行"
        fi

        # 检查驱动类型
        local driver
        driver=$(falco --version 2>/dev/null | grep -i 'driver' || true)
        info "驱动信息: ${driver:-未知}"
    fi
}

#=============================================================
# 安装 Falco
#=============================================================
install_falco() {
    plog "--- 安装 Falco ---"

    # 检查 GLIBC 版本（Falco 需要 2.28+）
    local glibc_ver
    glibc_ver=$(ldd --version 2>/dev/null | head -1 | grep -oP '[0-9]+\.[0-9]+' | head -1)
    if [[ -n "$glibc_ver" ]]; then
        local glibc_major glibc_minor
        glibc_major=$(echo "$glibc_ver" | cut -d. -f1)
        glibc_minor=$(echo "$glibc_ver" | cut -d. -f2)
        if [[ "$glibc_major" -lt 2 ]] || [[ "$glibc_major" -eq 2 && "$glibc_minor" -lt 28 ]]; then
            plog "GLIBC 版本 $glibc_ver 过低（需 2.28+），跳过 Falco 安装"
            return 1
        fi
    fi

    # 根据发行版选择安装方式
    case "$DISTRO_FAMILY:$PKG_MGR" in
        debian:apt-get)
            install_falco_deb
            ;;
        rhel:dnf|rhel:yum)
            install_falco_rpm
            ;;
        *)
            plog "不支持的发行版组合，跳过 Falco 安装"
            return 1
            ;;
    esac

    # 安装后验证
    if command -v falco &>/dev/null; then
        HAS_FALCO=true
        plog "Falco 安装成功"
    else
        plog "Falco 安装失败"
    fi
}

# Debian/Ubuntu 安装
install_falco_deb() {
    plog "使用 DEB 包安装 Falco..."

    # 1. 安装依赖
    pkg_install "curl"
    pkg_install "gnupg2"
    pkg_install "apt-transport-https"

    # 2. 添加 Falco 仓库 GPG 密钥
    plog "添加 Falco GPG 密钥..."
    curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
        gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg 2>/dev/null || true

    # 3. 添加仓库
    echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | \
        tee /etc/apt/sources.list.d/falcosecurity.list >/dev/null

    apt-get update >> "$INSTALL_LOG" 2>&1 || true

    # 4. 非交互安装（自动选择驱动）
    FALCO_FRONTEND=noninteractive apt-get install -y falco >> "$INSTALL_LOG" 2>&1
}

# RHEL/Amazon Linux 安装
install_falco_rpm() {
    plog "使用 RPM 包安装 Falco..."

    # 1. 添加仓库
    plog "添加 Falco YUM 仓库..."
    curl -fsSL https://falco.org/repo/falcosecurity-packages.repo | \
        tee /etc/yum.repos.d/falcosecurity.repo >/dev/null

    # 2. 导入 GPG 密钥
    rpm --import https://falco.org/repo/falcosecurity-packages.asc 2>/dev/null || true

    # 3. 安装（非交互）
    FALCO_FRONTEND=noninteractive $PKG_MGR install -y falco >> "$INSTALL_LOG" 2>&1
}

#=============================================================
# 配置 Falco
#=============================================================
configure_falco() {
    plog "--- 配置 Falco ---"

    # 确保目录存在
    mkdir -p /var/log/falco
    mkdir -p /etc/falco/rules.d

    # 检查是否已配置（幂等性）
    if grep -q 'json_output: true' "$FALCO_CONFIG" 2>/dev/null && \
       grep -q "$FALCO_ALERT_FILE" "$FALCO_CONFIG" 2>/dev/null; then
        plog "Falco 已配置，跳过"
        return
    fi

    # 备份原配置
    [[ ! -f "${FALCO_CONFIG}.bak" ]] && \
        cp "$FALCO_CONFIG" "${FALCO_CONFIG}.bak" 2>/dev/null || true

    # 1. 启用 JSON 输出
    if grep -q '^json_output:' "$FALCO_CONFIG" 2>/dev/null; then
        sed -i 's/^json_output:.*/json_output: true/' "$FALCO_CONFIG"
    else
        echo "json_output: true" >> "$FALCO_CONFIG"
    fi

    # 2. 启用 JSON 中包含输出属性
    if grep -q '^json_include_output_property:' "$FALCO_CONFIG" 2>/dev/null; then
        sed -i 's/^json_include_output_property:.*/json_include_output_property: true/' "$FALCO_CONFIG"
    else
        echo "json_include_output_property: true" >> "$FALCO_CONFIG"
    fi

    # 3. 配置文件输出
    if ! grep -q 'file_output:' "$FALCO_CONFIG" 2>/dev/null; then
        cat >> "$FALCO_CONFIG" <<EOF

# --- sec_audit 集成配置 ---
file_output:
  enabled: true
  keep_alive: false
  filename: ${FALCO_ALERT_FILE}

stdout_output:
  enabled: true

# 仅加载 Warning 及以上级别（减少噪声）
priority: warning
EOF
    else
        # 已存在 file_output 时，修改其配置
        sed -i "s|filename:.*|filename: ${FALCO_ALERT_FILE}|" "$FALCO_CONFIG"
    fi

    # 4. 配置日志轮转
    cat > /etc/logrotate.d/falco-sec_audit <<EOF
${FALCO_ALERT_FILE} {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        systemctl reload falco 2>/dev/null || true
    endscript
}
EOF

    # 5. 重启 Falco 服务
    if systemctl is-active --quiet falco 2>/dev/null; then
        systemctl restart falco 2>/dev/null || true
        sleep 3
    fi

    plog "Falco 配置完成: JSON 输出 → ${FALCO_ALERT_FILE}"
}

#=============================================================
# 部署自定义规则
#=============================================================
deploy_custom_rules() {
    plog "--- 部署自定义 Falco 规则 ---"

    # 幂等性检查
    if [[ -f "$FALCO_CUSTOM_RULES" ]]; then
        plog "自定义规则已存在，跳过"
        return
    fi

    cat > "$FALCO_CUSTOM_RULES" <<'FALCO_RULES'
#=============================================================
# sec_audit 自定义 Falco 规则
# 针对: 反弹 Shell | 容器逃逸 | 敏感文件访问 | C2 通信
#=============================================================

# --- 1. 反弹 Shell 检测 ---
- rule: SecAudit Reverse Shell via /dev/tcp
  desc: 检测通过 /dev/tcp 建立的反弹 Shell
  condition: >
    spawned_process and
    (proc.cmdline contains "/dev/tcp/" or
     proc.cmdline contains "/dev/udp/") and
    not proc.pname in (known_shell_spawners)
  output: >
    Reverse shell via /dev/tcp detected
    (user=%user.name pid=%proc.pid ppid=%proc.ppid
     command=%proc.cmdline parent=%proc.pname
     container_id=%container.id container_name=%container.name)
  priority: CRITICAL
  tags: [network, shell, mitre_execution]

- rule: SecAudit Reverse Shell via nc/socat
  desc: 检测通过 nc/socat 建立的反弹 Shell
  condition: >
    spawned_process and
    ((proc.name = nc or proc.name = ncat) and proc.cmdline contains " -e ") or
    (proc.name = socat and proc.cmdline contains "exec:")
  output: >
    Reverse shell via netcat/socat detected
    (user=%user.name pid=%proc.pid command=%proc.cmdline
     parent=%proc.pname container_id=%container.id)
  priority: CRITICAL
  tags: [network, shell, mitre_execution]

# --- 2. 容器逃逸检测 ---
- rule: SecAudit Container Escape via nsenter
  desc: 检测通过 nsenter 进入宿主命名空间
  condition: >
    spawned_process and
    proc.name = nsenter and
    proc.cmdline contains "--target 1" and
    container.id != host
  output: >
    Container escape attempt via nsenter
    (user=%user.name command=%proc.cmdline
     container_id=%container.id container_name=%container.name)
  priority: CRITICAL
  tags: [container, escape, mitre_privilege_escalation]

- rule: SecAudit Container Escape via mount
  desc: 检测容器内挂载宿主机文件系统
  condition: >
    spawned_process and
    proc.name = mount and
    container.id != host and
    (proc.cmdline contains "/host" or
     proc.cmdline contains "/proc" or
     proc.cmdline contains "/sys")
  output: >
    Container escape attempt via mount
    (user=%user.name command=%proc.cmdline
     container_id=%container.id container_name=%container.name)
  priority: CRITICAL
  tags: [container, escape, mitre_privilege_escalation]

- rule: SecAudit Docker Socket Access
  desc: 检测容器内访问 Docker socket
  condition: >
    open_read and
    container.id != host and
    fd.name = /var/run/docker.sock
  output: >
    Container accessed Docker socket
    (user=%user.name command=%proc.cmdline
     container_id=%container.id container_name=%container.name)
  priority: CRITICAL
  tags: [container, escape, mitre_privilege_escalation]

# --- 3. 敏感文件访问 ---
- rule: SecAudit Sensitive File Access
  desc: 检测对敏感系统文件的非授权访问
  condition: >
    open_read and
    fd.name in (/etc/shadow, /etc/sudoers, /root/.ssh/id_rsa,
                /root/.aws/credentials, /etc/kubernetes/admin.conf) and
    not proc.name in (known_sensitive_file_readers) and
    not user.name in (root, systemd)
  output: >
    Sensitive file accessed by non-trusted program
    (user=%user.name command=%proc.cmdline file=%fd.name
     container_id=%container.id)
  priority: ERROR
  tags: [filesystem, mitre_credential_access]

# --- 4. C2 通信检测 ---
- rule: SecAudit Outbound Connection on C2 Ports
  desc: 检测到 C2 常用端口的对外连接
  condition: >
    outbound and
    fd.sport in (4444, 5555, 8888, 9999, 1337, 31337, 6666, 12345) and
    not fd.sip in (127.0.0.1, ::1)
  output: >
    Outbound connection to C2 port detected
    (user=%user.name command=%proc.cmdline
     connection=%fd.name container_id=%container.id)
  priority: CRITICAL
  tags: [network, c2, mitre_command_and_control]

# --- 5. 隐蔽文件操作 ---
- rule: SecAudit Executable Created in Temp Directory
  desc: 检测在临时目录中创建可执行文件
  condition: >
    open_write and
    (fd.name startswith /tmp/ or
     fd.name startswith /dev/shm/ or
     fd.name startswith /var/tmp/) and
    (fd.name endswith .sh or
     fd.name endswith .py or
     fd.name endswith .pl or
     fd.name endswith .elf)
  output: >
    Executable created in temp directory
    (user=%user.name file=%fd.name command=%proc.cmdline
     container_id=%container.id)
  priority: WARNING
  tags: [filesystem, mitre_defense_evasion]

# --- 6. 进程注入 ---
- rule: SecAudit Process Injection via ptrace
  desc: 检测通过 ptrace 进行进程注入
  condition: >
    ptrace and
    evt.dir = < and
    not proc.name in (gdb, strace, ltrace, gdbserver) and
    not user.name = root
  output: >
    Process injection via ptrace detected
    (user=%user.name command=%proc.cmdline target=%ptrace.target)
  priority: ERROR
  tags: [process, injection, mitre_privilege_escalation]

# --- 7. 历史命令篡改 ---
- rule: SecAudit History File Modification
  desc: 检测历史命令文件的篡改或删除
  condition: >
    (open_write or unlink) and
    (fd.name endswith .bash_history or
     fd.name endswith .zsh_history or
     fd.name endswith .sh_history)
  output: >
    Shell history file modified or deleted
    (user=%user.name file=%fd.name command=%proc.cmdline)
  priority: WARNING
  tags: [filesystem, mitre_defense_evasion]

# --- 8. Shell 由 Web 服务派生 ---
- rule: SecAudit Shell Spawned by Web Server
  desc: 检测 Web 服务进程派生 Shell
  condition: >
    spawned_process and
    proc.name in (bash, sh, zsh, dash) and
    proc.pname in (nginx, java, httpd, php-fpm, node, tomcat, uwsgi, gunicorn)
  output: >
    Shell spawned by web server
    (user=%user.name shell=%proc.name parent=%proc.pname
     command=%proc.cmdline container_id=%container.id)
  priority: ERROR
  tags: [process, webshell, mitre_execution]
FALCO_RULES

    plog "自定义规则已部署: $FALCO_CUSTOM_RULES"

    # 验证规则语法
    if falco --validate "$FALCO_CUSTOM_RULES" &>/dev/null; then
        plog "规则语法验证通过"
    else
        plog "规则语法验证失败，检查 $FALCO_CUSTOM_RULES"
    fi
}

#=============================================================
# 检查 Falco 运行状态
#=============================================================
check_falco_status() {
    info "--- Falco 运行状态 ---"

    if systemctl is-active --quiet falco 2>/dev/null; then
        pass "Falco 服务运行中"

        # 检查最近的事件
        local uptime_sec
        uptime_sec=$(systemctl show falco --property=ActiveEnterTimestamp 2>/dev/null | \
            grep -oP 'ActiveEnterTimestamp=\K.*' || true)
        if [[ -n "$uptime_sec" ]]; then
            info "Falco 启动时间: $uptime_sec"
        fi

        # 检查驱动加载
        if lsmod 2>/dev/null | grep -q 'falco'; then
            pass "Falco 内核模块已加载"
        elif ls /sys/kernel/tracing/ 2>/dev/null | grep -q 'events'; then
            pass "eBPF 追踪可用"
        fi

        # 检查告警文件
        if [[ -f "$FALCO_ALERT_FILE" ]]; then
            local alert_count
            alert_count=$(wc -l < "$FALCO_ALERT_FILE" 2>/dev/null || echo 0)
            info "告警文件行数: $alert_count"
        else
            info "告警文件尚未生成（无告警触发）"
        fi
    else
        warn "Falco 服务未运行"
        show_remediation "start_falco"
    fi
}

#=============================================================
# 解析 Falco 告警
#=============================================================
analyze_falco_alerts() {
    info "--- Falco 告警分析 ---"

    [[ ! -f "$FALCO_ALERT_FILE" ]] && {
        info "无告警文件，跳过分析"
        return
    }

    local total_alerts
    total_alerts=$(wc -l < "$FALCO_ALERT_FILE" 2>/dev/null || echo 0)
    [[ "$total_alerts" -eq 0 ]] && {
        pass "Falco 未产生告警"
        return
    }

    info "Falco 告警总数: $total_alerts"

    # 按优先级统计
    local critical_count high_count medium_count
    critical_count=$(grep -c '"priority":"Critical"\|"priority":"Emergency"\|"priority":"Alert"' \
        "$FALCO_ALERT_FILE" 2>/dev/null || echo 0)
    high_count=$(grep -c '"priority":"Error"' "$FALCO_ALERT_FILE" 2>/dev/null || echo 0)
    medium_count=$(grep -c '"priority":"Warning"\|"priority":"Notice"' \
        "$FALCO_ALERT_FILE" 2>/dev/null || echo 0)

    log "       优先级分布: CRITICAL=$critical_count HIGH=$high_count MEDIUM=$medium_count"

    # 按规则统计
    log "       告警规则 Top10:"
    grep -oP '"rule":"\K[^"]+' "$FALCO_ALERT_FILE" 2>/dev/null | \
        sort | uniq -c | sort -rn | head -10 | while read -r count rule; do
        printf "       %-5s %s\n" "$count" "$rule" | tee -a "$REPORT_FILE"
    done

    # CRITICAL 级别告警详细输出
    if [[ "$critical_count" -gt 0 ]]; then
        fail "Falco 发现 $critical_count 条 CRITICAL 级别告警:"
        grep '"priority":"Critical"\|"priority":"Emergency"\|"priority":"Alert"' \
            "$FALCO_ALERT_FILE" 2>/dev/null | tail -5 | while IFS= read -r line; do
            local rule cmd output
            rule=$(echo "$line" | grep -oP '"rule":"\K[^"]+' | head -1)
            cmd=$(echo "$line" | grep -oP '"proc.cmdline":"\K[^"]+' | head -1)
            output=$(echo "$line" | grep -oP '"output":"\K[^"]+' | head -1)
            log "       └─ [$rule] ${output:0:150}"
        done
        show_remediation "falco_critical"
    fi

    # HIGH 级别告警
    if [[ "$high_count" -gt 0 ]]; then
        warn "Falco 发现 $high_count 条 HIGH 级别告警"
        grep '"priority":"Error"' "$FALCO_ALERT_FILE" 2>/dev/null | tail -3 | \
            while IFS= read -r line; do
                local rule output
                rule=$(echo "$line" | grep -oP '"rule":"\K[^"]+' | head -1)
                output=$(echo "$line" | grep -oP '"output":"\K[^"]+' | head -1)
                log "       └─ [$rule] ${output:0:150}"
            done
    fi

    # 导出摘要
    generate_falco_summary
}

# 生成 Falco 告警摘要
generate_falco_summary() {
    local summary_file="${REPORT_BASE_DIR}/falco_alerts_summary_${TIMESTAMP}.txt"

    {
        echo "============================================"
        echo "  Falco 告警摘要 — $(hostname) @ $(date)"
        echo "============================================"
        echo ""
        echo "--- 告警规则统计 ---"
        grep -oP '"rule":"\K[^"]+' "$FALCO_ALERT_FILE" 2>/dev/null | \
            sort | uniq -c | sort -rn | head -20
        echo ""
        echo "--- 最近 20 条告警 ---"
        tail -20 "$FALCO_ALERT_FILE" 2>/dev/null | while IFS= read -r line; do
            local time rule priority output
            time=$(echo "$line" | grep -oP '"time":"\K[^"]+' | head -1)
            rule=$(echo "$line" | grep -oP '"rule":"\K[^"]+' | head -1)
            priority=$(echo "$line" | grep -oP '"priority":"\K[^"]+' | head -1)
            output=$(echo "$line" | grep -oP '"output":"\K[^"]+' | head -1)
            echo "[$time] [$priority] $rule"
            echo "  $output"
            echo ""
        done
    } > "$summary_file"

    info "Falco 告警摘要: $summary_file"
}

#=============================================================
# 配置 Falco 自动响应
#=============================================================
setup_falco_auto_response() {
    info "--- Falco 自动响应配置 ---"

    # 创建 Falco 告警触发的自动响应脚本
    local response_script="/usr/local/bin/sec_audit_falco_responder.sh"

    if [[ -f "$response_script" ]]; then
        info "自动响应脚本已存在: $response_script"
        return
    fi

    cat > "$response_script" <<'RESPONDER'
#!/bin/bash
#=============================================================
# Falco 自动响应脚本
# 当 Falco 产生 CRITICAL 告警时，自动触发 sec_audit 全量扫描
# 部署方式: 在 Falco 配置中添加 program_output
#=============================================================

ALERT_FILE="/var/log/falco/alerts.json"
SEC_AUDIT="/usr/local/bin/sec_audit/sec_audit.sh"
RESPONSE_LOG="/var/log/sec_audit/falco_responder.log"

mkdir -p "$(dirname "$RESPONSE_LOG")"

# 从标准输入读取 Falco 告警
while IFS= read -r alert; do
    [[ -z "$alert" ]] && continue

    # 提取优先级
    priority=$(echo "$alert" | grep -oP '"priority":"\K[^"]+' | head -1)
    rule=$(echo "$alert" | grep -oP '"rule":"\K[^"]+' | head -1)

    # 仅对 CRITICAL 级别响应
    if [[ "$priority" == "Critical" || "$priority" == "Emergency" || "$priority" == "Alert" ]]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] CRITICAL alert: $rule" >> "$RESPONSE_LOG"

        # 触发全量安全扫描
        if [[ -x "$SEC_AUDIT" ]]; then
            "$SEC_AUDIT" --json --no-install >> "$RESPONSE_LOG" 2>&1 &
        fi
    fi
done
RESPONDER

    chmod +x "$response_script"
    info "自动响应脚本已部署: $response_script"
    info "       配置方式: 在 falco.yaml 中添加 program_output:"
    info "       program_output:"
    info "         enabled: true"
    info "         program: $response_script"

    # 如果 Falco 已配置 program_output，跳过
    if grep -q 'program_output:' "$FALCO_CONFIG" 2>/dev/null && \
       grep -q 'enabled: true' "$FALCO_CONFIG" 2>/dev/null; then
        info "Falco program_output 已配置"
    fi
}