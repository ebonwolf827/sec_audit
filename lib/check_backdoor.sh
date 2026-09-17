#!/bin/bash
#=============================================================
# lib/check_backdoor.sh — 阶段 6: 反弹 Shell 与 C2 后门检测
# 集成: 检测 → 提取阻断特征 → act_block_exec + act_kill 组合响应
#=============================================================

# C2 框架进程特征
C2_FRAMEWORK_PATTERNS=(
    "meterpreter|msf|metasploit"
    "cobaltstrike|beacon|teamserver"
    "sliver|sliverpb|sliver-server"
    "empire|powershell-empire"
    "havoc|demon\\.x64|demon\\.so"
    "brute.?ratel|bruteratel|badger"
    "mythic|apollo|athena"
    "pupy|pupysh"
    "merlin|merlinServer"
    "covenant|grunt"
)

# C2 常用端口
C2_PORTS="4444 5555 8888 9999 1337 31337 6666 12345 1080 8443 4443"

# 可疑进程可执行路径
SUSPICIOUS_PATHS=("/tmp/" "/dev/shm/" "/var/tmp/" "/run/")

#=============================================================
# 主入口
#=============================================================
phase_check_backdoor() {
    section "阶段 6: 反弹 Shell 与 C2 后门检测"

    detect_reverse_shell_cmdline
    detect_socket_shell
    detect_web_spawned_shell
    detect_c2_framework_signatures
    detect_c2_ports
    detect_suspicious_binaries
    detect_cron_backdoor
    detect_systemd_backdoor
    detect_ssh_backdoor
}

#=============================================================
# 辅助: 从命令行提取可阻断的恶意特征
#=============================================================
extract_block_patterns() {
    local cmdline="$1"
    local patterns=(
        "/dev/tcp/"
        "/dev/udp/"
        "bash -i"
        "sh -i"
        "nc -e"
        "ncat -e"
        "socat exec:"
        "mkfifo /tmp/"
        "exec 3<>/dev/tcp"
    )

    local found=()
    for p in "${patterns[@]}"; do
        echo "$cmdline" | grep -qF "$p" && found+=("$p")
    done

    # 提取 /dev/tcp/IP/PORT 精确特征
    local tcp_target
    tcp_target=$(echo "$cmdline" | grep -oP '/dev/tcp/\K[^/\s]+/\d+' | head -1 || true)
    [[ -n "$tcp_target" ]] && found+=("/dev/tcp/${tcp_target}")

    printf '%s\n' "${found[@]}" | sort -u
}

#=============================================================
# 辅助: 组合响应（阻断 + 终止）
#=============================================================
respond_reverse_shell() {
    local pid="$1"
    local cmdline="$2"
    local reason="$3"

    [[ -z "$pid" ]] && return 1

    # 第一步: 事前阻断特征（防止攻击者重试）
    local patterns
    patterns=$(extract_block_patterns "$cmdline")

    if [[ -n "$patterns" ]]; then
        info "       ${CYAN}[响应]${NC} 提取到 $(echo "$patterns" | wc -l) 个阻断特征，下发 eBPF 规则..."
        while IFS= read -r pattern; do
            [[ -z "$pattern" ]] && continue
            act_block_exec "pattern:$pattern" "$reason"
        done <<< "$patterns"
    fi

    # 第二步: 事前阻断高危工具进程名
    local comm
    comm=$(cat "/proc/$pid/comm" 2>/dev/null || true)
    case "$comm" in
        nc|ncat|socat|mkfifo|perl|ruby|php)
            act_block_exec "proc:$comm" "$reason (工具进程 $comm)"
            ;;
        bash|sh|dash|zsh)
            info "       ${CYAN}[响应]${NC} 通用 shell ($comm) 不做进程名阻断，仅阻断特征"
            ;;
    esac

    # 第三步: 事后终止当前进程
    act_kill "$pid" "$reason" "CRITICAL"

    # 第四步: 记录组合响应
    response_audit "REVERSE_SHELL_RESPONSE" "PID=$pid" "$reason" "KILL+BLOCK" \
        "patterns=$(echo "$patterns" | tr '\n' ',' | sed 's/,$//')"
}

#=============================================================
# 检测 1: 命令行反弹 Shell
#=============================================================
detect_reverse_shell_cmdline() {
    info "--- 命令行反弹 Shell 特征匹配 ---"

    local pattern='bash\s+-i|sh\s+-i|/dev/tcp/|nc\s+-e|ncat\s+-e|socat\s+.*exec|python[0-9]?\s+-c.*(socket|subprocess)|perl\s+-e.*Socket|php\s+-r.*fsockopen|ruby\s+-rsocket|mkfifo.*/tmp'
    local found=false

    for pid_dir in /proc/[0-9]*; do
        local pid="${pid_dir#/proc/}"
        [[ "$pid" == "$$" ]] && continue

        local cmdline
        cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null)
        [[ -z "$cmdline" ]] && continue
        [[ "$cmdline" == *"sec_audit"* ]] && continue

        if echo "$cmdline" | grep -qiE "$pattern"; then
            found=true
            fail "PID=$pid 反弹 Shell: ${cmdline:0:200}"
            show_remediation "reverse_shell"
            respond_reverse_shell "$pid" "$cmdline" "反弹 Shell 命令行特征"
        fi
    done

    $found || pass "未发现反弹 Shell 命令行"
}

#=============================================================
# 检测 2: 标准流指向 Socket
#=============================================================
detect_socket_shell() {
    info "--- 标准流指向 Socket 检测 ---"

    local found=false

    for pid_dir in /proc/[0-9]*; do
        local pid="${pid_dir#/proc/}"
        [[ "$pid" == "$$" ]] && continue

        local comm
        comm=$(cat "$pid_dir/comm" 2>/dev/null || true)
        [[ "$comm" =~ ^(bash|sh|dash|zsh|nc|ncat|socat|python[0-9]?|perl|ruby|php)$ ]] || continue

        local sock_fds="" sock_count=0
        for fd in 0 1 2; do
            local link
            link=$(readlink "$pid_dir/fd/$fd" 2>/dev/null || true)
            [[ "$link" == socket:* ]] && {
                sock_fds="$sock_fds fd$fd"
                sock_count=$((sock_count+1))
            }
        done

        if [[ "$sock_count" -ge 2 ]]; then
            found=true

            local cmdline
            cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null)

            local remote
            remote=$(ss -tnp 2>/dev/null | grep "pid=$pid" | grep 'ESTAB' | \
                awk '{print $5}' | head -1 || true)

            fail "PID=$pid ($comm) 标准流指向 Socket [$sock_fds]"
            [[ -n "$remote" ]] && log "       └─ 远端连接: $remote"
            show_remediation "reverse_shell"

            respond_reverse_shell "$pid" "$cmdline" "标准流指向 Socket 的反弹 Shell"

            # 额外: 封禁远端 IP
            if [[ -n "$remote" ]]; then
                local remote_ip
                remote_ip=$(echo "$remote" | cut -d: -f1 | tr -d '[]')
                if [[ -n "$remote_ip" ]] && ! is_protected_ip "$remote_ip"; then
                    act_block_ip "$remote_ip" "反弹 Shell 回连地址" "CRITICAL"
                fi
            fi
        fi
    done

    $found || pass "未发现标准流指向 Socket"
}

#=============================================================
# 检测 3: Web 服务派生的 Shell
#=============================================================
detect_web_spawned_shell() {
    info "--- Web 服务派生的 Shell 检测 ---"

    local found=false

    for pid in $(pgrep -x 'bash|sh|dash|zsh' 2>/dev/null || true); do
        local ppid
        ppid=$(awk '/PPid/{print $2}' /proc/$pid/status 2>/dev/null)
        [[ -z "$ppid" ]] && continue

        local pcomm
        pcomm=$(cat /proc/$ppid/comm 2>/dev/null || true)

        if [[ "$pcomm" =~ ^(nginx|java|php-fpm|httpd|node|tomcat|uwsgi|gunicorn)$ ]]; then
            found=true

            local cmdline
            cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)

            fail "Shell PID=$pid 由 Web 服务 $pcomm (PID=$ppid) 派生"
            log "       └─ 命令行: ${cmdline:0:180}"
            show_remediation "web_spawned_shell"

            respond_reverse_shell "$pid" "$cmdline" "Web 服务 $pcomm 派生的 Shell"
        fi
    done

    $found || pass "未发现 Web 服务派生的 Shell"
}

#=============================================================
# 检测 4: C2 框架进程签名
#=============================================================
detect_c2_framework_signatures() {
    info "--- C2 框架进程签名检测 ---"
    local found=false

    for pid_dir in /proc/[0-9]*; do
        local pid="${pid_dir#/proc/}"
        [[ "$pid" == "$$" ]] && continue

        local cmdline
        cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null)
        [[ -z "$cmdline" ]] && continue
        [[ "$cmdline" == *"sec_audit"* ]] && continue

        for pattern in "${C2_FRAMEWORK_PATTERNS[@]}"; do
            if echo "$cmdline" | grep -qiE "$pattern"; then
                found=true
                fail "PID=$pid 匹配 C2 框架特征 [$pattern]: ${cmdline:0:150}"

                # 事后终止
                act_kill "$pid" "C2 框架 $pattern" "CRITICAL"

                # 事前阻断进程名
                local comm
                comm=$(cat "$pid_dir/comm" 2>/dev/null || true)
                [[ -n "$comm" ]] && \
                    act_block_exec "proc:$comm" "C2 框架进程 $comm"
            fi
        done
    done

    $found || pass "未发现 C2 框架进程签名"
}

#=============================================================
# 检测 5: C2 端口通信
#=============================================================
detect_c2_ports() {
    info "--- C2 端口通信检测 ---"
    local found=false

    for port in $C2_PORTS; do
        local conns
        conns=$(ss -tnp 2>/dev/null | grep "ESTAB" | grep ":${port} " || true)
        if [[ -n "$conns" ]]; then
            found=true
            fail "发现连接 C2 常用端口 $port:"
            echo "$conns" | while read -r l; do log "       └─ ${l:0:150}"; done

            local remote_ip
            remote_ip=$(echo "$conns" | awk '{print $5}' | cut -d: -f1 | head -1)
            [[ -n "$remote_ip" ]] && act_block_ip "$remote_ip" "C2 端口 $port 通信" "CRITICAL"
        fi
    done

    $found || pass "未发现 C2 常用端口通信"
}

#=============================================================
# 检测 6: 可疑二进制文件
#=============================================================
detect_suspicious_binaries() {
    info "--- 可疑二进制文件检测 ---"
    local found=false
    local suspect=""

    for dir in /tmp /dev/shm /var/tmp /run; do
        [[ -d "$dir" ]] || continue
        local exes
        exes=$(find "$dir" -maxdepth 2 -type f -perm -111 \
            -not -name "*.sh" -not -name "*.py" \
            -newer /etc/hostname 2>/dev/null | head -20 || true)
        [[ -n "$exes" ]] && suspect="${suspect}${exes}"$'\n'
    done
    suspect=$(echo "$suspect" | grep -v '^$' | sort -u)

    if [[ -z "$suspect" ]]; then
        pass "未发现可疑二进制文件"
        return
    fi

    while IFS= read -r bin; do
        [[ -f "$bin" ]] || continue
        is_whitelisted "$bin" && continue
        file "$bin" 2>/dev/null | grep -q 'ELF' || continue

        if $HAS_YARA; then
            local result
            result=$(yara_scan_file "$bin" "malwares")
            if [[ -n "$result" ]]; then
                found=true
                local rule
                rule=$(echo "$result" | awk '{print $1}')
                fail "YARA 恶意软件命中 [$rule]: $bin"
                act_quarantine "$bin" "YARA 命中 $rule" "CRITICAL"
                continue
            fi
        fi

        found=true
        warn "可疑目录中的 ELF 二进制: $bin"
        local c2_strings
        c2_strings=$(strings "$bin" 2>/dev/null | \
            grep -oE 'https?://[^ "]+|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]+' | \
            sort -u | head -5 || true)
        [[ -n "$c2_strings" ]] && log "       └─ 内嵌地址: $(echo "$c2_strings" | tr '\n' ' ')"
    done <<< "$suspect"

    $found || pass "未发现可疑二进制文件"
}

#=============================================================
# 检测 7: Crontab 后门
#=============================================================
detect_cron_backdoor() {
    local bad=false

    for cfile in /var/spool/cron/crontabs/* /var/spool/cron/* /etc/cron.d/*; do
        [[ -f "$cfile" ]] || continue
        is_whitelisted "$cfile" && continue

        if grep -qiE 'curl|wget|base64|/dev/tcp|python.*-c|bash.*-i|nc.*-e|ncat' "$cfile" 2>/dev/null; then
            bad=true
            fail "可疑 crontab: $cfile"
            show_remediation "cron_backdoor"
            act_remove_persistence "crontab:$cfile" "可疑 crontab 后门"
        fi

        # 检测 C2 地址引用
        local c2_refs
        c2_refs=$(grep -oE 'https?://[^ ]+|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' "$cfile" 2>/dev/null | head -3 || true)
        if [[ -n "$c2_refs" ]]; then
            bad=true
            warn "crontab 中发现外部地址 ($cfile):"
            echo "$c2_refs" | while read -r r; do log "       └─ $r"; done
        fi
    done

    $bad || pass "定时任务正常"
}

#=============================================================
# 检测 8: Systemd 服务后门
#=============================================================
detect_systemd_backdoor() {
    info "--- Systemd 服务后门检测 ---"
    local found=false

    for svc in /etc/systemd/system/*.service /lib/systemd/system/*.service; do
        [[ -f "$svc" ]] || continue
        local exec_start
        exec_start=$(grep -E '^ExecStart=' "$svc" 2>/dev/null | head -1 || true)
        [[ -z "$exec_start" ]] && continue

        # 可执行路径在临时目录
        if echo "$exec_start" | grep -qE '/(tmp|dev/shm|var/tmp|run)/'; then
            found=true
            fail "服务 [$svc] ExecStart 指向可疑路径: $exec_start"
            local svc_name
            svc_name=$(basename "$svc" .service)
            act_remove_persistence "systemd:$svc_name" "可疑服务 ExecStart"
        fi

        # 包含网络下载命令
        if echo "$exec_start" | grep -qiE '(curl|wget|nc |ncat|socat)'; then
            found=true
            fail "服务 [$svc] ExecStart 包含网络命令: $exec_start"
            local svc_name
            svc_name=$(basename "$svc" .service)
            act_remove_persistence "systemd:$svc_name" "可疑服务网络命令"
        fi
    done

    $found || pass "未发现 systemd 服务后门"
}

#=============================================================
# 检测 9: SSH authorized_keys 后门
#=============================================================
detect_ssh_backdoor() {
    for authfile in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
        [[ -f "$authfile" ]] || continue

        # 排除 AWS 官方提示
        local suspect
        suspect=$(grep -nE 'command=|environment=' "$authfile" 2>/dev/null | \
            grep -v "Please login as the user" || true)

        if [[ -n "$suspect" ]]; then
            fail "SSH authorized_keys 可疑命令注入: $authfile"
            echo "$suspect" | while read -r l; do log "       └─ ${l:0:200}"; done
            show_remediation "ssh_backdoor"
            act_quarantine "$authfile" "SSH authorized_keys 后门" "HIGH"
        else
            pass "SSH authorized_keys 未发现异常 ($authfile)"
        fi
    done
}
