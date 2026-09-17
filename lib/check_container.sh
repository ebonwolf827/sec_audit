#!/bin/bash
#=============================================================
# lib/check_container.sh — 阶段 10: Docker 容器安全
# 基于 CIS Docker Benchmark 1.6.0
#=============================================================

DANGEROUS_MOUNTS=(
    "/var/run/docker.sock" "/run/docker.sock"
    "/var/run/containerd/containerd.sock"
    "/proc" "/sys" "/dev"
)
FULL_DIR_MOUNTS=("/etc" "/root" "/home" "/boot")
DANGEROUS_CAPS=(
    "SYS_ADMIN" "SYS_PTRACE" "SYS_MODULE" "DAC_READ_SEARCH"
    "NET_ADMIN" "NET_RAW" "SYS_RAWIO" "SYS_BOOT"
)
MALICIOUS_KEYWORDS=(
    "cryptonight" "xmrig" "stratum+tcp" "minerd"
    "nc -e" "ncat -e" "bash -i" "/dev/tcp"
)

phase_check_container() {
    section "阶段 10: Docker 容器安全"

    if ! command -v docker &>/dev/null; then
        info "未检测到 Docker"
        return
    fi

    HAS_DOCKER=true

    if ! docker info &>/dev/null 2>&1; then
        warn "Docker 已安装但 daemon 未运行"
        return
    fi

    local ver
    ver=$(docker --version 2>/dev/null | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    info "Docker 版本: $ver"

    check_docker_daemon
    check_docker_socket
    check_container_runtime
    check_container_images
    check_container_processes
}

check_docker_daemon() {
    info "--- Docker Daemon 配置检测 ---"

    local dc="/etc/docker/daemon.json"

    if [[ ! -f "$dc" ]]; then
        warn "daemon.json 不存在"
        show_remediation "docker_daemon_json"
    else
        pass "daemon.json 存在"
        check_daemon_json_bool "$dc" "userland-proxy" "false" "userland-proxy 已禁用" "docker_userland_proxy"
        check_daemon_json_bool "$dc" "icc" "false" "ICC 已禁用" "docker_icc"
        check_daemon_json_bool "$dc" "live-restore" "true" "live-restore 已启用" "docker_live_restore"
    fi

    # TCP 端口暴露
    local tcp
    tcp=$(ss -tlnp 2>/dev/null | grep -E ':2375|:2376' || true)
    if [[ -n "$tcp" ]]; then
        echo "$tcp" | grep -q ':2375' && \
            fail "Docker 通过 TCP 2375 明文端口暴露（极高危）" && \
            show_remediation "docker_tcp_plain"
    else
        pass "Docker 未通过 TCP 端口暴露"
    fi

    # Docker 数据目录权限
    local dd="/var/lib/docker"
    if [[ -d "$dd" ]]; then
        local perm
        perm=$(stat -c '%a' "$dd" 2>/dev/null)
        if [[ "$perm" == "710" || "$perm" == "700" ]]; then
            pass "Docker 数据目录权限正确 ($perm)"
        else
            warn "Docker 数据目录权限为 $perm（建议 710）"
        fi
    fi
}

check_daemon_json_bool() {
    local config="$1" key="$2" expected="$3" pass_msg="$4" rem_key="$5"
    if grep -q "\"$key\"" "$config" 2>/dev/null; then
        local value
        value=$(grep -oP "\"$key\"\s*:\s*\K(true|false)" "$config" 2>/dev/null | head -1)
        [[ "$value" == "$expected" ]] && pass "$pass_msg" || \
            warn "$pass_msg — 建议设为 $expected" && show_remediation "$rem_key"
    else
        warn "未设置 $key（建议 $expected）"
        show_remediation "$rem_key"
    fi
}

check_docker_socket() {
    info "--- Docker Socket 检查 ---"

    local sock="/var/run/docker.sock"
    if [[ -S "$sock" ]]; then
        local perm
        perm=$(stat -c '%a' "$sock" 2>/dev/null)
        if [[ "$perm" == "660" ]]; then
            pass "Docker socket 权限正确 ($perm)"
        else
            fail "Docker socket 权限过宽 ($perm)"
            act_fix_permission "$sock" "660" "Docker socket 权限过宽"
        fi
    fi

    # Socket 挂载到容器
    local containers
    containers=$(docker ps -q 2>/dev/null || true)
    [[ -z "$containers" ]] && return

    for cid in $containers; do
        if docker inspect --format='{{range .Mounts}}{{.Source}}{{"\n"}}{{end}}' "$cid" 2>/dev/null | \
            grep -qE '/var/run/docker\.sock|/run/docker\.sock'; then
            local cname
            cname=$(docker inspect --format='{{.Name}}' "$cid" 2>/dev/null | sed 's/^\///')
            fail "容器 [$cname] 挂载了 Docker socket（容器逃逸风险）"
            show_remediation "docker_socket_mounted"
        fi
    done
}

check_container_runtime() {
    info "--- 容器运行时安全检测 ---"

    local containers
    containers=$(docker ps -q 2>/dev/null || true)
    [[ -z "$containers" ]] && { info "无运行中的容器"; return; }

    local any=false

    for cid in $containers; do
        local cname
        cname=$(docker inspect --format='{{.Name}}' "$cid" 2>/dev/null | sed 's/^\///')
        is_whitelisted "$cname" && continue

        # 特权模式
        local priv
        priv=$(docker inspect --format='{{.HostConfig.Privileged}}' "$cid" 2>/dev/null)
        if [[ "$priv" == "true" ]]; then
            any=true
            fail "容器 [$cname] 以特权模式运行"
            show_remediation "container_privileged"
        fi

        # 危险挂载
        local mounts
        mounts=$(docker inspect --format='{{range .Mounts}}{{.Source}}{{"\n"}}{{end}}' "$cid" 2>/dev/null || true)
        for d in "${DANGEROUS_MOUNTS[@]}"; do
            echo "$mounts" | grep -qF "$d" 2>/dev/null && \
                any=true && fail "容器 [$cname] 挂载敏感路径: $d"
        done
        for fd in "${FULL_DIR_MOUNTS[@]}"; do
            echo "$mounts" | grep -qE "^${fd}$" 2>/dev/null && \
                any=true && fail "容器 [$cname] 整目录挂载: $fd"
        done

        # host 命名空间
        local pid_mode net_mode
        pid_mode=$(docker inspect --format='{{.HostConfig.PidMode}}' "$cid" 2>/dev/null)
        net_mode=$(docker inspect --format='{{.HostConfig.NetworkMode}}' "$cid" 2>/dev/null)
        [[ "$pid_mode" == "host" ]] && any=true && \
            fail "容器 [$cname] 使用 host PID 命名空间"
        [[ "$net_mode" == "host" ]] && \
            warn "容器 [$cname] 使用 host 网络模式"

        # 危险 Capabilities
        local caps
        caps=$(docker inspect --format='{{range .HostConfig.CapAdd}}{{.}}{{"\n"}}{{end}}' "$cid" 2>/dev/null || true)
        for cap in "${DANGEROUS_CAPS[@]}"; do
            echo "$caps" | grep -qi "^$cap$" 2>/dev/null && \
                any=true && fail "容器 [$cname] 添加危险 Capability: $cap"
        done

        # root 用户
        local user
        user=$(docker inspect --format='{{.Config.User}}' "$cid" 2>/dev/null)
        [[ -z "$user" || "$user" == "root" || "$user" == "0" ]] && \
            warn "容器 [$cname] 以 root 运行"
    done

    $any || pass "容器运行时配置未发现明显逃逸风险"
}

check_container_images() {
    info "--- 镜像安全检测 ---"

    local latest
    latest=$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep ':latest$' | head -10 || true)
    [[ -n "$latest" ]] && warn "使用 latest 标签的镜像: $(echo "$latest" | tr '\n' ' ')" || \
        pass "未发现 latest 标签"

    # 环境变量敏感信息
    local containers
    containers=$(docker ps -q 2>/dev/null || true)
    local sensitive=false
    for cid in $containers; do
        local cname
        cname=$(docker inspect --format='{{.Name}}' "$cid" 2>/dev/null | sed 's/^\///')
        local envs
        envs=$(docker inspect --format='{{range .Config.Env}}{{.}}{{"\n"}}{{end}}' "$cid" 2>/dev/null || true)
        local s
        s=$(echo "$envs" | \
            grep -iE '(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)=' | \
            grep -viE '=(true|false|\*+|null|)$' || true)
        if [[ -n "$s" ]]; then
            sensitive=true
            warn "容器 [$cname] 环境变量含敏感信息（已脱敏）:"
            echo "$s" | while read -r l; do
                log "       └─ $(echo "$l" | cut -d= -f1)=***"
            done
        fi
    done
    $sensitive || pass "环境变量未发现明文敏感信息"

    # Trivy
    if command -v trivy &>/dev/null; then
        info "使用 Trivy 扫描镜像漏洞..."
        local imgs
        imgs=$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '<none>' | head -5 || true)
        for img in $imgs; do
            local out
            out=$(trivy image --severity HIGH,CRITICAL --quiet --no-progress "$img" 2>/dev/null | \
                grep -E 'HIGH|CRITICAL' | head -3 || true)
            [[ -n "$out" ]] && warn "镜像 [$img] 高危漏洞: $(echo "$out" | head -1)"
        done
    fi
}

check_container_processes() {
    info "--- 容器内进程行为检测 ---"

    local containers
    containers=$(docker ps -q 2>/dev/null || true)
    [[ -z "$containers" ]] && return

    local any=false

    for cid in $containers; do
        local cname
        cname=$(docker inspect --format='{{.Name}}' "$cid" 2>/dev/null | sed 's/^\///')
        is_whitelisted "$cname" && continue

        local procs
        procs=$(docker top "$cid" 2>/dev/null | tail -n +2 || true)
        [[ -z "$procs" ]] && continue

        for kw in "${MALICIOUS_KEYWORDS[@]}"; do
            local hits
            hits=$(echo "$procs" | grep -iE "$kw" 2>/dev/null || true)
            if [[ -n "$hits" ]]; then
                any=true
                fail "容器 [$cname] 可疑进程 (关键字: $kw): $(echo "$hits" | head -1)"
                local pid
                pid=$(echo "$hits" | awk '{print $1}' | head -1)
                [[ -n "$pid" ]] && act_kill "$pid" "容器 $cname 恶意进程" "CRITICAL"
            fi
        done

        # 交互式 Shell
        local shells
        shells=$(echo "$procs" | grep -E '\b(bash|sh|zsh)\b' 2>/dev/null | \
            grep -vE '(entrypoint|start\.sh|docker-entrypoint|tini)' | head -3 || true)
        [[ -n "$shells" ]] && \
            warn "容器 [$cname] 存在交互式 Shell: $(echo "$shells" | head -1)"
    done

    $any || pass "容器内进程未发现明显异常"
}