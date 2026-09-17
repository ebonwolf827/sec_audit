#!/bin/bash
#=============================================================
# lib/check_nacos.sh — 阶段 6c: Nacos 安全检测
# 检测: 版本 | 鉴权配置 | 默认凭证 | 网络暴露 | 已知漏洞 | 运行时安全
#=============================================================

HAS_NACOS=false
NACOS_HOME=""
NACOS_VERSION=""
NACOS_PORT=""
NACOS_CONFIG_FILE=""
NACOS_IS_DOCKER=false
NACOS_ENV_FILE=""

NACOS_DEFAULT_PORTS=(8848 9848 9849 7848)
NACOS_DEFAULT_JWT_KEY="SecretKey012345678901234567890123456789012345678901234567890123456789"
NACOS_DEFAULT_IDENTITY_KEY="serverIdentity"
NACOS_DEFAULT_IDENTITY_VALUE="security"

phase_check_nacos() {
    section "阶段 6c: Nacos 安全检测"

    detect_nacos

    if ! $HAS_NACOS; then
        info "未检测到 Nacos 服务"
        return
    fi

    info "Nacos 部署方式: $($NACOS_IS_DOCKER && echo 'Docker' || echo '非Docker')"
    info "Nacos 版本: ${NACOS_VERSION:-未知}"
    info "Nacos 端口: ${NACOS_PORT:-未知}"

    check_nacos_version
    check_nacos_auth_config
    check_nacos_default_credentials
    check_nacos_network_exposure
    check_nacos_known_vulnerabilities
    check_nacos_config_security
    check_nacos_runtime_security
}

detect_nacos() {
    info "--- Nacos 部署探测 ---"

    local nacos_pids
    nacos_pids=$(pgrep -f 'nacos' 2>/dev/null || true)
    [[ -n "$nacos_pids" ]] && HAS_NACOS=true

    local port_found=""
    for port in "${NACOS_DEFAULT_PORTS[@]}"; do
        if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
            port_found="$port"
            HAS_NACOS=true
            break
        fi
    done
    [[ -n "$port_found" ]] && NACOS_PORT="$port_found"

    if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        local container
        container=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -i nacos | head -1 || true)
        if [[ -n "$container" ]]; then
            HAS_NACOS=true
            NACOS_IS_DOCKER=true
            NACOS_ENV_FILE=$(docker inspect "$container" \
                --format '{{range .Config.Env}}{{.}}{{"\n"}}{{end}}' 2>/dev/null || true)
        fi
    fi

    for nacos_dir in /opt/nacos /usr/local/nacos /home/nacos /data/nacos /app/nacos; do
        [[ -d "$nacos_dir" ]] || continue
        if [[ -f "${nacos_dir}/conf/application.properties" ]]; then
            HAS_NACOS=true
            NACOS_HOME="$nacos_dir"
            NACOS_CONFIG_FILE="${nacos_dir}/conf/application.properties"
            break
        fi
    done

    if [[ -z "$NACOS_VERSION" && -n "$NACOS_PORT" ]]; then
        NACOS_VERSION=$(curl -s -m 5 "http://127.0.0.1:${NACOS_PORT}/nacos/v1/console/server/state" 2>/dev/null | \
            grep -oP '"version":"\K[^"]+' | head -1 || true)
    fi
}

check_nacos_version() {
    info "--- Nacos 版本安全检查 ---"
    [[ -z "$NACOS_VERSION" ]] && { warn "无法获取 Nacos 版本"; return; }

    info "Nacos 版本: $NACOS_VERSION"

    version_lt() { printf '%s\n%s\n' "$1" "$2" | sort -V -C 2>/dev/null && return 1 || return 0; }

    if version_lt "$NACOS_VERSION" "1.4.1"; then
        fail "Nacos $NACOS_VERSION 低于 1.4.1，存在认证绕过 (CVE-2021-29441)"
        show_remediation "nacos_upgrade"
    elif version_lt "$NACOS_VERSION" "2.4.0"; then
        warn "Nacos $NACOS_VERSION 低于 2.4.0，存在 RCE 风险"
        show_remediation "nacos_upgrade"
    fi
}

check_nacos_auth_config() {
    info "--- Nacos 鉴权配置检测 ---"

    if $NACOS_IS_DOCKER && [[ -n "$NACOS_ENV_FILE" ]]; then
        check_docker_env_auth
        return
    fi

    [[ ! -f "$NACOS_CONFIG_FILE" ]] && { warn "未找到 Nacos 配置文件"; return; }
    info "配置文件: $NACOS_CONFIG_FILE"

    local auth_enabled
    auth_enabled=$(grep -oP '^\s*nacos\.core\.auth\.enabled\s*=\s*\K\w+' "$NACOS_CONFIG_FILE" 2>/dev/null | head -1 || echo "false")
    if [[ "$auth_enabled" == "true" ]]; then
        pass "鉴权开关已开启"
    else
        fail "鉴权开关未开启 (nacos.core.auth.enabled=$auth_enabled)"
        show_remediation "nacos_enable_auth"
    fi

    local jwt_key
    jwt_key=$(grep -oP '^\s*nacos\.core\.auth\.plugin\.nacos\.token\.secret\.key\s*=\s*\K.*' "$NACOS_CONFIG_FILE" 2>/dev/null | head -1 || true)
    if [[ -z "$jwt_key" ]]; then
        fail "JWT 密钥未配置"
        show_remediation "nacos_jwt_key"
    elif [[ "$jwt_key" == "$NACOS_DEFAULT_JWT_KEY" ]]; then
        fail "JWT 密钥使用默认值"
        show_remediation "nacos_jwt_key"
    else
        pass "JWT 密钥已自定义"
    fi

    local id_key id_val
    id_key=$(grep -oP '^\s*nacos\.core\.auth\.server\.identity\.key\s*=\s*\K.*' "$NACOS_CONFIG_FILE" 2>/dev/null | head -1 || true)
    id_val=$(grep -oP '^\s*nacos\.core\.auth\.server\.identity\.value\s*=\s*\K.*' "$NACOS_CONFIG_FILE" 2>/dev/null | head -1 || true)

    if [[ "$id_key" == "$NACOS_DEFAULT_IDENTITY_KEY" || "$id_val" == "$NACOS_DEFAULT_IDENTITY_VALUE" ]]; then
        fail "server.identity 使用默认值"
        show_remediation "nacos_server_identity"
    elif [[ -n "$id_key" && -n "$id_val" ]]; then
        pass "server.identity 已自定义"
    fi
}

check_docker_env_auth() {
    info "从 Docker 环境变量检测鉴权配置..."

    if echo "$NACOS_ENV_FILE" | grep -q 'NACOS_AUTH_ENABLE=true'; then
        pass "Docker 环境鉴权已开启"
    else
        fail "Docker 环境鉴权未开启"
        show_remediation "nacos_enable_auth"
    fi

    local jwt
    jwt=$(echo "$NACOS_ENV_FILE" | grep -oP 'NACOS_AUTH_TOKEN=\K.*' | head -1 || true)
    if [[ -z "$jwt" ]]; then
        fail "Docker 环境未配置 NACOS_AUTH_TOKEN"
    elif [[ "$jwt" == "$NACOS_DEFAULT_JWT_KEY" ]]; then
        fail "Docker 环境 NACOS_AUTH_TOKEN 使用默认值"
    else
        pass "Docker 环境 JWT 密钥已自定义"
    fi
}

check_nacos_default_credentials() {
    info "--- Nacos 默认凭证检测 ---"
    [[ -z "$NACOS_PORT" ]] && return

    local base="http://127.0.0.1:${NACOS_PORT}"

    local login
    login=$(curl -s -m 5 -X POST "${base}/nacos/v1/auth/users/login" \
        -d "username=nacos&password=nacos" 2>/dev/null || true)

    if echo "$login" | grep -q 'accessToken'; then
        fail "Nacos 使用默认账号密码 nacos/nacos（极高危）"
        show_remediation "nacos_default_password"
    else
        pass "默认账号 nacos/nacos 登录失败"
    fi

    local console_code
    console_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
        "${base}/nacos/v1/console/" 2>/dev/null || echo "000")

    if [[ "$console_code" == "200" ]]; then
        fail "Nacos 控制台可未授权访问"
        show_remediation "nacos_unauthorized"
    else
        pass "Nacos 控制台需要鉴权 (HTTP $console_code)"
    fi
}

check_nacos_network_exposure() {
    info "--- Nacos 网络暴露检测 ---"
    [[ -z "$NACOS_PORT" ]] && return

    local addr
    addr=$(ss -tlnp 2>/dev/null | grep ":${NACOS_PORT} " | awk '{print $4}' | head -1 || true)
    if [[ "$addr" == "0.0.0.0:${NACOS_PORT}" || "$addr" == "*:${NACOS_PORT}" ]]; then
        warn "Nacos 监听所有网络接口，建议绑定内网 IP"
        show_remediation "nacos_bind_internal"
    fi

    local public_ip
    public_ip=$(curl -s -m 3 https://checkip.amazonaws.com 2>/dev/null || true)
    if [[ -n "$public_ip" ]]; then
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
            "http://${public_ip}:${NACOS_PORT}/nacos/" 2>/dev/null || echo "000")
        if [[ "$code" == "200" ]]; then
            fail "Nacos 可通过公网访问 (${public_ip}:${NACOS_PORT})"
            show_remediation "nacos_public_exposure"
        fi
    fi
}

check_nacos_known_vulnerabilities() {
    info "--- Nacos 已知漏洞检测 ---"
    [[ -z "$NACOS_PORT" ]] && return

    local base="http://127.0.0.1:${NACOS_PORT}"

    # CVE-2021-29441: User-Agent 绕过
    local bypass
    bypass=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
        -H "User-Agent: Nacos-Server" \
        "${base}/nacos/v1/auth/users?pageNo=1&pageSize=1" 2>/dev/null || echo "000")

    if [[ "$bypass" == "200" ]]; then
        fail "CVE-2021-29441: User-Agent 绕过认证漏洞"
        show_remediation "nacos_cve_2021_29441"
    else
        pass "CVE-2021-29441: 未命中"
    fi

    # Nacos 3.x 权限绕过 (3.0.0~3.2.3)
    if [[ -n "$NACOS_VERSION" ]]; then
        version_lt() { printf '%s\n%s\n' "$1" "$2" | sort -V -C 2>/dev/null && return 1 || return 0; }
        if ! version_lt "$NACOS_VERSION" "3.0.0" && version_lt "$NACOS_VERSION" "3.2.4"; then
            local v3test
            v3test=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
                -X POST "${base}/nacos/v3/auth/user" \
                -d "username=sec_test_$(date +%s)&password=Test@2026" 2>/dev/null || echo "000")
            [[ "$v3test" == "200" ]] && \
                fail "Nacos 3.x 权限绕过: /v3/auth/user 可未授权创建用户" && \
                show_remediation "nacos_v3_bypass" || \
                pass "Nacos 3.x /v3/auth/user 接口需要鉴权"
        fi
    fi

    # removal/derby 接口
    local removal
    removal=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
        "${base}/nacos/v1/cs/ops/data/removal" 2>/dev/null || echo "000")
    [[ "$removal" == "200" ]] && \
        fail "Nacos removal 接口可未授权访问（RCE 风险）" && \
        show_remediation "nacos_rce"
}

check_nacos_config_security() {
    info "--- Nacos 配置安全检测 ---"
    [[ ! -f "$NACOS_CONFIG_FILE" ]] && return

    local db_pass
    db_pass=$(grep -oP '^\s*db\.password\s*=\s*\K.*' "$NACOS_CONFIG_FILE" 2>/dev/null | head -1 || true)
    if [[ -n "$db_pass" && ${#db_pass} -lt 8 ]]; then
        fail "数据库密码过短 (${#db_pass} 字符)"
        show_remediation "nacos_db_password"
    fi

    local db_platform
    db_platform=$(grep -oP '^\s*spring\.datasource\.platform\s*=\s*\K.*' "$NACOS_CONFIG_FILE" 2>/dev/null | head -1 || true)
    if echo "$db_platform" | grep -qi 'derby'; then
        warn "使用 Derby 内嵌数据库（生产环境不推荐）"
        show_remediation "nacos_db_external"
    fi
}

check_nacos_runtime_security() {
    info "--- Nacos 运行时安全检测 ---"
    [[ -z "$NACOS_HOME" ]] && return

    local pid user
    pid=$(pgrep -f 'nacos' 2>/dev/null | head -1 || true)
    if [[ -n "$pid" ]]; then
        user=$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ' || true)
        if [[ "$user" == "root" ]]; then
            warn "Nacos 以 root 用户运行"
            show_remediation "nacos_run_as_root"
        else
            pass "Nacos 运行用户: $user"
        fi
    fi

    local conf_dir="${NACOS_HOME}/conf"
    if [[ -d "$conf_dir" ]]; then
        local perm
        perm=$(stat -c '%a' "$conf_dir" 2>/dev/null)
        if [[ "$perm" == "755" || "$perm" == "750" || "$perm" == "700" ]]; then
            pass "配置目录权限: $perm"
        else
            warn "配置目录权限为 $perm（建议 750）"
        fi
    fi
}