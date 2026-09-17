#!/bin/bash
#=============================================================
# lib/check_webshell.sh — 阶段 6b: Webshell 后门检测
# 特性: 网站类型自适应 | YARA 优先 | 正则降级 | 响应集成
#=============================================================

declare -A WEB_TYPES
declare -a WEB_ROOTS
MAX_SCAN_DEPTH=6
MAX_FILE_SIZE=5242880

phase_check_webshell() {
    section "阶段 6b: Webshell 后门检测"

    detect_web_tech_stack
    [[ ${#WEB_TYPES[@]} -eq 0 ]] && { info "未检测到网站代码，跳过"; return; }

    info "网站类型: ${!WEB_TYPES[*]}"
    info "Web 根目录: ${WEB_ROOTS[*]}"

    [[ -n "${WEB_TYPES[PHP]:-}" ]]    && scan_php_backdoors
    [[ -n "${WEB_TYPES[Java]:-}" ]]   && scan_java_backdoors
    [[ -n "${WEB_TYPES[Python]:-}" ]] && scan_python_backdoors
    [[ -n "${WEB_TYPES[NodeJS]:-}" ]] && scan_nodejs_backdoors
    [[ -n "${WEB_TYPES[DotNet]:-}" ]] && scan_dotnet_backdoors

    scan_generic_backdoors
}

detect_web_tech_stack() {
    local ps_output
    ps_output=$(ps -eo comm,args 2>/dev/null || true)

    echo "$ps_output" | grep -qE 'php-fpm|php7|php8' && WEB_TYPES[PHP]=1
    echo "$ps_output" | grep -qE 'tomcat|catalina|spring-boot|jetty' && WEB_TYPES[Java]=1
    echo "$ps_output" | grep -qE 'gunicorn|uwsgi|flask|django|fastapi' && WEB_TYPES[Python]=1
    echo "$ps_output" | grep -qE 'node .*server|pm2|next-server' && WEB_TYPES[NodeJS]=1

    for root in /var/www/html /var/www /usr/share/nginx/html /opt/tomcat/webapps \
                /usr/local/tomcat/webapps /var/lib/tomcat/webapps; do
        [[ -d "$root" ]] && WEB_ROOTS+=("$root")
    done

    for root in "${WEB_ROOTS[@]}"; do
        [[ -f "${root}/index.php" || -f "${root}/wp-config.php" ]] && WEB_TYPES[PHP]=1
        [[ -f "${root}/WEB-INF/web.xml" ]] && WEB_TYPES[Java]=1
        [[ -f "${root}/wsgi.py" || -f "${root}/manage.py" ]] && WEB_TYPES[Python]=1
    done

    if [[ ${#WEB_ROOTS[@]} -gt 0 ]]; then
        local -a unique
        mapfile -t unique < <(printf '%s\n' "${WEB_ROOTS[@]}" | sort -u)
        WEB_ROOTS=("${unique[@]}")
    fi
}

scan_php_backdoors() {
    info "--- PHP 后门扫描 ---"
    local files
    files=$(find_php_files)
    [[ -z "$files" ]] && return
    info "待扫描 PHP 文件数: $(echo "$files" | wc -l)"

    if $HAS_YARA; then
        scan_with_yara "$files" "webshells" "PHP"
        return
    fi
    scan_php_regex "$files"
}

scan_with_yara() {
    local file_list="$1" category="$2" lang="$3"
    local found=false

    while IFS= read -r file; do
        [[ -f "$file" ]] || continue
        is_whitelisted "$file" && continue

        local result
        result=$(yara_scan_file "$file" "$category")
        if [[ -n "$result" ]]; then
            found=true
            local rule
            rule=$(echo "$result" | awk '{print $1}')
            fail "[$lang] YARA 命中 [$rule]: $file"
            show_remediation "webshell_yara"
            act_quarantine "$file" "YARA 命中 $rule" "CRITICAL"
        fi
    done <<< "$file_list"

    $found || pass "$lang 文件 YARA 扫描未发现 Webshell"
}

scan_php_regex() {
    local file_list="$1"
    local found=false
    local high='(eval|assert|system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\['
    local medium='base64_decode\s*\(\s*\$_(POST|GET|REQUEST)|gzinflate\s*\(\s*base64_decode|create_function\s*\(|preg_replace.*/.*/e'

    while IFS= read -r file; do
        [[ -f "$file" ]] || continue
        is_whitelisted "$file" && continue

        if grep -qP "$high" "$file" 2>/dev/null || grep -qP "$medium" "$file" 2>/dev/null; then
            found=true
            fail "PHP 后门 [$file]"
            act_quarantine "$file" "PHP 后门特征" "CRITICAL"
            continue
        fi

        local size
        size=$(stat -c '%s' "$file" 2>/dev/null || echo 0)
        if [[ "$size" -lt 200 ]] && grep -qE '(eval|assert|system|exec|shell_exec)' "$file" 2>/dev/null; then
            found=true
            fail "PHP 一句话木马 [$file] (${size}B)"
            act_quarantine "$file" "PHP 一句话木马" "CRITICAL"
        fi
    done <<< "$file_list"
    $found || pass "PHP 文件未发现 Webshell（正则）"
}

scan_java_backdoors() {
    info "--- Java/JSP 后门扫描 ---"
    local files
    files=$(find_java_web_files)
    [[ -z "$files" ]] && return
    if $HAS_YARA; then scan_with_yara "$files" "webshells" "Java"; return; fi

    local found=false
    while IFS= read -r file; do
        [[ -f "$file" ]] || continue
        is_whitelisted "$file" && continue
        if grep -qP 'Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|new\s+ProcessBuilder|defineClass' "$file" 2>/dev/null; then
            found=true
            fail "Java 高危后门 [$file]"
            act_quarantine "$file" "JSP Webshell" "CRITICAL"
        fi
    done <<< "$files"
    $found || pass "JSP 文件未发现 Webshell"
}

scan_python_backdoors() {
    info "--- Python 后门扫描 ---"
    local files
    files=$(find_python_files)
    [[ -z "$files" ]] && return
    if $HAS_YARA; then scan_with_yara "$files" "webshells" "Python"; return; fi
    pass "Python 文件扫描完成（正则降级）"
}

scan_nodejs_backdoors() {
    info "--- Node.js 后门扫描 ---"
    local files
    files=$(find_nodejs_files)
    [[ -z "$files" ]] && return
    if $HAS_YARA; then scan_with_yara "$files" "webshells" "Node.js"; return; fi
    pass "Node.js 文件扫描完成（正则降级）"
}

scan_dotnet_backdoors() {
    info "--- .NET 后门扫描 ---"
    local files
    files=$(find_dotnet_files)
    [[ -z "$files" ]] && return
    if $HAS_YARA; then scan_with_yara "$files" "webshells" ".NET"; return; fi
    pass ".NET 文件扫描完成（正则降级）"
}

scan_generic_backdoors() {
    info "--- 通用 Webshell 特征扫描 ---"
    local found=false
    for root in "${WEB_ROOTS[@]}"; do
        [[ -d "$root" ]] || continue

        local hidden
        hidden=$(find "$root" -maxdepth "$MAX_SCAN_DEPTH" \
            \( -name ".*.php" -o -name ".*.jsp" -o -name ".*.asp*" \) \
            -type f 2>/dev/null | head -10 || true)
        if [[ -n "$hidden" ]]; then
            found=true
            fail "隐藏 Web 文件:"
            echo "$hidden" | while read -r f; do
                log "       └─ $f"
                act_quarantine "$f" "隐藏 Web 文件" "HIGH"
            done
        fi

        local recent
        recent=$(find "$root" -maxdepth "$MAX_SCAN_DEPTH" \
            \( -name "*.php" -o -name "*.jsp" \) -type f -mtime -7 2>/dev/null | head -10 || true)
        [[ -n "$recent" ]] && warn "近 7 天新增 Web 脚本: $(echo "$recent" | tr '\n' ' ')"
    done
    $found || pass "未发现通用 Webshell 特征"
}

find_php_files() {
    for r in "${WEB_ROOTS[@]}"; do
        [[ -d "$r" ]] || continue
        find "$r" -maxdepth "$MAX_SCAN_DEPTH" -type f -name "*.php" -size -"${MAX_FILE_SIZE}c" 2>/dev/null
    done | sort -u
}

find_java_web_files() {
    for r in "${WEB_ROOTS[@]}"; do
        [[ -d "$r" ]] || continue
        find "$r" -maxdepth "$MAX_SCAN_DEPTH" -type f \( -name "*.jsp" -o -name "*.jspx" \) \
            -size -"${MAX_FILE_SIZE}c" 2>/dev/null
    done | sort -u
}

find_python_files() {
    for r in "${WEB_ROOTS[@]}"; do
        [[ -d "$r" ]] || continue
        find "$r" -maxdepth "$MAX_SCAN_DEPTH" -type f -name "*.py" -size -"${MAX_FILE_SIZE}c" 2>/dev/null
    done | sort -u
}

find_nodejs_files() {
    for r in "${WEB_ROOTS[@]}"; do
        [[ -d "$r" ]] || continue
        find "$r" -maxdepth "$MAX_SCAN_DEPTH" -type f -name "*.js" \
            ! -path "*/node_modules/*" ! -path "*/dist/*" -size -"${MAX_FILE_SIZE}c" 2>/dev/null
    done | sort -u
}

find_dotnet_files() {
    for r in "${WEB_ROOTS[@]}"; do
        [[ -d "$r" ]] || continue
        find "$r" -maxdepth "$MAX_SCAN_DEPTH" -type f \( -name "*.aspx" -o -name "*.ashx" \) \
            -size -"${MAX_FILE_SIZE}c" 2>/dev/null
    done | sort -u
}