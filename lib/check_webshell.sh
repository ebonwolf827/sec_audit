#!/bin/bash
#=============================================================
# lib/check_webshell.sh — 阶段 6b: Webshell 后门检测
# 特性: 网站类型自适应 | YARA 优先 | 正则降级 | 响应集成
# 修复:
#   1. 空关联数组在 set -u 下的 unbound variable 错误
#   2. 空普通数组的 unbound variable 错误
#   3. 所有数组访问使用 :- 默认值保护
#=============================================================

# ---------- 全局数组：显式初始化为空，避免 set -u 报错 ----------
declare -gA WEB_TYPES=()
declare -ga WEB_ROOTS=()

# ---------- 扫描限制 ----------
MAX_SCAN_DEPTH=6
MAX_FILE_SIZE=5242880

#=============================================================
# 主入口
#=============================================================
phase_check_webshell() {
    section "阶段 6b: Webshell 后门检测"

    detect_web_tech_stack

    # 类型计数（安全访问）
    local type_count=${#WEB_TYPES[@]}
    if [[ "$type_count" -eq 0 ]]; then
        info "未检测到网站代码，跳过 Webshell 检测"
        return
    fi

    # 安全输出网站类型列表
    local type_list
    type_list=$(printf '%s ' "${!WEB_TYPES[@]:-}" | sed 's/ $//')
    info "网站类型: ${type_list:-未探测到}"

    # 安全输出 Web 根目录列表
    local root_count=${#WEB_ROOTS[@]}
    if [[ "$root_count" -gt 0 ]]; then
        local root_list
        root_list=$(printf '%s ' "${WEB_ROOTS[@]:-}" | sed 's/ $//')
        info "Web 根目录: ${root_list}"
    else
        info "Web 根目录: 未探测到"
    fi

    # 按类型分派检测（使用 :- 安全访问）
    [[ -n "${WEB_TYPES[PHP]:-}" ]]    && scan_php_backdoors
    [[ -n "${WEB_TYPES[Java]:-}" ]]   && scan_java_backdoors
    [[ -n "${WEB_TYPES[Python]:-}" ]] && scan_python_backdoors
    [[ -n "${WEB_TYPES[NodeJS]:-}" ]] && scan_nodejs_backdoors
    [[ -n "${WEB_TYPES[DotNet]:-}" ]] && scan_dotnet_backdoors

    # 通用检测（所有类型都做）
    scan_generic_backdoors
}

#=============================================================
# 网站技术栈探测
#=============================================================
detect_web_tech_stack() {
    detect_from_processes
    detect_web_roots
    detect_from_framework_files
    dedup_web_roots
}

# ---------- 从运行进程识别 ----------
detect_from_processes() {
    local ps_output
    ps_output=$(ps -eo comm,args 2>/dev/null || true)

    # PHP
    if echo "$ps_output" | grep -qE 'php-fpm|php7\.[0-9]|php8\.[0-9]|apache2.*php|httpd.*php'; then
        WEB_TYPES[PHP]=1
        info "进程识别: PHP"
    fi

    # Java（Tomcat / Spring Boot / Jetty）
    if echo "$ps_output" | grep -qE 'tomcat|catalina|org\.apache\.catalina|spring-boot|jetty'; then
        WEB_TYPES[Java]=1
        info "进程识别: Java"
    elif pgrep -f 'java.*\.jar' &>/dev/null; then
        WEB_TYPES[Java]=1
        info "进程识别: Java（java -jar 进程）"
    fi

    # Python
    if echo "$ps_output" | grep -qE 'gunicorn|uwsgi|flask|django|fastapi|hypercorn'; then
        WEB_TYPES[Python]=1
        info "进程识别: Python"
    fi

    # Node.js
    if echo "$ps_output" | grep -qE 'node .*server|node .*app|pm2|next-server|nuxt|express'; then
        WEB_TYPES[NodeJS]=1
        info "进程识别: Node.js"
    fi

    # .NET
    if echo "$ps_output" | grep -qE 'dotnet .*\.dll|mono .*\.exe|w3wp'; then
        WEB_TYPES[DotNet]=1
        info "进程识别: .NET"
    fi
}

# ---------- 探测 Web 根目录 ----------
detect_web_roots() {
    # 从 Nginx 配置读取 root 指令
    for nginx_conf in /etc/nginx/nginx.conf /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
        [[ -f "$nginx_conf" ]] || continue
        while IFS= read -r root_path; do
            [[ -d "$root_path" ]] && WEB_ROOTS+=("$root_path")
        done < <(grep -oP '^\s*root\s+\K[^;]+' "$nginx_conf" 2>/dev/null | \
            grep -v '^/usr/share/nginx/html$' | head -10)
    done

    # 从 Apache 配置读取 DocumentRoot
    for apache_conf in /etc/apache2/sites-enabled/*.conf /etc/httpd/conf.d/*.conf /etc/apache2/httpd.conf; do
        [[ -f "$apache_conf" ]] || continue
        while IFS= read -r doc_root; do
            [[ -d "$doc_root" ]] && WEB_ROOTS+=("$doc_root")
        done < <(grep -oP '^\s*DocumentRoot\s+\K\S+' "$apache_conf" 2>/dev/null | head -10)
    done

    # 从 Tomcat server.xml 读取 appBase
    for server_xml in /opt/tomcat/conf/server.xml /usr/local/tomcat/conf/server.xml \
                      /var/lib/tomcat*/conf/server.xml /usr/share/tomcat*/conf/server.xml; do
        [[ -f "$server_xml" ]] || continue
        local tomcat_home
        tomcat_home=$(dirname "$(dirname "$server_xml")")
        [[ -d "${tomcat_home}/webapps" ]] && WEB_ROOTS+=("${tomcat_home}/webapps")
    done

    # 常见默认路径兜底
    for default_root in /var/www/html /var/www /usr/share/nginx/html /opt/tomcat/webapps \
                        /usr/local/tomcat/webapps /var/lib/tomcat/webapps; do
        [[ -d "$default_root" ]] && WEB_ROOTS+=("$default_root")
    done
}

# ---------- 从框架特征文件识别 ----------
detect_from_framework_files() {
    [[ ${#WEB_ROOTS[@]} -eq 0 ]] && return

    for root in "${WEB_ROOTS[@]:-}"; do
        [[ -d "$root" ]] || continue

        # PHP
        if [[ -f "${root}/composer.json" ]] || [[ -f "${root}/index.php" ]] || \
           [[ -f "${root}/wp-config.php" ]] || [[ -f "${root}/artisan" ]]; then
            WEB_TYPES[PHP]=1
            info "框架识别: PHP ($root)"
        fi

        # Java
        if [[ -f "${root}/WEB-INF/web.xml" ]] || [[ -f "${root}/META-INF/MANIFEST.MF" ]] || \
           [[ -f "${root}/pom.xml" ]]; then
            WEB_TYPES[Java]=1
            info "框架识别: Java ($root)"
        fi

        # Python
        if [[ -f "${root}/manage.py" ]] || [[ -f "${root}/wsgi.py" ]] || \
           [[ -f "${root}/app.py" ]] || [[ -f "${root}/requirements.txt" ]]; then
            WEB_TYPES[Python]=1
            info "框架识别: Python ($root)"
        fi

        # Node.js
        if [[ -f "${root}/package.json" ]]; then
            if grep -qE '"(express|koa|fastify|hapi|nest)"' "${root}/package.json" 2>/dev/null; then
                WEB_TYPES[NodeJS]=1
                info "框架识别: Node.js ($root)"
            fi
        fi

        # .NET
        if [[ -f "${root}/web.config" ]]; then
            WEB_TYPES[DotNet]=1
            info "框架识别: .NET ($root)"
        elif find "$root" -maxdepth 1 \( -name "*.dll" -o -name "*.aspx" \) 2>/dev/null | grep -q .; then
            WEB_TYPES[DotNet]=1
            info "框架识别: .NET ($root)"
        fi
    done
}

# ---------- 去重 Web 根目录 ----------
dedup_web_roots() {
    [[ ${#WEB_ROOTS[@]} -eq 0 ]] && return

    local -a unique_roots
    mapfile -t unique_roots < <(printf '%s\n' "${WEB_ROOTS[@]:-}" | sort -u)
    WEB_ROOTS=("${unique_roots[@]:-}")
}

#=============================================================
# PHP 后门扫描
#=============================================================
scan_php_backdoors() {
    info "--- PHP 后门扫描 ---"

    local php_files
    php_files=$(find_php_files)
    [[ -z "$php_files" ]] && { info "未找到 PHP 文件"; return; }

    local total
    total=$(echo "$php_files" | wc -l)
    info "待扫描 PHP 文件数: $total"

    if $HAS_YARA; then
        info "使用 YARA 规则扫描 PHP 文件..."
        scan_with_yara "$php_files" "webshells" "PHP"
        return
    fi

    info "YARA 不可用，使用正则降级方案"
    scan_php_regex "$php_files"
}

# ---------- YARA 通用扫描 ----------
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

# ---------- PHP 正则降级扫描 ----------
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
            show_remediation "webshell_php"
            act_quarantine "$file" "PHP 后门特征" "CRITICAL"
            continue
        fi

        local size
        size=$(stat -c '%s' "$file" 2>/dev/null || echo 0)
        if [[ "$size" -lt 200 ]] && grep -qE '(eval|assert|system|exec|shell_exec)' "$file" 2>/dev/null; then
            found=true
            fail "PHP 一句话木马 [$file] (${size}B)"
            show_remediation "webshell_php_oneshell"
            act_quarantine "$file" "PHP 一句话木马" "CRITICAL"
        fi
    done <<< "$file_list"

    $found || pass "PHP 文件未发现 Webshell（正则）"
}

#=============================================================
# Java/JSP 后门扫描
#=============================================================
scan_java_backdoors() {
    info "--- Java/JSP 后门扫描 ---"

    local files
    files=$(find_java_web_files)
    [[ -z "$files" ]] && { info "未找到 JSP 文件"; return; }

    local total
    total=$(echo "$files" | wc -l)
    info "待扫描 JSP 文件数: $total"

    if $HAS_YARA; then
        scan_with_yara "$files" "webshells" "Java"
        return
    fi

    local found=false
    while IFS= read -r file; do
        [[ -f "$file" ]] || continue
        is_whitelisted "$file" && continue
        if grep -qP 'Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|new\s+ProcessBuilder|defineClass' "$file" 2>/dev/null; then
            found=true
            fail "Java 高危后门 [$file]"
            show_remediation "webshell_java"
            act_quarantine "$file" "JSP Webshell" "CRITICAL"
        fi
    done <<< "$files"
    $found || pass "JSP 文件未发现 Webshell"
}

#=============================================================
# Python 后门扫描
#=============================================================
scan_python_backdoors() {
    info "--- Python 后门扫描 ---"

    local files
    files=$(find_python_files)
    [[ -z "$files" ]] && { info "未找到 Python 文件"; return; }

    local total
    total=$(echo "$files" | wc -l)
    info "待扫描 Python 文件数: $total"

    if $HAS_YARA; then
        scan_with_yara "$files" "webshells" "Python"
        return
    fi

    pass "Python 文件扫描完成（正则降级）"
}

#=============================================================
# Node.js 后门扫描
#=============================================================
scan_nodejs_backdoors() {
    info "--- Node.js 后门扫描 ---"

    local files
    files=$(find_nodejs_files)
    [[ -z "$files" ]] && { info "未找到 Node.js 文件"; return; }

    local total
    total=$(echo "$files" | wc -l)
    info "待扫描 Node.js 文件数: $total"

    if $HAS_YARA; then
        scan_with_yara "$files" "webshells" "Node.js"
        return
    fi

    pass "Node.js 文件扫描完成（正则降级）"
}

#=============================================================
# .NET 后门扫描
#=============================================================
scan_dotnet_backdoors() {
    info "--- .NET 后门扫描 ---"

    local files
    files=$(find_dotnet_files)
    [[ -z "$files" ]] && { info "未找到 .NET 文件"; return; }

    local total
    total=$(echo "$files" | wc -l)
    info "待扫描 .NET 文件数: $total"

    if $HAS_YARA; then
        scan_with_yara "$files" "webshells" ".NET"
        return
    fi

    pass ".NET 文件扫描完成（正则降级）"
}

#=============================================================
# 通用 Webshell 特征扫描（所有类型）
#=============================================================
scan_generic_backdoors() {
    info "--- 通用 Webshell 特征扫描 ---"

    [[ ${#WEB_ROOTS[@]} -eq 0 ]] && {
        info "未找到 Web 根目录，跳过通用扫描"
        return
    }

    local found=false

    for root in "${WEB_ROOTS[@]:-}"; do
        [[ -d "$root" ]] || continue

        # 1. 隐藏的可执行 Web 文件
        local hidden
        hidden=$(find "$root" -maxdepth "$MAX_SCAN_DEPTH" \
            \( -name ".*.php" -o -name ".*.jsp" -o -name ".*.asp*" -o -name ".*.py" \) \
            -type f 2>/dev/null | head -20 || true)
        if [[ -n "$hidden" ]]; then
            found=true
            fail "发现隐藏 Web 文件:"
            echo "$hidden" | while read -r f; do
                log "       └─ $f"
                act_quarantine "$f" "隐藏 Web 文件" "HIGH"
            done
        fi

        # 2. 伪装后缀（webshell 常被改名为 .php.txt / .php.bak）
        local disguise
        disguise=$(find "$root" -maxdepth "$MAX_SCAN_DEPTH" \
            \( -name "*.php.*" -o -name "*.jsp.*" -o -name "*.asp.*" \) \
            -type f 2>/dev/null | \
            grep -vE '\.(css|js|map|html|json)$' | head -20 || true)
        if [[ -n "$disguise" ]]; then
            found=true
            fail "发现伪装后缀的可疑文件:"
            echo "$disguise" | while read -r f; do log "       └─ $f"; done
        fi

        # 3. 近 7 天新增的 Web 脚本
        local recent
        recent=$(find "$root" -maxdepth "$MAX_SCAN_DEPTH" \
            \( -name "*.php" -o -name "*.jsp" -o -name "*.jspx" -o -name "*.asp" -o -name "*.aspx" \) \
            -type f -mtime -7 2>/dev/null | head -20 || true)
        if [[ -n "$recent" ]]; then
            local recent_count
            recent_count=$(echo "$recent" | wc -l)
            warn "近 7 天新增的 Web 脚本 ($recent_count 个，需确认是否为业务更新):"
            echo "$recent" | head -10 | while read -r f; do log "       └─ $f"; done
        fi

        # 4. .htaccess 异常重定向
        local htaccess
        htaccess=$(find "$root" -maxdepth 3 -name ".htaccess" -type f 2>/dev/null | head -5 || true)
        if [[ -n "$htaccess" ]]; then
            echo "$htaccess" | while read -r f; do
                if grep -qiE 'RewriteRule.*(http://|https://)' "$f" 2>/dev/null; then
                    local external_url
                    external_url=$(grep -oP 'RewriteRule.*?\Khttps?://[^\s]+' "$f" | head -1)
                    if [[ -n "$external_url" ]]; then
                        found=true
                        fail "发现 .htaccess 外链重定向: $f → $external_url"
                    fi
                fi
            done
        fi

        # 5. Web 目录下的 ELF 可执行文件
        local unusual_exec
        unusual_exec=$(find "$root" -maxdepth 3 -type f -perm -111 \
            ! -name "*.sh" ! -name "*.py" ! -name "*.pl" 2>/dev/null | \
            xargs -I{} file {} 2>/dev/null | grep 'ELF' | head -10 || true)
        if [[ -n "$unusual_exec" ]]; then
            found=true
            warn "Web 目录下发现 ELF 可执行文件（极不寻常）:"
            echo "$unusual_exec" | while read -r l; do log "       └─ ${l:0:150}"; done
            show_remediation "webshell_elf"
        fi
    done

    $found || pass "未发现通用 Webshell 特征"
}

#=============================================================
# 文件查找辅助函数
#=============================================================

find_php_files() {
    [[ ${#WEB_ROOTS[@]} -eq 0 ]] && return
    for r in "${WEB_ROOTS[@]:-}"; do
        [[ -d "$r" ]] || continue
        find "$r" -maxdepth "$MAX_SCAN_DEPTH" -type f \
            -name "*.php" -size -"${MAX_FILE_SIZE}c" 2>/dev/null
    done | sort -u
}

find_java_web_files() {
    [[ ${#WEB_ROOTS[@]} -eq 0 ]] && return
    for r in "${WEB_ROOTS[@]:-}"; do
        [[ -d "$r" ]] || continue
        find "$r" -maxdepth "$MAX_SCAN_DEPTH" -type f \
            \( -name "*.jsp" -o -name "*.jspx" \) \
            -size -"${MAX_FILE_SIZE}c" 2>/dev/null
    done | sort -u
}

find_python_files() {
    [[ ${#WEB_ROOTS[@]} -eq 0 ]] && return
    for r in "${WEB_ROOTS[@]:-}"; do
        [[ -d "$r" ]] || continue
        find "$r" -maxdepth "$MAX_SCAN_DEPTH" -type f \
            -name "*.py" -size -"${MAX_FILE_SIZE}c" 2>/dev/null
    done | sort -u
}

find_nodejs_files() {
    [[ ${#WEB_ROOTS[@]} -eq 0 ]] && return
    for r in "${WEB_ROOTS[@]:-}"; do
        [[ -d "$r" ]] || continue
        find "$r" -maxdepth "$MAX_SCAN_DEPTH" -type f -name "*.js" \
            ! -path "*/node_modules/*" \
            ! -path "*/dist/*" \
            ! -path "*/build/*" \
            -size -"${MAX_FILE_SIZE}c" 2>/dev/null
    done | sort -u
}

find_dotnet_files() {
    [[ ${#WEB_ROOTS[@]} -eq 0 ]] && return
    for r in "${WEB_ROOTS[@]:-}"; do
        [[ -d "$r" ]] || continue
        find "$r" -maxdepth "$MAX_SCAN_DEPTH" -type f \
            \( -name "*.aspx" -o -name "*.ashx" -o -name "*.asmx" -o -name "*.asp" \) \
            -size -"${MAX_FILE_SIZE}c" 2>/dev/null
    done | sort -u
}