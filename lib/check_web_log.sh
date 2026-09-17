#!/bin/bash
#=============================================================
# lib/check_web_log.sh — 阶段 8: Web 日志审计
# 目标: Nginx + Tomcat | SQL注入 | Webshell | 扫描器 | 404分析
#=============================================================

NGINX_ACCESS_LOG=""
TOMCAT_ACCESS_LOG=""

SCANNER_UA="sqlmap|nikto|nmap|masscan|acunetix|burpsuite|dirbuster|gobuster|dirb|wfuzz|nuclei|xray|afrog"

SQLI_PATTERN="union.*select|or\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema|load_file\s*\(|into\s+outfile|extractvalue\s*\(|updatexml\s*\(|%27|%22"

XSS_PATTERN="<script|onerror\s*=|javascript\s*:|alert\s*\(|document\.cookie"

RCE_PATTERN="eval\s*\(|base64_decode\s*\(|system\s*\(|Runtime\.exec|ProcessBuilder|/bin/bash|/bin/sh"

LFI_PATTERN="\.\./|/etc/passwd|/WEB-INF/web\.xml|%2e%2e|%252e%252e"

SENSITIVE_PATHS="\.env|\.git|\.svn|wp-config|phpmyadmin|/manager/html|/host-manager|/actuator|/druid|/swagger"

DESERIALIZE_PATTERN="rememberMe|JSESSIONID=\.|ObjectInputStream|readObject|ysoserial|CommonsCollections|shiro|fastjson"

phase_check_web_log() {
    section "阶段 8: Web 日志审计"

    detect_web_logs
    if [[ -z "$NGINX_ACCESS_LOG" && -z "$TOMCAT_ACCESS_LOG" ]]; then
        info "未找到 Nginx/Tomcat 日志"
        return
    fi

    [[ -n "$NGINX_ACCESS_LOG" ]] && audit_nginx_logs
    [[ -n "$TOMCAT_ACCESS_LOG" ]] && audit_tomcat_logs

    audit_web_attack_patterns
    audit_scanner_activity
    audit_high_frequency_404
}

detect_web_logs() {
    for lf in /var/log/nginx/access.log /var/log/nginx/access.log.1 /usr/local/nginx/logs/access.log; do
        [[ -f "$lf" && -r "$lf" ]] && { NGINX_ACCESS_LOG="$lf"; info "Nginx access: $lf"; break; }
    done

    for th in /opt/tomcat /usr/local/tomcat /var/lib/tomcat /var/lib/tomcat9 /usr/share/tomcat; do
        [[ -d "$th/logs" ]] || continue
        local al
        al=$(find "$th/logs" -name "localhost_access_log*" -type f 2>/dev/null | sort | tail -1)
        [[ -n "$al" && -r "$al" ]] && { TOMCAT_ACCESS_LOG="$al"; info "Tomcat access: $al"; break; }
    done
}

audit_nginx_logs() {
    info "--- Nginx 日志审计 ---"
    local total
    total=$(wc -l < "$NGINX_ACCESS_LOG" 2>/dev/null || echo 0)
    info "access.log 总行数: $total"

    info "HTTP 方法分布:"
    awk '{print $6}' "$NGINX_ACCESS_LOG" 2>/dev/null | tr -d '"' | \
        sort | uniq -c | sort -rn | head -10 | while read -r c m; do
        printf "       %-5s %s\n" "$c" "$m" | tee -a "$REPORT_FILE"
    done

    info "HTTP 状态码分布:"
    awk '{print $9}' "$NGINX_ACCESS_LOG" 2>/dev/null | \
        sort | uniq -c | sort -rn | head -10 | while read -r c code; do
        printf "       %-5s %s\n" "$c" "$code" | tee -a "$REPORT_FILE"
    done

    local abnormal
    abnormal=$(awk '$6 ~ /"(PUT|DELETE|TRACE|TRACK|CONNECT)/ {print $1, $6, $7}' \
        "$NGINX_ACCESS_LOG" 2>/dev/null | head -10 || true)
    [[ -n "$abnormal" ]] && warn "非常规 HTTP 方法: $(echo "$abnormal" | head -1)"
}

audit_tomcat_logs() {
    info "--- Tomcat 日志审计 ---"
    local total
    total=$(wc -l < "$TOMCAT_ACCESS_LOG" 2>/dev/null || echo 0)
    info "localhost_access_log 总行数: $total"

    local manager
    manager=$(grep -E '/(manager|host-manager)/' "$TOMCAT_ACCESS_LOG" 2>/dev/null | tail -5 || true)
    if [[ -n "$manager" ]]; then
        warn "Tomcat 管理后台访问 ($(echo "$manager" | wc -l) 次)"
        echo "$manager" | tail -3 | while read -r l; do log "       └─ ${l:0:180}"; done
        show_remediation "tomcat_manager_access"
    fi
}

audit_web_attack_patterns() {
    info "--- Web 攻击特征检测 ---"

    local log=""
    [[ -n "$NGINX_ACCESS_LOG" ]] && log="$NGINX_ACCESS_LOG"
    [[ -z "$log" && -n "$TOMCAT_ACCESS_LOG" ]] && log="$TOMCAT_ACCESS_LOG"
    [[ -z "$log" ]] && return

    local sqli
    sqli=$(grep -iE "$SQLI_PATTERN" "$log" 2>/dev/null | tail -5 || true)
    [[ -n "$sqli" ]] && fail "SQL 注入尝试: $(echo "$sqli" | head -1 | cut -c1-180)" && \
        show_remediation "web_sqli" || pass "未发现 SQL 注入"

    local xss
    xss=$(grep -iE "$XSS_PATTERN" "$log" 2>/dev/null | tail -5 || true)
    [[ -n "$xss" ]] && warn "XSS 尝试: $(echo "$xss" | head -1 | cut -c1-180)" || true

    local rce
    rce=$(grep -iE "$RCE_PATTERN" "$log" 2>/dev/null | tail -5 || true)
    [[ -n "$rce" ]] && fail "命令注入/Webshell: $(echo "$rce" | head -1 | cut -c1-180)" && \
        show_remediation "web_rce" || true

    local lfi
    lfi=$(grep -iE "$LFI_PATTERN" "$log" 2>/dev/null | tail -5 || true)
    [[ -n "$lfi" ]] && fail "路径遍历: $(echo "$lfi" | head -1 | cut -c1-180)" && \
        show_remediation "web_lfi" || true

    local sensitive
    sensitive=$(grep -iE "$SENSITIVE_PATHS" "$log" 2>/dev/null | tail -5 || true)
    [[ -n "$sensitive" ]] && warn "敏感路径探测: $(echo "$sensitive" | head -1 | cut -c1-180)" || true

    local deser
    deser=$(grep -iE "$DESERIALIZE_PATTERN" "$log" 2>/dev/null | tail -5 || true)
    [[ -n "$deser" ]] && fail "反序列化攻击: $(echo "$deser" | head -1 | cut -c1-180)" && \
        show_remediation "web_deserialization" || true
}

audit_scanner_activity() {
    info "--- 扫描器活动检测 ---"

    local log=""
    [[ -n "$NGINX_ACCESS_LOG" ]] && log="$NGINX_ACCESS_LOG"
    [[ -z "$log" && -n "$TOMCAT_ACCESS_LOG" ]] && log="$TOMCAT_ACCESS_LOG"
    [[ -z "$log" ]] && return

    local hits
    hits=$(grep -iE "$SCANNER_UA" "$log" 2>/dev/null || true)
    if [[ -n "$hits" ]]; then
        local count
        count=$(echo "$hits" | wc -l)
        fail "扫描器 UA ($count 条)"
        echo "$hits" | grep -oiE "$SCANNER_UA" | sort | uniq -c | sort -rn | head -5 | \
            while read -r c ua; do
                printf "       %-5s %s\n" "$c" "$ua" | tee -a "$REPORT_FILE"
            done
        show_remediation "web_scanner"

        # 封禁 Top 扫描器 IP
        echo "$hits" | awk '{print $1}' | sort | uniq -c | sort -rn | head -3 | \
            while read -r c ip; do
                [[ "$c" -gt 50 ]] && act_block_ip "$ip" "扫描器活动 $c 次" "HIGH"
            done
    else
        pass "未发现扫描器 UA"
    fi

    # 高频请求 IP
    local top_ips
    top_ips=$(awk '{print $1}' "$log" 2>/dev/null | sort | uniq -c | sort -rn | head -10 || true)
    if [[ -n "$top_ips" ]]; then
        info "请求量 Top10 IP:"
        echo "$top_ips" | while read -r c ip; do
            if [[ "$c" -gt 10000 ]]; then
                fail "IP $ip 请求量异常 ($c 次)"
                act_block_ip "$ip" "请求量异常 $c 次" "HIGH"
            else
                printf "       %-8s %s\n" "$c" "$ip" | tee -a "$REPORT_FILE"
            fi
        done
    fi
}

audit_high_frequency_404() {
    info "--- 高频 404 检测 ---"

    local log=""
    [[ -n "$NGINX_ACCESS_LOG" ]] && log="$NGINX_ACCESS_LOG"
    [[ -z "$log" && -n "$TOMCAT_ACCESS_LOG" ]] && log="$TOMCAT_ACCESS_LOG"
    [[ -z "$log" ]] && return

    local total_404
    total_404=$(grep -cE '" 404 | 404 ' "$log" 2>/dev/null || echo 0)
    if [[ "$total_404" -gt 0 ]]; then
        info "404 请求总数: $total_404"
        local top
        top=$(grep -E '" 404 | 404 ' "$log" 2>/dev/null | \
            awk '{print $1}' | sort | uniq -c | sort -rn | head -5 || true)
        echo "$top" | while read -r c ip; do
            if [[ "$c" -gt 500 ]]; then
                fail "IP $ip 触发 404 异常 ($c 次，疑似目录扫描)"
                act_block_ip "$ip" "404 异常 $c 次" "HIGH"
            elif [[ "$c" -gt 100 ]]; then
                warn "IP $ip 触发 404 较多 ($c 次)"
            fi
        done
    else
        pass "未发现 404 请求"
    fi
}