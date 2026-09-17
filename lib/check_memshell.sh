#!/bin/bash
#=============================================================
# lib/check_memshell.sh — 阶段 2: Java 内存马检测
# 检测: memory-shell-detector | jcmd 关键字 | 非标准路径 JAR | 网络连接
#=============================================================

phase_check_memshell() {
    section "阶段 2: Java 内存马检测"

    local java_pids
    java_pids=$(pgrep -f 'java' 2>/dev/null || true)

    if [[ -z "$java_pids" ]]; then
        info "未检测到运行中的 Java 进程"
        return
    fi

    local any_found=false
    for PID in $java_pids; do
        check_java_process "$PID" && any_found=true
    done

    $any_found || pass "Java 进程内存马检测未发现明确威胁"
}

check_java_process() {
    local pid="$1"
    local proc_name
    proc_name=$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | cut -c1-120)
    info "检查 Java 进程 PID=$pid: $proc_name"

    local found=false

    if $HAS_MEMSHELL_DETECTOR; then
        detect_by_msd "$pid" && found=true
    fi

    if ! $found && command -v jcmd &>/dev/null; then
        detect_by_jcmd "$pid" && found=true
    fi

    detect_nonstandard_jars "$pid"

    $found && return 0 || return 1
}

detect_by_msd() {
    local pid="$1"
    local report="/tmp/msd_${pid}_$$.json"

    java -jar "${TOOLS_DIR}/memory-shell-detector-cli.jar" \
        -s "$pid" --report "$report" -f json >/dev/null 2>&1 || true

    if [[ -f "$report" ]]; then
        local count
        count=$(grep -o '"type"' "$report" 2>/dev/null | wc -l || echo 0)
        if [[ "$count" -gt 0 ]]; then
            fail "PID=$pid memory-shell-detector 发现 $count 个可疑特征"
            log "       详细报告: $report"
            show_remediation "memshell_detected"
            return 0
        fi
    fi
    return 1
}

detect_by_jcmd() {
    local pid="$1"
    local tmp="/tmp/class_hist_$$_${pid}.txt"
    jcmd "$pid" GC.class_histogram > "$tmp" 2>/dev/null || true

    local evil_pattern='evil|shell|cmd|backdoor|hack|exploit|payload|behinder|godzilla|antsword|memshell|webshell|inject|malicious|trojan|reverse'
    local hits
    hits=$(grep -iE "$evil_pattern" "$tmp" 2>/dev/null || true)

    if [[ -n "$hits" ]]; then
        warn "PID=$pid (jcmd) 发现可疑类名:"
        echo "$hits" | head -5 | while read -r l; do log "       └─ $l"; done
        log "       使用 memory-shell-detector -v <类名> -p $pid 反编译审查"
        rm -f "$tmp"
        return 0
    fi
    rm -f "$tmp"
    return 1
}

detect_nonstandard_jars() {
    local pid="$1"
    local jars
    jars=$(grep -iE '\.jar' /proc/$pid/maps 2>/dev/null \
        | awk '{print $NF}' | sort -u \
        | grep -viE '/(usr|opt|home)/.*/(lib|jdk|jre|tomcat|spring|maven)/' \
        | grep -viE '\.m2/|\.gradle/' || true)

    [[ -n "$jars" ]] && \
        warn "PID=$pid 存在非标准路径 JAR: $(echo "$jars" | tr '\n' ' ')"
}