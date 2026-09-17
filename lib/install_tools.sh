#!/bin/bash
#=============================================================
# lib/install_tools.sh — 阶段 1: 工具安装
#=============================================================

phase_install_tools() {
    section "阶段 1: 工具自动安装与配置"

    if $SKIP_INSTALL; then
        plog "跳过工具安装（--no-install）"
        command -v rkhunter   &>/dev/null && HAS_RKHUNTER=true
        command -v chkrootkit &>/dev/null && HAS_CHKROOTKIT=true
        command -v unhide     &>/dev/null && HAS_UNHIDE=true
        command -v aide       &>/dev/null && HAS_AIDE=true
        command -v lynis      &>/dev/null && HAS_LYNIS=true
        [[ -f "${TOOLS_DIR}/memory-shell-detector-cli.jar" ]] && HAS_MEMSHELL_DETECTOR=true
        [[ -f "${TOOLS_DIR}/KMBA.jar" ]] && HAS_KMBA=true
    else
        fix_dpkg_state
        enable_epel
        install_jdk
        install_rkhunter
        install_chkrootkit
        install_unhide
        install_aide
        install_lynis
        install_memshell_detector
    fi

    configure_tools
    print_tool_summary
}

enable_epel() {
    $EPEL_NEEDED || return 0
    [[ "$DISTRO_FAMILY" != "rhel" ]] && return 0
    rpm -q epel-release &>/dev/null && return 0
    $PKG_MGR install -y epel-release >> "$INSTALL_LOG" 2>&1 || \
    $PKG_MGR install -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm" >> "$INSTALL_LOG" 2>&1 || true
}

install_jdk() {
    command -v jcmd &>/dev/null && return 0
    if command -v java &>/dev/null; then
        local java_bin jcmd_guess
        java_bin=$(readlink -f "$(command -v java)")
        jcmd_guess="$(dirname "$java_bin")/jcmd"
        [[ -x "$jcmd_guess" ]] && { export PATH="$(dirname "$java_bin"):$PATH"; return 0; }
    fi
    pkg_install "$PKG_JDK" "jcmd" || true
}

install_rkhunter() {
    command -v rkhunter &>/dev/null && { HAS_RKHUNTER=true; return; }
    preset_debconf
    pkg_install "rkhunter" && HAS_RKHUNTER=true
}

install_chkrootkit() {
    command -v chkrootkit &>/dev/null && { HAS_CHKROOTKIT=true; return; }
    pkg_install "chkrootkit" && HAS_CHKROOTKIT=true
}

install_unhide() {
    command -v unhide &>/dev/null && { HAS_UNHIDE=true; return; }
    pkg_install "unhide" && HAS_UNHIDE=true
}

install_aide() {
    command -v aide &>/dev/null && { HAS_AIDE=true; return; }
    pkg_install "aide" && HAS_AIDE=true
}

install_lynis() {
    command -v lynis &>/dev/null && { HAS_LYNIS=true; return; }
    pkg_install "lynis" && HAS_LYNIS=true
}

install_memshell_detector() {
    if [[ -f "${TOOLS_DIR}/memory-shell-detector-cli.jar" ]] && \
       [[ -f "${TOOLS_DIR}/detector-agent-1.0.0-SNAPSHOT.jar" ]]; then
        HAS_MEMSHELL_DETECTOR=true
        return
    fi

    command -v unzip &>/dev/null || pkg_install "unzip"
    command -v unzip &>/dev/null || return 1

    local tmp_dir="/tmp/msd_build_$$"
    mkdir -p "$tmp_dir" && cd "$tmp_dir" || return 1

    local archive_url="https://github.com/private-xss/memory-shell-detector/archive/refs/tags/5.zip"
    local urls=(
        "$archive_url"
        "https://ghproxy.net/${archive_url}"
        "https://xget.xi-xu.me/gh/private-xss/memory-shell-detector/archive/refs/tags/5.zip"
    )

    local ok=false
    for url in "${urls[@]}"; do
        if curl -sL --max-time 120 --retry 2 -o msd.zip "$url" 2>/dev/null; then
            file msd.zip 2>/dev/null | grep -qi 'zip archive' && { ok=true; break; }
            rm -f msd.zip
        fi
    done
    $ok || { cd / && rm -rf "$tmp_dir"; return 1; }

    unzip -q msd.zip 2>/dev/null || { cd / && rm -rf "$tmp_dir"; return 1; }

    local src_dir
    src_dir=$(find . -maxdepth 1 -type d -name 'memory-shell-detector-*' | head -1)
    [[ -z "$src_dir" ]] && { cd / && rm -rf "$tmp_dir"; return 1; }

    local cli_jar agent_jar core_jar
    cli_jar=$(find "$src_dir" -name "memory-shell-detector-cli.jar" -type f 2>/dev/null | head -1)
    agent_jar=$(find "$src_dir" -name "detector-agent-*.jar" -type f 2>/dev/null | head -1)
    core_jar=$(find "$src_dir" -name "detector-core-*.jar" -type f 2>/dev/null | head -1)

    if [[ -n "$cli_jar" && -n "$agent_jar" ]]; then
        cp -f "$cli_jar" "${TOOLS_DIR}/memory-shell-detector-cli.jar"
        cp -f "$agent_jar" "${TOOLS_DIR}/detector-agent-1.0.0-SNAPSHOT.jar"
        [[ -n "$core_jar" ]] && cp -f "$core_jar" "${TOOLS_DIR}/detector-core-1.0.0-SNAPSHOT.jar"
        chmod 644 "${TOOLS_DIR}"/*.jar
        java -jar "${TOOLS_DIR}/memory-shell-detector-cli.jar" --help >/dev/null 2>&1 && \
            HAS_MEMSHELL_DETECTOR=true
    fi
    cd / && rm -rf "$tmp_dir"
}

configure_tools() {
    if $HAS_RKHUNTER; then
        touch /etc/rkhunter.conf.local
        for entry in \
            "ALLOWHIDDENDIR=/etc/.java" \
            "ALLOWHIDDENFILE=/etc/.resolv.conf.systemd-resolved.bak" \
            "ALLOWHIDDENFILE=/etc/.updated" \
            "ALLOWHIDDENFILE=/etc/.pwd.lock" \
            "ALLOWHIDDENDIR=/dev/.udev" \
            "ALLOWDEVFILE=/dev/shm/.panelTask.pl"; do
            grep -qF "$entry" /etc/rkhunter.conf.local 2>/dev/null || echo "$entry" >> /etc/rkhunter.conf.local
        done
        silent rkhunter --update
        silent rkhunter --propupd
    fi

    if $HAS_AIDE && [[ ! -f /var/lib/aide/aide.db.gz ]]; then
        silent aide --init
        [[ -f /var/lib/aide/aide.db.new.gz ]] && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    fi
}

print_tool_summary() {
    info "工具可用性: rkhunter=$HAS_RKHUNTER chkrootkit=$HAS_CHKROOTKIT " \
         "unhide=$HAS_UNHIDE aide=$HAS_AIDE lynis=$HAS_LYNIS " \
         "memshell=$HAS_MEMSHELL_DETECTOR yara=$HAS_YARA " \
         "jcmd=$([[ -n "$(command -v jcmd)" ]] && echo true || echo false)"
}