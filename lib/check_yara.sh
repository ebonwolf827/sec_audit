#!/bin/bash
#=============================================================
# lib/check_yara.sh — YARA 安装、规则管理、扫描接口
#=============================================================

YARA_RULES_DIR="${SCRIPT_DIR}/rules"
YARA_COMPILED="${YARA_RULES_DIR}/compiled.yarc"

phase_install_yara() {
    section "阶段 1b: YARA 安装与规则管理"

    if $SKIP_INSTALL; then
        command -v yara &>/dev/null && HAS_YARA=true
        return
    fi

    install_yara
    update_community_rules
    compile_yara_rules
}

install_yara() {
    command -v yara &>/dev/null && { HAS_YARA=true; return; }
    case "$PKG_MGR" in
        apt-get) pkg_install "yara" && HAS_YARA=true ;;
        dnf|yum) $EPEL_NEEDED && pkg_install "epel-release" 2>/dev/null || true
                 pkg_install "yara" && HAS_YARA=true ;;
    esac
}

update_community_rules() {
    local community_dir="${YARA_RULES_DIR}/community"
    mkdir -p "$community_dir"

    if [[ -d "${community_dir}/yara-detection-rules" ]]; then
        cd "${community_dir}/yara-detection-rules" && git pull --depth 1 2>/dev/null || true
        cd - >/dev/null
    else
        git clone --depth 1 https://github.com/leonardosmoutinho/yara-detection-rules.git \
            "${community_dir}/yara-detection-rules" 2>/dev/null || true
    fi
}

compile_yara_rules() {
    $HAS_YARA || return
    local count
    count=$(find "$YARA_RULES_DIR" -name "*.yar" 2>/dev/null | wc -l)
    [[ "$count" -eq 0 ]] && return

    local all="${YARA_RULES_DIR}/all_rules.yar"
    : > "$all"
    find "$YARA_RULES_DIR" -name "*.yar" 2>/dev/null | while read -r f; do
        echo "include \"$f\"" >> "$all"
    done

    yara -C -w "$all" "$YARA_COMPILED" 2>/dev/null || rm -f "$YARA_COMPILED"
}

yara_scan_file() {
    local file="$1" category="$2"
    $HAS_YARA || return 1
    [[ -f "$file" ]] || return 1

    local rules_path
    if [[ -f "$YARA_COMPILED" ]]; then
        rules_path="$YARA_COMPILED"
    else
        rules_path="${YARA_RULES_DIR}/${category}"
        [[ -d "$rules_path" ]] || return 1
    fi
    yara -w -s -m "$rules_path" "$file" 2>/dev/null || true
}