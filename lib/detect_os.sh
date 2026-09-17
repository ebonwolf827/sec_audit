#!/bin/bash
#=============================================================
# lib/detect_os.sh — 阶段 0: 系统探测与包源决策
#=============================================================

phase_detect_os() {
    section "阶段 0: 系统信息探测与包源决策"

    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO_ID="${ID:-unknown}"
        DISTRO_VER="${VERSION_ID:-unknown}"
        DISTRO_CODENAME="${VERSION_CODENAME:-unknown}"
        OS_PRETTY="${PRETTY_NAME:-unknown}"
    fi

    case "$DISTRO_ID" in
        ubuntu|debian|linuxmint|pop|kali) DISTRO_FAMILY="debian" ;;
        amzn|rhel|centos|fedora|rocky|almalinux|ol|oracle) DISTRO_FAMILY="rhel" ;;
        *)
            if command -v apt-get &>/dev/null; then DISTRO_FAMILY="debian"
            elif command -v dnf &>/dev/null || command -v yum &>/dev/null; then DISTRO_FAMILY="rhel"
            fi
            ;;
    esac

    if [[ "$DISTRO_FAMILY" == "debian" ]]; then PKG_MGR="apt-get"
    elif command -v dnf &>/dev/null; then PKG_MGR="dnf"
    elif command -v yum &>/dev/null; then PKG_MGR="yum"
    fi

    local aws_id aws_region aws_ami
    aws_id=$(imds_get instance-id 2>/dev/null || echo "N/A")
    aws_region=$(imds_get placement/region 2>/dev/null || echo "N/A")
    aws_ami=$(imds_get ami-id 2>/dev/null || echo "N/A")

    local net_github="不可达" net_ubuntu="不可达" net_amazon="不可达"
    curl -sI --max-time 5 https://github.com &>/dev/null && net_github="可达"
    curl -sI --max-time 5 http://archive.ubuntu.com &>/dev/null && net_ubuntu="可达"
    curl -sI --max-time 5 https://cdn.amazonlinux.com &>/dev/null && net_amazon="可达"

    {
        echo "============================================================"
        echo "  系统信息探测 — $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
        echo "Hostname        : $(hostname)"
        echo "OS              : ${OS_PRETTY}"
        echo "发行版 ID       : ${DISTRO_ID}"
        echo "发行版版本      : ${DISTRO_VER}"
        echo "发行版家族      : ${DISTRO_FAMILY}"
        echo "包管理器        : ${PKG_MGR:-未检测到}"
        echo "架构            : $(uname -m)"
        echo "内核            : $(uname -r)"
        echo "CPU 核心        : $(nproc 2>/dev/null || echo '?')"
        echo "内存总量        : $(free -h 2>/dev/null | awk '/^Mem:/{print $2}' || echo '?')"
        echo "AWS Instance ID : ${aws_id}"
        echo "AWS Region      : ${aws_region}"
        echo "AWS AMI ID      : ${aws_ami}"
        echo "网络 GitHub     : ${net_github}"
        echo "网络 Ubuntu 源  : ${net_ubuntu}"
        echo "网络 Amazon 源  : ${net_amazon}"
        echo "============================================================"
    } | tee "$VERSION_FILE"

    # 包名决策
    case "$DISTRO_FAMILY:$DISTRO_ID" in
        debian:*) PKG_JDK="openjdk-17-jdk-headless"; EPEL_NEEDED=false ;;
        rhel:amzn) PKG_JDK="java-17-amazon-corretto-devel"; EPEL_NEEDED=true ;;
        rhel:fedora) PKG_JDK="java-17-openjdk-devel"; EPEL_NEEDED=false ;;
        rhel:*) PKG_JDK="java-17-openjdk-devel"; EPEL_NEEDED=true ;;
        *) PKG_JDK="openjdk-17-jdk-headless"; EPEL_NEEDED=false ;;
    esac

    plog "包名决策: JDK=$PKG_JDK EPEL=$EPEL_NEEDED"
}