# AWS Linux 安全检测与响应系统 v7.1 完整部署手册

> 一站式 Linux 主机安全检测、告警与主动响应工具，覆盖 120+ 检测项，集成 YARA 规则引擎、分级响应引擎与 eBPF 进程执行阻断。

---

## 目录

- [一、项目简介](#一项目简介)
- [二、目录结构](#二目录结构)
- [三、系统要求](#三系统要求)
- [四、完整部署步骤](#四完整部署步骤)
- [五、检测能力全景](#五检测能力全景)
- [六、响应动作引擎](#六响应动作引擎)
- [七、eBPF 进程阻断](#七ebpf-进程阻断)
- [八、YARA 规则引擎](#八yara-规则引擎)
- [九、配置文件](#九配置文件)
- [十、使用手册](#十使用手册)
- [十一、故障排查](#十一故障排查)
- [十二、附录](#十二附录)

---

## 一、项目简介

### 1.1 概述

**AWS Linux 安全检测与响应系统 v7.1** 是一款面向 Linux 主机（重点适配 AWS EC2）的模块化安全检测与主动响应工具。系统采用「检测 + 告警 + 响应 + 阻断」四层架构，在 v6.x 检测能力基础上新增**分级响应引擎**与**eBPF 进程执行阻断**，实现从「发现问题」到「处置问题」的完整闭环。

### 1.2 核心特性

| 特性 | 说明 |
|---|---|
| **模块化架构** | 18 个独立模块，职责清晰，可单独测试与扩展 |
| **全自动化安装** | 首次运行自动安装所有依赖工具，零手工操作 |
| **发行版自适应** | Ubuntu / Debian / Amazon Linux / RHEL / CentOS / Rocky / Fedora |
| **工具优先降级** | 优先使用专业工具，不可用时自动降级到自研逻辑 |
| **YARA 规则引擎** | Webshell + 恶意二进制检测，正则作为降级方案 |
| **分级响应引擎** | L1-L5 五级响应，取证优先，白名单保护，可回滚 |
| **eBPF 进程阻断** | LSM Hook 在 execve 层面拦截高危进程执行 |
| **误报自动过滤** | AWS 官方配置、系统标准文件自动识别为白名单 |
| **结构化输出** | 文本报告 + 摘要 + JSON + 系统信息快照 |
| **并发安全** | flock 锁防止重复执行，幂等设计 |

### 1.3 版本演进

| 版本 | 主要变更 |
|---|---|
| v1.0 | 单文件脚本，基础基线检查 |
| v2.0 | 增加 Java 内存马、后门、反弹 Shell |
| v3.0 | 引入专业工具链（rkhunter、chkrootkit 等） |
| v4.0 | 修复 sed 特殊字符、Ubuntu 适配、误报过滤 |
| v5.0 | 系统信息前置探测、发行版自适应 |
| v6.0 | 模块化架构、CIS Docker 集成、C2 后门增强、日志审计 |
| v6.1 | 集成 YARA 规则引擎 |
| v7.0 | 新增响应动作引擎（L1-L5 分级）、内核级日志审计、Nacos 检测 |
| **v7.1** | **新增 eBPF 进程执行阻断、eBPF 环境诊断、退出码分级** |

---

## 二、目录结构

```
/usr/local/bin/sec_audit/
├── sec_audit.sh                     # 主入口（v7.1）
├── lib/                             # 检测与响应模块（18 个）
│   ├── common.sh                    # 公共函数
│   ├── response.sh                  # 响应动作引擎（含 BLOCK_EXEC）
│   ├── detect_os.sh                 # 阶段 0: 系统探测
│   ├── install_tools.sh             # 阶段 1: 工具安装
│   ├── check_yara.sh                # 阶段 1b: YARA 管理
│   ├── check_memshell.sh            # 阶段 2: Java 内存马
│   ├── check_rootkit.sh             # 阶段 3: Rootkit
│   ├── check_integrity.sh           # 阶段 4: 文件完整性
│   ├── check_system.sh              # 阶段 5: Lynis 审计
│   ├── check_backdoor.sh            # 阶段 6: 反弹 Shell/C2
│   ├── check_webshell.sh            # 阶段 6b: Webshell
│   ├── check_nacos.sh               # 阶段 6c: Nacos
│   ├── check_log_audit.sh           # 阶段 7: 系统日志审计
│   ├── check_web_log.sh             # 阶段 8: Web 日志审计
│   ├── check_baseline.sh            # 阶段 9: 安全基线
│   ├── check_container.sh           # 阶段 10: Docker
│   ├── check_falco.sh               # 阶段 11: Falco
│   └── report.sh                    # 阶段 12: 汇总报告
├── rules/                           # YARA 规则库
│   ├── webshells/                   # Webshell 规则（5 个）
│   │   ├── php_webshell.yar
│   │   ├── java_webshell.yar
│   │   ├── asp_webshell.yar
│   │   ├── python_backdoor.yar
│   │   └── nodejs_backdoor.yar
│   ├── malwares/                    # 恶意软件规则（3 个）
│   │   ├── linux_miner.yar
│   │   ├── linux_backdoor.yar
│   │   └── linux_ransomware.yar
│   ├── community/                   # 社区规则（git 引入）
│   │   └── README.md
│   └── compiled.yarc                # 编译后的规则（运行时生成）
├── conf/                            # 配置文件
│   ├── whitelist.conf               # 检测白名单
│   ├── remediation.conf             # 修复建议映射
│   └── response_whitelist.conf      # 响应保护名单
└── ebpf/                            # eBPF 组件
    ├── vmlinux.h                    # 内核头文件（生成）
    ├── block_exec.bpf.c             # eBPF LSM 程序源码
    ├── block_exec.bpf.o             # 编译产物
    └── block_exec_ctl.c             # 用户态控制工具源码
```

### 2.1 运行时目录

| 路径 | 用途 |
|---|---|
| `/var/log/sec_audit/` | 报告输出目录 |
| `/var/lib/sec_audit/` | 基线数据存储 |
| `/var/lib/sec_audit/response/` | 响应动作证据与隔离文件 |
| `/var/lib/sec_audit/response/quarantine/` | 隔离文件 |
| `/var/lib/sec_audit/response/evidence/` | 取证文件 |
| `/var/lib/sec_audit/response/rollback/` | 回滚记录 |
| `/opt/sec_audit/tools/` | 第三方工具与 JAR |
| `/sys/fs/bpf/block_exec/` | eBPF 程序挂载点 |
| `/etc/sec_audit/` | 环境变量配置 |

---

## 三、系统要求

### 3.1 最低要求

| 项目 | 要求 |
|---|---|
| **操作系统** | Ubuntu 20.04+ / Debian 11+ / Amazon Linux 2+ / RHEL 8+ / CentOS 8+ / Rocky 8+ / Fedora 36+ |
| **内核版本** | 4.15+（检测功能）；5.7+（eBPF 阻断） |
| **CPU** | 2 核心 |
| **内存** | 2 GB |
| **磁盘** | 5 GB 可用空间 |
| **权限** | root |

### 3.2 eBPF 阻断额外要求

| 项目 | 要求 |
|---|---|
| **内核版本** | 5.7+ |
| **BPF LSM** | 已启用（`/sys/kernel/security/lsm` 包含 `bpf`） |
| **BTF** | `/sys/kernel/btf/vmlinux` 存在 |
| **工具链** | bpftool 7.0+ / clang 10+ / libbpf-dev |

### 3.3 快速环境检查

```bash
# 系统要求检查
cat /etc/os-release | grep -E "^(ID|VERSION_ID)="
uname -r
sudo -v && echo "OK: root 权限正常"
curl -sI --max-time 5 https://github.com &>/dev/null && echo "OK: GitHub 可达" || echo "WARN: GitHub 不可达"
```

---

## 四、完整部署步骤

### 4.1 部署前准备

#### 4.1.1 依赖安装

**Ubuntu / Debian**：

```bash
sudo apt-get update
sudo apt-get install -y \
    curl wget git unzip tar gzip \
    bash coreutils procps findutils \
    gcc make clang llvm \
    libbpf-dev libelf-dev zlib1g-dev \
    linux-tools-common linux-tools-generic \
    jq bc file
```

**RHEL / CentOS / Rocky / Amazon Linux**：

```bash
sudo dnf install -y \
    curl wget git unzip tar gzip \
    bash coreutils procps-ng findutils \
    gcc make clang llvm \
    libbpf-devel elfutils-libelf-devel zlib-devel \
    bpftool \
    jq bc file
```

#### 4.1.2 环境快照

```bash
{
    echo "=== 部署前环境快照 ==="
    echo "时间: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "主机: $(hostname)"
    echo "内核: $(uname -r)"
    echo "发行版: $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2)"
    echo "glibc: $(ldd --version 2>/dev/null | head -1)"
    echo "bpftool: $(bpftool version 2>/dev/null | head -1 || echo '未安装')"
    echo "clang: $(clang --version 2>/dev/null | head -1 || echo '未安装')"
} | tee /tmp/sec_audit_deploy_env.txt
```

---

### 4.2 完整重装（清理旧版本）

**首次部署可跳过此节**。如果已安装旧版本，需要先清理。

#### 4.2.1 停止运行中的实例

```bash
# 检查并停止正在运行的实例
pgrep -f "sec_audit.sh" && {
    echo "正在停止运行中的实例..."
    pkill -f "sec_audit.sh"
    sleep 2
}

# 清理锁文件
sudo rm -f /var/run/sec_audit.lock
```

#### 4.2.2 卸载 eBPF 程序

```bash
if [[ -d /sys/fs/bpf/block_exec ]]; then
    echo "正在卸载 eBPF 程序..."
    sudo bpftool prog detach pinned /sys/fs/bpf/block_exec/block_exec_hook \
        lsm bprm_check_security 2>/dev/null || true
    sudo rm -rf /sys/fs/bpf/block_exec
fi

ls /sys/fs/bpf/block_exec 2>/dev/null && echo "WARN: eBPF 未完全卸载" || echo "OK: eBPF 已卸载"
```

#### 4.2.3 备份旧数据

```bash
BACKUP_DIR="/tmp/sec_audit_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

[[ -d /usr/local/bin/sec_audit/conf ]] && \
    cp -r /usr/local/bin/sec_audit/conf "$BACKUP_DIR/"
[[ -d /var/log/sec_audit ]] && \
    cp -r /var/log/sec_audit "$BACKUP_DIR/logs" 2>/dev/null || true
[[ -d /var/lib/sec_audit ]] && \
    cp -r /var/lib/sec_audit "$BACKUP_DIR/baselines" 2>/dev/null || true
[[ -d /opt/sec_audit/tools ]] && \
    cp -r /opt/sec_audit/tools "$BACKUP_DIR/tools" 2>/dev/null || true

echo "备份完成: $BACKUP_DIR"
echo "备份大小: $(du -sh "$BACKUP_DIR" | cut -f1)"
```

#### 4.2.4 移除旧版本

```bash
# 停止定时任务
sudo rm -f /etc/cron.d/sec_audit /etc/cron.d/sec_audit_update

# 移除脚本目录
sudo rm -rf /usr/local/bin/sec_audit
sudo rm -f /usr/local/bin/sec_audit

# 可选：清理运行时数据
read -p "是否清理运行时数据？(y/N): " CLEAN_DATA
if [[ "$CLEAN_DATA" == "y" ]]; then
    sudo rm -rf /var/log/sec_audit /var/lib/sec_audit
    echo "运行时数据已清理"
fi

# 确认清理完成
[[ -d /usr/local/bin/sec_audit ]] && echo "WARN: 脚本目录仍存在" || echo "OK: 脚本目录已移除"
[[ -f /etc/cron.d/sec_audit ]] && echo "WARN: 定时任务仍存在" || echo "OK: 定时任务已移除"
```

---

### 4.3 首次部署 / 升级部署

#### 4.3.1 获取脚本源码

```bash
# 场景 A: 从 tar 包解压
cd /tmp
sudo tar xzf sec_audit_v7.1.tar.gz -C /tmp/
ls /tmp/sec_audit/

# 场景 B: 从 git 仓库克隆
cd /tmp
git clone https://your-git-repo/sec_audit.git
```

#### 4.3.2 创建目录结构

```bash
sudo mkdir -p /usr/local/bin/sec_audit/{lib,conf,rules/webshells,rules/malwares,rules/community,ebpf}
sudo mkdir -p /var/log/sec_audit /var/lib/sec_audit /opt/sec_audit/tools
sudo mkdir -p /sys/fs/bpf/block_exec

ls -la /usr/local/bin/sec_audit/
```

#### 4.3.3 部署脚本文件

```bash
SRC_DIR="/tmp/sec_audit"

# 1. 主入口
sudo cp "$SRC_DIR/sec_audit.sh" /usr/local/bin/sec_audit/

# 2. 库文件
sudo cp "$SRC_DIR/lib/"*.sh /usr/local/bin/sec_audit/lib/

# 3. 配置文件
sudo cp "$SRC_DIR/conf/"*.conf /usr/local/bin/sec_audit/conf/

# 4. YARA 规则
sudo cp -r "$SRC_DIR/rules/"* /usr/local/bin/sec_audit/rules/

# 5. eBPF 源码
sudo cp "$SRC_DIR/ebpf/"*.c /usr/local/bin/sec_audit/ebpf/

# 验证
echo "=== 部署文件清单 ==="
ls /usr/local/bin/sec_audit/*.sh
ls /usr/local/bin/sec_audit/lib/*.sh | wc -l
ls /usr/local/bin/sec_audit/conf/*.conf | wc -l
ls /usr/local/bin/sec_audit/rules/webshells/*.yar | wc -l
ls /usr/local/bin/sec_audit/rules/malwares/*.yar | wc -l
```

**预期输出**：

```
/usr/local/bin/sec_audit/sec_audit.sh
18
3
5
3
```

#### 4.3.4 设置权限

```bash
sudo chmod 755 /usr/local/bin/sec_audit/sec_audit.sh
sudo chmod 644 /usr/local/bin/sec_audit/lib/*.sh
sudo chmod 644 /usr/local/bin/sec_audit/conf/*.conf
sudo chmod 644 /usr/local/bin/sec_audit/rules/webshells/*.yar
sudo chmod 644 /usr/local/bin/sec_audit/rules/malwares/*.yar
sudo chmod 644 /usr/local/bin/sec_audit/ebpf/*.c
sudo chown -R root:root /usr/local/bin/sec_audit

ls -la /usr/local/bin/sec_audit/
```

#### 4.3.5 创建便捷命令

```bash
sudo ln -sf /usr/local/bin/sec_audit/sec_audit.sh /usr/local/bin/sec_audit
which sec_audit
sec_audit --help | head -5
```

---

### 4.4 编译 eBPF 组件

#### 4.4.1 生成 vmlinux.h

```bash
cd /usr/local/bin/sec_audit

if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
    echo "错误: 内核未启用 BTF"
    echo "Ubuntu: apt install linux-headers-$(uname -r)"
    echo "RHEL: dnf install kernel-devel-$(uname -r)"
    exit 1
fi

sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c | \
    sudo tee ebpf/vmlinux.h > /dev/null

echo "vmlinux.h 生成完成: $(wc -l < ebpf/vmlinux.h) 行"
```

#### 4.4.2 编译 eBPF 程序

```bash
cd /usr/local/bin/sec_audit

sudo clang -O2 -g -target bpf \
    -D__TARGET_ARCH_x86 \
    -I./ebpf \
    -c ebpf/block_exec.bpf.c \
    -o ebpf/block_exec.bpf.o

if [[ -f ebpf/block_exec.bpf.o ]]; then
    echo "OK: eBPF 程序编译成功"
    file ebpf/block_exec.bpf.o
    ls -lh ebpf/block_exec.bpf.o
else
    echo "ERROR: eBPF 程序编译失败"
fi
```

#### 4.4.3 编译控制工具

```bash
cd /usr/local/bin/sec_audit

sudo gcc -O2 -o /opt/sec_audit/tools/block_exec_ctl \
    ebpf/block_exec_ctl.c \
    -lbpf -lelf -lz

if [[ -x /opt/sec_audit/tools/block_exec_ctl ]]; then
    echo "OK: 控制工具编译成功"
    ls -lh /opt/sec_audit/tools/block_exec_ctl
else
    echo "ERROR: 控制工具编译失败"
fi
```

#### 4.4.4 设置编译产物权限

```bash
sudo chmod 644 /usr/local/bin/sec_audit/ebpf/block_exec.bpf.o
sudo chmod 755 /opt/sec_audit/tools/block_exec_ctl
sudo chown -R root:root /usr/local/bin/sec_audit/ebpf
sudo chown root:root /opt/sec_audit/tools/block_exec_ctl

ls -la /usr/local/bin/sec_audit/ebpf/
ls -la /opt/sec_audit/tools/
```

---

### 4.5 首次配置

#### 4.5.1 配置检测白名单

```bash
sudo vi /usr/local/bin/sec_audit/conf/whitelist.conf
```

**示例**：

```
# 业务文件白名单
/var/www/html/legacy/oldsafe.php
/etc/cron.d/business-backup

# 业务容器白名单
myapp-web
myapp-db
```

#### 4.5.2 配置响应保护名单

```bash
sudo vi /usr/local/bin/sec_audit/conf/response_whitelist.conf
```

**示例**：

```
# 业务关键文件（不可被自动隔离）
/var/www/html/index.php
/opt/app/config/application.yml

# 关键容器
container:nginx-proxy
container:mysql-primary
```

#### 4.5.3 环境变量配置（可选）

```bash
sudo mkdir -p /etc/sec_audit
sudo tee /etc/sec_audit/env > /dev/null <<'EOF'
# sec_audit 环境变量配置
# 主机隔离时保留的管理 IP
MGMT_IPS="10.0.1.100 10.0.1.101"

# GitHub API Token（避免限流）
# GITHUB_TOKEN="ghp_xxxxx"

# 通知 Webhook
# NOTIFY_WEBHOOK="https://hooks.slack.com/services/xxx"
EOF
sudo chmod 600 /etc/sec_audit/env
```

---

### 4.6 验证部署

#### 4.6.1 eBPF 环境诊断

```bash
sudo sec_audit --check-ebpf
```

**预期输出**：

```
阶段 eBPF 环境诊断

[PASS] 内核版本 5.15.0-1072-aws（≥ 5.7，支持 BPF LSM）
[PASS] BPF LSM 已启用: lockdown,capability,landlock,yama,bpf
[PASS] bpftool 已安装: 7.2.0
[PASS] clang 已安装: 14.0.0
[PASS] block_exec_ctl 已编译
[PASS] eBPF 程序已编译
[INFO] eBPF 阻断程序未加载（会在 --response-level=4 时自动加载）
```

**如果 BPF LSM 未启用**：

```bash
# Ubuntu / Debian
sudo vi /etc/default/grub
# 找到 GRUB_CMDLINE_LINUX，添加: lsm=lockdown,capability,landlock,yama,bpf
sudo update-grub
sudo reboot

# RHEL / CentOS / Amazon Linux
sudo vi /etc/default/grub
# 添加: lsm=lockdown,capability,landlock,yama,bpf
sudo grub2-mkconfig -o /boot/grub2/grub.cfg
sudo reboot
```

#### 4.6.2 干跑测试

```bash
# 干跑 L1（只检测）
sudo sec_audit --no-install --dry-run 2>&1 | tail -20

# 干跑 L4（查看会执行哪些响应动作）
sudo sec_audit --response-level=4 --dry-run --no-install 2>&1 | tail -40
```

**检查点**：

- 各阶段无报错
- 响应动作列表符合预期
- 无 FAIL 项（首次部署可能因未安装工具而产生 INFO）

#### 4.6.3 eBPF 阻断功能测试

```bash
# 1. 手动加载 eBPF 程序
sudo mkdir -p /sys/fs/bpf/block_exec
sudo bpftool prog loadall /usr/local/bin/sec_audit/ebpf/block_exec.bpf.o /sys/fs/bpf/block_exec
sudo bpftool prog attach pinned /sys/fs/bpf/block_exec/block_exec_hook lsm bprm_check_security

# 2. 添加阻断规则
sudo /opt/sec_audit/tools/block_exec_ctl add-pattern "/dev/tcp/"

# 3. 测试阻断
bash -i >& /dev/tcp/127.0.0.1/4444 0>&1
# 预期: bash: /dev/tcp/127.0.0.1/4444: Operation not permitted

# 4. 查看统计
sudo /opt/sec_audit/tools/block_exec_ctl stats
# 预期: 已阻断进程: 1

# 5. 解除阻断
sudo /opt/sec_audit/tools/block_exec_ctl del-pattern "/dev/tcp/"

# 6. 卸载 eBPF 程序（可选）
sudo bpftool prog detach pinned /sys/fs/bpf/block_exec/block_exec_hook lsm bprm_check_security
sudo rm -rf /sys/fs/bpf/block_exec
```

#### 4.6.4 完整运行测试

```bash
# 首次完整运行
sudo sec_audit --json --no-install

# 检查输出
ls -la /var/log/sec_audit/
cat /var/log/sec_audit/summary_*.txt | tail -30
```

---

### 4.7 配置定时任务

#### 4.7.1 自动配置

```bash
sudo sec_audit --schedule --no-install
```

**预期输出**：

```
[PASS] 定时任务已配置: 每日 03:00 执行
[PASS] 工具更新任务已配置: 每周日 04:00
```

#### 4.7.2 验证定时任务

```bash
cat /etc/cron.d/sec_audit
cat /etc/cron.d/sec_audit_update
```

#### 4.7.3 手动配置（可选）

```bash
sudo tee /etc/cron.d/sec_audit > /dev/null <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
0 3 * * * root /usr/local/bin/sec_audit/sec_audit.sh --json --no-install >/dev/null 2>&1
EOF
sudo chmod 644 /etc/cron.d/sec_audit
```

---

### 4.8 部署后验证清单

```bash
cat <<'CHECKLIST'
============================================
  部署后验证清单
============================================
CHECKLIST

echo "1. 目录结构"
for dir in /usr/local/bin/sec_audit /usr/local/bin/sec_audit/lib \
           /usr/local/bin/sec_audit/conf /usr/local/bin/sec_audit/rules \
           /usr/local/bin/sec_audit/ebpf /var/log/sec_audit \
           /var/lib/sec_audit /opt/sec_audit/tools; do
    [[ -d "$dir" ]] && echo "  [OK] $dir" || echo "  [FAIL] $dir"
done

echo ""
echo "2. 关键文件"
for file in /usr/local/bin/sec_audit/sec_audit.sh \
            /usr/local/bin/sec_audit/lib/response.sh \
            /usr/local/bin/sec_audit/lib/check_backdoor.sh \
            /usr/local/bin/sec_audit/ebpf/block_exec.bpf.o \
            /opt/sec_audit/tools/block_exec_ctl \
            /usr/local/bin/sec_audit/conf/whitelist.conf \
            /usr/local/bin/sec_audit/conf/response_whitelist.conf; do
    [[ -f "$file" ]] && echo "  [OK] $file" || echo "  [FAIL] $file"
done

echo ""
echo "3. 权限"
[[ -x /usr/local/bin/sec_audit/sec_audit.sh ]] && echo "  [OK] 主入口可执行" || echo "  [FAIL] 主入口不可执行"
[[ -x /opt/sec_audit/tools/block_exec_ctl ]] && echo "  [OK] 控制工具可执行" || echo "  [FAIL] 控制工具不可执行"

echo ""
echo "4. 便捷命令"
[[ -L /usr/local/bin/sec_audit ]] && echo "  [OK] 便捷命令已创建" || echo "  [FAIL] 便捷命令未创建"

echo ""
echo "5. 定时任务"
[[ -f /etc/cron.d/sec_audit ]] && echo "  [OK] cron 已配置" || echo "  [WARN] cron 未配置"

echo ""
echo "6. 环境诊断"
sudo /usr/local/bin/sec_audit/sec_audit.sh --check-ebpf 2>&1 | grep -E "PASS|FAIL|WARN" | head -10

echo ""
echo "============================================
  验证完成
============================================"
```

---

## 五、检测能力全景

### 5.1 十二个检测阶段

| 阶段 | 模块 | 核心能力 |
|---|---|---|
| 0 | detect_os | 系统信息、包管理器、AWS 元数据、网络探测 |
| 1 | install_tools | 工具自动安装、版本动态获取、首次配置 |
| 1b | check_yara | YARA 安装、规则管理、规则编译 |
| 2 | check_memshell | memory-shell-detector + jcmd 关键字 |
| 3 | check_rootkit | rkhunter + chkrootkit + unhide |
| 4 | check_integrity | AIDE + SHA256 基线 + SUID 基线 |
| 5 | check_system | Lynis 加固指数 |
| 6 | check_backdoor | 反弹 Shell + C2 框架 + 持久化 |
| 6b | check_webshell | 网站类型自适应 + YARA + 正则降级 |
| 6c | check_nacos | 配置检测 + 漏洞检测 + 默认凭证 |
| 7 | check_log_audit | SSH Top10 + auditd + 日志完整性 + 反取证 |
| 8 | check_web_log | Nginx/Tomcat 攻击特征 + 扫描器 |
| 9 | check_baseline | 账户/权限/sysctl/SSH/AWS |
| 10 | check_container | CIS Docker Benchmark |
| 11 | check_falco | Falco 实时监控 |
| 12 | report | 风险评分 + JSON + 修复建议 |

### 5.2 检测项分类统计

| 类别 | 检测项数 | 关键检测项 |
|---|---|---|
| Java 内存马 | 3 | 工具检测、jcmd 关键字、非标准路径 JAR |
| Rootkit | 7 | rkhunter、chkrootkit、unhide、内核模块、LD_PRELOAD |
| 文件完整性 | 3 | AIDE、SHA256 基线、SUID 基线 |
| C2 / 后门 | 12 | 反弹 Shell、C2 框架、Beaconing、命名管道、Systemd 后门 |
| Webshell | 15+ | PHP/JSP/ASP/Python/Node.js + YARA 规则 |
| 系统日志 | 14 | SSH Top10、暴力破解、sudo 未授权、auditd |
| Web 日志 | 14 | SQL 注入、XSS、Webshell、扫描器、404 分析 |
| 安全基线 | 9 | UID=0、空密码、sysctl、SSH、IMDSv2 |
| Docker 容器 | 30+ | 主机配置、Daemon、配置文件、镜像、运行时 |
| Nacos | 17 | 版本、鉴权、默认凭证、CVE |
| Falco | 8 | 实时运行时安全告警 |

**总检测项：约 120+ 项**

---

## 六、响应动作引擎

### 6.1 响应级别

| 级别 | 能力 | 典型动作 |
|---|---|---|
| **L1** | 仅记录（默认） | 记录到报告 |
| **L2** | 记录 + 告警 | 输出 FAIL/WARN |
| **L3** | + 低风险处置 | 文件隔离、权限修复、持久化移除 |
| **L4** | + 高风险处置 | 终止进程、封禁 IP、锁定账户、eBPF 阻断 |
| **L5** | + 主机隔离 | 仅保留管理 IP 的 SSH |

### 6.2 支持的动作

| 动作 | 级别 | 说明 |
|---|---|---|
| `QUARANTINE_FILE` | L3 | 隔离文件（复制到隔离区 + chattr +i） |
| `FIX_PERMISSION` | L3 | 修复文件权限 |
| `REMOVE_PERSISTENCE` | L3 | 移除 crontab/systemd 持久化 |
| `DISABLE_SERVICE` | L3 | 禁用 systemd 服务 |
| `KILL_PROCESS` | L4 | 终止进程（先 SIGSTOP 取证再 kill） |
| `BLOCK_IP` | L4 | iptables 双向封禁 |
| `LOCK_ACCOUNT` | L4 | 锁定账户 + 终止用户进程 |
| `BLOCK_EXEC` | L4 | eBPF 进程执行阻断 |
| `ISOLATE_HOST` | L5 | 主机网络隔离 |

### 6.3 安全机制

| 机制 | 说明 |
|---|---|
| **默认 L1** | 不指定 `--response-level` 时，不执行任何处置动作 |
| **干跑模式** | `--dry-run` 预览所有动作 |
| **白名单保护** | 关键文件/进程/用户/IP/容器不会被处置 |
| **取证优先** | 所有高风险动作先取证 |
| **可回滚** | 所有动作记录到 `rollback/actions.log` |
| **完整审计** | 每次动作记录到 `response_actions.log` |

### 6.4 三重保护

```
保护 1: 响应保护名单（response_whitelist.conf）
  ↓
保护 2: 硬编码保护（PROTECTED_PIDS/USERS/IPS）
  ↓
保护 3: 最小级别控制（每个动作有 min_level）
```

---

## 七、eBPF 进程阻断

### 7.1 工作原理

eBPF 程序通过 LSM Hook `bprm_check_security` 在 `execve` 系统调用**执行之前**拦截进程创建。匹配到阻断规则时返回 `-EPERM`，内核直接拒绝执行。

```
检测模块
   ↓ act_block_exec()
response.sh
   ↓ 写入 eBPF Map
eBPF LSM Hook（内核态）
   ↓ 读取 Map 匹配
匹配成功 → 返回 -EPERM → 进程无法启动
```

### 7.2 阻断类型

| 类型 | 格式 | 说明 |
|---|---|---|
| 进程名阻断 | `proc:<进程名>` | 阻断特定可执行文件 |
| 特征阻断 | `pattern:<特征串>` | 阻断命令行包含特定特征 |

### 7.3 组合响应

检测到反弹 Shell 时，**同时调用** `act_kill` 和 `act_block_exec`：

```bash
# 第一步: 事前阻断特征（防止攻击者重试）
act_block_exec "pattern:/dev/tcp/" "反弹 Shell 命令行特征"
act_block_exec "pattern:/dev/tcp/45.33.32.156/4444" "反弹 Shell 精确特征"
act_block_exec "pattern:bash -i" "反弹 Shell 命令行特征"

# 第二步: 事前阻断高危工具进程名
act_block_exec "proc:nc" "反弹 Shell 使用的工具进程"

# 第三步: 事后终止当前进程
act_kill "$pid" "反弹 Shell 命令行特征" "CRITICAL"

# 第四步: 记录组合响应
response_audit "REVERSE_SHELL_RESPONSE" "PID=$pid" "$reason" "KILL+BLOCK"
```

### 7.4 规则管理

```bash
# 查看当前所有阻断规则
sudo /opt/sec_audit/tools/block_exec_ctl list

# 查看阻断统计
sudo /opt/sec_audit/tools/block_exec_ctl stats

# 添加进程名阻断
sudo /opt/sec_audit/tools/block_exec_ctl add-proc curl

# 添加特征阻断
sudo /opt/sec_audit/tools/block_exec_ctl add-pattern "/dev/tcp/"

# 解除阻断
sudo /opt/sec_audit/tools/block_exec_ctl del-proc curl
sudo /opt/sec_audit/tools/block_exec_ctl del-pattern "/dev/tcp/"
```

---

## 八、YARA 规则引擎

### 8.1 集成范围

| 场景 | 集成 YARA | 说明 |
|---|---|---|
| Webshell 内容检测 | ✅ | PHP/JSP/ASP/Python/Node.js |
| 恶意二进制识别 | ✅ | ELF 可执行文件、共享库 |
| 进程命令行匹配 | ❌ | 保留正则 |
| 日志模式匹配 | ❌ | 保留正则 |

### 8.2 规则文件清单

| 分类 | 文件 | 用途 |
|---|---|---|
| Webshell | `php_webshell.yar` | 7 条规则，覆盖一句话、C99、r57、编码 |
| Webshell | `java_webshell.yar` | 7 条规则，覆盖 JSP、冰蝎、哥斯拉 |
| Webshell | `asp_webshell.yar` | 3 条规则，覆盖 ASP/ASPX |
| Webshell | `python_backdoor.yar` | 4 条规则，覆盖反弹 Shell、反序列化 |
| Webshell | `nodejs_backdoor.yar` | 3 条规则，覆盖命令执行、动态 eval |
| Malware | `linux_miner.yar` | 4 条规则，覆盖 XMRig、Kinsing |
| Malware | `linux_backdoor.yar` | 5 条规则，覆盖反弹 Shell、Mirai |
| Malware | `linux_ransomware.yar` | 3 条规则，覆盖通用勒索、RansomEXX |

### 8.3 社区规则来源

| 项目 | 地址 | 许可 |
|---|---|---|
| yara-detection-rules | https://github.com/leonardosmoutinho/yara-detection-rules | MIT |
| signature-base | https://github.com/Neo23x0/signature-base | DRL 1.1 |
| Yara-Rules/rules | https://github.com/Yara-Rules/rules | 混合 |

---

## 九、配置文件

### 9.1 `conf/whitelist.conf` — 检测白名单

```conf
# 检测白名单（每行一个条目）

# 业务文件
# /var/www/html/legacy/safe.php

# 容器
# nginx-proxy
# mysql-primary

# 定时任务
# /etc/cron.d/business-backup
```

### 9.2 `conf/remediation.conf` — 修复建议映射

```conf
# 格式: KEY=修复命令

ssh_permitrootlogin=echo "PermitRootLogin no" >> /etc/ssh/sshd_config.d/99-hardening.conf && sshd -t && systemctl reload sshd
sysctl:net.ipv4.ip_forward=echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.d/99-hardening.conf && sysctl --system
perm:/etc/shadow:640=chmod 640 /etc/shadow && chown root:root /etc/shadow
imdsv2=aws ec2 modify-instance-metadata-options --instance-id <实例ID> --http-tokens required
```

**完整映射表包含 100+ 条目**，覆盖系统基线、Java 内存马、Rootkit、反弹 Shell、Webshell、Web 日志、系统日志、Nacos、Docker 容器、响应动作说明。

### 9.3 `conf/response_whitelist.conf` — 响应保护名单

```conf
# 系统关键文件（不可隔离）
/etc/passwd
/etc/shadow
/etc/group
/etc/gshadow
/etc/sudoers
/etc/ssh/sshd_config
/etc/pam.d/system-auth
/etc/ld.so.preload

# 业务文件（按需添加）
# /var/www/html/index.php

# 关键容器
# container:nginx-proxy
# container:mysql-primary
```

---

## 十、使用手册

### 10.1 参数说明

| 参数 | 说明 |
|---|---|
| `--json` | 生成 JSON 格式报告 |
| `--schedule` | 配置定时任务 |
| `--no-install` | 跳过工具安装 |
| `--fix` | 自动修复低风险基线项 |
| `--response-level=N` | 响应级别 1-5（默认 1） |
| `--dry-run` | 干跑模式 |
| `--rollback` | 查看回滚信息 |
| `--check-ebpf` | eBPF 环境诊断 |
| `-h, --help` | 显示帮助 |

### 10.2 使用场景

```bash
# 日常巡检（默认 L1，只检测）
sudo sec_audit --json --no-install

# eBPF 环境检查
sudo sec_audit --check-ebpf

# 演练响应策略（干跑 L4）
sudo sec_audit --response-level=4 --dry-run --no-install

# 低风险自动处置
sudo sec_audit --response-level=3 --no-install

# 应急响应（终止进程、封禁 IP、eBPF 阻断）
sudo sec_audit --response-level=4 --json --no-install

# 主机隔离
sudo sec_audit --response-level=5 --no-install

# 查看历史响应动作
sudo sec_audit --rollback
```

### 10.3 输出文件

| 文件 | 路径 | 内容 |
|---|---|---|
| 完整报告 | `/var/log/sec_audit/audit_*.log` | 所有检测详情 |
| 摘要 | `/var/log/sec_audit/summary_*.txt` | FAIL/WARN 清单 |
| 系统快照 | `/var/log/sec_audit/sysinfo_*.txt` | 环境信息 |
| JSON 报告 | `/var/log/sec_audit/report_*.json` | SIEM 集成 |
| 安装日志 | `/var/log/sec_audit/install_*.log` | 工具部署记录 |
| 响应审计 | `/var/lib/sec_audit/response/response_actions.log` | 响应动作记录 |
| 证据目录 | `/var/lib/sec_audit/response/evidence/` | 取证文件 |
| 隔离目录 | `/var/lib/sec_audit/response/quarantine/` | 隔离文件 |
| 回滚记录 | `/var/lib/sec_audit/response/rollback/actions.log` | 回滚命令 |

### 10.4 风险评分

```
风险评分 = FAIL_COUNT × 10 + WARN_COUNT × 3

≥ 50   → 高危（立即响应）
20-49  → 中危（24h 内处置）
5-19   → 低危（48h 内处置）
< 5    → 安全
```

### 10.5 退出码

| 退出码 | 含义 |
|---|---|
| `0` | 无 FAIL，响应动作全部成功 |
| `1` | 有 FAIL，但响应动作未失败 |
| `2` | 响应动作执行失败 |

---

## 十一、故障排查

### 11.1 部署类

| 现象 | 排查方向 | 解决方案 |
|---|---|---|
| `--check-ebpf` 报 BPF LSM 未启用 | 内核启动参数缺 `bpf` | 修改 GRUB 后重启 |
| eBPF 程序加载失败 | bpftool 版本不匹配 | 升级到 7.0+ |
| `block_exec_ctl` 编译失败 | 缺 libbpf-dev | `apt install libbpf-dev` |
| 脚本运行卡住 | dpkg 损坏或网络慢 | 检查 `ps aux \| grep -E "apt\|dnf"` |
| 响应动作不执行 | 级别不足或白名单 | 检查 `--response-level` 和 `response_whitelist.conf` |
| 检测报告为空 | 日志源不可用 | 检查 `/var/log/auth.log` 或 `journalctl` |
| 内存马检测无结果 | jcmd 未安装 | `apt install openjdk-17-jdk-headless` |
| YARA 规则编译失败 | 规则语法错误 | `yara -w <规则> /dev/null` 定位 |
| 定时任务不执行 | cron 服务未启动 | `systemctl status cron` |

### 11.2 运行时类

| 现象 | 原因 | 解决方案 |
|---|---|---|
| `sed: unknown option to 's'` | sed 分隔符与 `/` 冲突 | 已修复，`add_finding` 改用纯 Bash |
| `command not found` | 函数定义后置 | 已修复，所有辅助函数前置 |
| `apt-get install` 卡住 | postinst 等待交互 | 已修复，使用 `DEBIAN_FRONTEND=noninteractive` |
| Ubuntu 无 corretto 包 | 包名仅 Amazon Linux 有 | 已修复，阶段 0 动态决策 |

### 11.3 误报处理

| 误报源 | 处理 |
|---|---|
| AWS authorized_keys 提示 | 已自动过滤 |
| rkhunter `/etc/.java` | 已自动加入白名单 |
| rkhunter `/etc/.updated` | 已自动加入白名单 |
| Docker 业务容器告警 | `whitelist.conf` 按容器名跳过 |

### 11.4 回滚操作

```bash
# 查看所有可回滚的操作
sudo sec_audit --rollback

# 手动解除文件隔离
sudo chattr -i /path/to/file
sudo chmod 644 /path/to/file

# 手动解除 IP 封禁
sudo iptables -D INPUT -s <IP> -j DROP
sudo iptables -D OUTPUT -d <IP> -j DROP

# 手动解除账户锁定
sudo usermod -U <用户名>
sudo usermod -s /bin/bash <用户名>

# 手动解除主机隔离
sudo iptables -F INPUT

# 手动解除 eBPF 阻断
sudo /opt/sec_audit/tools/block_exec_ctl del-proc <进程名>
sudo /opt/sec_audit/tools/block_exec_ctl del-pattern <特征>
```

---

## 十二、附录

### 12.1 文件清单

```
/usr/local/bin/sec_audit/
├── sec_audit.sh                 # 主入口
├── lib/                          # 18 个模块
├── conf/                         # 3 个配置
│   ├── whitelist.conf
│   ├── remediation.conf
│   └── response_whitelist.conf
├── rules/                        # YARA 规则
│   ├── webshells/ (5 个 .yar)
│   ├── malwares/ (3 个 .yar)
│   └── community/
└── ebpf/                         # eBPF 组件
    ├── vmlinux.h                 # 生成
    ├── block_exec.bpf.c
    ├── block_exec.bpf.o          # 编译产物
    └── block_exec_ctl.c
```

### 12.2 工具清单

| 工具 | 用途 | 最新版本 |
|---|---|---|
| rkhunter | Rootkit 检测 | 1.4.6-31 |
| chkrootkit | Rootkit 检测 | 0.59 |
| unhide | 隐藏进程/端口 | 20240510 |
| AIDE | 文件完整性 | 0.19.3 |
| Lynis | 系统审计 | 3.1.7 |
| memory-shell-detector | Java 内存马 | v0.1.5 |
| YARA | 模式匹配 | 4.5+ |
| Falco | 运行时监控 | 0.38+ |
| Trivy | 镜像漏洞（可选） | 最新 |

### 12.3 参考资源

| 资源 | 地址 |
|---|---|
| CIS Docker Benchmark | https://www.cisecurity.org/benchmark/docker |
| CIS Kubernetes Benchmark | https://www.cisecurity.org/benchmark/kubernetes |
| AWS IMDSv2 文档 | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html |
| memory-shell-detector | https://github.com/private-xss/memory-shell-detector |
| YARA 官方 | https://github.com/VirusTotal/yara |
| yara-detection-rules | https://github.com/leonardosmoutinho/yara-detection-rules |
| signature-base | https://github.com/Neo23x0/signature-base |
| Falco | https://falco.org/ |
| Tetragon | https://github.com/cilium/tetragon |
| OpenRASP | https://github.com/baidu/openrasp |

### 12.4 合规对照

| 检测项 | CIS Benchmark | 等保 2.0 |
|---|---|---|
| SSH 配置加固 | CIS 5.2.x | 8.1.4.1 |
| 账户安全 | CIS 4.x | 8.1.2 |
| 内核参数 | CIS 1.x | 8.1.4.7 |
| 文件权限 | CIS 6.x | 8.1.4.8 |
| 日志审计 | CIS 4.1.x | 8.1.3 |
| Docker 安全 | CIS Docker 1.6.0 | — |

### 12.5 扩展方向

| 优先级 | 方向 | 说明 |
|---|---|---|
| **P0** | SOAR 编排层 | 将响应逻辑从脚本解耦为 Playbook |
| **P0** | EDR 执行预防 | 已通过 eBPF BLOCK_EXEC 实现 |
| **P1** | 威胁情报集成 | IOC 查询提升响应决策准确性 |
| **P1** | Kubernetes 安全 | 集成 Kubescape 4.0 |
| **P1** | Runtime SBOM | 识别运行时实际执行的组件 |
| **P2** | 欺骗技术 | 蜜罐、蜜标文件、蜜标凭证 |
| **P2** | AI 基础设施安全 | 集成 AI-Infra-Guard |
| **P3** | 响应度量与优化 | MTTD/MTTR 统计 |

---

## 文档信息

| 项目 | 内容 |
|---|---|
| 文档版本 | 1.0 |
| 对应脚本版本 | v7.1 |
| 最后更新 | 2026-09-18 |
| 文档类型 | 综合部署手册 |
| 维护者 | 安全运维团队 |
| 适用环境 | AWS EC2 / 通用 Linux |

---

> 本文档为 AWS Linux 安全检测与响应系统 v7.1 的完整部署手册，涵盖从环境准备、部署、编译、配置到日常运维的全流程。系统默认保持 L1 安全模式（仅检测），按需启用 L2-L5 响应级别。所有处置动作都有取证、白名单保护、审计、回滚四重保障，可在生产环境安全使用。
