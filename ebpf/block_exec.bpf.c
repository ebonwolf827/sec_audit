//=============================================================
// ebpf/block_exec.bpf.c — eBPF LSM Hook 进程执行阻断
// Hook: lsm/bprm_check_security
// 功能: 在 execve 执行前拦截高危进程
// 编译:
//   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
//       -I./ebpf -c ebpf/block_exec.bpf.c -o ebpf/block_exec.bpf.o
//=============================================================

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// ---------- 进程名黑名单 Map ----------
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[32]);
    __type(value, __u8);
} blocked_procs SEC(".maps");

// ---------- 命令行特征 Map ----------
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[64]);
    __type(value, __u8);
} blocked_patterns SEC(".maps");

// ---------- 统计 Map ----------
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

#define STAT_BLOCKED    0
#define STAT_PASSED     1
#define STAT_PATTERN    2
#define STAT_PROC       3

// ---------- 辅助: 读取进程名 ----------
static __always_inline int read_proc_name(struct linux_binprm *bprm, char *buf, int size) {
    const char *filename;
    long ret;
    int base_off = 0;

    filename = BPF_CORE_READ(bprm, filename);
    if (!filename)
        return -1;

    ret = bpf_probe_read_kernel_str(buf, size, filename);
    if (ret <= 0)
        return -1;

    // 取 basename
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (i >= size - 1 || buf[i] == '\0')
            break;
        if (buf[i] == '/')
            base_off = i + 1;
    }

    if (base_off > 0) {
        #pragma unroll
        for (int i = 0; i < 32; i++) {
            if (i + base_off >= size)
                break;
            buf[i] = buf[i + base_off];
            if (buf[i] == '\0')
                break;
        }
    }
    return 0;
}

// ---------- 辅助: 读取命令行 ----------
static __always_inline int read_cmdline(struct linux_binprm *bprm, char *buf, int size) {
    const char *const *argv;
    const char *arg;
    long ret;
    int offset = 0;

    argv = BPF_CORE_READ(bprm, argv);
    if (!argv)
        return -1;

    #pragma unroll
    for (int i = 0; i < 4; i++) {
        bpf_probe_read_kernel(&arg, sizeof(arg), &argv[i]);
        if (!arg)
            break;

        ret = bpf_probe_read_kernel_str(buf + offset, size - offset, arg);
        if (ret <= 0)
            break;

        offset += ret;
        if (offset < size - 1)
            buf[offset - 1] = ' ';
        if (offset >= size - 1)
            break;
    }
    buf[size - 1] = '\0';
    return 0;
}

// ---------- 辅助: 命令行包含指定特征 ----------
static __always_inline int cmdline_contains(const char *cmdline, const char *pattern, int pattern_len) {
    // 简化匹配: 检查命令行前 200 字节
    #pragma unroll
    for (int i = 0; i < 200; i++) {
        int match = 1;
        #pragma unroll
        for (int j = 0; j < 16; j++) {
            if (j >= pattern_len)
                break;
            if (cmdline[i + j] != pattern[j]) {
                match = 0;
                break;
            }
        }
        if (match)
            return 1;
    }
    return 0;
}

// ---------- LSM Hook ----------
SEC("lsm/bprm_check_security")
int BPF_PROG(block_exec_hook, struct linux_binprm *bprm)
{
    char proc_name[32] = {};
    char cmdline[256] = {};
    __u8 *blocked;
    __u32 key;
    __u64 *counter;

    // 1. 读取进程名
    if (read_proc_name(bprm, proc_name, sizeof(proc_name)) < 0)
        return 0;

    // 2. 进程名黑名单匹配
    blocked = bpf_map_lookup_elem(&blocked_procs, proc_name);
    if (blocked && *blocked == 1) {
        key = STAT_PROC;
        counter = bpf_map_lookup_elem(&stats, &key);
        if (counter) __sync_fetch_and_add(counter, 1);

        key = STAT_BLOCKED;
        counter = bpf_map_lookup_elem(&stats, &key);
        if (counter) __sync_fetch_and_add(counter, 1);

        return -EPERM;
    }

    // 3. 读取命令行
    if (read_cmdline(bprm, cmdline, sizeof(cmdline)) < 0)
        return 0;

    // 4. 关键特征匹配（硬编码常见反弹 Shell 特征）
    int matched = 0;

    if (cmdline_contains(cmdline, "/dev/tcp/", 9))
        matched = 1;
    else if (cmdline_contains(cmdline, "/dev/udp/", 9))
        matched = 1;
    else if (cmdline_contains(cmdline, "bash -i", 7))
        matched = 1;
    else if (cmdline_contains(cmdline, "nc -e", 5))
        matched = 1;
    else if (cmdline_contains(cmdline, "ncat -e", 7))
        matched = 1;
    else if (cmdline_contains(cmdline, "socat exec:", 11))
        matched = 1;
    else if (cmdline_contains(cmdline, "mkfifo /tmp/", 12))
        matched = 1;

    if (matched) {
        key = STAT_PATTERN;
        counter = bpf_map_lookup_elem(&stats, &key);
        if (counter) __sync_fetch_and_add(counter, 1);

        key = STAT_BLOCKED;
        counter = bpf_map_lookup_elem(&stats, &key);
        if (counter) __sync_fetch_and_add(counter, 1);

        return -EPERM;
    }

    key = STAT_PASSED;
    counter = bpf_map_lookup_elem(&stats, &key);
    if (counter) __sync_fetch_and_add(counter, 1);

    return 0;
}
