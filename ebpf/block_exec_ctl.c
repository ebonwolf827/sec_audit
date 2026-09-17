//=============================================================
// ebpf/block_exec_ctl.c — eBPF 阻断规则控制工具
// 用法:
//   block_exec_ctl add-proc <进程名>      添加进程名黑名单
//   block_exec_ctl del-proc <进程名>      删除进程名黑名单
//   block_exec_ctl add-pattern <特征>     添加命令行特征
//   block_exec_ctl del-pattern <特征>     删除命令行特征
//   block_exec_ctl stats                  查看统计
//   block_exec_ctl list                   列出当前规则
// 编译:
//   gcc -O2 -o block_exec_ctl block_exec_ctl.c -lbpf -lelf -lz
//=============================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define PROC_MAP_PATH    "/sys/fs/bpf/block_exec/procs"
#define PATTERN_MAP_PATH "/sys/fs/bpf/block_exec/patterns"
#define STATS_MAP_PATH   "/sys/fs/bpf/block_exec/stats"

static int update_proc_rule(const char *proc_name, int add) {
    int fd = bpf_obj_get(PROC_MAP_PATH);
    if (fd < 0) {
        fprintf(stderr, "无法打开进程规则 Map: %s\n", strerror(errno));
        return -1;
    }

    char key[32] = {};
    strncpy(key, proc_name, sizeof(key) - 1);

    if (add) {
        __u8 val = 1;
        if (bpf_map_update_elem(fd, key, &val, BPF_ANY) < 0) {
            fprintf(stderr, "添加规则失败: %s\n", strerror(errno));
            close(fd);
            return -1;
        }
        printf("已添加进程黑名单: %s\n", proc_name);
    } else {
        if (bpf_map_delete_elem(fd, key) < 0) {
            fprintf(stderr, "删除规则失败: %s\n", strerror(errno));
            close(fd);
            return -1;
        }
        printf("已删除进程黑名单: %s\n", proc_name);
    }
    close(fd);
    return 0;
}

static int update_pattern_rule(const char *pattern, int add) {
    int fd = bpf_obj_get(PATTERN_MAP_PATH);
    if (fd < 0) {
        fprintf(stderr, "无法打开特征规则 Map: %s\n", strerror(errno));
        return -1;
    }

    char key[64] = {};
    strncpy(key, pattern, sizeof(key) - 1);

    if (add) {
        __u8 val = 1;
        if (bpf_map_update_elem(fd, key, &val, BPF_ANY) < 0) {
            fprintf(stderr, "添加特征失败: %s\n", strerror(errno));
            close(fd);
            return -1;
        }
        printf("已添加命令行特征: %s\n", pattern);
    } else {
        if (bpf_map_delete_elem(fd, key) < 0) {
            fprintf(stderr, "删除特征失败: %s\n", strerror(errno));
            close(fd);
            return -1;
        }
        printf("已删除命令行特征: %s\n", pattern);
    }
    close(fd);
    return 0;
}

static void show_stats(void) {
    int fd = bpf_obj_get(STATS_MAP_PATH);
    if (fd < 0) {
        fprintf(stderr, "无法打开统计 Map: %s\n", strerror(errno));
        return;
    }

    __u64 values[4] = {};
    __u32 key;

    key = 0; bpf_map_lookup_elem(fd, &key, &values[0]);
    key = 1; bpf_map_lookup_elem(fd, &key, &values[1]);
    key = 2; bpf_map_lookup_elem(fd, &key, &values[2]);
    key = 3; bpf_map_lookup_elem(fd, &key, &values[3]);

    printf("=== 阻断统计 ===\n");
    printf("  已阻断进程: %llu\n", (unsigned long long)values[0]);
    printf("  已放行进程: %llu\n", (unsigned long long)values[1]);
    printf("  特征匹配数: %llu\n", (unsigned long long)values[2]);
    printf("  进程名匹配: %llu\n", (unsigned long long)values[3]);
    close(fd);
}

static void list_rules(void) {
    printf("=== 进程名黑名单 ===\n");
    int fd = bpf_obj_get(PROC_MAP_PATH);
    if (fd >= 0) {
        char key[32], next_key[32];
        __u8 val;
        int first = 1;
        while (bpf_map_get_next_key(fd, first ? NULL : key, next_key) == 0) {
            bpf_map_lookup_elem(fd, next_key, &val);
            printf("  %s\n", next_key);
            memcpy(key, next_key, sizeof(key));
            first = 0;
        }
        close(fd);
    }

    printf("=== 命令行特征 ===\n");
    fd = bpf_obj_get(PATTERN_MAP_PATH);
    if (fd >= 0) {
        char key[64], next_key[64];
        __u8 val;
        int first = 1;
        while (bpf_map_get_next_key(fd, first ? NULL : key, next_key) == 0) {
            bpf_map_lookup_elem(fd, next_key, &val);
            printf("  %s\n", next_key);
            memcpy(key, next_key, sizeof(key));
            first = 0;
        }
        close(fd);
    }
}

static void usage(const char *prog) {
    fprintf(stderr,
        "用法: %s <命令> [参数]\n"
        "\n"
        "命令:\n"
        "  add-proc <进程名>       添加进程名黑名单\n"
        "  del-proc <进程名>       删除进程名黑名单\n"
        "  add-pattern <特征>      添加命令行特征\n"
        "  del-pattern <特征>      删除命令行特征\n"
        "  stats                   查看阻断统计\n"
        "  list                    列出所有规则\n"
        "\n"
        "示例:\n"
        "  %s add-proc curl\n"
        "  %s add-pattern '/dev/tcp/'\n"
        "  %s stats\n",
        prog, prog, prog, prog);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "add-proc") == 0 && argc >= 3)
        return update_proc_rule(argv[2], 1);
    else if (strcmp(argv[1], "del-proc") == 0 && argc >= 3)
        return update_proc_rule(argv[2], 0);
    else if (strcmp(argv[1], "add-pattern") == 0 && argc >= 3)
        return update_pattern_rule(argv[2], 1);
    else if (strcmp(argv[1], "del-pattern") == 0 && argc >= 3)
        return update_pattern_rule(argv[2], 0);
    else if (strcmp(argv[1], "stats") == 0)
        show_stats();
    else if (strcmp(argv[1], "list") == 0)
        list_rules();
    else {
        usage(argv[0]);
        return 1;
    }

    return 0;
}
