/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __KSHIELD_BPF_H__
#define __KSHIELD_BPF_H__

#include "headers/vmlinux.h"

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN  256
#define MAX_ARGS_LEN  256

enum event_type {
    EVENT_TYPE_UNKNOWN = 0,
    EVENT_TYPE_EXECVE  = 1,
    EVENT_TYPE_CONNECT = 2,
    EVENT_TYPE_OPENAT  = 3,
};

struct exec_data {
    char filename[MAX_PATH_LEN];
    char args[MAX_ARGS_LEN];
};

struct connect_data {
    __u32 sa_family;
    __u16 dport;
    __u8  pad[2];
    __u8  daddr[16];   /* IPv4 uses first 4 bytes; IPv6 uses all 16 */
    __s32 fd;
    __u8  reserved[484];
};

struct openat_data {
    char  filename[MAX_PATH_LEN];
    __s32 flags;
    __s32 dfd;
    __u8  reserved[248];
};

struct event {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 event_type;
    char  comm[TASK_COMM_LEN];
    union {
        struct exec_data    exec;
        struct connect_data connect;
        struct openat_data  openat;
    };
};

#endif /* __KSHIELD_BPF_H__ */
