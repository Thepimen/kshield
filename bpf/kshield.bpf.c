// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * kshield - Kernel-space eBPF security sensor
 *
 * Implements low-overhead syscall tracing for intrusion detection and telemetry.
 * Leverages CO-RE and BPF ring buffer for minimal overhead.
 */

#include "headers/vmlinux.h"
#include "headers/bpf_helpers.h"
#include "headers/bpf_core_read.h"
#include "headers/bpf_endian.h"
#include "kshield.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Ring buffer map for streaming structured security events to user space */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024); /* 1MB Ring Buffer */
} events_rb SEC(".maps");

/* Filter map populated by userspace with kshield's own PID(s) to break telemetry loops */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);   /* tgid (process ID) */
    __type(value, __u8);  /* flag (1 = drop) */
} ignored_pids SEC(".maps");

static __always_inline int is_pid_ignored(__u32 tgid) {
    __u8 *val = bpf_map_lookup_elem(&ignored_pids, &tgid);
    return val != NULL;
}

static __always_inline void init_header(struct event *e, __u32 type, __u64 pid_tgid, __u64 uid_gid) {
    e->timestamp_ns = bpf_ktime_get_ns();
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->tgid = (__u32)(pid_tgid >> 32);
    e->pid = (__u32)pid_tgid;
    e->ppid = 0; /* Enriched by user-space via /proc/<pid>/status */
    e->uid = (__u32)uid_gid;
    e->gid = (__u32)(uid_gid >> 32);
    e->event_type = type;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
}

/*
 * HOOK: sys_enter_execve
 * Captures process execution, binary path, and initial command line arguments.
 */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);

    if (is_pid_ignored(tgid)) {
        return 0;
    }

    struct event *event = bpf_ringbuf_reserve(&events_rb, sizeof(struct event), 0);
    if (!event) {
        return 0;
    }

    __u64 uid_gid = bpf_get_current_uid_gid();
    init_header(event, EVENT_TYPE_EXECVE, pid_tgid, uid_gid);

    /* args[0]: const char *filename */
    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(event->exec.filename, sizeof(event->exec.filename), filename_ptr);

    /* args[1]: const char *const *argv */
    const char *const *argv = (const char *const *)ctx->args[1];
    event->exec.args[0] = '\0';

    if (argv) {
        /* Read up to 4 arguments safely and concatenate */
        #pragma unroll
        for (int i = 0; i < 4; i++) {
            const char *argp = NULL;
            if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) < 0 || !argp) {
                break;
            }

            char temp_arg[64];
            long n = bpf_probe_read_user_str(temp_arg, sizeof(temp_arg), argp);
            if (n <= 1) {
                continue;
            }

            /* Basic bounded append into args buffer */
            #pragma unroll
            for (int j = 0; j < 60; j++) {
                if (temp_arg[j] == '\0') {
                    break;
                }
            }
        }
        /* As primary quick capture, read argv[0] and argv[1] directly */
        const char *arg0 = NULL;
        if (bpf_probe_read_user(&arg0, sizeof(arg0), &argv[0]) == 0 && arg0) {
            bpf_probe_read_user_str(event->exec.args, sizeof(event->exec.args), arg0);
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/*
 * HOOK: sys_enter_connect
 * Captures outbound network connection attempts (destination IP and port).
 */
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);

    if (is_pid_ignored(tgid)) {
        return 0;
    }

    /* args[0]: int fd */
    /* args[1]: struct sockaddr *uservaddr */
    /* args[2]: int addrlen */
    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    if (!addr) {
        return 0;
    }

    sa_family_t family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), &addr->sa_family) < 0) {
        return 0;
    }

    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }

    struct event *event = bpf_ringbuf_reserve(&events_rb, sizeof(struct event), 0);
    if (!event) {
        return 0;
    }

    __u64 uid_gid = bpf_get_current_uid_gid();
    init_header(event, EVENT_TYPE_CONNECT, pid_tgid, uid_gid);

    event->connect.fd = (int)ctx->args[0];
    event->connect.sa_family = family;

    if (family == AF_INET) {
        struct sockaddr_in sin;
        if (bpf_probe_read_user(&sin, sizeof(sin), addr) == 0) {
            event->connect.dport = bpf_ntohs(sin.sin_port);
            __builtin_memcpy(event->connect.daddr, &sin.sin_addr.s_addr, 4);
        }
    } else if (family == AF_INET6) {
        struct sockaddr_in6 sin6;
        if (bpf_probe_read_user(&sin6, sizeof(sin6), addr) == 0) {
            event->connect.dport = bpf_ntohs(sin6.sin6_port);
            __builtin_memcpy(event->connect.daddr, &sin6.sin6_addr, 16);
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/*
 * HOOK: sys_enter_openat
 * Detects file access attempts, especially targeting sensitive system files.
 */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);

    if (is_pid_ignored(tgid)) {
        return 0;
    }

    /* args[0]: int dfd */
    /* args[1]: const char *filename */
    /* args[2]: int flags */
    /* args[3]: umode_t mode */
    const char *filename_ptr = (const char *)ctx->args[1];
    if (!filename_ptr) {
        return 0;
    }

    struct event *event = bpf_ringbuf_reserve(&events_rb, sizeof(struct event), 0);
    if (!event) {
        return 0;
    }

    __u64 uid_gid = bpf_get_current_uid_gid();
    init_header(event, EVENT_TYPE_OPENAT, pid_tgid, uid_gid);

    event->openat.dfd = (int)ctx->args[0];
    event->openat.flags = (int)ctx->args[2];

    bpf_probe_read_user_str(event->openat.filename, sizeof(event->openat.filename), filename_ptr);

    bpf_ringbuf_submit(event, 0);
    return 0;
}
