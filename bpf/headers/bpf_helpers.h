#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

#include "vmlinux.h"

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#ifndef SEC
#define SEC(name) __attribute__((section(name), used))
#endif

/* Macros BTF para definición de mapas */
#ifndef __uint
#define __uint(name, val) int (*name)[val]
#endif

#ifndef __type
#define __type(name, val) typeof(val) *name
#endif

#ifndef __array
#define __array(name, val) typeof(val) *name[]
#endif

/* Constantes de red y sockets */
#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifndef sa_family_t
typedef unsigned short sa_family_t;
#endif

/* Prototipos de helpers del Kernel BPF */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;
static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;
static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *) 6;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *) 15;
static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *) 16;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *) 80;
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 112;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 113;
static long (*bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 114;
static long (*bpf_probe_read_kernel_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 115;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *) 131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *) 132;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *) 133;

#endif /* __BPF_HELPERS_H */
