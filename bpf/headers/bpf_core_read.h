/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BPF_CORE_READ_H__
#define __BPF_CORE_READ_H__

#ifndef BPF_CORE_READ
#define BPF_CORE_READ(src, a, ...) ({                                       \
    ___type((src), a, ##__VA_ARGS__) __val;                                 \
    BPF_CORE_READ_INTO(&__val, src, a, ##__VA_ARGS__);                      \
    __val;                                                                  \
})
#endif

#ifndef BPF_CORE_READ_INTO
#define BPF_CORE_READ_INTO(dst, src, a, ...) ({                             \
    bpf_probe_read_kernel(dst, sizeof(*(dst)), &((src)->a));                \
})
#endif

#endif /* __BPF_CORE_READ_H__ */
