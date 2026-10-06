/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BPF_ENDIAN_H__
#define __BPF_ENDIAN_H__

#define ___bpf_mvb(val, b, n, m) ((__u##b)(val) << (n) >> (m))
#define ___bpf_swab16(val) ((__u16)(___bpf_mvb(val, 16, 8, 0) | ___bpf_mvb(val, 16, 0, 8)))
#define ___bpf_swab32(val) ((__u32)(___bpf_mvb(val, 32, 24, 0) | ___bpf_mvb(val, 32, 8, 16) | \
                                    ___bpf_mvb(val, 32, 0, 16) | ___bpf_mvb(val, 32, 0, 24)))
#define ___bpf_swab64(val) ((__u64)(___bpf_mvb(val, 64, 56, 0) | ___bpf_mvb(val, 64, 40, 16) | \
                                    ___bpf_mvb(val, 64, 24, 32) | ___bpf_mvb(val, 64, 8, 48) | \
                                    ___bpf_mvb(val, 64, 0, 48) | ___bpf_mvb(val, 64, 0, 32) | \
                                    ___bpf_mvb(val, 64, 0, 16) | ___bpf_mvb(val, 64, 0, 56)))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define __bpf_ntohs(x) ___bpf_swab16(x)
# define __bpf_htons(x) ___bpf_swab16(x)
# define __bpf_ntohl(x) ___bpf_swab32(x)
# define __bpf_htonl(x) ___bpf_swab32(x)
# define __bpf_be64_to_cpu(x) ___bpf_swab64(x)
# define __bpf_cpu_to_be64(x) ___bpf_swab64(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define __bpf_ntohs(x) (x)
# define __bpf_htons(x) (x)
# define __bpf_ntohl(x) (x)
# define __bpf_htonl(x) (x)
# define __bpf_be64_to_cpu(x) (x)
# define __bpf_cpu_to_be64(x) (x)
#else
# error "Unknown __BYTE_ORDER__"
#endif

#define bpf_htons(x) __bpf_htons(x)
#define bpf_ntohs(x) __bpf_ntohs(x)
#define bpf_htonl(x) __bpf_htonl(x)
#define bpf_ntohl(x) __bpf_ntohl(x)

#endif /* __BPF_ENDIAN_H__ */
