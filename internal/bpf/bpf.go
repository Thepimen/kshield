package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf -cc clang -cflags "-O2 -g -Wall -I../../bpf -I../../bpf/headers" bpf ../../bpf/kshield.bpf.c -- -I../../bpf/headers
