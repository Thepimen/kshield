//go:build !linux

package bpf

import (
	"context"
	"errors"
)

// Manager stub for non-Linux environments.
type Manager struct{}

func NewManager(bpfElfPath string) (*Manager, error) {
	return nil, errors.New("kshield eBPF manager requires a Linux kernel with BTF enabled")
}

func (m *Manager) IgnorePID(pid uint32) error {
	return nil
}

func (m *Manager) Attach() error {
	return errors.New("cannot attach eBPF tracepoints on non-Linux platform")
}

func (m *Manager) ConsumeEvents(ctx context.Context, handler func(*Event)) error {
	<-ctx.Done()
	return nil
}

func (m *Manager) Close() error {
	return nil
}
