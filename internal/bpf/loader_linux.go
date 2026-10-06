//go:build linux

package bpf

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// BpfObjects holds the loaded eBPF maps and programs.
type BpfObjects struct {
	EventsRb    *ebpf.Map `ebpf:"events_rb"`
	IgnoredPids *ebpf.Map `ebpf:"ignored_pids"`

	TraceSysEnterExecve  *ebpf.Program `ebpf:"trace_sys_enter_execve"`
	TraceSysEnterConnect *ebpf.Program `ebpf:"trace_sys_enter_connect"`
	TraceSysEnterOpenat  *ebpf.Program `ebpf:"trace_sys_enter_openat"`
}

func (o *BpfObjects) Close() error {
	var errs []error
	if o.TraceSysEnterExecve != nil {
		errs = append(errs, o.TraceSysEnterExecve.Close())
	}
	if o.TraceSysEnterConnect != nil {
		errs = append(errs, o.TraceSysEnterConnect.Close())
	}
	if o.TraceSysEnterOpenat != nil {
		errs = append(errs, o.TraceSysEnterOpenat.Close())
	}
	if o.EventsRb != nil {
		errs = append(errs, o.EventsRb.Close())
	}
	if o.IgnoredPids != nil {
		errs = append(errs, o.IgnoredPids.Close())
	}
	return errors.Join(errs...)
}

// Manager orchestrates the lifecycle of eBPF programs, maps, and ring buffer reader.
type Manager struct {
	objects    BpfObjects
	collection *ebpf.Collection
	links      []link.Link
	ringReader *ringbuf.Reader
	mu         sync.Mutex
	closed     bool
}

// NewManager loads the compiled eBPF ELF binary, creates maps and verifies programs.
func NewManager(bpfElfPath string) (*Manager, error) {
	// Remove memory locking limits for eBPF map allocations
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(bpfElfPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load BPF collection spec from %s: %w", bpfElfPath, err)
	}

	var objs BpfObjects
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create BPF collection: %w", err)
	}

	objs.EventsRb = coll.Maps["events_rb"]
	objs.IgnoredPids = coll.Maps["ignored_pids"]
	objs.TraceSysEnterExecve = coll.Programs["trace_sys_enter_execve"]
	objs.TraceSysEnterConnect = coll.Programs["trace_sys_enter_connect"]
	objs.TraceSysEnterOpenat = coll.Programs["trace_sys_enter_openat"]

	mgr := &Manager{
		objects:    objs,
		collection: coll,
		links:      make([]link.Link, 0, 4),
	}

	return mgr, nil
}

// IgnorePID adds a process ID to the in-kernel filter map to prevent feedback loops.
func (m *Manager) IgnorePID(pid uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.objects.IgnoredPids == nil {
		return errors.New("ignored_pids map not initialized")
	}

	val := uint8(1)
	if err := m.objects.IgnoredPids.Put(pid, val); err != nil {
		return fmt.Errorf("failed to register PID %d in ignored_pids map: %w", pid, err)
	}
	return nil
}

// Attach attaches all tracepoints to their respective kernel hooks.
func (m *Manager) Attach() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. Attach tracepoint/syscalls/sys_enter_execve
	if m.objects.TraceSysEnterExecve != nil {
		l, err := link.Tracepoint("syscalls", "sys_enter_execve", m.objects.TraceSysEnterExecve, nil)
		if err != nil {
			return fmt.Errorf("failed to attach sys_enter_execve tracepoint: %w", err)
		}
		m.links = append(m.links, l)
	}

	// 2. Attach tracepoint/syscalls/sys_enter_connect
	if m.objects.TraceSysEnterConnect != nil {
		l, err := link.Tracepoint("syscalls", "sys_enter_connect", m.objects.TraceSysEnterConnect, nil)
		if err != nil {
			return fmt.Errorf("failed to attach sys_enter_connect tracepoint: %w", err)
		}
		m.links = append(m.links, l)
	}

	// 3. Attach tracepoint/syscalls/sys_enter_openat
	if m.objects.TraceSysEnterOpenat != nil {
		l, err := link.Tracepoint("syscalls", "sys_enter_openat", m.objects.TraceSysEnterOpenat, nil)
		if err != nil {
			return fmt.Errorf("failed to attach sys_enter_openat tracepoint: %w", err)
		}
		m.links = append(m.links, l)
	}

	return nil
}

// ConsumeEvents initiates a non-blocking consumer loop on the BPF ring buffer.
func (m *Manager) ConsumeEvents(ctx context.Context, handler func(*Event)) error {
	m.mu.Lock()
	if m.objects.EventsRb == nil {
		m.mu.Unlock()
		return errors.New("events_rb map not initialized")
	}

	reader, err := ringbuf.NewReader(m.objects.EventsRb)
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("failed to open BPF ring buffer reader: %w", err)
	}
	m.ringReader = reader
	m.mu.Unlock()

	go func() {
		<-ctx.Done()
		m.mu.Lock()
		if m.ringReader != nil {
			_ = m.ringReader.Close()
		}
		m.mu.Unlock()
	}()

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			select {
			case <-ctx.Done():
				return nil
			default:
				continue
			}
		}

		event, err := ParseRawEvent(record.RawSample)
		if err != nil {
			continue
		}

		handler(event)
	}
}

// Close detaches links, unloads BPF programs, and closes maps cleanly.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}
	m.closed = true

	var errs []error

	if m.ringReader != nil {
		errs = append(errs, m.ringReader.Close())
	}

	for _, l := range m.links {
		if l != nil {
			errs = append(errs, l.Close())
		}
	}

	if m.collection != nil {
		m.collection.Close()
	}

	return errors.Join(errs...)
}
