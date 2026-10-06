package bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// EventType defines the category of intercepted kernel syscall event.
type EventType uint32

const (
	EventTypeUnknown EventType = 0
	EventTypeExecve  EventType = 1
	EventTypeConnect EventType = 2
	EventTypeOpenat  EventType = 3
)

func (t EventType) String() string {
	switch t {
	case EventTypeExecve:
		return "EXECVE"
	case EventTypeConnect:
		return "CONNECT"
	case EventTypeOpenat:
		return "OPENAT"
	default:
		return "UNKNOWN"
	}
}

// Raw event size expected from BPF RingBuffer (must match sizeof(struct event)).
const ExpectedEventSize = 568

// ExecData holds intercepted arguments and target binary for sys_enter_execve.
type ExecData struct {
	Filename string `json:"filename"`
	Args     string `json:"args"`
}

// ConnectData holds intercepted socket destination for sys_enter_connect.
type ConnectData struct {
	Family   uint32 `json:"family"`
	DestIP   net.IP `json:"dest_ip"`
	DestPort uint16 `json:"dest_port"`
	FD       int32  `json:"fd"`
}

// OpenatData holds intercepted file path and flags for sys_enter_openat.
type OpenatData struct {
	Filename string `json:"filename"`
	Flags    int32  `json:"flags"`
	DFD      int32  `json:"dfd"`
}

// EnrichedMetadata encapsulates user-space enriched telemetry context.
type EnrichedMetadata struct {
	Username       string `json:"username,omitempty"`
	PPID           uint32 `json:"ppid,omitempty"`
	ParentComm     string `json:"parent_comm,omitempty"`
	ParentCmdline  string `json:"parent_cmdline,omitempty"`
	FullCmdline    string `json:"full_cmdline,omitempty"`
	IsContainer    bool   `json:"is_container"`
	ContainerID    string `json:"container_id,omitempty"`
	ContainerName  string `json:"container_name,omitempty"`
	ContainerType  string `json:"container_type,omitempty"`
}

// Event represents a normalized, typed security event.
type Event struct {
	Timestamp    time.Time         `json:"timestamp"`
	TimestampRaw uint64            `json:"timestamp_raw_ns"`
	CgroupID     uint64            `json:"cgroup_id"`
	PID          uint32            `json:"pid"`
	TGID         uint32            `json:"tgid"`
	PPID         uint32            `json:"ppid"`
	UID          uint32            `json:"uid"`
	GID          uint32            `json:"gid"`
	Type         EventType         `json:"event_type"`
	Comm         string            `json:"comm"`
	Exec         *ExecData         `json:"exec,omitempty"`
	Connect      *ConnectData      `json:"connect,omitempty"`
	Openat       *OpenatData       `json:"openat,omitempty"`
	Enriched     *EnrichedMetadata `json:"enriched,omitempty"`
}

// ParseRawEvent decodes raw binary payload emitted by the BPF RingBuffer into Event.
func ParseRawEvent(data []byte) (*Event, error) {
	if len(data) < ExpectedEventSize {
		return nil, fmt.Errorf("invalid event payload size: expected %d bytes, got %d", ExpectedEventSize, len(data))
	}

	rawTime := binary.LittleEndian.Uint64(data[0:8])
	cgroupID := binary.LittleEndian.Uint64(data[8:16])
	pid := binary.LittleEndian.Uint32(data[16:20])
	tgid := binary.LittleEndian.Uint32(data[20:24])
	ppid := binary.LittleEndian.Uint32(data[24:28])
	uid := binary.LittleEndian.Uint32(data[28:32])
	gid := binary.LittleEndian.Uint32(data[32:36])
	rawType := binary.LittleEndian.Uint32(data[36:40])
	comm := extractCString(data[40:56])

	event := &Event{
		Timestamp:    time.Now().UTC(),
		TimestampRaw: rawTime,
		CgroupID:     cgroupID,
		PID:          pid,
		TGID:         tgid,
		PPID:         ppid,
		UID:          uid,
		GID:          gid,
		Type:         EventType(rawType),
		Comm:         comm,
	}

	unionData := data[56:]

	switch event.Type {
	case EventTypeExecve:
		event.Exec = &ExecData{
			Filename: extractCString(unionData[0:256]),
			Args:     extractCString(unionData[256:512]),
		}
	case EventTypeConnect:
		family := binary.LittleEndian.Uint32(unionData[0:4])
		dport := binary.LittleEndian.Uint16(unionData[4:6])
		var ip net.IP
		if family == 2 { // AF_INET
			ip = net.IPv4(unionData[8], unionData[9], unionData[10], unionData[11])
		} else if family == 10 { // AF_INET6
			ip = make(net.IP, 16)
			copy(ip, unionData[8:24])
		} else {
			ip = net.IPv4zero
		}
		fd := int32(binary.LittleEndian.Uint32(unionData[24:28]))

		event.Connect = &ConnectData{
			Family:   family,
			DestIP:   ip,
			DestPort: dport,
			FD:       fd,
		}
	case EventTypeOpenat:
		event.Openat = &OpenatData{
			Filename: extractCString(unionData[0:256]),
			Flags:    int32(binary.LittleEndian.Uint32(unionData[256:260])),
			DFD:      int32(binary.LittleEndian.Uint32(unionData[260:264])),
		}
	default:
		return nil, fmt.Errorf("unrecognized event type: %d", rawType)
	}

	return event, nil
}

// extractCString extracts a Go string from a null-terminated byte slice.
func extractCString(b []byte) string {
	idx := bytes.IndexByte(b, 0)
	if idx >= 0 {
		return string(b[:idx])
	}
	return string(b)
}
