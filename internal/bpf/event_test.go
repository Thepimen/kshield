package bpf

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestParseRawEvent_Execve(t *testing.T) {
	buf := make([]byte, ExpectedEventSize)

	// Header
	binary.LittleEndian.PutUint64(buf[0:8], 1234567890) // timestamp
	binary.LittleEndian.PutUint64(buf[8:16], 42)         // cgroup_id
	binary.LittleEndian.PutUint32(buf[16:20], 1001)      // pid
	binary.LittleEndian.PutUint32(buf[20:24], 1001)      // tgid
	binary.LittleEndian.PutUint32(buf[24:28], 1000)      // ppid
	binary.LittleEndian.PutUint32(buf[28:32], 0)         // uid (root)
	binary.LittleEndian.PutUint32(buf[32:36], 0)         // gid
	binary.LittleEndian.PutUint32(buf[36:40], uint32(EventTypeExecve))
	copy(buf[40:56], "bash\x00")

	// Payload union: execve
	copy(buf[56:56+256], "/bin/bash\x00")
	copy(buf[56+256:56+512], "bash -i\x00")

	event, err := ParseRawEvent(buf)
	if err != nil {
		t.Fatalf("unexpected error parsing execve event: %v", err)
	}

	if event.Type != EventTypeExecve {
		t.Errorf("expected EventTypeExecve, got %v", event.Type)
	}
	if event.PID != 1001 {
		t.Errorf("expected PID 1001, got %d", event.PID)
	}
	if event.Comm != "bash" {
		t.Errorf("expected Comm 'bash', got '%s'", event.Comm)
	}
	if event.Exec == nil {
		t.Fatal("expected ExecData to be non-nil")
	}
	if event.Exec.Filename != "/bin/bash" {
		t.Errorf("expected Filename '/bin/bash', got '%s'", event.Exec.Filename)
	}
	if event.Exec.Args != "bash -i" {
		t.Errorf("expected Args 'bash -i', got '%s'", event.Exec.Args)
	}
}

func TestParseRawEvent_Connect(t *testing.T) {
	buf := make([]byte, ExpectedEventSize)

	// Header
	binary.LittleEndian.PutUint32(buf[16:20], 2048)
	binary.LittleEndian.PutUint32(buf[36:40], uint32(EventTypeConnect))
	copy(buf[40:56], "nc\x00")

	// Connect payload:
	// union starts at offset 56
	// sa_family (offset 56..60)
	binary.LittleEndian.PutUint32(buf[56:60], 2) // AF_INET
	// dport (offset 60..62)
	binary.LittleEndian.PutUint16(buf[60:62], 4444)
	// daddr IPv4 (offset 64..68)
	buf[64] = 192
	buf[65] = 168
	buf[66] = 1
	buf[67] = 50
	// fd (offset 80..84)
	binary.LittleEndian.PutUint32(buf[80:84], 3)

	event, err := ParseRawEvent(buf)
	if err != nil {
		t.Fatalf("unexpected error parsing connect event: %v", err)
	}

	if event.Type != EventTypeConnect {
		t.Errorf("expected EventTypeConnect, got %v", event.Type)
	}
	if event.Connect == nil {
		t.Fatal("expected ConnectData to be non-nil")
	}
	if event.Connect.DestPort != 4444 {
		t.Errorf("expected DestPort 4444, got %d", event.Connect.DestPort)
	}
	expectedIP := net.IPv4(192, 168, 1, 50)
	if !event.Connect.DestIP.Equal(expectedIP) {
		t.Errorf("expected DestIP %v, got %v", expectedIP, event.Connect.DestIP)
	}
}

func TestParseRawEvent_Openat(t *testing.T) {
	buf := make([]byte, ExpectedEventSize)

	// Header
	binary.LittleEndian.PutUint32(buf[16:20], 3050)
	binary.LittleEndian.PutUint32(buf[36:40], uint32(EventTypeOpenat))
	copy(buf[40:56], "cat\x00")

	// Openat payload:
	// filename (offset 56..312)
	copy(buf[56:56+256], "/etc/shadow\x00")
	// flags (offset 312..316)
	binary.LittleEndian.PutUint32(buf[312:316], 0) // O_RDONLY
	// dfd (offset 316..320)
	binary.LittleEndian.PutUint32(buf[316:320], 0xffffff9c) // AT_FDCWD (-100)

	event, err := ParseRawEvent(buf)
	if err != nil {
		t.Fatalf("unexpected error parsing openat event: %v", err)
	}

	if event.Type != EventTypeOpenat {
		t.Errorf("expected EventTypeOpenat, got %v", event.Type)
	}
	if event.Openat == nil {
		t.Fatal("expected OpenatData to be non-nil")
	}
	if event.Openat.Filename != "/etc/shadow" {
		t.Errorf("expected Filename '/etc/shadow', got '%s'", event.Openat.Filename)
	}
}

func TestParseRawEvent_Truncated(t *testing.T) {
	shortBuf := make([]byte, 100)
	_, err := ParseRawEvent(shortBuf)
	if err == nil {
		t.Fatal("expected error on truncated buffer, got nil")
	}
}
