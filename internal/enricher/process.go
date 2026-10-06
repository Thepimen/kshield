package enricher

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProcessMeta stores metadata discovered from /proc/<pid>.
type ProcessMeta struct {
	PID           uint32
	PPID          uint32
	Comm          string
	Exe           string
	Cmdline       string
	ParentComm    string
	ParentCmdline string
	CachedAt      time.Time
}

// ProcessResolver manages /proc inspections and in-memory process tree cache.
type ProcessResolver struct {
	cache sync.Map // map[uint32]*ProcessMeta
	ttl   time.Duration
}

// NewProcessResolver creates a new process tree resolver.
func NewProcessResolver(ttl time.Duration) *ProcessResolver {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &ProcessResolver{
		ttl: ttl,
	}
}

// Resolve looks up /proc details for the given PID, traversing up to its parent.
func (pr *ProcessResolver) Resolve(pid uint32) *ProcessMeta {
	if pid == 0 {
		return &ProcessMeta{PID: 0, Comm: "swapper/0"}
	}

	if val, ok := pr.cache.Load(pid); ok {
		meta := val.(*ProcessMeta)
		if time.Since(meta.CachedAt) < pr.ttl {
			return meta
		}
	}

	meta := &ProcessMeta{
		PID:      pid,
		CachedAt: time.Now(),
	}

	// 1. Read /proc/<pid>/status
	statusBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err == nil {
		meta.PPID, meta.Comm = ParseProcStatus(string(statusBytes))
	}

	// 2. Read /proc/<pid>/cmdline
	cmdlineBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err == nil {
		meta.Cmdline = formatCmdline(cmdlineBytes)
	}

	// 3. Readlink /proc/<pid>/exe
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err == nil {
		meta.Exe = exePath
	}

	// 4. Resolve Parent information if PPID is valid
	if meta.PPID > 0 {
		parentStatus, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", meta.PPID))
		if err == nil {
			_, meta.ParentComm = ParseProcStatus(string(parentStatus))
		}

		parentCmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", meta.PPID))
		if err == nil {
			meta.ParentCmdline = formatCmdline(parentCmdline)
		}
	}

	pr.cache.Store(pid, meta)
	return meta
}

// ParseProcStatus parses PPid and Name fields from /proc/<pid>/status content.
func ParseProcStatus(content string) (ppid uint32, comm string) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "PPid:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				val, err := strconv.ParseUint(parts[1], 10, 32)
				if err == nil {
					ppid = uint32(val)
				}
			}
		} else if strings.HasPrefix(line, "Name:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				comm = parts[1]
			}
		}
	}
	return ppid, comm
}

// formatCmdline joins null-byte separated arguments into a single string.
func formatCmdline(b []byte) string {
	b = bytes.TrimRight(b, "\x00")
	parts := bytes.Split(b, []byte{0})
	var clean []string
	for _, p := range parts {
		if len(p) > 0 {
			clean = append(clean, string(p))
		}
	}
	return strings.Join(clean, " ")
}
