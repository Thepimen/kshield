package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/luispimentel/kshield/internal/bpf"
	"github.com/luispimentel/kshield/internal/engine"
)

// OutputFormat defines console rendering style.
type OutputFormat string

const (
	FormatTable OutputFormat = "table"
	FormatJSON  OutputFormat = "json"
)

// ANSI color codes for terminal rendering.
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[1;31m"
	colorYellow  = "\033[1;33m"
	colorMagenta = "\033[1;35m"
	colorCyan    = "\033[1;36m"
	colorBlue    = "\033[1;34m"
	colorGreen   = "\033[1;32m"
	colorDim     = "\033[2m"
	colorBold    = "\033[1m"
)

// Formatter handles structured logging and display of telemetry events and alerts.
type Formatter struct {
	writer      io.Writer
	format      OutputFormat
	minSeverity engine.Severity
	mu          sync.Mutex
	isTerminal  bool
}

// NewFormatter creates a new event formatter.
func NewFormatter(writer io.Writer, format OutputFormat, minSeverity engine.Severity) *Formatter {
	if writer == nil {
		writer = os.Stdout
	}
	if format == "" {
		format = FormatTable
	}

	return &Formatter{
		writer:      writer,
		format:      format,
		minSeverity: minSeverity,
		isTerminal:  true,
	}
}

// PrintBanner outputs a sleek ASCII status header on startup.
func (f *Formatter) PrintBanner(version string, ruleCount int) {
	if f.format == FormatJSON {
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	banner := fmt.Sprintf(`%s
  ██╗  ██╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ 
  ██║ ██╔╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
  █████╔╝ ███████╗███████║██║█████╗  ██║     ██║  ██║
  ██╔═██╗ ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
  ██║  ██╗███████║██║  ██║██║███████╗███████╗██████╔╝
  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ %s
  eBPF Kernel-Space Observability & Intrusion Detection Sensor
  Version: %s%s%s | Active Rules: %s%d%s | Kernel RingBuf: %sActive%s
`,
		colorCyan, colorReset,
		colorBold, version, colorReset,
		colorGreen, ruleCount, colorReset,
		colorGreen, colorReset)

	fmt.Fprint(f.writer, banner)
	fmt.Fprintf(f.writer, "%s--------------------------------------------------------------------------------------------------------%s\n", colorDim, colorReset)
}

// EmitAlert formats and outputs a detection alert.
func (f *Formatter) EmitAlert(alert *engine.Alert) {
	if alert.Severity.Weight() < f.minSeverity.Weight() {
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if f.format == FormatJSON {
		data, err := json.Marshal(alert)
		if err == nil {
			fmt.Fprintln(f.writer, string(data))
		}
		return
	}

	// Rich Table / Card Format
	timeStr := alert.Timestamp.Format("15:04:05.000")
	sevColor, icon := getSeverityVisuals(alert.Severity)

	userStr := "root"
	containerStr := "host"
	commStr := alert.Event.Comm
	pid := alert.Event.PID

	if alert.Event.Enriched != nil {
		if alert.Event.Enriched.Username != "" {
			userStr = alert.Event.Enriched.Username
		}
		if alert.Event.Enriched.IsContainer {
			containerStr = fmt.Sprintf("[%s:%s]", alert.Event.Enriched.ContainerType, truncate(alert.Event.Enriched.ContainerID, 8))
		}
	}

	fmt.Fprintf(f.writer, "%s %s[%-8s]%s %s %s%-12s%s | PID:%-6d | User:%-8s | %-12s | %s%s%s\n",
		timeStr,
		sevColor, alert.Severity, colorReset,
		icon,
		colorBold, alert.RuleID, colorReset,
		pid,
		userStr,
		containerStr,
		colorBold, alert.RuleName, colorReset,
	)

	fmt.Fprintf(f.writer, "  %s├─ Process:%s %s (Comm: %s, PPID: %d)\n", colorDim, colorReset, commStr, alert.Event.Comm, alert.Event.PPID)
	fmt.Fprintf(f.writer, "  %s├─ Trigger:%s %s\n", colorDim, colorReset, alert.Reason)
	if alert.MitreTechnique != "" {
		fmt.Fprintf(f.writer, "  %s└─ MITRE ATT&CK:%s %s%s%s | Action: %s\n", colorDim, colorReset, colorYellow, alert.MitreTechnique, colorReset, alert.Action)
	} else {
		fmt.Fprintf(f.writer, "  %s└─ Action:%s %s\n", colorDim, colorReset, alert.Action)
	}
	fmt.Fprintf(f.writer, "%s--------------------------------------------------------------------------------------------------------%s\n", colorDim, colorReset)
}

// EmitEvent outputs raw telemetry when debug/verbose mode is enabled.
func (f *Formatter) EmitEvent(event *bpf.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.format == FormatJSON {
		data, err := json.Marshal(event)
		if err == nil {
			fmt.Fprintln(f.writer, string(data))
		}
		return
	}

	timeStr := event.Timestamp.Format("15:04:05.000")
	detail := formatEventDetail(event)
	userStr := "unknown"
	if event.Enriched != nil && event.Enriched.Username != "" {
		userStr = event.Enriched.Username
	}

	fmt.Fprintf(f.writer, "%s%s [EVENT] %-7s%s | PID:%-6d | User:%-8s | %s: %s\n",
		colorDim, timeStr, event.Type.String(), colorReset,
		event.PID, userStr, event.Comm, detail)
}

func getSeverityVisuals(s engine.Severity) (string, string) {
	switch s {
	case engine.SeverityCritical:
		return colorRed, "🚨"
	case engine.SeverityHigh:
		return colorYellow, "⚠️ "
	case engine.SeverityMedium:
		return colorMagenta, "⚡"
	case engine.SeverityLow:
		return colorCyan, "ℹ️ "
	default:
		return colorBlue, "🔍"
	}
}

func formatEventDetail(e *bpf.Event) string {
	switch e.Type {
	case bpf.EventTypeExecve:
		if e.Exec != nil {
			return fmt.Sprintf("exe=%s args=%s", e.Exec.Filename, e.Exec.Args)
		}
	case bpf.EventTypeConnect:
		if e.Connect != nil {
			return fmt.Sprintf("dest=%s:%d fd=%d", e.Connect.DestIP.String(), e.Connect.DestPort, e.Connect.FD)
		}
	case bpf.EventTypeOpenat:
		if e.Openat != nil {
			return fmt.Sprintf("file=%s flags=0x%x dfd=%d", e.Openat.Filename, e.Openat.Flags, e.Openat.DFD)
		}
	}
	return ""
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}
