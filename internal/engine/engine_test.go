package engine

import (
	"net"
	"testing"
	"time"

	"github.com/luispimentel/kshield/internal/bpf"
)

func sampleRules() []Rule {
	return []Rule{
		{
			ID:             "TEST-001",
			Name:           "Interactive Shell",
			Description:    "Detects interactive shell",
			Severity:       SeverityCritical,
			EventType:      "execve",
			MitreTechnique: "T1059.004",
			Action:         "ALERT",
			Conditions: RuleConditions{
				ArgsPattern: "(\\b(sh|bash)\\s+-i)",
			},
		},
		{
			ID:          "TEST-002",
			Name:        "Sensitive Shadow Access",
			Description: "Detects /etc/shadow read",
			Severity:    SeverityCritical,
			EventType:   "openat",
			Action:      "ALERT",
			Conditions: RuleConditions{
				TargetPaths:  []string{"/etc/shadow"},
				ExcludeUsers: []string{"passwd-service"},
			},
		},
		{
			ID:          "TEST-003",
			Name:        "Backdoor Port Connect",
			Description: "Outbound connect to port 4444",
			Severity:    SeverityHigh,
			EventType:   "connect",
			Action:      "ALERT",
			Conditions: RuleConditions{
				TargetPorts: []uint16{4444, 1337},
			},
		},
	}
}

func TestEngine_ExecveMatch(t *testing.T) {
	eng, err := NewEngine(sampleRules())
	if err != nil {
		t.Fatalf("failed creating engine: %v", err)
	}

	event := &bpf.Event{
		Timestamp: time.Now(),
		PID:       1234,
		Type:      bpf.EventTypeExecve,
		Comm:      "bash",
		Exec: &bpf.ExecData{
			Filename: "/bin/bash",
			Args:     "bash -i",
		},
		Enriched: &bpf.EnrichedMetadata{
			Username: "attacker",
		},
	}

	alerts := eng.Evaluate(event)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].RuleID != "TEST-001" {
		t.Errorf("expected rule TEST-001, got %s", alerts[0].RuleID)
	}
	if alerts[0].Severity != SeverityCritical {
		t.Errorf("expected severity CRITICAL, got %s", alerts[0].Severity)
	}
}

func TestEngine_OpenatMatchAndExclusion(t *testing.T) {
	eng, err := NewEngine(sampleRules())
	if err != nil {
		t.Fatalf("failed creating engine: %v", err)
	}

	// 1. Attacker opens /etc/shadow
	eventAttacker := &bpf.Event{
		Timestamp: time.Now(),
		PID:       2001,
		Type:      bpf.EventTypeOpenat,
		Comm:      "cat",
		Openat: &bpf.OpenatData{
			Filename: "/etc/shadow",
			Flags:    0,
		},
		Enriched: &bpf.EnrichedMetadata{
			Username: "hacker",
		},
	}

	alerts := eng.Evaluate(eventAttacker)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for unauthorized shadow read, got %d", len(alerts))
	}
	if alerts[0].RuleID != "TEST-002" {
		t.Errorf("expected rule TEST-002, got %s", alerts[0].RuleID)
	}

	// 2. Excluded user accesses /etc/shadow
	eventExcluded := &bpf.Event{
		Timestamp: time.Now(),
		PID:       2002,
		Type:      bpf.EventTypeOpenat,
		Comm:      "shadowd",
		Openat: &bpf.OpenatData{
			Filename: "/etc/shadow",
			Flags:    0,
		},
		Enriched: &bpf.EnrichedMetadata{
			Username: "passwd-service",
		},
	}

	alertsExcluded := eng.Evaluate(eventExcluded)
	if len(alertsExcluded) != 0 {
		t.Errorf("expected 0 alerts for excluded user, got %d", len(alertsExcluded))
	}
}

func TestEngine_ConnectMatch(t *testing.T) {
	eng, err := NewEngine(sampleRules())
	if err != nil {
		t.Fatalf("failed creating engine: %v", err)
	}

	event := &bpf.Event{
		Timestamp: time.Now(),
		PID:       5555,
		Type:      bpf.EventTypeConnect,
		Comm:      "revshell",
		Connect: &bpf.ConnectData{
			DestIP:   net.ParseIP("192.168.1.100"),
			DestPort: 4444,
		},
	}

	alerts := eng.Evaluate(event)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for port 4444 connect, got %d", len(alerts))
	}
	if alerts[0].RuleID != "TEST-003" {
		t.Errorf("expected rule TEST-003, got %s", alerts[0].RuleID)
	}
}

func TestSeverity_Weight(t *testing.T) {
	if SeverityCritical.Weight() <= SeverityHigh.Weight() {
		t.Error("Critical should have greater weight than High")
	}
	if SeverityHigh.Weight() <= SeverityMedium.Weight() {
		t.Error("High should have greater weight than Medium")
	}
	if SeverityMedium.Weight() <= SeverityLow.Weight() {
		t.Error("Medium should have greater weight than Low")
	}
}
