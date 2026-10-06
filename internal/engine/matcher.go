package engine

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/luispimentel/kshield/internal/bpf"
)

// Alert represents an anomaly or rule detection triggered by a kernel event.
type Alert struct {
	Timestamp      time.Time   `json:"timestamp"`
	RuleID         string      `json:"rule_id"`
	RuleName       string      `json:"rule_name"`
	Description    string      `json:"description"`
	Severity       Severity    `json:"severity"`
	MitreTechnique string      `json:"mitre_technique,omitempty"`
	Action         string      `json:"action"`
	Reason         string      `json:"reason"`
	Event          *bpf.Event  `json:"event"`
}

// CompiledRule optimizes rule evaluation through pre-compiled lookups and regexes.
type CompiledRule struct {
	Rule               Rule
	argsRegex          *regexp.Regexp
	processNames       map[string]struct{}
	binaryPrefixes     []string
	targetPathPrefixes []string
	targetPorts        map[uint16]struct{}
	excludeUsers       map[string]struct{}
}

// CompileRule constructs a high-performance compiled rule instance.
func CompileRule(r Rule) (*CompiledRule, error) {
	cr := &CompiledRule{
		Rule:               r,
		processNames:       make(map[string]struct{}),
		binaryPrefixes:     r.Conditions.BinaryPaths,
		targetPathPrefixes: r.Conditions.TargetPaths,
		targetPorts:        make(map[uint16]struct{}),
		excludeUsers:       make(map[string]struct{}),
	}

	for _, p := range r.Conditions.ProcessNames {
		cr.processNames[strings.ToLower(p)] = struct{}{}
	}

	for _, port := range r.Conditions.TargetPorts {
		cr.targetPorts[port] = struct{}{}
	}

	for _, u := range r.Conditions.ExcludeUsers {
		cr.excludeUsers[strings.ToLower(u)] = struct{}{}
	}

	if r.Conditions.ArgsPattern != "" {
		re, err := regexp.Compile(r.Conditions.ArgsPattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex '%s' in rule %s: %w", r.Conditions.ArgsPattern, r.ID, err)
		}
		cr.argsRegex = re
	}

	return cr, nil
}

// Matches tests an enriched kernel event against the rule's criteria.
func (cr *CompiledRule) Matches(e *bpf.Event) (bool, string) {
	// 1. Event Type filter
	if cr.Rule.EventType != "" && !strings.EqualFold(cr.Rule.EventType, "any") {
		if !strings.EqualFold(cr.Rule.EventType, e.Type.String()) {
			return false, ""
		}
	}

	// 2. User exclusions
	if e.Enriched != nil && e.Enriched.Username != "" {
		if _, excluded := cr.excludeUsers[strings.ToLower(e.Enriched.Username)]; excluded {
			return false, ""
		}
	}

	// 3. Container only condition
	if cr.Rule.Conditions.ContainerOnly {
		if e.Enriched == nil || !e.Enriched.IsContainer {
			return false, ""
		}
	}

	// 4. Process Name filter
	if len(cr.processNames) > 0 {
		matched := false
		if _, ok := cr.processNames[strings.ToLower(e.Comm)]; ok {
			matched = true
		}
		if !matched && e.Enriched != nil {
			if _, ok := cr.processNames[strings.ToLower(e.Enriched.ParentComm)]; ok {
				matched = true
			}
		}
		if !matched {
			return false, ""
		}
	}

	// 5. Sycall specific evaluations
	switch e.Type {
	case bpf.EventTypeExecve:
		return cr.matchExecve(e)
	case bpf.EventTypeConnect:
		return cr.matchConnect(e)
	case bpf.EventTypeOpenat:
		return cr.matchOpenat(e)
	default:
		return false, ""
	}
}

func (cr *CompiledRule) matchExecve(e *bpf.Event) (bool, string) {
	if e.Exec == nil {
		return false, ""
	}

	// Match Binary Path
	if len(cr.binaryPrefixes) > 0 {
		matched := false
		for _, prefix := range cr.binaryPrefixes {
			if strings.HasPrefix(e.Exec.Filename, prefix) || e.Exec.Filename == prefix {
				matched = true
				break
			}
		}
		if !matched {
			return false, ""
		}
	}

	// Match Args pattern
	if cr.argsRegex != nil {
		cmdline := e.Exec.Args
		if e.Enriched != nil && e.Enriched.FullCmdline != "" {
			cmdline = e.Enriched.FullCmdline
		}
		if !cr.argsRegex.MatchString(cmdline) && !cr.argsRegex.MatchString(e.Exec.Filename) {
			return false, ""
		}
		return true, fmt.Sprintf("Command matches suspicious signature: %s", cmdline)
	}

	if len(cr.binaryPrefixes) > 0 {
		return true, fmt.Sprintf("Execution of watched binary: %s", e.Exec.Filename)
	}

	return false, ""
}

func (cr *CompiledRule) matchConnect(e *bpf.Event) (bool, string) {
	if e.Connect == nil {
		return false, ""
	}

	// Match Destination Port
	if len(cr.targetPorts) > 0 {
		if _, found := cr.targetPorts[e.Connect.DestPort]; found {
			return true, fmt.Sprintf("Outbound connection to watched port %d (%s:%d)",
				e.Connect.DestPort, e.Connect.DestIP.String(), e.Connect.DestPort)
		}
	}

	return false, ""
}

func (cr *CompiledRule) matchOpenat(e *bpf.Event) (bool, string) {
	if e.Openat == nil {
		return false, ""
	}

	// Match Target Path
	if len(cr.targetPathPrefixes) > 0 {
		for _, p := range cr.targetPathPrefixes {
			if strings.HasPrefix(e.Openat.Filename, p) || strings.Contains(e.Openat.Filename, p) {
				return true, fmt.Sprintf("Access to sensitive target file: %s (flags: 0x%x)",
					e.Openat.Filename, e.Openat.Flags)
			}
		}
	}

	return false, ""
}
