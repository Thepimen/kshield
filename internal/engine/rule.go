package engine

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Severity indicates the threat level of a security event.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Weight returns a numeric score for comparison and sorting.
func (s Severity) Weight() int {
	switch strings.ToUpper(string(s)) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
}

// RuleConditions specifies the filters that must match for a rule to trigger.
type RuleConditions struct {
	ProcessNames []string `yaml:"process_names,omitempty"`
	BinaryPaths  []string `yaml:"binary_paths,omitempty"`
	ArgsPattern  string   `yaml:"args_pattern,omitempty"`
	TargetPaths  []string `yaml:"target_paths,omitempty"`
	TargetPorts  []uint16 `yaml:"target_ports,omitempty"`
	ExcludeUsers []string `yaml:"exclude_users,omitempty"`
	ContainerOnly bool    `yaml:"container_only,omitempty"`
}

// Rule represents a detection signature.
type Rule struct {
	ID             string         `yaml:"id"`
	Name           string         `yaml:"name"`
	Description    string         `yaml:"description"`
	Severity       Severity       `yaml:"severity"`
	EventType      string         `yaml:"event_type"` // execve, connect, openat, any
	MitreTechnique string         `yaml:"mitre_technique,omitempty"`
	Action         string         `yaml:"action"` // ALERT, LOG
	Conditions     RuleConditions `yaml:"conditions"`
}

// RuleConfig root structure for parsing rules.yaml.
type RuleConfig struct {
	Version string `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

// LoadRulesFromFile reads and deserializes YAML detection signatures.
func LoadRulesFromFile(path string) (*RuleConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules configuration file at %s: %w", path, err)
	}

	var cfg RuleConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal rules YAML: %w", err)
	}

	return &cfg, nil
}
