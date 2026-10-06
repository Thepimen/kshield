package engine

import (
	"fmt"
	"sync"
	"time"

	"github.com/luispimentel/kshield/internal/bpf"
)

// Engine evaluates security events against compiled detection signatures.
type Engine struct {
	mu    sync.RWMutex
	rules []*CompiledRule
}

// NewEngine compiles and indexes a set of rules.
func NewEngine(rules []Rule) (*Engine, error) {
	compiled := make([]*CompiledRule, 0, len(rules))
	for _, r := range rules {
		cr, err := CompileRule(r)
		if err != nil {
			return nil, fmt.Errorf("failed compiling rule %s: %w", r.ID, err)
		}
		compiled = append(compiled, cr)
	}

	return &Engine{
		rules: compiled,
	}, nil
}

// NewEngineFromConfig initializes an engine directly from RuleConfig.
func NewEngineFromConfig(cfg *RuleConfig) (*Engine, error) {
	if cfg == nil {
		return nil, fmt.Errorf("rule config cannot be nil")
	}
	return NewEngine(cfg.Rules)
}

// Evaluate runs all active signatures against an enriched event.
func (eng *Engine) Evaluate(event *bpf.Event) []*Alert {
	eng.mu.RLock()
	defer eng.mu.RUnlock()

	var alerts []*Alert
	for _, cr := range eng.rules {
		matched, reason := cr.Matches(event)
		if matched {
			alerts = append(alerts, &Alert{
				Timestamp:      time.Now().UTC(),
				RuleID:         cr.Rule.ID,
				RuleName:       cr.Rule.Name,
				Description:    cr.Rule.Description,
				Severity:       cr.Rule.Severity,
				MitreTechnique: cr.Rule.MitreTechnique,
				Action:         cr.Rule.Action,
				Reason:         reason,
				Event:          event,
			})
		}
	}

	return alerts
}

// RuleCount returns the number of active detection rules.
func (eng *Engine) RuleCount() int {
	eng.mu.RLock()
	defer eng.mu.RUnlock()
	return len(eng.rules)
}
