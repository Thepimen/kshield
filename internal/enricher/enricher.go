package enricher

import (
	"time"

	"github.com/luispimentel/kshield/internal/bpf"
)

// Enricher orchestrates process, user, and container enrichment pipelines.
type Enricher struct {
	processes  *ProcessResolver
	users      *UserResolver
	containers *ContainerResolver
}

// NewEnricher initializes the enrichment engine.
func NewEnricher() *Enricher {
	return &Enricher{
		processes:  NewProcessResolver(30 * time.Second),
		users:      NewUserResolver(),
		containers: NewContainerResolver(),
	}
}

// Enrich decorates a raw bpf.Event with userspace context.
func (e *Enricher) Enrich(event *bpf.Event) {
	if event == nil {
		return
	}

	meta := &bpf.EnrichedMetadata{}

	// 1. Resolve User
	meta.Username = e.users.Resolve(event.UID)

	// 2. Resolve Process details & hierarchy
	procMeta := e.processes.Resolve(event.PID)
	if procMeta != nil {
		if procMeta.PPID > 0 {
			event.PPID = procMeta.PPID
			meta.PPID = procMeta.PPID
		}
		meta.ParentComm = procMeta.ParentComm
		meta.ParentCmdline = procMeta.ParentCmdline
		meta.FullCmdline = procMeta.Cmdline
	}

	// 3. Resolve Container context
	cntMeta := e.containers.Resolve(event.PID)
	if cntMeta != nil && cntMeta.IsContainer {
		meta.IsContainer = true
		meta.ContainerType = cntMeta.Runtime
		meta.ContainerID = cntMeta.ContainerID
	}

	event.Enriched = meta
}
