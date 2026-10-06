package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/luispimentel/kshield/internal/bpf"
	"github.com/luispimentel/kshield/internal/engine"
	"github.com/luispimentel/kshield/internal/enricher"
	"github.com/luispimentel/kshield/internal/output"
)

const (
	Version = "0.1.0-alpha"
)

func main() {
	configPath := flag.String("config", "config/rules.yaml", "Path to detection rules YAML file")
	bpfObjPath := flag.String("bpf-obj", "bpf/kshield.bpf.o", "Path to compiled eBPF object (.o)")
	formatFlag := flag.String("format", "table", "Output format: 'table' or 'json'")
	minSevFlag := flag.String("min-severity", "LOW", "Minimum severity to alert on (INFO, LOW, MEDIUM, HIGH, CRITICAL)")
	verboseFlag := flag.Bool("verbose", false, "Stream all raw telemetry events alongside alerts")
	versionFlag := flag.Bool("version", false, "Print kshield version and exit")

	flag.Parse()

	if *versionFlag {
		fmt.Printf("kshield v%s (Linux eBPF Runtime)\n", Version)
		os.Exit(0)
	}

	// 1. Initialize Formatter
	formatter := output.NewFormatter(os.Stdout, output.OutputFormat(*formatFlag), engine.Severity(*minSevFlag))

	// 2. Load Detection Rules
	ruleCfg, err := engine.LoadRulesFromFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error loading rules from %s: %v\n", *configPath, err)
		os.Exit(1)
	}

	detEngine, err := engine.NewEngineFromConfig(ruleCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error compiling rule engine: %v\n", err)
		os.Exit(1)
	}

	// 3. Print Startup Banner
	formatter.PrintBanner(Version, detEngine.RuleCount())

	// 4. Initialize Telemetry Enricher
	eventEnricher := enricher.NewEnricher()

	// 5. Initialize Context with Signal Notification
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// 6. Bootstrap eBPF Kernel Manager
	bpfMgr, err := bpf.NewManager(*bpfObjPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed initializing eBPF subsystem: %v\n", err)
		fmt.Fprintln(os.Stderr, "[*] Verify that the process is running as root (CAP_BPF/CAP_SYS_ADMIN) and kernel BTF is supported.")
		os.Exit(1)
	}
	defer bpfMgr.Close()

	// 7. In-Kernel Filtering: Register kshield's own PID to break telemetry loops
	selfPID := uint32(os.Getpid())
	if err := bpfMgr.IgnorePID(selfPID); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Warning: failed to register agent PID %d in filter map: %v\n", selfPID, err)
	}

	// 8. Attach Tracepoints
	if err := bpfMgr.Attach(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed attaching kernel tracepoints: %v\n", err)
		os.Exit(1)
	}

	// 9. Start Ring Buffer Consumer
	errChan := make(chan error, 1)
	go func() {
		errChan <- bpfMgr.ConsumeEvents(ctx, func(rawEvent *bpf.Event) {
			// Step A: Enrich event with procfs, uid, and cgroup metadata
			eventEnricher.Enrich(rawEvent)

			// Step B: Optional raw telemetry stream
			if *verboseFlag {
				formatter.EmitEvent(rawEvent)
			}

			// Step C: Evaluate against detection signatures
			alerts := detEngine.Evaluate(rawEvent)
			for _, alert := range alerts {
				formatter.EmitAlert(alert)
			}
		})
	}()

	// 10. Wait for shutdown signal or fatal consumer error
	select {
	case <-ctx.Done():
		if *formatFlag != "json" {
			fmt.Println("\n[*] Received shutdown signal. Gracefully unloading eBPF hooks...")
		}
	case err := <-errChan:
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Consumer error: %v\n", err)
		}
	}
}
