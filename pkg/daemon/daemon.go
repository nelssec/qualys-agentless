package daemon

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/nelssec/qualys-agentless/pkg/auth"
	"github.com/nelssec/qualys-agentless/pkg/collector"
	"github.com/nelssec/qualys-agentless/pkg/compliance"
	"k8s.io/client-go/rest"
)

type Config struct {
	ScanInterval       time.Duration
	ScanOnChange       bool
	ClusterConfigs     map[string]*rest.Config
	Frameworks         []string
	NamespacesInclude  []string
	NamespacesExclude  []string
	ResultsCallback    func(*compliance.ScanResult)
}

type Daemon struct {
	config    Config
	engine    *compliance.Engine
	running   bool
	mu        sync.Mutex
	stopCh    chan struct{}
	clusters  map[string]auth.ClusterInfo
}

func New(cfg Config) (*Daemon, error) {
	if cfg.ScanInterval <= 0 {
		cfg.ScanInterval = 6 * time.Hour
	}

	engine := compliance.NewEngine()
	engine.RegisterDefaultControls()

	return &Daemon{
		config:   cfg,
		engine:   engine,
		stopCh:   make(chan struct{}),
		clusters: make(map[string]auth.ClusterInfo),
	}, nil
}

func (d *Daemon) Start(ctx context.Context) error {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return fmt.Errorf("daemon already running")
	}
	d.running = true
	d.mu.Unlock()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		select {
		case <-sigCh:
			d.Stop()
		case <-ctx.Done():
			d.Stop()
		}
	}()

	ticker := time.NewTicker(d.config.ScanInterval)
	defer ticker.Stop()

	if err := d.runScanCycle(ctx); err != nil {
		fmt.Printf("Initial scan failed: %v\n", err)
	}

	for {
		select {
		case <-d.stopCh:
			return nil
		case <-ticker.C:
			if err := d.runScanCycle(ctx); err != nil {
				fmt.Printf("Scan cycle failed: %v\n", err)
			}
		}
	}
}

func (d *Daemon) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.running {
		close(d.stopCh)
		d.running = false
	}
}

func (d *Daemon) IsRunning() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.running
}

func (d *Daemon) runScanCycle(ctx context.Context) error {
	for clusterName, restConfig := range d.config.ClusterConfigs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		result, err := d.scanCluster(ctx, clusterName, restConfig)
		if err != nil {
			fmt.Printf("Failed to scan cluster %s: %v\n", clusterName, err)
			continue
		}

		if d.config.ResultsCallback != nil {
			d.config.ResultsCallback(result)
		}
	}

	return nil
}

func (d *Daemon) scanCluster(ctx context.Context, name string, restConfig *rest.Config) (*compliance.ScanResult, error) {
	mgr, err := collector.NewManager(restConfig, collector.ManagerOptions{
		Namespaces:        d.config.NamespacesInclude,
		NamespacesExclude: d.config.NamespacesExclude,
		Parallel:          5,
		Timeout:           5 * time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create collector: %w", err)
	}

	mgr.RegisterDefaultCollectors()

	inv, err := mgr.Collect(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to collect inventory: %w", err)
	}

	inv.Cluster.Name = name

	result, err := d.engine.Evaluate(ctx, inv, d.config.Frameworks)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate compliance: %w", err)
	}

	return result, nil
}

type Scheduler struct {
	daemon   *Daemon
	schedule string
}

func NewScheduler(d *Daemon, schedule string) *Scheduler {
	return &Scheduler{
		daemon:   d,
		schedule: schedule,
	}
}
