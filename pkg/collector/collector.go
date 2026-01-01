package collector

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Collector is the interface for resource collectors.
type Collector interface {
	// Name returns the collector name for logging.
	Name() string

	// Collect gathers resources from the cluster.
	Collect(ctx context.Context, clientset *kubernetes.Clientset) error

	// Results returns the collected data.
	// The concrete type depends on the collector.
	Results() interface{}
}

// Manager coordinates multiple collectors.
type Manager struct {
	clientset  *kubernetes.Clientset
	config     *rest.Config
	collectors []Collector
	options    ManagerOptions
	mu         sync.Mutex
}

// ManagerOptions configures the collector manager.
type ManagerOptions struct {
	// Namespaces to include (empty = all)
	Namespaces []string

	// NamespacesExclude to exclude
	NamespacesExclude []string

	// Parallel determines number of concurrent collectors
	Parallel int

	// Timeout for collection
	Timeout time.Duration
}

// NewManager creates a new collector manager.
func NewManager(config *rest.Config, opts ManagerOptions) (*Manager, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	if opts.Parallel <= 0 {
		opts.Parallel = 5
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Minute
	}

	return &Manager{
		clientset:  clientset,
		config:     config,
		collectors: make([]Collector, 0),
		options:    opts,
	}, nil
}

// RegisterCollector adds a collector to the manager.
func (m *Manager) RegisterCollector(c Collector) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.collectors = append(m.collectors, c)
}

// RegisterDefaultCollectors registers all standard collectors.
func (m *Manager) RegisterDefaultCollectors() {
	m.RegisterCollector(NewNamespaceCollector(m.options.Namespaces, m.options.NamespacesExclude))
	m.RegisterCollector(NewNodeCollector())
	m.RegisterCollector(NewWorkloadCollector(m.options.Namespaces, m.options.NamespacesExclude))
	m.RegisterCollector(NewRBACCollector())
	m.RegisterCollector(NewNetworkPolicyCollector(m.options.Namespaces, m.options.NamespacesExclude))
	m.RegisterCollector(NewServiceAccountCollector(m.options.Namespaces, m.options.NamespacesExclude))
	m.RegisterCollector(NewConfigCollector(m.options.Namespaces, m.options.NamespacesExclude))
	m.RegisterCollector(NewServiceCollector(m.options.Namespaces, m.options.NamespacesExclude))
	m.RegisterCollector(NewIngressCollector(m.options.Namespaces, m.options.NamespacesExclude))
	m.RegisterCollector(NewEventCollector(time.Hour))
	m.RegisterCollector(NewQuotaCollector(m.options.Namespaces, m.options.NamespacesExclude))
	m.RegisterCollector(NewAutoscalingCollector(m.options.Namespaces, m.options.NamespacesExclude))
	m.RegisterCollector(NewStorageCollector(m.options.Namespaces, m.options.NamespacesExclude))
	m.RegisterCollector(NewWebhookCollector())
	m.RegisterCollector(NewClusterResourceCollector())
	m.RegisterCollector(NewCRDCollector())
	m.RegisterCollector(NewEndpointCollector(m.options.Namespaces, m.options.NamespacesExclude))
}

// Collect runs all registered collectors and returns the inventory.
func (m *Manager) Collect(ctx context.Context) (*inventory.ClusterInventory, error) {
	ctx, cancel := context.WithTimeout(ctx, m.options.Timeout)
	defer cancel()

	// Get cluster metadata first
	clusterMeta, err := m.getClusterMetadata(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster metadata: %w", err)
	}

	// Run collectors in parallel with a semaphore
	sem := make(chan struct{}, m.options.Parallel)
	errChan := make(chan error, len(m.collectors))
	var wg sync.WaitGroup

	for _, collector := range m.collectors {
		wg.Add(1)
		go func(c Collector) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if err := c.Collect(ctx, m.clientset); err != nil {
				errChan <- fmt.Errorf("%s collector: %w", c.Name(), err)
			}
		}(collector)
	}

	wg.Wait()
	close(errChan)

	// Check for errors
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		// Log errors but don't fail - partial collection is still useful
		for _, err := range errs {
			fmt.Printf("Warning: %v\n", err)
		}
	}

	// Build the inventory from collector results
	inv := &inventory.ClusterInventory{
		Cluster:     *clusterMeta,
		CollectedAt: time.Now().UTC(),
	}

	for _, c := range m.collectors {
		m.mergeResults(inv, c)
	}

	return inv, nil
}

// getClusterMetadata retrieves cluster version and node count.
func (m *Manager) getClusterMetadata(ctx context.Context) (*inventory.ClusterMetadata, error) {
	// Get server version
	version, err := m.clientset.Discovery().ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to get server version: %w", err)
	}

	// Get node count
	nodes, err := m.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	return &inventory.ClusterMetadata{
		Version:    version.String(),
		NodeCount:  len(nodes.Items),
		APIVersion: version.GitVersion,
		Endpoint:   m.config.Host,
	}, nil
}

// mergeResults merges collector results into the inventory.
func (m *Manager) mergeResults(inv *inventory.ClusterInventory, c Collector) {
	switch c.Name() {
	case "namespace":
		if nc, ok := c.(*NamespaceCollector); ok {
			inv.Namespaces = nc.Results().([]inventory.NamespaceInfo)
		}
	case "node":
		if nc, ok := c.(*NodeCollector); ok {
			inv.Nodes = nc.Results().([]inventory.NodeInfo)
		}
	case "workload":
		if wc, ok := c.(*WorkloadCollector); ok {
			inv.Workloads = wc.Results().(inventory.WorkloadInventory)
		}
	case "rbac":
		if rc, ok := c.(*RBACCollector); ok {
			inv.RBAC = rc.Results().(inventory.RBACInventory)
		}
	case "networkpolicy":
		if npc, ok := c.(*NetworkPolicyCollector); ok {
			inv.NetworkPolicies = npc.Results().([]inventory.NetworkPolicyInfo)
		}
	case "serviceaccount":
		if sac, ok := c.(*ServiceAccountCollector); ok {
			inv.ServiceAccounts = sac.Results().([]inventory.ServiceAccountInfo)
		}
	case "config":
		if cc, ok := c.(*ConfigCollector); ok {
			results := cc.Results().(ConfigResults)
			inv.ConfigMaps = results.ConfigMaps
			inv.Secrets = results.Secrets
		}
	case "service":
		if sc, ok := c.(*ServiceCollector); ok {
			inv.Services = sc.Results().([]inventory.ServiceInfo)
		}
	case "ingress":
		if ic, ok := c.(*IngressCollector); ok {
			inv.Ingresses = ic.Results().([]inventory.IngressInfo)
		}
	case "event":
		if ec, ok := c.(*EventCollector); ok {
			inv.Events = ec.Results().([]inventory.EventInfo)
		}
	case "quota":
		if qc, ok := c.(*QuotaCollector); ok {
			inv.ResourceQuotas = qc.ResourceQuotas()
			inv.LimitRanges = qc.LimitRanges()
		}
	case "autoscaling":
		if ac, ok := c.(*AutoscalingCollector); ok {
			inv.PDBs = ac.PDBs()
			inv.HPAs = ac.HPAs()
		}
	case "storage":
		if sc, ok := c.(*StorageCollector); ok {
			inv.Storage = sc.Results().(inventory.StorageInventory)
		}
	case "webhook":
		if wc, ok := c.(*WebhookCollector); ok {
			inv.Webhooks = wc.Results().(inventory.WebhookInventory)
		}
	case "clusterresource":
		if crc, ok := c.(*ClusterResourceCollector); ok {
			inv.PriorityClasses = crc.PriorityClasses()
		}
	case "crd":
		if cc, ok := c.(*CRDCollector); ok {
			inv.CRDs = cc.Results().([]inventory.CRDInfo)
		}
	case "endpoint":
		if ec, ok := c.(*EndpointCollector); ok {
			inv.Endpoints = ec.Results().([]inventory.EndpointInfo)
		}
	}
}

// shouldIncludeNamespace checks if a namespace should be included.
func shouldIncludeNamespace(ns string, include, exclude []string) bool {
	// Check exclusion list first
	for _, excluded := range exclude {
		if ns == excluded {
			return false
		}
	}

	// If include list is specified, check it
	if len(include) > 0 {
		for _, included := range include {
			if ns == included {
				return true
			}
		}
		return false
	}

	return true
}
