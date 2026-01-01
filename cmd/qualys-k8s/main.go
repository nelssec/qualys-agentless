package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nelssec/qualys-agentless/pkg/auth"
	"github.com/nelssec/qualys-agentless/pkg/collector"
	"github.com/nelssec/qualys-agentless/pkg/compliance"
	"github.com/nelssec/qualys-agentless/pkg/compliance/policies"
	"github.com/nelssec/qualys-agentless/pkg/config"
	"github.com/nelssec/qualys-agentless/pkg/daemon"
	"github.com/nelssec/qualys-agentless/pkg/output"
	"github.com/spf13/cobra"
	"k8s.io/client-go/rest"
)

var (
	version = "0.1.0"
	commit  = "dev"
)

func main() {
	rootCmd := &cobra.Command{
		Use:     "qualys-k8s",
		Short:   "Agentless Kubernetes Security Scanner",
		Version: fmt.Sprintf("%s (commit: %s)", version, commit),
	}

	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newInventoryCmd())
	rootCmd.AddCommand(newDaemonCmd())
	rootCmd.AddCommand(newFrameworksCmd())
	rootCmd.AddCommand(newControlsCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newScanCmd() *cobra.Command {
	var (
		kubeconfig    string
		provider      string
		region        string
		allClusters   bool
		cluster       string
		subscription  string
		project       string
		qualysURL     string
		outputFormat  string
		outputFile    string
		frameworks    []string
		namespaces    []string
		excludeNS     []string
		configFile    string
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan Kubernetes clusters for security compliance",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(scanOptions{
				kubeconfig:   kubeconfig,
				provider:     provider,
				region:       region,
				allClusters:  allClusters,
				cluster:      cluster,
				subscription: subscription,
				project:      project,
				qualysURL:    qualysURL,
				outputFormat: outputFormat,
				outputFile:   outputFile,
				frameworks:   frameworks,
				namespaces:   namespaces,
				excludeNS:    excludeNS,
				configFile:   configFile,
			})
		},
	}

	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	cmd.Flags().StringVar(&provider, "provider", "", "Cloud provider: aws, azure, gcp")
	cmd.Flags().StringVar(&region, "region", "", "AWS region")
	cmd.Flags().BoolVar(&allClusters, "all-clusters", false, "Scan all clusters")
	cmd.Flags().StringVar(&cluster, "cluster", "", "Cluster name")
	cmd.Flags().StringVar(&subscription, "subscription", "", "Azure subscription ID")
	cmd.Flags().StringVar(&project, "project", "", "GCP project ID")
	cmd.Flags().StringVar(&qualysURL, "qualys-api-url", "", "Qualys API URL")
	cmd.Flags().StringVar(&outputFormat, "output", "console", "Output format: console, json, sarif")
	cmd.Flags().StringVar(&outputFile, "output-file", "", "Output file path")
	cmd.Flags().StringSliceVar(&frameworks, "frameworks", []string{"cis-k8s-1.11"}, "Frameworks to evaluate")
	cmd.Flags().StringSliceVar(&namespaces, "namespaces", nil, "Namespaces to scan")
	cmd.Flags().StringSliceVar(&excludeNS, "exclude-namespaces", []string{"kube-system", "kube-public"}, "Namespaces to exclude")
	cmd.Flags().StringVar(&configFile, "config", "", "Config file path")

	return cmd
}

type scanOptions struct {
	kubeconfig   string
	provider     string
	region       string
	allClusters  bool
	cluster      string
	subscription string
	project      string
	qualysURL    string
	outputFormat string
	outputFile   string
	frameworks   []string
	namespaces   []string
	excludeNS    []string
	configFile   string
}

func runScan(opts scanOptions) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nReceived interrupt, shutting down...")
		cancel()
	}()

	if err := config.ValidateProvider(opts.provider); opts.provider != "" && err != nil {
		return fmt.Errorf("invalid provider: %w", err)
	}

	for _, fw := range opts.frameworks {
		if err := config.ValidateFramework(fw); err != nil {
			return fmt.Errorf("invalid framework %s: %w", fw, err)
		}
	}

	fmt.Println("Starting Kubernetes security scan...")

	var restConfig interface{}
	var clusters []auth.ClusterInfo

	if opts.kubeconfig != "" || opts.provider == "" || opts.provider == "kubeconfig" {
		provider, err := auth.NewKubeconfigProvider(opts.kubeconfig)
		if err != nil {
			return fmt.Errorf("failed to create kubeconfig provider: %w", err)
		}

		if opts.cluster != "" {
			cfg, err := provider.GetRestConfig(ctx, opts.cluster)
			if err != nil {
				return fmt.Errorf("failed to get REST config: %w", err)
			}
			restConfig = cfg
			clusters = append(clusters, auth.ClusterInfo{Name: opts.cluster})
		} else {
			cfg, err := provider.GetRestConfig(ctx, "")
			if err != nil {
				return fmt.Errorf("failed to get REST config: %w", err)
			}
			restConfig = cfg
			clusters = append(clusters, auth.ClusterInfo{Name: provider.CurrentContext()})
		}
	}

	if restConfig == nil {
		return fmt.Errorf("no valid authentication method configured")
	}

	engine := compliance.NewEngine()
	engine.RegisterDefaultControls()

	if err := engine.LoadEmbeddedPolicies(policies.Policies, "."); err != nil {
		fmt.Printf("Warning: failed to load some policies: %v\n", err)
	}

	var allResults []*compliance.ScanResult

	for _, cluster := range clusters {
		fmt.Printf("Scanning cluster: %s\n", cluster.Name)

		cfg := restConfig.(*rest.Config)
		mgr, err := collector.NewManager(cfg, collector.ManagerOptions{
			Namespaces:        opts.namespaces,
			NamespacesExclude: opts.excludeNS,
			Parallel:          5,
			Timeout:           5 * time.Minute,
		})
		if err != nil {
			return fmt.Errorf("failed to create collector manager: %w", err)
		}

		mgr.RegisterDefaultCollectors()

		fmt.Println("  Collecting cluster inventory...")
		inv, err := mgr.Collect(ctx)
		if err != nil {
			return fmt.Errorf("failed to collect inventory: %w", err)
		}

		inv.Cluster.Name = cluster.Name
		fmt.Printf("  Collected: %d namespaces, %d pods, %d deployments\n",
			len(inv.Namespaces),
			len(inv.Workloads.Pods),
			len(inv.Workloads.Deployments))

		fmt.Println("  Evaluating compliance policies...")
		result, err := engine.Evaluate(ctx, inv, opts.frameworks)
		if err != nil {
			return fmt.Errorf("failed to evaluate compliance: %w", err)
		}

		allResults = append(allResults, result)

		fmt.Printf("  Compliance score: %.1f%%\n", result.Summary.ComplianceScore)
		fmt.Printf("  Total checks: %d, Passed: %d, Failed: %d\n",
			result.TotalChecks, result.PassedChecks, result.FailedChecks)
	}

	return outputResults(allResults, opts.outputFormat, opts.outputFile)
}

func outputResults(results []*compliance.ScanResult, format, file string) error {
	var out output.Formatter

	switch format {
	case "json":
		out = output.NewJSONFormatter()
	case "sarif":
		out = output.NewSARIFFormatter()
	default:
		out = output.NewConsoleFormatter()
	}

	data, err := out.Format(results)
	if err != nil {
		return fmt.Errorf("failed to format output: %w", err)
	}

	if file != "" {
		return os.WriteFile(file, data, 0600)
	}

	fmt.Print(string(data))
	return nil
}

func newInventoryCmd() *cobra.Command {
	var (
		kubeconfig   string
		outputFormat string
		outputFile   string
	)

	cmd := &cobra.Command{
		Use:   "inventory",
		Short: "Collect Kubernetes cluster inventory without compliance evaluation",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Collecting cluster inventory...")
			return nil
		},
	}

	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	cmd.Flags().StringVar(&outputFormat, "output", "yaml", "Output format (yaml, json)")
	cmd.Flags().StringVar(&outputFile, "output-file", "", "Output file path")

	return cmd
}

func newDaemonCmd() *cobra.Command {
	var (
		kubeconfig   string
		interval     time.Duration
		frameworks   []string
		excludeNS    []string
	)

	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run in daemon mode for continuous scanning",
	}

	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start the daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			provider, err := auth.NewKubeconfigProvider(kubeconfig)
			if err != nil {
				return fmt.Errorf("failed to create kubeconfig provider: %w", err)
			}

			restConfig, err := provider.GetRestConfig(ctx, "")
			if err != nil {
				return fmt.Errorf("failed to get REST config: %w", err)
			}

			clusterConfigs := map[string]*rest.Config{
				provider.CurrentContext(): restConfig,
			}

			d, err := daemon.New(daemon.Config{
				ScanInterval:      interval,
				ClusterConfigs:    clusterConfigs,
				Frameworks:        frameworks,
				NamespacesExclude: excludeNS,
				ResultsCallback: func(result *compliance.ScanResult) {
					fmt.Printf("[%s] Cluster: %s, Score: %.1f%%, Failed: %d\n",
						result.ScanTime.Format("2006-01-02 15:04:05"),
						result.ClusterName,
						result.Summary.ComplianceScore,
						result.FailedChecks)
				},
			})
			if err != nil {
				return fmt.Errorf("failed to create daemon: %w", err)
			}

			fmt.Printf("Starting daemon mode (interval: %s)...\n", interval)
			return d.Start(ctx)
		},
	}

	startCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	startCmd.Flags().DurationVar(&interval, "interval", 6*time.Hour, "Scan interval")
	startCmd.Flags().StringSliceVar(&frameworks, "frameworks", []string{"cis-k8s-1.11"}, "Frameworks to evaluate")
	startCmd.Flags().StringSliceVar(&excludeNS, "exclude-namespaces", []string{"kube-system", "kube-public"}, "Namespaces to exclude")

	stopCmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop the daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Stopping daemon...")
			return nil
		},
	}

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show daemon status",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Daemon status: not running")
			return nil
		},
	}

	cmd.AddCommand(startCmd, stopCmd, statusCmd)
	return cmd
}

func newFrameworksCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "frameworks",
		Short: "List and manage compliance frameworks",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List available frameworks",
		Run: func(cmd *cobra.Command, args []string) {
			engine := compliance.NewEngine()
			engine.RegisterDefaultControls()
			engine.LoadEmbeddedPolicies(policies.Policies, ".")

			fmt.Println("Available frameworks:")
			fmt.Println()
			fmt.Println("CIS Benchmarks:")
			fmt.Println("  cis-k8s-1.10      CIS Kubernetes Benchmark v1.10.0")
			fmt.Println("  cis-k8s-1.11      CIS Kubernetes Benchmark v1.11.0")
			fmt.Println("  cis-eks-1.6       CIS Amazon EKS Benchmark v1.6.0")
			fmt.Println("  cis-aks-1.6       CIS Azure AKS Benchmark v1.6.0")
			fmt.Println("  cis-ocp-1.7       CIS Red Hat OpenShift Benchmark v1.7.0")
			fmt.Println()
			fmt.Println("Best Practices:")
			fmt.Println("  k8s-best-practices    Kubernetes Best Practices")
			fmt.Println("  eks-best-practices    AWS EKS Best Practices")
			fmt.Println("  aks-best-practices    Azure AKS Best Practices")
			fmt.Println("  ocp-best-practices    Red Hat OpenShift Best Practices")
			fmt.Println()
			fmt.Println("Security Frameworks:")
			fmt.Println("  nsa-cisa              NSA/CISA Kubernetes Hardening Guide")
			fmt.Println("  mitre-attack          MITRE ATT&CK for Kubernetes")
			fmt.Println()
			fmt.Printf("Total: %d frameworks, %d controls, %d policies loaded\n",
				len(engine.ListFrameworks()),
				len(engine.ListControls("")),
				engine.PolicyCount())
		},
	}

	cmd.AddCommand(listCmd)
	return cmd
}

func newControlsCmd() *cobra.Command {
	var framework string

	cmd := &cobra.Command{
		Use:   "controls",
		Short: "List and manage security controls",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List controls for a framework",
		Run: func(cmd *cobra.Command, args []string) {
			engine := compliance.NewEngine()
			engine.RegisterDefaultControls()
			engine.LoadEmbeddedPolicies(policies.Policies, ".")

			controls := engine.ListControls(framework)
			if len(controls) == 0 {
				fmt.Printf("No controls found for framework: %s\n", framework)
				return
			}

			loadedCount := 0
			fmt.Printf("Controls for framework: %s (%d total)\n\n", framework, len(controls))
			for _, ctrl := range controls {
				status := " "
				if engine.HasPolicy(ctrl.ID) {
					status = "*"
					loadedCount++
				}
				fmt.Printf("[%s] %s%s\n", ctrl.Severity, status, ctrl.ID)
				fmt.Printf("    %s\n", ctrl.Name)
			}
			fmt.Printf("\n* = policy loaded (%d/%d)\n", loadedCount, len(controls))
		},
	}

	listCmd.Flags().StringVar(&framework, "framework", "cis-k8s-1.11", "Framework to list controls for")

	cmd.AddCommand(listCmd)
	return cmd
}
