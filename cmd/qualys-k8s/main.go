package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nelssec/qualys-agentless/pkg/auth"
	"github.com/nelssec/qualys-agentless/pkg/collector"
	"github.com/nelssec/qualys-agentless/pkg/compliance"
	"github.com/nelssec/qualys-agentless/pkg/docker"
	"github.com/nelssec/qualys-agentless/pkg/compliance/policies"
	"github.com/nelssec/qualys-agentless/pkg/config"
	"github.com/nelssec/qualys-agentless/pkg/daemon"
	"github.com/nelssec/qualys-agentless/pkg/graph"
	"github.com/nelssec/qualys-agentless/pkg/graph/analyzers"
	"github.com/nelssec/qualys-agentless/pkg/graph/export"
	"github.com/nelssec/qualys-agentless/pkg/helm"
	"github.com/nelssec/qualys-agentless/pkg/inventory"
	"github.com/nelssec/qualys-agentless/pkg/manifest"
	"github.com/nelssec/qualys-agentless/pkg/netpol"
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
	rootCmd.AddCommand(newScanManifestCmd())
	rootCmd.AddCommand(newScanHelmCmd())
	rootCmd.AddCommand(newInventoryCmd())
	rootCmd.AddCommand(newGraphCmd())
	rootCmd.AddCommand(newDaemonCmd())
	rootCmd.AddCommand(newFrameworksCmd())
	rootCmd.AddCommand(newControlsCmd())
	rootCmd.AddCommand(newDockerCmd())
	rootCmd.AddCommand(newNetpolCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newScanCmd() *cobra.Command {
	var (
		kubeconfig          string
		provider            string
		region              string
		cluster             string
		subscription        string
		project             string
		outputFormat        string
		outputFile          string
		frameworks          []string
		namespaces          []string
		excludeNS           []string
		complianceThreshold float64
		severityThreshold   string
		includeInventory    bool
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan Kubernetes clusters for security compliance",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(scanOptions{
				kubeconfig:          kubeconfig,
				provider:            provider,
				region:              region,
				cluster:             cluster,
				subscription:        subscription,
				project:             project,
				outputFormat:        outputFormat,
				outputFile:          outputFile,
				frameworks:          frameworks,
				namespaces:          namespaces,
				excludeNS:           excludeNS,
				complianceThreshold: complianceThreshold,
				severityThreshold:   severityThreshold,
				includeInventory:    includeInventory,
			})
		},
	}

	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	cmd.Flags().StringVar(&provider, "provider", "", "Cloud provider: aws, azure, gcp")
	cmd.Flags().StringVar(&region, "region", "", "AWS region")
	cmd.Flags().StringVar(&cluster, "cluster", "", "Cluster name")
	cmd.Flags().StringVar(&subscription, "subscription", "", "Azure subscription ID")
	cmd.Flags().StringVar(&project, "project", "", "GCP project ID")
	cmd.Flags().StringVar(&outputFormat, "output", "console", "Output format: console, json, sarif, junit")
	cmd.Flags().StringVar(&outputFile, "output-file", "", "Output file path")
	cmd.Flags().StringSliceVar(&frameworks, "frameworks", []string{"cis-k8s-1.11"}, "Frameworks to evaluate")
	cmd.Flags().StringSliceVar(&namespaces, "namespaces", nil, "Namespaces to scan")
	cmd.Flags().StringSliceVar(&excludeNS, "exclude-namespaces", []string{"kube-system", "kube-public", "qualys"}, "Namespaces to exclude")
	cmd.Flags().Float64Var(&complianceThreshold, "compliance-threshold", 0, "Minimum compliance score (0-100), exit 1 if below")
	cmd.Flags().StringVar(&severityThreshold, "severity-threshold", "", "Fail if findings at or above severity (low, medium, high, critical)")
	cmd.Flags().BoolVar(&includeInventory, "include-inventory", false, "Include full cluster inventory in JSON output")

	return cmd
}

type scanOptions struct {
	kubeconfig          string
	provider            string
	region              string
	cluster             string
	subscription        string
	project             string
	outputFormat        string
	outputFile          string
	frameworks          []string
	namespaces          []string
	excludeNS           []string
	complianceThreshold float64
	severityThreshold   string
	includeInventory    bool
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

	var restConfig *rest.Config
	var clusters []auth.ClusterInfo

	switch opts.provider {
	case "aws":
		if !auth.HasCloudProvider("aws") {
			return fmt.Errorf("AWS provider not available (built without AWS support)")
		}
		if opts.cluster == "" {
			return fmt.Errorf("--cluster is required for AWS provider")
		}
		if opts.region == "" {
			return fmt.Errorf("--region is required for AWS provider")
		}
		provider, err := auth.NewEKSProvider(ctx, auth.EKSProviderOptions{
			Region: opts.region,
		})
		if err != nil {
			return fmt.Errorf("failed to create EKS provider: %w", err)
		}
		cfg, err := provider.GetRestConfig(ctx, opts.cluster)
		if err != nil {
			return fmt.Errorf("failed to get EKS cluster config: %w", err)
		}
		restConfig = cfg
		clusters = append(clusters, auth.ClusterInfo{Name: opts.cluster, Provider: "aws", Region: opts.region})

	case "azure":
		if !auth.HasCloudProvider("azure") {
			return fmt.Errorf("azure provider not available (built without Azure support)")
		}
		if opts.cluster == "" {
			return fmt.Errorf("--cluster is required for Azure provider")
		}
		provider, err := auth.NewAKSProvider(ctx, auth.AKSProviderOptions{
			SubscriptionID: opts.subscription,
		})
		if err != nil {
			return fmt.Errorf("failed to create AKS provider: %w", err)
		}
		cfg, err := provider.GetRestConfig(ctx, opts.cluster)
		if err != nil {
			return fmt.Errorf("failed to get AKS cluster config: %w", err)
		}
		restConfig = cfg
		clusters = append(clusters, auth.ClusterInfo{Name: opts.cluster, Provider: "azure"})

	case "gcp":
		if !auth.HasCloudProvider("gcp") {
			return fmt.Errorf("GCP provider not available (built without GCP support)")
		}
		if opts.cluster == "" {
			return fmt.Errorf("--cluster is required for GCP provider")
		}
		projects := []string{}
		if opts.project != "" {
			projects = []string{opts.project}
		}
		provider, err := auth.NewGKEProvider(ctx, auth.GKEProviderOptions{
			Projects: projects,
		})
		if err != nil {
			return fmt.Errorf("failed to create GKE provider: %w", err)
		}
		cfg, err := provider.GetRestConfig(ctx, opts.cluster)
		if err != nil {
			return fmt.Errorf("failed to get GKE cluster config: %w", err)
		}
		restConfig = cfg
		clusters = append(clusters, auth.ClusterInfo{Name: opts.cluster, Provider: "gcp"})

	case "", "kubeconfig":
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

	default:
		return fmt.Errorf("unknown provider: %s (valid: aws, azure, gcp, kubeconfig)", opts.provider)
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
	var allInventories []*inventory.ClusterInventory

	for _, cluster := range clusters {
		fmt.Printf("Scanning cluster: %s\n", cluster.Name)

		mgr, err := collector.NewManager(restConfig, collector.ManagerOptions{
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
		if opts.includeInventory {
			allInventories = append(allInventories, inv)
		}

		fmt.Printf("  Compliance score: %.1f%%\n", result.Summary.ComplianceScore)
		fmt.Printf("  Total checks: %d, Passed: %d, Failed: %d\n",
			result.TotalChecks, result.PassedChecks, result.FailedChecks)
	}

	if err := outputResults(allResults, allInventories, opts.outputFormat, opts.outputFile, opts.includeInventory); err != nil {
		return err
	}

	return checkThresholds(allResults, opts.complianceThreshold, opts.severityThreshold)
}

func checkThresholds(results []*compliance.ScanResult, complianceThreshold float64, severityThreshold string) error {
	if complianceThreshold > 0 {
		for _, result := range results {
			if result.Summary.ComplianceScore < complianceThreshold {
				return fmt.Errorf("compliance score %.1f%% is below threshold %.1f%%",
					result.Summary.ComplianceScore, complianceThreshold)
			}
		}
	}

	if severityThreshold != "" {
		sevOrder := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
		threshold, ok := sevOrder[strings.ToLower(severityThreshold)]
		if !ok {
			return fmt.Errorf("invalid severity threshold: %s (use low, medium, high, critical)", severityThreshold)
		}

		for _, result := range results {
			for _, finding := range result.Findings {
				if finding.Status != compliance.StatusFail {
					continue
				}
				findingSev := sevOrder[strings.ToLower(string(finding.Severity))]
				if findingSev >= threshold {
					return fmt.Errorf("found %s severity finding: %s",
						finding.Severity, finding.ControlID)
				}
			}
		}
	}

	return nil
}

type FullScanOutput struct {
	Results   []*compliance.ScanResult       `json:"results"`
	Inventory []*inventory.ClusterInventory  `json:"inventory,omitempty"`
}

func outputResults(results []*compliance.ScanResult, inventories []*inventory.ClusterInventory, format, file string, includeInventory bool) error {
	var data []byte
	var err error

	switch format {
	case "json":
		if includeInventory && len(inventories) > 0 {
			fullOutput := FullScanOutput{
				Results:   results,
				Inventory: inventories,
			}
			data, err = json.MarshalIndent(fullOutput, "", "  ")
		} else {
			data, err = json.MarshalIndent(results, "", "  ")
		}
	case "sarif":
		out := output.NewSARIFFormatter()
		data, err = out.Format(results)
	case "junit":
		out := output.NewJUnitFormatter()
		data, err = out.Format(results)
	default:
		out := output.NewConsoleFormatter()
		data, err = out.Format(results)
	}

	if err != nil {
		return fmt.Errorf("failed to format output: %w", err)
	}

	if file != "" {
		return os.WriteFile(file, data, 0600)
	}

	fmt.Print(string(data))
	return nil
}

func newScanManifestCmd() *cobra.Command {
	var (
		outputFormat string
		outputFile   string
		frameworks   []string
	)

	cmd := &cobra.Command{
		Use:   "scan-manifest [file or directory]",
		Short: "Scan YAML manifests for security issues",
		Long:  "Scan Kubernetes YAML manifests before deployment (shift-left security)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			parser := manifest.NewParser()

			var inv *inventory.ClusterInventory
			var err error

			path := args[0]
			info, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("cannot access %s: %w", path, err)
			}

			if info.IsDir() {
				inv, err = parser.ParseDirectory(path)
			} else {
				inv, err = parser.ParseFile(path)
			}
			if err != nil {
				return fmt.Errorf("failed to parse manifests: %w", err)
			}

			engine := compliance.NewEngine()
			engine.RegisterDefaultControls()

			if err := engine.LoadEmbeddedPolicies(policies.Policies, "."); err != nil {
				fmt.Printf("Warning: failed to load some policies: %v\n", err)
			}

			if len(frameworks) == 0 {
				frameworks = []string{"cis-k8s-1.11"}
			}

			result, err := engine.Evaluate(context.Background(), inv, frameworks)
			if err != nil {
				return fmt.Errorf("failed to evaluate policies: %w", err)
			}

			result.ClusterName = path

			results := []*compliance.ScanResult{result}
			return outputResults(results, nil, outputFormat, outputFile, false)
		},
	}

	cmd.Flags().StringVar(&outputFormat, "output", "console", "Output format: console, json, sarif, junit")
	cmd.Flags().StringVar(&outputFile, "output-file", "", "Output file path")
	cmd.Flags().StringSliceVar(&frameworks, "frameworks", []string{"cis-k8s-1.11"}, "Frameworks to evaluate")

	return cmd
}

func newScanHelmCmd() *cobra.Command {
	var (
		outputFormat string
		outputFile   string
		frameworks   []string
		valueFiles   []string
		setValues    []string
		releaseName  string
		namespace    string
	)

	cmd := &cobra.Command{
		Use:   "scan-helm [chart]",
		Short: "Scan Helm charts for security issues",
		Long:  "Scan Helm charts before deployment (shift-left security). Supports local charts, .tgz archives, and OCI registries.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			chartPath := args[0]

			renderer := helm.NewRenderer()
			opts := helm.RenderOptions{
				ReleaseName: releaseName,
				Namespace:   namespace,
				ValueFiles:  valueFiles,
				Values:      setValues,
			}

			fmt.Printf("Rendering Helm chart: %s\n", chartPath)

			inv, err := renderer.RenderChart(chartPath, opts)
			if err != nil {
				return fmt.Errorf("failed to render chart: %w", err)
			}

			fmt.Printf("Parsed: %d pods, %d deployments, %d roles\n",
				len(inv.Workloads.Pods),
				len(inv.Workloads.Deployments),
				len(inv.RBAC.Roles)+len(inv.RBAC.ClusterRoles))

			engine := compliance.NewEngine()
			engine.RegisterDefaultControls()

			if err := engine.LoadEmbeddedPolicies(policies.Policies, "."); err != nil {
				fmt.Printf("Warning: failed to load some policies: %v\n", err)
			}

			if len(frameworks) == 0 {
				frameworks = []string{"cis-k8s-1.11"}
			}

			result, err := engine.Evaluate(context.Background(), inv, frameworks)
			if err != nil {
				return fmt.Errorf("failed to evaluate policies: %w", err)
			}

			result.ClusterName = chartPath

			results := []*compliance.ScanResult{result}
			return outputResults(results, nil, outputFormat, outputFile, false)
		},
	}

	cmd.Flags().StringVar(&outputFormat, "output", "console", "Output format: console, json, sarif, junit")
	cmd.Flags().StringVar(&outputFile, "output-file", "", "Output file path")
	cmd.Flags().StringSliceVar(&frameworks, "frameworks", []string{"cis-k8s-1.11"}, "Frameworks to evaluate")
	cmd.Flags().StringSliceVarP(&valueFiles, "values", "f", nil, "Values files to use (can specify multiple)")
	cmd.Flags().StringSliceVar(&setValues, "set", nil, "Set values on the command line (key=value)")
	cmd.Flags().StringVar(&releaseName, "release-name", "release", "Release name for rendering")
	cmd.Flags().StringVarP(&namespace, "namespace", "n", "default", "Namespace for rendering")

	return cmd
}

func newInventoryCmd() *cobra.Command {
	var (
		kubeconfig   string
		provider     string
		region       string
		cluster      string
		subscription string
		project      string
		outputFormat string
		outputFile   string
		namespaces   []string
		excludeNS    []string
	)

	cmd := &cobra.Command{
		Use:   "inventory",
		Short: "Collect Kubernetes cluster inventory without compliance evaluation",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigChan
				fmt.Println("\nReceived interrupt, shutting down...")
				cancel()
			}()

			var restConfig *rest.Config
			var clusterName string

			switch provider {
			case "aws":
				if !auth.HasCloudProvider("aws") {
					return fmt.Errorf("AWS provider not available (built without AWS support)")
				}
				if cluster == "" {
					return fmt.Errorf("--cluster is required for AWS provider")
				}
				if region == "" {
					return fmt.Errorf("--region is required for AWS provider")
				}
				p, err := auth.NewEKSProvider(ctx, auth.EKSProviderOptions{Region: region})
				if err != nil {
					return fmt.Errorf("failed to create EKS provider: %w", err)
				}
				cfg, err := p.GetRestConfig(ctx, cluster)
				if err != nil {
					return fmt.Errorf("failed to get EKS cluster config: %w", err)
				}
				restConfig = cfg
				clusterName = cluster

			case "azure":
				if !auth.HasCloudProvider("azure") {
					return fmt.Errorf("azure provider not available (built without Azure support)")
				}
				if cluster == "" {
					return fmt.Errorf("--cluster is required for Azure provider")
				}
				p, err := auth.NewAKSProvider(ctx, auth.AKSProviderOptions{SubscriptionID: subscription})
				if err != nil {
					return fmt.Errorf("failed to create AKS provider: %w", err)
				}
				cfg, err := p.GetRestConfig(ctx, cluster)
				if err != nil {
					return fmt.Errorf("failed to get AKS cluster config: %w", err)
				}
				restConfig = cfg
				clusterName = cluster

			case "gcp":
				if !auth.HasCloudProvider("gcp") {
					return fmt.Errorf("GCP provider not available (built without GCP support)")
				}
				if cluster == "" {
					return fmt.Errorf("--cluster is required for GCP provider")
				}
				projects := []string{}
				if project != "" {
					projects = []string{project}
				}
				p, err := auth.NewGKEProvider(ctx, auth.GKEProviderOptions{Projects: projects})
				if err != nil {
					return fmt.Errorf("failed to create GKE provider: %w", err)
				}
				cfg, err := p.GetRestConfig(ctx, cluster)
				if err != nil {
					return fmt.Errorf("failed to get GKE cluster config: %w", err)
				}
				restConfig = cfg
				clusterName = cluster

			case "", "kubeconfig":
				p, err := auth.NewKubeconfigProvider(kubeconfig)
				if err != nil {
					return fmt.Errorf("failed to create kubeconfig provider: %w", err)
				}
				if cluster != "" {
					cfg, err := p.GetRestConfig(ctx, cluster)
					if err != nil {
						return fmt.Errorf("failed to get REST config: %w", err)
					}
					restConfig = cfg
					clusterName = cluster
				} else {
					cfg, err := p.GetRestConfig(ctx, "")
					if err != nil {
						return fmt.Errorf("failed to get REST config: %w", err)
					}
					restConfig = cfg
					clusterName = p.CurrentContext()
				}

			default:
				return fmt.Errorf("unknown provider: %s (valid: aws, azure, gcp, kubeconfig)", provider)
			}

			fmt.Printf("Collecting inventory from: %s\n", clusterName)

			mgr, err := collector.NewManager(restConfig, collector.ManagerOptions{
				Namespaces:        namespaces,
				NamespacesExclude: excludeNS,
				Parallel:          5,
				Timeout:           5 * time.Minute,
			})
			if err != nil {
				return fmt.Errorf("failed to create collector manager: %w", err)
			}

			mgr.RegisterDefaultCollectors()

			inv, err := mgr.Collect(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect inventory: %w", err)
			}

			inv.Cluster.Name = clusterName

			fmt.Printf("Collected: %d namespaces, %d nodes, %d pods, %d deployments, %d services\n",
				len(inv.Namespaces),
				len(inv.Nodes),
				len(inv.Workloads.Pods),
				len(inv.Workloads.Deployments),
				len(inv.Services))

			var data []byte
			switch outputFormat {
			case "json":
				data, err = json.MarshalIndent(inv, "", "  ")
			case "yaml":
				data, err = marshalYAML(inv)
			default:
				return fmt.Errorf("unknown output format: %s (valid: json, yaml)", outputFormat)
			}
			if err != nil {
				return fmt.Errorf("failed to format output: %w", err)
			}

			if outputFile != "" {
				if err := os.WriteFile(outputFile, data, 0600); err != nil {
					return fmt.Errorf("failed to write output file: %w", err)
				}
				fmt.Printf("Inventory written to: %s\n", outputFile)
			} else {
				fmt.Print(string(data))
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	cmd.Flags().StringVar(&provider, "provider", "", "Cloud provider: aws, azure, gcp")
	cmd.Flags().StringVar(&region, "region", "", "AWS region")
	cmd.Flags().StringVar(&cluster, "cluster", "", "Cluster name")
	cmd.Flags().StringVar(&subscription, "subscription", "", "Azure subscription ID")
	cmd.Flags().StringVar(&project, "project", "", "GCP project ID")
	cmd.Flags().StringVar(&outputFormat, "output", "json", "Output format (json, yaml)")
	cmd.Flags().StringVar(&outputFile, "output-file", "", "Output file path")
	cmd.Flags().StringSliceVar(&namespaces, "namespaces", nil, "Namespaces to collect")
	cmd.Flags().StringSliceVar(&excludeNS, "exclude-namespaces", []string{"kube-system", "kube-public", "qualys"}, "Namespaces to exclude")

	return cmd
}

func marshalYAML(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
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
			_ = engine.LoadEmbeddedPolicies(policies.Policies, ".")

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
			_ = engine.LoadEmbeddedPolicies(policies.Policies, ".")

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

func newGraphCmd() *cobra.Command {
	var (
		kubeconfig     string
		provider       string
		region         string
		cluster        string
		subscription   string
		project        string
		outputFormat   string
		outputFile     string
		namespaces     []string
		excludeNS      []string
		graphType      string
		includeAnalysis bool
	)

	cmd := &cobra.Command{
		Use:   "graph",
		Short: "Generate security relationship graphs and attack path analysis",
		Long:  "Build a graph of security relationships between Kubernetes resources and analyze attack paths, container escapes, and external exposure",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigChan
				fmt.Println("\nReceived interrupt, shutting down...")
				cancel()
			}()

			var restConfig *rest.Config
			var clusterName string

			switch provider {
			case "aws":
				if !auth.HasCloudProvider("aws") {
					return fmt.Errorf("AWS provider not available")
				}
				if cluster == "" || region == "" {
					return fmt.Errorf("--cluster and --region required for AWS")
				}
				p, err := auth.NewEKSProvider(ctx, auth.EKSProviderOptions{Region: region})
				if err != nil {
					return err
				}
				restConfig, err = p.GetRestConfig(ctx, cluster)
				if err != nil {
					return err
				}
				clusterName = cluster

			case "azure":
				if !auth.HasCloudProvider("azure") {
					return fmt.Errorf("azure provider not available")
				}
				if cluster == "" {
					return fmt.Errorf("--cluster required for Azure")
				}
				p, err := auth.NewAKSProvider(ctx, auth.AKSProviderOptions{SubscriptionID: subscription})
				if err != nil {
					return err
				}
				restConfig, err = p.GetRestConfig(ctx, cluster)
				if err != nil {
					return err
				}
				clusterName = cluster

			case "gcp":
				if !auth.HasCloudProvider("gcp") {
					return fmt.Errorf("GCP provider not available")
				}
				if cluster == "" {
					return fmt.Errorf("--cluster required for GCP")
				}
				projects := []string{}
				if project != "" {
					projects = []string{project}
				}
				p, err := auth.NewGKEProvider(ctx, auth.GKEProviderOptions{Projects: projects})
				if err != nil {
					return err
				}
				restConfig, err = p.GetRestConfig(ctx, cluster)
				if err != nil {
					return err
				}
				clusterName = cluster

			default:
				p, err := auth.NewKubeconfigProvider(kubeconfig)
				if err != nil {
					return err
				}
				if cluster != "" {
					restConfig, err = p.GetRestConfig(ctx, cluster)
					clusterName = cluster
				} else {
					restConfig, err = p.GetRestConfig(ctx, "")
					clusterName = p.CurrentContext()
				}
				if err != nil {
					return err
				}
			}

			fmt.Printf("Building security graph for: %s\n", clusterName)

			mgr, err := collector.NewManager(restConfig, collector.ManagerOptions{
				Namespaces:        namespaces,
				NamespacesExclude: excludeNS,
				Parallel:          5,
				Timeout:           5 * time.Minute,
			})
			if err != nil {
				return err
			}

			mgr.RegisterDefaultCollectors()

			fmt.Println("  Collecting cluster inventory...")
			inv, err := mgr.Collect(ctx)
			if err != nil {
				return err
			}
			inv.Cluster.Name = clusterName

			fmt.Printf("  Collected: %d pods, %d services, %d roles\n",
				len(inv.Workloads.Pods), len(inv.Services),
				len(inv.RBAC.Roles)+len(inv.RBAC.ClusterRoles))

			fmt.Println("  Building security graph...")
			builder := graph.NewBuilder(inv)
			g := builder.Build()

			fmt.Printf("  Graph: %d nodes, %d edges\n", len(g.Nodes), len(g.Edges))

			var analysisOutput *GraphAnalysisOutput
			if includeAnalysis {
				fmt.Println("  Running security analyzers...")
				analysisOutput = runGraphAnalyzers(g, inv)
				fmt.Printf("  Found: %d escalation paths, %d escape vectors, %d exposures\n",
					len(analysisOutput.EscalationPaths),
					len(analysisOutput.ContainerEscapes),
					len(analysisOutput.Exposures))
			}

			return outputGraph(g, analysisOutput, clusterName, graphType, outputFormat, outputFile)
		},
	}

	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	cmd.Flags().StringVar(&provider, "provider", "", "Cloud provider: aws, azure, gcp")
	cmd.Flags().StringVar(&region, "region", "", "AWS region")
	cmd.Flags().StringVar(&cluster, "cluster", "", "Cluster name")
	cmd.Flags().StringVar(&subscription, "subscription", "", "Azure subscription ID")
	cmd.Flags().StringVar(&project, "project", "", "GCP project ID")
	cmd.Flags().StringVar(&outputFormat, "format", "topology,json", "Output format(s): topology, html, json, dot, mermaid (comma-separated)")
	cmd.Flags().StringVar(&outputFile, "output", "", "Output directory or file path (default: ./qualys-k8s-{cluster}.*)")
	cmd.Flags().StringSliceVar(&namespaces, "namespaces", nil, "Namespaces to include")
	cmd.Flags().StringSliceVar(&excludeNS, "exclude-namespaces", []string{"kube-system", "kube-public", "qualys"}, "Namespaces to exclude")
	cmd.Flags().StringVar(&graphType, "type", "full", "Graph type: full, attack-paths, exposure")
	cmd.Flags().BoolVar(&includeAnalysis, "analyze", true, "Include security analysis")

	return cmd
}

type GraphAnalysisOutput struct {
	EscalationPaths   []analyzers.EscalationPath       `json:"escalationPaths,omitempty"`
	ContainerEscapes  []analyzers.ContainerEscapeVector `json:"containerEscapes,omitempty"`
	Exposures         []analyzers.ExternalExposure      `json:"externalExposures,omitempty"`
	CloudMetadataRisks []analyzers.CloudMetadataRisk    `json:"cloudMetadataRisks,omitempty"`
}

func runGraphAnalyzers(g *graph.SecurityGraph, inv *inventory.ClusterInventory) *GraphAnalysisOutput {
	output := &GraphAnalysisOutput{}

	escAnalyzer := analyzers.NewEscalationAnalyzer(g)
	output.EscalationPaths = escAnalyzer.Analyze()

	escapeAnalyzer := analyzers.NewEscapeAnalyzer(g, inv)
	output.ContainerEscapes = escapeAnalyzer.Analyze()

	expAnalyzer := analyzers.NewExposureAnalyzer(g, inv)
	output.Exposures = expAnalyzer.Analyze()

	cloudAnalyzer := analyzers.NewCloudMetadataAnalyzer(g, inv)
	output.CloudMetadataRisks = cloudAnalyzer.Analyze()

	return output
}

type FullGraphOutput struct {
	Graph    *graph.SecurityGraph `json:"graph"`
	Analysis *GraphAnalysisOutput `json:"analysis,omitempty"`
}

func outputGraph(g *graph.SecurityGraph, analysis *GraphAnalysisOutput, clusterName, graphType, formats, outputPath string) error {
	formatList := strings.Split(formats, ",")
	for i := range formatList {
		formatList[i] = strings.TrimSpace(formatList[i])
	}

	safeClusterName := strings.ReplaceAll(clusterName, "/", "-")
	safeClusterName = strings.ReplaceAll(safeClusterName, ":", "-")
	safeClusterName = strings.ReplaceAll(safeClusterName, " ", "-")

	outputDir := "."
	if outputPath != "" {
		info, err := os.Stat(outputPath)
		if err == nil && info.IsDir() {
			outputDir = outputPath
		} else if len(formatList) == 1 {
			return outputSingleFormat(g, analysis, graphType, formatList[0], outputPath)
		} else {
			outputDir = outputPath
			_ = os.MkdirAll(outputDir, 0750)
		}
	}

	var htmlFile string
	for _, format := range formatList {
		ext := format
		if format == "topology" {
			ext = "html"
		}
		filename := fmt.Sprintf("qualys-k8s-%s.%s", safeClusterName, ext)
		filepath := fmt.Sprintf("%s/%s", outputDir, filename)

		if err := outputSingleFormat(g, analysis, graphType, format, filepath); err != nil {
			return err
		}

		if format == "topology" || format == "html" {
			htmlFile = filepath
		}
	}

	if htmlFile != "" {
		absPath, _ := os.Getwd()
		if !strings.HasPrefix(htmlFile, "/") {
			htmlFile = absPath + "/" + htmlFile
		}
		fmt.Printf("Open in browser: file://%s\n", htmlFile)
	}

	return nil
}

func outputSingleFormat(g *graph.SecurityGraph, analysis *GraphAnalysisOutput, graphType, format, file string) error {
	var data []byte
	var err error

	switch format {
	case "json":
		fullOutput := FullGraphOutput{Graph: g, Analysis: analysis}
		data, err = json.MarshalIndent(fullOutput, "", "  ")

	case "dot":
		exporter := export.NewDOTExporter(g)
		switch graphType {
		case "attack-paths":
			data = []byte(exporter.ExportAttackPaths())
		default:
			data = []byte(exporter.Export())
		}

	case "mermaid":
		exporter := export.NewMermaidExporter(g)
		switch graphType {
		case "attack-paths":
			data = []byte(exporter.ExportAttackPaths())
		case "exposure":
			data = []byte(exporter.ExportExposureFlow())
		default:
			data = []byte(exporter.Export())
		}

	case "html":
		exporter := export.NewD3Exporter(g)
		data = []byte(exporter.ExportHTML())

	case "topology":
		exporter := export.NewTopologyExporter(g)
		remLookup := compliance.GetDefaultRemediationLookup()
		remInfo := make(map[string]*export.RemediationInfo)
		for pattern, ctrl := range remLookup {
			remInfo[pattern] = &export.RemediationInfo{
				ID:          ctrl.ID,
				Name:        ctrl.Name,
				Severity:    ctrl.Severity,
				Section:     ctrl.Section,
				Remediation: ctrl.Remediation,
				Framework:   ctrl.Framework,
			}
		}
		exporter.SetRemediation(remInfo)
		data = []byte(exporter.ExportHTML())

	default:
		return fmt.Errorf("unknown format: %s", format)
	}

	if err != nil {
		return err
	}

	if err := os.WriteFile(file, data, 0600); err != nil {
		return err
	}
	fmt.Printf("  Written: %s\n", file)

	return nil
}

func newDockerCmd() *cobra.Command {
	var (
		host          string
		outputFormat  string
		outputFile    string
		inventoryOnly bool
		graphOutput   bool
	)

	cmd := &cobra.Command{
		Use:   "docker",
		Short: "Scan Docker/Podman containers for security issues",
		Long:  "Connect to Docker or Podman daemon and scan containers, images, networks, and volumes for security misconfigurations based on CIS Docker Benchmark",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigChan
				fmt.Println("\nReceived interrupt, shutting down...")
				cancel()
			}()

			var opts []docker.ClientOption
			if host != "" {
				opts = append(opts, docker.WithHost(host))
			}

			scanner, err := docker.NewScanner(opts...)
			if err != nil {
				return fmt.Errorf("failed to connect to Docker: %w", err)
			}

			fmt.Println("Scanning Docker/Podman environment...")

			result, err := scanner.Scan(ctx)
			if err != nil {
				return err
			}

			fmt.Printf("  Host: %s (%s %s)\n", result.Inventory.Host.Hostname, result.Inventory.Host.Runtime, result.Inventory.Host.RuntimeVersion)
			fmt.Printf("  Containers: %d running, %d total\n", result.Summary.RunningContainers, result.Summary.TotalContainers)
			fmt.Printf("  Images: %d\n", result.Summary.TotalImages)
			fmt.Printf("  Findings: %d\n", result.Summary.TotalFindings)

			if inventoryOnly {
				return outputDockerResult(result.Inventory, outputFormat, outputFile, false, nil)
			}

			if graphOutput || strings.Contains(outputFormat, "topology") || strings.Contains(outputFormat, "graph") {
				fmt.Println("  Building attack path graph...")
				graphBuilder := docker.NewGraphBuilder(result.Inventory)
				g := graphBuilder.Build()
				fmt.Printf("  Graph: %d nodes, %d edges, %d escape vectors\n",
					len(g.Nodes), len(g.Edges), g.Summary.ContainerEscapes)

				return outputDockerResult(result, outputFormat, outputFile, true, g)
			}

			return outputDockerResult(result, outputFormat, outputFile, false, nil)
		},
	}

	cmd.Flags().StringVar(&host, "host", "", "Docker/Podman socket (default: auto-detect)")
	cmd.Flags().StringVar(&outputFormat, "output", "console", "Output format: console, json, topology, graph")
	cmd.Flags().StringVar(&outputFile, "output-file", "", "Output file path")
	cmd.Flags().BoolVar(&inventoryOnly, "inventory-only", false, "Only collect inventory, skip security checks")
	cmd.Flags().BoolVar(&graphOutput, "graph", false, "Generate attack path visualization")

	return cmd
}

func outputDockerResult(result interface{}, format, file string, hasGraph bool, g *graph.SecurityGraph) error {
	formatList := strings.Split(format, ",")
	for i := range formatList {
		formatList[i] = strings.TrimSpace(formatList[i])
	}

	scanResult, isScanResult := result.(*docker.ScanResult)
	hostName := "docker-host"
	if isScanResult && scanResult.Inventory != nil {
		hostName = scanResult.Inventory.Host.Hostname
	}

	safeHostName := strings.ReplaceAll(hostName, "/", "-")
	safeHostName = strings.ReplaceAll(safeHostName, ":", "-")

	for _, fmt := range formatList {
		switch fmt {
		case "json":
			var data []byte
			var err error
			if hasGraph && g != nil {
				fullOutput := struct {
					Scan  interface{}          `json:"scan"`
					Graph *graph.SecurityGraph `json:"graph"`
				}{Scan: result, Graph: g}
				data, err = json.MarshalIndent(fullOutput, "", "  ")
			} else {
				data, err = json.MarshalIndent(result, "", "  ")
			}
			if err != nil {
				return err
			}
			outFile := file
			if outFile == "" && len(formatList) > 1 {
				outFile = "qualys-docker-" + safeHostName + ".json"
			}
			if outFile != "" {
				if err := os.WriteFile(outFile, data, 0600); err != nil {
					return err
				}
				printfSafe("  Written: %s\n", outFile)
			} else {
				printfSafe("%s\n", string(data))
			}

		case "topology", "graph":
			if g == nil {
				return fmtErrorf("graph not available for topology output")
			}
			exporter := export.NewTopologyExporter(g)
			remLookup := compliance.GetDefaultRemediationLookup()
			remInfo := make(map[string]*export.RemediationInfo)
			for pattern, ctrl := range remLookup {
				remInfo[pattern] = &export.RemediationInfo{
					ID:          ctrl.ID,
					Name:        ctrl.Name,
					Severity:    ctrl.Severity,
					Section:     ctrl.Section,
					Remediation: ctrl.Remediation,
					Framework:   ctrl.Framework,
				}
			}
			exporter.SetRemediation(remInfo)
			data := []byte(exporter.ExportHTML())
			outFile := file
			if outFile == "" {
				outFile = "qualys-docker-" + safeHostName + ".html"
			}
			if err := os.WriteFile(outFile, data, 0600); err != nil {
				return err
			}
			printfSafe("  Written: %s\n", outFile)
			absPath, _ := os.Getwd()
			if !strings.HasPrefix(outFile, "/") {
				outFile = absPath + "/" + outFile
			}
			printfSafe("Open in browser: file://%s\n", outFile)

		case "console":
			if !isScanResult {
				data, _ := json.MarshalIndent(result, "", "  ")
				printfSafe("%s\n", string(data))
				return nil
			}

			if len(scanResult.Findings) == 0 {
				printfSafe("\nNo security issues found.\n")
				return nil
			}

			printfSafe("\nFindings by Severity:\n")
			for sev, count := range scanResult.Summary.BySeverity {
				printfSafe("  %s: %d\n", sev, count)
			}

			if hasGraph && g != nil {
				printfSafe("\nAttack Surface:\n")
				printfSafe("  External exposures: %d\n", g.Summary.ExternalExposures)
				printfSafe("  Container escapes: %d\n", g.Summary.ContainerEscapes)
				printfSafe("  Data exfiltration risks: %d\n", g.Summary.DataExfiltrationRisks)
			}

			printfSafe("\nFindings:\n")
			for _, f := range scanResult.Findings {
				printfSafe("\n[%s] %s - %s\n", f.Severity, f.ID, f.Name)
				printfSafe("   Resource: %s (%s)\n", f.Resource, f.ResourceID)
				printfSafe("   %s\n", f.Message)
				printfSafe("   Fix: %s\n", f.Remediation)
			}

		default:
			return fmtErrorf("unknown output format: %s", fmt)
		}
	}

	return nil
}

func printfSafe(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

func fmtErrorf(format string, args ...interface{}) error {
	return fmt.Errorf(format, args...)
}

func newNetpolCmd() *cobra.Command {
	var (
		kubeconfig   string
		provider     string
		region       string
		cluster      string
		subscription string
		project      string
		outputFormat string
		outputFile   string
		namespaces   []string
		excludeNS    []string
		mode         string
		analyzeOnly  bool
	)

	cmd := &cobra.Command{
		Use:   "netpol",
		Short: "Generate NetworkPolicy recommendations",
		Long: `Analyze cluster workloads and generate NetworkPolicy YAML recommendations.

IMPORTANT: NetworkPolicies require a CNI that supports them (Calico, Cilium, Weave).
Flannel does NOT support NetworkPolicies - they will have no effect.

Modes:
  baseline - Safe policies: DNS egress, service-specific ingress (default)
  strict   - Zero-trust: default-deny + explicit allow rules (use with caution)

Best Practices:
  1. Always test policies in a non-production environment first
  2. Apply DNS egress policies before deny-all policies
  3. Monitor for connectivity issues after applying policies
  4. Use --analyze to understand your cluster before generating policies

References:
  - Kubernetes Network Policy Recipes: github.com/ahmetb/kubernetes-network-policy-recipes
  - Network Policy Editor: editor.networkpolicy.io`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigChan
				fmt.Println("\nReceived interrupt, shutting down...")
				cancel()
			}()

			var restConfig *rest.Config
			var clusterName string

			switch provider {
			case "aws":
				if !auth.HasCloudProvider("aws") {
					return fmt.Errorf("AWS provider not available")
				}
				if cluster == "" || region == "" {
					return fmt.Errorf("--cluster and --region required for AWS")
				}
				p, err := auth.NewEKSProvider(ctx, auth.EKSProviderOptions{Region: region})
				if err != nil {
					return err
				}
				restConfig, err = p.GetRestConfig(ctx, cluster)
				if err != nil {
					return err
				}
				clusterName = cluster

			case "azure":
				if !auth.HasCloudProvider("azure") {
					return fmt.Errorf("azure provider not available")
				}
				if cluster == "" {
					return fmt.Errorf("--cluster required for Azure")
				}
				p, err := auth.NewAKSProvider(ctx, auth.AKSProviderOptions{SubscriptionID: subscription})
				if err != nil {
					return err
				}
				restConfig, err = p.GetRestConfig(ctx, cluster)
				if err != nil {
					return err
				}
				clusterName = cluster

			case "gcp":
				if !auth.HasCloudProvider("gcp") {
					return fmt.Errorf("GCP provider not available")
				}
				if cluster == "" {
					return fmt.Errorf("--cluster required for GCP")
				}
				projects := []string{}
				if project != "" {
					projects = []string{project}
				}
				p, err := auth.NewGKEProvider(ctx, auth.GKEProviderOptions{Projects: projects})
				if err != nil {
					return err
				}
				restConfig, err = p.GetRestConfig(ctx, cluster)
				if err != nil {
					return err
				}
				clusterName = cluster

			default:
				p, err := auth.NewKubeconfigProvider(kubeconfig)
				if err != nil {
					return err
				}
				if cluster != "" {
					restConfig, err = p.GetRestConfig(ctx, cluster)
					clusterName = cluster
				} else {
					restConfig, err = p.GetRestConfig(ctx, "")
					clusterName = p.CurrentContext()
				}
				if err != nil {
					return err
				}
			}

			fmt.Printf("Analyzing cluster: %s\n", clusterName)

			mgr, err := collector.NewManager(restConfig, collector.ManagerOptions{
				Namespaces:        namespaces,
				NamespacesExclude: excludeNS,
				Parallel:          5,
				Timeout:           5 * time.Minute,
			})
			if err != nil {
				return err
			}

			mgr.RegisterDefaultCollectors()

			fmt.Println("  Collecting cluster inventory...")
			inv, err := mgr.Collect(ctx)
			if err != nil {
				return err
			}
			inv.Cluster.Name = clusterName

			fmt.Printf("  Found: %d namespaces, %d pods, %d services, %d existing policies\n",
				len(inv.Namespaces), len(inv.Workloads.Pods), len(inv.Services), len(inv.NetworkPolicies))

			generator := netpol.NewGenerator(inv)

			if analyzeOnly {
				fmt.Println()
				fmt.Print(generator.GetAnalysisSummary())
				return nil
			}

			switch mode {
			case "baseline":
				generator.SetMode(netpol.ModeBaseline)
			case "strict":
				generator.SetMode(netpol.ModeStrict)
				fmt.Println("\n  WARNING: Strict mode generates default-deny policies.")
				fmt.Println("  These WILL break connectivity if applied without proper allow rules.")
				fmt.Println("  Test in a non-production environment first.")
			default:
				return fmt.Errorf("unknown mode: %s (use baseline or strict)", mode)
			}

			policies := generator.Generate()

			if len(policies) == 0 {
				fmt.Println("\n  No policies to generate. Cluster may already have adequate coverage.")
				return nil
			}

			fmt.Printf("  Generated: %d policies (mode: %s)\n\n", len(policies), mode)

			return outputNetpol(policies, outputFormat, outputFile)
		},
	}

	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	cmd.Flags().StringVar(&provider, "provider", "", "Cloud provider: aws, azure, gcp")
	cmd.Flags().StringVar(&region, "region", "", "AWS region")
	cmd.Flags().StringVar(&cluster, "cluster", "", "Cluster name")
	cmd.Flags().StringVar(&subscription, "subscription", "", "Azure subscription ID")
	cmd.Flags().StringVar(&project, "project", "", "GCP project ID")
	cmd.Flags().StringVar(&outputFormat, "output", "yaml", "Output format: yaml, json")
	cmd.Flags().StringVar(&outputFile, "output-file", "", "Output file path")
	cmd.Flags().StringSliceVar(&namespaces, "namespaces", nil, "Namespaces to analyze")
	cmd.Flags().StringSliceVar(&excludeNS, "exclude-namespaces", []string{"kube-system", "kube-public", "qualys"}, "Namespaces to exclude")
	cmd.Flags().StringVar(&mode, "mode", "baseline", "Policy mode: baseline (safe), strict (zero-trust)")
	cmd.Flags().BoolVar(&analyzeOnly, "analyze", false, "Only analyze, do not generate policies")

	return cmd
}

func outputNetpol(policies []netpol.GeneratedPolicy, format, file string) error {
	var output strings.Builder

	switch format {
	case "yaml":
		for i, p := range policies {
			if i > 0 {
				output.WriteString("---\n")
			}
			output.WriteString(fmt.Sprintf("# Namespace: %s\n", p.Namespace))
			output.WriteString(fmt.Sprintf("# Reason: %s\n", p.Reason))
			output.WriteString(fmt.Sprintf("# Risk: %s\n", p.Risk))
			output.WriteString(fmt.Sprintf("# Impact: %s\n", p.Impact))
			if p.Recipe != "" {
				output.WriteString(fmt.Sprintf("# Recipe: %s\n", p.Recipe))
			}
			output.WriteString(fmt.Sprintf("# Affected workloads: %s\n", strings.Join(p.Workloads, ", ")))
			output.WriteString(p.YAML)
		}

	case "json":
		data, err := json.MarshalIndent(policies, "", "  ")
		if err != nil {
			return err
		}
		output.Write(data)

	default:
		return fmt.Errorf("unknown output format: %s", format)
	}

	if file != "" {
		if err := os.WriteFile(file, []byte(output.String()), 0600); err != nil {
			return err
		}
		fmt.Printf("Policies written to: %s\n", file)
	} else {
		fmt.Print(output.String())
	}

	fmt.Println("\n# To apply these policies:")
	fmt.Println("#   kubectl apply -f <output-file>")
	fmt.Println("#")
	fmt.Println("# IMPORTANT: Test in a non-production environment first.")
	fmt.Println("# Monitor for connectivity issues after applying.")

	return nil
}
