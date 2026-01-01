//go:build !nohelm

package helm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
	"github.com/nelssec/qualys-agentless/pkg/manifest"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/getter"
)

type Renderer struct {
	settings *cli.EnvSettings
}

type RenderOptions struct {
	ReleaseName string
	Namespace   string
	ValueFiles  []string
	Values      []string
	APIVersions []string
}

func NewRenderer() *Renderer {
	return &Renderer{
		settings: cli.New(),
	}
}

func (r *Renderer) RenderChart(chartPath string, opts RenderOptions) (*inventory.ClusterInventory, error) {
	if opts.ReleaseName == "" {
		opts.ReleaseName = "release"
	}
	if opts.Namespace == "" {
		opts.Namespace = "default"
	}

	chart, err := loader.Load(chartPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load chart: %w", err)
	}

	valueOpts := &values.Options{
		ValueFiles: opts.ValueFiles,
		Values:     opts.Values,
	}

	providers := getter.All(r.settings)
	vals, err := valueOpts.MergeValues(providers)
	if err != nil {
		return nil, fmt.Errorf("failed to merge values: %w", err)
	}

	client := action.NewInstall(&action.Configuration{})
	client.DryRun = true
	client.ReleaseName = opts.ReleaseName
	client.Namespace = opts.Namespace
	client.Replace = true
	client.ClientOnly = true
	client.IncludeCRDs = true

	if len(opts.APIVersions) > 0 {
		client.APIVersions = opts.APIVersions
	}

	caps := chartutil.DefaultCapabilities
	if len(opts.APIVersions) > 0 {
		caps.APIVersions = opts.APIVersions
	}

	rel, err := client.Run(chart, vals)
	if err != nil {
		return nil, fmt.Errorf("failed to render chart: %w", err)
	}

	parser := manifest.NewParser()
	inv, err := parser.Parse([]byte(rel.Manifest), chartPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rendered manifests: %w", err)
	}

	for _, hook := range rel.Hooks {
		hookInv, err := parser.Parse([]byte(hook.Manifest), chartPath+"/"+hook.Name)
		if err != nil {
			continue
		}
		mergeInventory(inv, hookInv)
	}

	return inv, nil
}

func (r *Renderer) RenderDirectory(dir string, opts RenderOptions) (*inventory.ClusterInventory, error) {
	inv := &inventory.ClusterInventory{
		Workloads: inventory.WorkloadInventory{},
		RBAC:      inventory.RBACInventory{},
	}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if _, err := os.Stat(filepath.Join(path, "Chart.yaml")); err == nil {
				chartInv, err := r.RenderChart(path, opts)
				if err != nil {
					return nil
				}
				mergeInventory(inv, chartInv)
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(info.Name(), ".tgz") {
			chartInv, err := r.RenderChart(path, opts)
			if err != nil {
				return nil
			}
			mergeInventory(inv, chartInv)
		}
		return nil
	})

	return inv, err
}

func mergeInventory(dst, src *inventory.ClusterInventory) {
	dst.Namespaces = append(dst.Namespaces, src.Namespaces...)
	dst.Workloads.Pods = append(dst.Workloads.Pods, src.Workloads.Pods...)
	dst.Workloads.Deployments = append(dst.Workloads.Deployments, src.Workloads.Deployments...)
	dst.Workloads.DaemonSets = append(dst.Workloads.DaemonSets, src.Workloads.DaemonSets...)
	dst.Workloads.StatefulSets = append(dst.Workloads.StatefulSets, src.Workloads.StatefulSets...)
	dst.Workloads.Jobs = append(dst.Workloads.Jobs, src.Workloads.Jobs...)
	dst.Workloads.CronJobs = append(dst.Workloads.CronJobs, src.Workloads.CronJobs...)
	dst.RBAC.ClusterRoles = append(dst.RBAC.ClusterRoles, src.RBAC.ClusterRoles...)
	dst.RBAC.ClusterRoleBindings = append(dst.RBAC.ClusterRoleBindings, src.RBAC.ClusterRoleBindings...)
	dst.RBAC.Roles = append(dst.RBAC.Roles, src.RBAC.Roles...)
	dst.RBAC.RoleBindings = append(dst.RBAC.RoleBindings, src.RBAC.RoleBindings...)
	dst.NetworkPolicies = append(dst.NetworkPolicies, src.NetworkPolicies...)
	dst.ServiceAccounts = append(dst.ServiceAccounts, src.ServiceAccounts...)
	dst.Services = append(dst.Services, src.Services...)
}
