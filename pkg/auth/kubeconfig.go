package auth

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

type KubeconfigProvider struct {
	kubeconfigPath string
	config         *api.Config
}

func NewKubeconfigProvider(path string) (*KubeconfigProvider, error) {
	if path == "" {
		path = getDefaultKubeconfigPath()
	}

	config, err := clientcmd.LoadFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load kubeconfig from %s: %w", path, err)
	}

	return &KubeconfigProvider{
		kubeconfigPath: path,
		config:         config,
	}, nil
}

func (p *KubeconfigProvider) Name() string {
	return "kubeconfig"
}

func (p *KubeconfigProvider) GetRestConfig(ctx context.Context, clusterID string) (*rest.Config, error) {
	loadingRules := &clientcmd.ClientConfigLoadingRules{
		ExplicitPath: p.kubeconfigPath,
	}

	overrides := &clientcmd.ConfigOverrides{}
	if clusterID != "" {
		overrides.CurrentContext = clusterID
	}

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)

	restConfig, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create REST config: %w", err)
	}

	restConfig.QPS = 50
	restConfig.Burst = 100

	return restConfig, nil
}

func (p *KubeconfigProvider) ListClusters(ctx context.Context) ([]ClusterInfo, error) {
	clusters := make([]ClusterInfo, 0, len(p.config.Contexts))

	for contextName, context := range p.config.Contexts {
		clusterConfig, ok := p.config.Clusters[context.Cluster]
		if !ok {
			continue
		}

		clusters = append(clusters, ClusterInfo{
			Name:     contextName,
			Provider: "kubeconfig",
			Endpoint: clusterConfig.Server,
			Tags: map[string]string{
				"context":   contextName,
				"cluster":   context.Cluster,
				"namespace": context.Namespace,
			},
		})
	}

	return clusters, nil
}

func (p *KubeconfigProvider) GetClusterInfo(ctx context.Context, clusterID string) (*ClusterInfo, error) {
	context, ok := p.config.Contexts[clusterID]
	if !ok {
		return nil, fmt.Errorf("context not found")
	}

	clusterConfig, ok := p.config.Clusters[context.Cluster]
	if !ok {
		return nil, fmt.Errorf("cluster not found")
	}

	return &ClusterInfo{
		Name:     clusterID,
		Provider: "kubeconfig",
		Endpoint: clusterConfig.Server,
		Tags: map[string]string{
			"context":   clusterID,
			"cluster":   context.Cluster,
			"namespace": context.Namespace,
		},
	}, nil
}

func (p *KubeconfigProvider) CurrentContext() string {
	return p.config.CurrentContext
}

func getDefaultKubeconfigPath() string {
	if kubeconfigEnv := os.Getenv("KUBECONFIG"); kubeconfigEnv != "" {
		paths := filepath.SplitList(kubeconfigEnv)
		if len(paths) > 0 {
			return paths[0]
		}
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(homeDir, ".kube", "config")
}

func init() {
}
