//go:build nocloud || noazure

package auth

import (
	"context"
	"fmt"

	"k8s.io/client-go/rest"
)

type AKSProvider struct{}

type AKSProviderOptions struct {
	SubscriptionID string
	ResourceGroups []string
}

func NewAKSProvider(ctx context.Context, opts AKSProviderOptions) (*AKSProvider, error) {
	return nil, fmt.Errorf("Azure/AKS support not compiled in (build without -tags noazure or nocloud)")
}

func (p *AKSProvider) Name() string { return "azure" }
func (p *AKSProvider) GetRestConfig(ctx context.Context, clusterID string) (*rest.Config, error) {
	return nil, fmt.Errorf("Azure/AKS support not compiled in")
}
func (p *AKSProvider) ListClusters(ctx context.Context) ([]ClusterInfo, error) {
	return nil, fmt.Errorf("Azure/AKS support not compiled in")
}
func (p *AKSProvider) GetClusterInfo(ctx context.Context, clusterID string) (*ClusterInfo, error) {
	return nil, fmt.Errorf("Azure/AKS support not compiled in")
}
