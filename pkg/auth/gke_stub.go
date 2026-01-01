//go:build nocloud || nogcp

package auth

import (
	"context"
	"fmt"

	"k8s.io/client-go/rest"
)

type GKEProvider struct{}

type GKEProviderOptions struct {
	Projects  []string
	Locations []string
}

func NewGKEProvider(ctx context.Context, opts GKEProviderOptions) (*GKEProvider, error) {
	return nil, fmt.Errorf("GCP/GKE support not compiled in (build without -tags nogcp or nocloud)")
}

func (p *GKEProvider) Name() string { return "gcp" }
func (p *GKEProvider) GetRestConfig(ctx context.Context, clusterID string) (*rest.Config, error) {
	return nil, fmt.Errorf("GCP/GKE support not compiled in")
}
func (p *GKEProvider) ListClusters(ctx context.Context) ([]ClusterInfo, error) {
	return nil, fmt.Errorf("GCP/GKE support not compiled in")
}
func (p *GKEProvider) GetClusterInfo(ctx context.Context, clusterID string) (*ClusterInfo, error) {
	return nil, fmt.Errorf("GCP/GKE support not compiled in")
}
func (p *GKEProvider) Close() error { return nil }
