//go:build nocloud || noaws

package auth

import (
	"context"
	"fmt"

	"k8s.io/client-go/rest"
)

type EKSProvider struct{}

type EKSProviderOptions struct {
	Region  string
	Regions []string
	RoleARN string
	Profile string
}

func NewEKSProvider(ctx context.Context, opts EKSProviderOptions) (*EKSProvider, error) {
	return nil, fmt.Errorf("AWS/EKS support not compiled in (build without -tags noaws or nocloud)")
}

func (p *EKSProvider) Name() string                                                   { return "aws" }
func (p *EKSProvider) GetRestConfig(ctx context.Context, clusterName string) (*rest.Config, error) {
	return nil, fmt.Errorf("AWS/EKS support not compiled in")
}
func (p *EKSProvider) ListClusters(ctx context.Context) ([]ClusterInfo, error) {
	return nil, fmt.Errorf("AWS/EKS support not compiled in")
}
func (p *EKSProvider) GetClusterInfo(ctx context.Context, clusterName string) (*ClusterInfo, error) {
	return nil, fmt.Errorf("AWS/EKS support not compiled in")
}
