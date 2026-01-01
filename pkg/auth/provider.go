package auth

import (
	"context"
	"fmt"

	"k8s.io/client-go/rest"
)

type ClusterInfo struct {
	Name          string
	Provider      string
	Region        string
	Endpoint      string
	Version       string
	AccountID     string
	ResourceGroup string
	Tags          map[string]string
}

type Provider interface {
	Name() string
	GetRestConfig(ctx context.Context, clusterID string) (*rest.Config, error)
	ListClusters(ctx context.Context) ([]ClusterInfo, error)
	GetClusterInfo(ctx context.Context, clusterID string) (*ClusterInfo, error)
}

type ProviderConfig struct {
	Region         string
	Regions        []string
	SubscriptionID string
	ProjectID      string
	Projects       []string
	RoleARN        string
	TimeoutSeconds int
}

type Registry struct {
	providers map[string]Provider
}

func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]Provider),
	}
}

func (r *Registry) Register(p Provider) {
	r.providers[p.Name()] = p
}

func (r *Registry) Get(name string) (Provider, error) {
	p, ok := r.providers[name]
	if !ok {
		return nil, fmt.Errorf("unknown auth provider: %s", name)
	}
	return p, nil
}

func (r *Registry) List() []string {
	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	return names
}

var DefaultRegistry = NewRegistry()

func Register(p Provider) {
	DefaultRegistry.Register(p)
}

func Get(name string) (Provider, error) {
	return DefaultRegistry.Get(name)
}
