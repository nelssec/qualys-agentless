//go:build !nocloud && !nogcp

package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"

	container "cloud.google.com/go/container/apiv1"
	"cloud.google.com/go/container/apiv1/containerpb"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iterator"
	"k8s.io/client-go/rest"
)

type GKEProvider struct {
	clusterClient *container.ClusterManagerClient
	tokenSource   oauth2.TokenSource
	projects      []string
	locations     []string
}

type GKEProviderOptions struct {
	Projects  []string
	Locations []string
}

func NewGKEProvider(ctx context.Context, opts GKEProviderOptions) (*GKEProvider, error) {
	client, err := container.NewClusterManagerClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create GKE client: %w", err)
	}

	tokenSource, err := google.DefaultTokenSource(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, fmt.Errorf("failed to get token source: %w", err)
	}

	locations := opts.Locations
	if len(locations) == 0 {
		locations = []string{"-"}
	}

	return &GKEProvider{
		clusterClient: client,
		tokenSource:   tokenSource,
		projects:      opts.Projects,
		locations:     locations,
	}, nil
}

func (p *GKEProvider) Name() string {
	return "gcp"
}

func (p *GKEProvider) GetRestConfig(ctx context.Context, clusterID string) (*rest.Config, error) {
	cluster, err := p.clusterClient.GetCluster(ctx, &containerpb.GetClusterRequest{
		Name: clusterID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to access cluster (check credentials and permissions)")
	}

	caData, err := base64.StdEncoding.DecodeString(cluster.MasterAuth.ClusterCaCertificate)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CA certificate")
	}

	token, err := p.tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to get access token")
	}

	endpoint := fmt.Sprintf("https://%s", cluster.Endpoint)

	return &rest.Config{
		Host:        endpoint,
		BearerToken: token.AccessToken,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: caData,
		},
		QPS:           50,
		Burst:         100,
		WrapTransport: newTokenRefreshTransport(p.tokenSource),
	}, nil
}

func (p *GKEProvider) ListClusters(ctx context.Context) ([]ClusterInfo, error) {
	var allClusters []ClusterInfo

	for _, project := range p.projects {
		for _, location := range p.locations {
			clusters, err := p.listClustersInLocation(ctx, project, location)
			if err != nil {
				continue
			}
			allClusters = append(allClusters, clusters...)
		}
	}

	return allClusters, nil
}

func (p *GKEProvider) listClustersInLocation(ctx context.Context, project, location string) ([]ClusterInfo, error) {
	parent := fmt.Sprintf("projects/%s/locations/%s", project, location)

	resp, err := p.clusterClient.ListClusters(ctx, &containerpb.ListClustersRequest{
		Parent: parent,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list clusters")
	}

	var clusters []ClusterInfo
	for _, cluster := range resp.Clusters {
		labels := make(map[string]string)
		for k, v := range cluster.ResourceLabels {
			labels[k] = v
		}

		clusters = append(clusters, ClusterInfo{
			Name:      cluster.Name,
			Provider:  "gcp",
			Region:    cluster.Location,
			Endpoint:  fmt.Sprintf("https://%s", cluster.Endpoint),
			Version:   cluster.CurrentMasterVersion,
			AccountID: project,
			Tags:      labels,
		})
	}

	return clusters, nil
}

func (p *GKEProvider) GetClusterInfo(ctx context.Context, clusterID string) (*ClusterInfo, error) {
	cluster, err := p.clusterClient.GetCluster(ctx, &containerpb.GetClusterRequest{
		Name: clusterID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to access cluster (check credentials and permissions)")
	}

	labels := make(map[string]string)
	for k, v := range cluster.ResourceLabels {
		labels[k] = v
	}

	project := extractProjectFromClusterName(clusterID)

	return &ClusterInfo{
		Name:      cluster.Name,
		Provider:  "gcp",
		Region:    cluster.Location,
		Endpoint:  fmt.Sprintf("https://%s", cluster.Endpoint),
		Version:   cluster.CurrentMasterVersion,
		AccountID: project,
		Tags:      labels,
	}, nil
}

func (p *GKEProvider) Close() error {
	return p.clusterClient.Close()
}

func extractProjectFromClusterName(name string) string {
	const prefix = "projects/"
	start := 0
	for i := 0; i+len(prefix) <= len(name); i++ {
		if name[i:i+len(prefix)] == prefix {
			start = i + len(prefix)
			break
		}
	}
	if start == 0 {
		return ""
	}

	end := start
	for ; end < len(name); end++ {
		if name[end] == '/' {
			break
		}
	}

	return name[start:end]
}

func newTokenRefreshTransport(ts oauth2.TokenSource) func(rt http.RoundTripper) http.RoundTripper {
	return func(rt http.RoundTripper) http.RoundTripper {
		return &oauth2.Transport{
			Source: ts,
			Base:   rt,
		}
	}
}

var _ = iterator.Done

func init() {
	registerCloudProvider("gcp")
}
