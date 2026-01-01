//go:build !nocloud && !noazure

package auth

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v4"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type AKSProvider struct {
	credential     *azidentity.DefaultAzureCredential
	subscriptionID string
	resourceGroups []string
}

type AKSProviderOptions struct {
	SubscriptionID string
	ResourceGroups []string
}

func NewAKSProvider(ctx context.Context, opts AKSProviderOptions) (*AKSProvider, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure credential: %w", err)
	}

	return &AKSProvider{
		credential:     cred,
		subscriptionID: opts.SubscriptionID,
		resourceGroups: opts.ResourceGroups,
	}, nil
}

func (p *AKSProvider) Name() string {
	return "azure"
}

func (p *AKSProvider) GetRestConfig(ctx context.Context, clusterID string) (*rest.Config, error) {
	resourceGroup, clusterName, err := parseAKSClusterID(clusterID)
	if err != nil {
		return nil, err
	}

	client, err := armcontainerservice.NewManagedClustersClient(p.subscriptionID, p.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to access cluster (check credentials and permissions)")
	}

	credResult, err := client.ListClusterUserCredentials(ctx, resourceGroup, clusterName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to access cluster (check credentials and permissions)")
	}

	if len(credResult.Kubeconfigs) == 0 {
		return nil, fmt.Errorf("no credentials returned for cluster")
	}

	kubeconfig := credResult.Kubeconfigs[0].Value
	clientConfig, err := clientcmd.NewClientConfigFromBytes(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cluster credentials")
	}

	restConfig, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create REST config")
	}

	restConfig.QPS = 50
	restConfig.Burst = 100

	return restConfig, nil
}

func (p *AKSProvider) ListClusters(ctx context.Context) ([]ClusterInfo, error) {
	client, err := armcontainerservice.NewManagedClustersClient(p.subscriptionID, p.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to access clusters (check credentials and permissions)")
	}

	var clusters []ClusterInfo

	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list clusters")
		}

		for _, cluster := range page.Value {
			resourceGroup := extractResourceGroup(*cluster.ID)

			if len(p.resourceGroups) > 0 && !containsString(p.resourceGroups, resourceGroup) {
				continue
			}

			tags := make(map[string]string)
			if cluster.Tags != nil {
				for k, v := range cluster.Tags {
					if v != nil {
						tags[k] = *v
					}
				}
			}

			version := ""
			if cluster.Properties != nil && cluster.Properties.KubernetesVersion != nil {
				version = *cluster.Properties.KubernetesVersion
			}

			endpoint := ""
			if cluster.Properties != nil && cluster.Properties.Fqdn != nil {
				endpoint = fmt.Sprintf("https://%s", *cluster.Properties.Fqdn)
			}

			clusters = append(clusters, ClusterInfo{
				Name:          *cluster.Name,
				Provider:      "azure",
				Region:        *cluster.Location,
				Endpoint:      endpoint,
				Version:       version,
				AccountID:     p.subscriptionID,
				ResourceGroup: resourceGroup,
				Tags:          tags,
			})
		}
	}

	return clusters, nil
}

func (p *AKSProvider) GetClusterInfo(ctx context.Context, clusterID string) (*ClusterInfo, error) {
	resourceGroup, clusterName, err := parseAKSClusterID(clusterID)
	if err != nil {
		return nil, err
	}

	client, err := armcontainerservice.NewManagedClustersClient(p.subscriptionID, p.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to access cluster (check credentials and permissions)")
	}

	cluster, err := client.Get(ctx, resourceGroup, clusterName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to access cluster (check credentials and permissions)")
	}

	tags := make(map[string]string)
	if cluster.Tags != nil {
		for k, v := range cluster.Tags {
			if v != nil {
				tags[k] = *v
			}
		}
	}

	version := ""
	if cluster.Properties != nil && cluster.Properties.KubernetesVersion != nil {
		version = *cluster.Properties.KubernetesVersion
	}

	endpoint := ""
	if cluster.Properties != nil && cluster.Properties.Fqdn != nil {
		endpoint = fmt.Sprintf("https://%s", *cluster.Properties.Fqdn)
	}

	return &ClusterInfo{
		Name:          *cluster.Name,
		Provider:      "azure",
		Region:        *cluster.Location,
		Endpoint:      endpoint,
		Version:       version,
		AccountID:     p.subscriptionID,
		ResourceGroup: resourceGroup,
		Tags:          tags,
	}, nil
}

func parseAKSClusterID(clusterID string) (resourceGroup, clusterName string, err error) {
	var parts []string
	for i := 0; i < len(clusterID); i++ {
		if clusterID[i] == '/' {
			parts = append(parts, clusterID[:i])
			parts = append(parts, clusterID[i+1:])
			break
		}
	}

	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid cluster ID format")
	}

	return parts[0], parts[1], nil
}

func extractResourceGroup(resourceID string) string {
	var inResourceGroups bool
	var start, end int

	for i := 0; i < len(resourceID); i++ {
		if i+15 <= len(resourceID) && resourceID[i:i+15] == "resourceGroups/" {
			start = i + 15
			inResourceGroups = true
			continue
		}
		if inResourceGroups && resourceID[i] == '/' {
			end = i
			break
		}
	}

	if end > start {
		return resourceID[start:end]
	}
	return ""
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func init() {
	registerCloudProvider("azure")
}
