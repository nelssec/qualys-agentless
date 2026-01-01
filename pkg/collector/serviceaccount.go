package collector

import (
	"context"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ServiceAccountCollector collects ServiceAccount resources.
type ServiceAccountCollector struct {
	include []string
	exclude []string
	results []inventory.ServiceAccountInfo
}

// NewServiceAccountCollector creates a new service account collector.
func NewServiceAccountCollector(include, exclude []string) *ServiceAccountCollector {
	return &ServiceAccountCollector{
		include: include,
		exclude: exclude,
	}
}

// Name returns the collector name.
func (c *ServiceAccountCollector) Name() string {
	return "serviceaccount"
}

// Collect gathers all ServiceAccount resources.
func (c *ServiceAccountCollector) Collect(ctx context.Context, clientset *kubernetes.Clientset) error {
	serviceAccounts, err := clientset.CoreV1().ServiceAccounts("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	c.results = make([]inventory.ServiceAccountInfo, 0, len(serviceAccounts.Items))

	for _, sa := range serviceAccounts.Items {
		if !shouldIncludeNamespace(sa.Namespace, c.include, c.exclude) {
			continue
		}

		secrets := make([]string, len(sa.Secrets))
		for i, s := range sa.Secrets {
			secrets[i] = s.Name
		}

		c.results = append(c.results, inventory.ServiceAccountInfo{
			Name:                         sa.Name,
			Namespace:                    sa.Namespace,
			Labels:                       sa.Labels,
			AutomountServiceAccountToken: sa.AutomountServiceAccountToken,
			Secrets:                      secrets,
		})
	}

	return nil
}

// Results returns the collected service accounts.
func (c *ServiceAccountCollector) Results() interface{} {
	return c.results
}
