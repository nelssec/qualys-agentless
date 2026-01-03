package collector

import (
	"context"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type ServiceAccountCollector struct {
	include []string
	exclude []string
	results []inventory.ServiceAccountInfo
}

func NewServiceAccountCollector(include, exclude []string) *ServiceAccountCollector {
	return &ServiceAccountCollector{
		include: include,
		exclude: exclude,
	}
}

func (c *ServiceAccountCollector) Name() string {
	return "serviceaccount"
}

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

func (c *ServiceAccountCollector) Results() interface{} {
	return c.results
}
