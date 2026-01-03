package collector

import (
	"context"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type NamespaceCollector struct {
	include []string
	exclude []string
	results []inventory.NamespaceInfo
}

func NewNamespaceCollector(include, exclude []string) *NamespaceCollector {
	return &NamespaceCollector{
		include: include,
		exclude: exclude,
	}
}

func (c *NamespaceCollector) Name() string {
	return "namespace"
}

func (c *NamespaceCollector) Collect(ctx context.Context, clientset *kubernetes.Clientset) error {
	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	c.results = make([]inventory.NamespaceInfo, 0, len(namespaces.Items))

	for _, ns := range namespaces.Items {
		if !shouldIncludeNamespace(ns.Name, c.include, c.exclude) {
			continue
		}

		c.results = append(c.results, inventory.NamespaceInfo{
			Name:        ns.Name,
			Labels:      ns.Labels,
			Annotations: ns.Annotations,
			Phase:       string(ns.Status.Phase),
		})
	}

	return nil
}

func (c *NamespaceCollector) Results() interface{} {
	return c.results
}

func (c *NamespaceCollector) GetNamespaceList() []string {
	names := make([]string, len(c.results))
	for i, ns := range c.results {
		names[i] = ns.Name
	}
	return names
}
