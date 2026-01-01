package collector

import (
	"context"
	"fmt"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type EndpointCollector struct {
	include []string
	exclude []string
	results []inventory.EndpointInfo
}

func NewEndpointCollector(include, exclude []string) *EndpointCollector {
	return &EndpointCollector{
		include: include,
		exclude: exclude,
	}
}

func (c *EndpointCollector) Name() string {
	return "endpoint"
}

func (c *EndpointCollector) Collect(ctx context.Context, clientset *kubernetes.Clientset) error {
	endpoints, err := clientset.CoreV1().Endpoints("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	c.results = make([]inventory.EndpointInfo, 0)
	for _, ep := range endpoints.Items {
		if !shouldIncludeNamespace(ep.Namespace, c.include, c.exclude) {
			continue
		}

		subsets := make([]inventory.EndpointSubset, 0, len(ep.Subsets))
		for _, subset := range ep.Subsets {
			ports := make([]string, 0, len(subset.Ports))
			for _, p := range subset.Ports {
				ports = append(ports, fmt.Sprintf("%s/%d", p.Protocol, p.Port))
			}

			subsets = append(subsets, inventory.EndpointSubset{
				Addresses:         len(subset.Addresses),
				NotReadyAddresses: len(subset.NotReadyAddresses),
				Ports:             ports,
			})
		}

		c.results = append(c.results, inventory.EndpointInfo{
			Name:      ep.Name,
			Namespace: ep.Namespace,
			Labels:    ep.Labels,
			Subsets:   subsets,
		})
	}

	return nil
}

func (c *EndpointCollector) Results() interface{} {
	return c.results
}
