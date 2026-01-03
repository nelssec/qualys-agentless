package collector

import (
	"context"
	"fmt"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
	"k8s.io/client-go/kubernetes"
)

type CRDCollector struct {
	results []inventory.CRDInfo
}

func NewCRDCollector() *CRDCollector {
	return &CRDCollector{}
}

func (c *CRDCollector) Name() string {
	return "crd"
}

func (c *CRDCollector) Collect(ctx context.Context, clientset *kubernetes.Clientset) error {
	discovery := clientset.Discovery()
	_, apiResourceLists, err := discovery.ServerGroupsAndResources()
	if err != nil {
		return nil
	}

	crdMap := make(map[string]*inventory.CRDInfo)

	for _, apiList := range apiResourceLists {
		for _, res := range apiList.APIResources {
			if res.Group != "" && !isBuiltinGroup(res.Group) {
				key := fmt.Sprintf("%s/%s", res.Group, res.Kind)
				if _, exists := crdMap[key]; !exists {
					scope := "Namespaced"
					if !res.Namespaced {
						scope = "Cluster"
					}

					crdMap[key] = &inventory.CRDInfo{
						Name:     res.Name + "." + res.Group,
						Group:    res.Group,
						Scope:    scope,
						Kind:     res.Kind,
						Versions: []string{res.Version},
					}
				}
			}
		}
	}

	c.results = make([]inventory.CRDInfo, 0, len(crdMap))
	for _, crd := range crdMap {
		c.results = append(c.results, *crd)
	}

	return nil
}

func (c *CRDCollector) Results() interface{} {
	return c.results
}

func isBuiltinGroup(group string) bool {
	builtins := map[string]bool{
		"":                              true,
		"admissionregistration.k8s.io":  true,
		"apiextensions.k8s.io":          true,
		"apiregistration.k8s.io":        true,
		"apps":                          true,
		"authentication.k8s.io":         true,
		"authorization.k8s.io":          true,
		"autoscaling":                   true,
		"batch":                         true,
		"certificates.k8s.io":           true,
		"coordination.k8s.io":           true,
		"discovery.k8s.io":              true,
		"events.k8s.io":                 true,
		"extensions":                    true,
		"flowcontrol.apiserver.k8s.io":  true,
		"networking.k8s.io":             true,
		"node.k8s.io":                   true,
		"policy":                        true,
		"rbac.authorization.k8s.io":     true,
		"scheduling.k8s.io":             true,
		"storage.k8s.io":                true,
	}
	return builtins[group]
}
