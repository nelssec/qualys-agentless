package collector

import (
	"context"
	"fmt"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type ClusterResourceCollector struct {
	crds            []inventory.CRDInfo
	priorityClasses []inventory.PriorityClassInfo
}

func NewClusterResourceCollector() *ClusterResourceCollector {
	return &ClusterResourceCollector{}
}

func (c *ClusterResourceCollector) Name() string {
	return "clusterresource"
}

func (c *ClusterResourceCollector) Collect(ctx context.Context, clientset *kubernetes.Clientset) error {
	pcs, err := clientset.SchedulingV1().PriorityClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	c.priorityClasses = make([]inventory.PriorityClassInfo, 0, len(pcs.Items))
	for _, pc := range pcs.Items {
		var preemptionPolicy string
		if pc.PreemptionPolicy != nil {
			preemptionPolicy = string(*pc.PreemptionPolicy)
		}

		c.priorityClasses = append(c.priorityClasses, inventory.PriorityClassInfo{
			Name:             pc.Name,
			Labels:           pc.Labels,
			Value:            pc.Value,
			GlobalDefault:    pc.GlobalDefault,
			PreemptionPolicy: preemptionPolicy,
			Description:      pc.Description,
		})
	}

	return nil
}

func (c *ClusterResourceCollector) Results() interface{} {
	return struct {
		CRDs            []inventory.CRDInfo
		PriorityClasses []inventory.PriorityClassInfo
	}{
		CRDs:            c.crds,
		PriorityClasses: c.priorityClasses,
	}
}

func (c *ClusterResourceCollector) PriorityClasses() []inventory.PriorityClassInfo {
	return c.priorityClasses
}

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
