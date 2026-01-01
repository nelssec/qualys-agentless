package collector

import (
	"context"
	"strings"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type NodeCollector struct {
	results []inventory.NodeInfo
}

func NewNodeCollector() *NodeCollector {
	return &NodeCollector{}
}

func (c *NodeCollector) Name() string {
	return "node"
}

func (c *NodeCollector) Collect(ctx context.Context, clientset *kubernetes.Clientset) error {
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	c.results = make([]inventory.NodeInfo, 0, len(nodes.Items))
	for _, node := range nodes.Items {
		taints := make([]inventory.TaintInfo, 0, len(node.Spec.Taints))
		for _, t := range node.Spec.Taints {
			taints = append(taints, inventory.TaintInfo{
				Key:    t.Key,
				Value:  t.Value,
				Effect: string(t.Effect),
			})
		}

		conditions := make([]inventory.NodeCondition, 0, len(node.Status.Conditions))
		for _, cond := range node.Status.Conditions {
			conditions = append(conditions, inventory.NodeCondition{
				Type:    string(cond.Type),
				Status:  string(cond.Status),
				Reason:  cond.Reason,
				Message: cond.Message,
			})
		}

		capacity := make(map[string]string)
		for k, v := range node.Status.Capacity {
			capacity[string(k)] = v.String()
		}

		allocatable := make(map[string]string)
		for k, v := range node.Status.Allocatable {
			allocatable[string(k)] = v.String()
		}

		runtime := node.Status.NodeInfo.ContainerRuntimeVersion
		if idx := strings.Index(runtime, "://"); idx > 0 {
			runtime = runtime[:idx]
		}

		c.results = append(c.results, inventory.NodeInfo{
			Name:             node.Name,
			Labels:           node.Labels,
			Annotations:      node.Annotations,
			Taints:           taints,
			Conditions:       conditions,
			Capacity:         capacity,
			Allocatable:      allocatable,
			KubeletVersion:   node.Status.NodeInfo.KubeletVersion,
			ContainerRuntime: runtime,
			OSImage:          node.Status.NodeInfo.OSImage,
			Architecture:     node.Status.NodeInfo.Architecture,
			KernelVersion:    node.Status.NodeInfo.KernelVersion,
			Unschedulable:    node.Spec.Unschedulable,
			CreatedAt:        node.CreationTimestamp.Time,
		})
	}

	return nil
}

func (c *NodeCollector) Results() interface{} {
	return c.results
}
