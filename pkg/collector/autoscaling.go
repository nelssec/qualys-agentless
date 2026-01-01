package collector

import (
	"context"
	"fmt"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type AutoscalingCollector struct {
	include []string
	exclude []string
	pdbs    []inventory.PDBInfo
	hpas    []inventory.HPAInfo
}

func NewAutoscalingCollector(include, exclude []string) *AutoscalingCollector {
	return &AutoscalingCollector{
		include: include,
		exclude: exclude,
	}
}

func (c *AutoscalingCollector) Name() string {
	return "autoscaling"
}

func (c *AutoscalingCollector) Collect(ctx context.Context, clientset *kubernetes.Clientset) error {
	pdbs, err := clientset.PolicyV1().PodDisruptionBudgets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	c.pdbs = make([]inventory.PDBInfo, 0)
	for _, pdb := range pdbs.Items {
		if !shouldIncludeNamespace(pdb.Namespace, c.include, c.exclude) {
			continue
		}

		info := inventory.PDBInfo{
			Name:               pdb.Name,
			Namespace:          pdb.Namespace,
			Labels:             pdb.Labels,
			CurrentHealthy:     pdb.Status.CurrentHealthy,
			DesiredHealthy:     pdb.Status.DesiredHealthy,
			DisruptionsAllowed: pdb.Status.DisruptionsAllowed,
			ExpectedPods:       pdb.Status.ExpectedPods,
		}

		if pdb.Spec.MinAvailable != nil {
			info.MinAvailable = pdb.Spec.MinAvailable.String()
		}
		if pdb.Spec.MaxUnavailable != nil {
			info.MaxUnavailable = pdb.Spec.MaxUnavailable.String()
		}

		c.pdbs = append(c.pdbs, info)
	}

	hpas, err := clientset.AutoscalingV2().HorizontalPodAutoscalers("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	c.hpas = make([]inventory.HPAInfo, 0)
	for _, hpa := range hpas.Items {
		if !shouldIncludeNamespace(hpa.Namespace, c.include, c.exclude) {
			continue
		}

		metrics := make([]inventory.HPAMetric, 0)
		for _, m := range hpa.Spec.Metrics {
			metric := inventory.HPAMetric{
				Type: string(m.Type),
			}

			switch m.Type {
			case "Resource":
				if m.Resource != nil {
					metric.Name = string(m.Resource.Name)
					metric.TargetType = string(m.Resource.Target.Type)
					if m.Resource.Target.AverageUtilization != nil {
						metric.TargetValue = fmt.Sprintf("%d%%", *m.Resource.Target.AverageUtilization)
					} else if m.Resource.Target.AverageValue != nil {
						metric.TargetValue = m.Resource.Target.AverageValue.String()
					}
				}
			case "Pods":
				if m.Pods != nil {
					metric.Name = m.Pods.Metric.Name
					metric.TargetType = string(m.Pods.Target.Type)
					if m.Pods.Target.AverageValue != nil {
						metric.TargetValue = m.Pods.Target.AverageValue.String()
					}
				}
			case "Object":
				if m.Object != nil {
					metric.Name = m.Object.Metric.Name
					metric.TargetType = string(m.Object.Target.Type)
					if m.Object.Target.Value != nil {
						metric.TargetValue = m.Object.Target.Value.String()
					}
				}
			case "External":
				if m.External != nil {
					metric.Name = m.External.Metric.Name
					metric.TargetType = string(m.External.Target.Type)
					if m.External.Target.Value != nil {
						metric.TargetValue = m.External.Target.Value.String()
					}
				}
			}

			metrics = append(metrics, metric)
		}

		c.hpas = append(c.hpas, inventory.HPAInfo{
			Name:            hpa.Name,
			Namespace:       hpa.Namespace,
			Labels:          hpa.Labels,
			ScaleTargetRef:  fmt.Sprintf("%s/%s", hpa.Spec.ScaleTargetRef.Kind, hpa.Spec.ScaleTargetRef.Name),
			MinReplicas:     hpa.Spec.MinReplicas,
			MaxReplicas:     hpa.Spec.MaxReplicas,
			CurrentReplicas: hpa.Status.CurrentReplicas,
			DesiredReplicas: hpa.Status.DesiredReplicas,
			Metrics:         metrics,
		})
	}

	return nil
}

func (c *AutoscalingCollector) Results() interface{} {
	return struct {
		PDBs []inventory.PDBInfo
		HPAs []inventory.HPAInfo
	}{
		PDBs: c.pdbs,
		HPAs: c.hpas,
	}
}

func (c *AutoscalingCollector) PDBs() []inventory.PDBInfo {
	return c.pdbs
}

func (c *AutoscalingCollector) HPAs() []inventory.HPAInfo {
	return c.hpas
}
