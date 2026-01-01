package collector

import (
	"context"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type QuotaCollector struct {
	include        []string
	exclude        []string
	resourceQuotas []inventory.ResourceQuotaInfo
	limitRanges    []inventory.LimitRangeInfo
}

func NewQuotaCollector(include, exclude []string) *QuotaCollector {
	return &QuotaCollector{
		include: include,
		exclude: exclude,
	}
}

func (c *QuotaCollector) Name() string {
	return "quota"
}

func (c *QuotaCollector) Collect(ctx context.Context, clientset *kubernetes.Clientset) error {
	quotas, err := clientset.CoreV1().ResourceQuotas("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	c.resourceQuotas = make([]inventory.ResourceQuotaInfo, 0)
	for _, q := range quotas.Items {
		if !shouldIncludeNamespace(q.Namespace, c.include, c.exclude) {
			continue
		}

		hard := make(map[string]string)
		for k, v := range q.Status.Hard {
			hard[string(k)] = v.String()
		}

		used := make(map[string]string)
		for k, v := range q.Status.Used {
			used[string(k)] = v.String()
		}

		c.resourceQuotas = append(c.resourceQuotas, inventory.ResourceQuotaInfo{
			Name:      q.Name,
			Namespace: q.Namespace,
			Labels:    q.Labels,
			Hard:      hard,
			Used:      used,
		})
	}

	limitRanges, err := clientset.CoreV1().LimitRanges("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	c.limitRanges = make([]inventory.LimitRangeInfo, 0)
	for _, lr := range limitRanges.Items {
		if !shouldIncludeNamespace(lr.Namespace, c.include, c.exclude) {
			continue
		}

		limits := make([]inventory.LimitRangeItem, 0, len(lr.Spec.Limits))
		for _, l := range lr.Spec.Limits {
			item := inventory.LimitRangeItem{
				Type: string(l.Type),
			}

			if len(l.Max) > 0 {
				item.Max = make(map[string]string)
				for k, v := range l.Max {
					item.Max[string(k)] = v.String()
				}
			}
			if len(l.Min) > 0 {
				item.Min = make(map[string]string)
				for k, v := range l.Min {
					item.Min[string(k)] = v.String()
				}
			}
			if len(l.Default) > 0 {
				item.Default = make(map[string]string)
				for k, v := range l.Default {
					item.Default[string(k)] = v.String()
				}
			}
			if len(l.DefaultRequest) > 0 {
				item.DefaultRequest = make(map[string]string)
				for k, v := range l.DefaultRequest {
					item.DefaultRequest[string(k)] = v.String()
				}
			}

			limits = append(limits, item)
		}

		c.limitRanges = append(c.limitRanges, inventory.LimitRangeInfo{
			Name:      lr.Name,
			Namespace: lr.Namespace,
			Labels:    lr.Labels,
			Limits:    limits,
		})
	}

	return nil
}

func (c *QuotaCollector) Results() interface{} {
	return struct {
		ResourceQuotas []inventory.ResourceQuotaInfo
		LimitRanges    []inventory.LimitRangeInfo
	}{
		ResourceQuotas: c.resourceQuotas,
		LimitRanges:    c.limitRanges,
	}
}

func (c *QuotaCollector) ResourceQuotas() []inventory.ResourceQuotaInfo {
	return c.resourceQuotas
}

func (c *QuotaCollector) LimitRanges() []inventory.LimitRangeInfo {
	return c.limitRanges
}
