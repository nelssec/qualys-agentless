package collector

import (
	"context"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type NetworkPolicyCollector struct {
	include []string
	exclude []string
	results []inventory.NetworkPolicyInfo
}

func NewNetworkPolicyCollector(include, exclude []string) *NetworkPolicyCollector {
	return &NetworkPolicyCollector{
		include: include,
		exclude: exclude,
	}
}

func (c *NetworkPolicyCollector) Name() string {
	return "networkpolicy"
}

func (c *NetworkPolicyCollector) Collect(ctx context.Context, clientset *kubernetes.Clientset) error {
	policies, err := clientset.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	c.results = make([]inventory.NetworkPolicyInfo, 0, len(policies.Items))

	for _, np := range policies.Items {
		if !shouldIncludeNamespace(np.Namespace, c.include, c.exclude) {
			continue
		}

		policyTypes := make([]string, len(np.Spec.PolicyTypes))
		for i, pt := range np.Spec.PolicyTypes {
			policyTypes[i] = string(pt)
		}

		podSelector := make(map[string]string)
		if np.Spec.PodSelector.MatchLabels != nil {
			podSelector = np.Spec.PodSelector.MatchLabels
		}

		c.results = append(c.results, inventory.NetworkPolicyInfo{
			Name:         np.Name,
			Namespace:    np.Namespace,
			Labels:       np.Labels,
			PodSelector:  podSelector,
			PolicyTypes:  policyTypes,
			IngressRules: len(np.Spec.Ingress),
			EgressRules:  len(np.Spec.Egress),
		})
	}

	return nil
}

func (c *NetworkPolicyCollector) Results() interface{} {
	return c.results
}

func HasDefaultDenyPolicy(policies []inventory.NetworkPolicyInfo, namespace string) bool {
	for _, np := range policies {
		if np.Namespace != namespace {
			continue
		}

		if len(np.PodSelector) == 0 {
			for _, pt := range np.PolicyTypes {
				if pt == "Ingress" && np.IngressRules == 0 {
					return true
				}
				if pt == "Egress" && np.EgressRules == 0 {
					return true
				}
			}
		}
	}
	return false
}
