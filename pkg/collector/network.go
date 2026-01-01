package collector

import (
	"context"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// NetworkPolicyCollector collects NetworkPolicy resources.
type NetworkPolicyCollector struct {
	include []string
	exclude []string
	results []inventory.NetworkPolicyInfo
}

// NewNetworkPolicyCollector creates a new network policy collector.
func NewNetworkPolicyCollector(include, exclude []string) *NetworkPolicyCollector {
	return &NetworkPolicyCollector{
		include: include,
		exclude: exclude,
	}
}

// Name returns the collector name.
func (c *NetworkPolicyCollector) Name() string {
	return "networkpolicy"
}

// Collect gathers all NetworkPolicy resources.
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

		// Convert policy types to strings
		policyTypes := make([]string, len(np.Spec.PolicyTypes))
		for i, pt := range np.Spec.PolicyTypes {
			policyTypes[i] = string(pt)
		}

		// Convert pod selector labels
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

// Results returns the collected network policies.
func (c *NetworkPolicyCollector) Results() interface{} {
	return c.results
}

// HasDefaultDenyPolicy checks if a namespace has a default deny network policy.
func HasDefaultDenyPolicy(policies []inventory.NetworkPolicyInfo, namespace string) bool {
	for _, np := range policies {
		if np.Namespace != namespace {
			continue
		}

		// A default deny policy has an empty pod selector and no rules
		if len(np.PodSelector) == 0 {
			// Check for deny-all ingress
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
