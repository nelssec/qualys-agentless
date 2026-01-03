package netpol

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
)

type PolicyMode string

const (
	ModeAudit    PolicyMode = "audit"
	ModeBaseline PolicyMode = "baseline"
	ModeStrict   PolicyMode = "strict"
)

type Generator struct {
	inv  *inventory.ClusterInventory
	mode PolicyMode
}

type NetworkPolicySpec struct {
	Name        string            `json:"name" yaml:"name"`
	Namespace   string            `json:"namespace" yaml:"namespace"`
	PodSelector map[string]string `json:"podSelector" yaml:"podSelector"`
	Ingress     []IngressRule     `json:"ingress,omitempty" yaml:"ingress,omitempty"`
	Egress      []EgressRule      `json:"egress,omitempty" yaml:"egress,omitempty"`
	PolicyTypes []string          `json:"policyTypes" yaml:"policyTypes"`
}

type IngressRule struct {
	From  []PeerSpec `json:"from,omitempty" yaml:"from,omitempty"`
	Ports []PortSpec `json:"ports,omitempty" yaml:"ports,omitempty"`
}

type EgressRule struct {
	To    []PeerSpec `json:"to,omitempty" yaml:"to,omitempty"`
	Ports []PortSpec `json:"ports,omitempty" yaml:"ports,omitempty"`
}

type PeerSpec struct {
	PodSelector       map[string]string `json:"podSelector,omitempty" yaml:"podSelector,omitempty"`
	NamespaceSelector map[string]string `json:"namespaceSelector,omitempty" yaml:"namespaceSelector,omitempty"`
	IPBlock           *IPBlockSpec      `json:"ipBlock,omitempty" yaml:"ipBlock,omitempty"`
}

type IPBlockSpec struct {
	CIDR   string   `json:"cidr" yaml:"cidr"`
	Except []string `json:"except,omitempty" yaml:"except,omitempty"`
}

type PortSpec struct {
	Protocol string `json:"protocol" yaml:"protocol"`
	Port     int32  `json:"port" yaml:"port"`
}

type GeneratedPolicy struct {
	Spec        NetworkPolicySpec
	YAML        string
	Reason      string
	Namespace   string
	Workloads   []string
	Impact      string
	Risk        string
	Recipe      string
	ApplyOrder  int
}

type AnalysisResult struct {
	CNISupported      bool
	CNIName           string
	ExistingPolicies  int
	UnprotectedNS     []string
	ExposedServices   []ServiceExposure
	CrossNSTraffic    []CrossNamespaceFlow
	Recommendations   []Recommendation
	Policies          []GeneratedPolicy
}

type ServiceExposure struct {
	Namespace   string
	Service     string
	Type        string
	Ports       []int32
	ExposedTo   string
}

type CrossNamespaceFlow struct {
	SourceNS      string
	SourceApp     string
	TargetNS      string
	TargetService string
}

type Recommendation struct {
	Priority    int
	Category    string
	Description string
	Impact      string
	Action      string
}

func NewGenerator(inv *inventory.ClusterInventory) *Generator {
	return &Generator{
		inv:  inv,
		mode: ModeBaseline,
	}
}

func (g *Generator) SetMode(mode PolicyMode) {
	g.mode = mode
}

func (g *Generator) Analyze() *AnalysisResult {
	result := &AnalysisResult{
		ExistingPolicies: len(g.inv.NetworkPolicies),
	}

	result.CNISupported, result.CNIName = g.detectCNISupport()
	result.UnprotectedNS = g.findUnprotectedNamespaces()
	result.ExposedServices = g.findExposedServices()
	result.CrossNSTraffic = g.findCrossNamespaceFlows()
	result.Recommendations = g.generateRecommendations(result)

	return result
}

func (g *Generator) Generate() []GeneratedPolicy {
	analysis := g.Analyze()
	var policies []GeneratedPolicy

	switch g.mode {
	case ModeAudit:
		policies = g.generateAuditPolicies(analysis)
	case ModeBaseline:
		policies = g.generateBaselinePolicies(analysis)
	case ModeStrict:
		policies = g.generateStrictPolicies(analysis)
	}

	sort.Slice(policies, func(i, j int) bool {
		return policies[i].ApplyOrder < policies[j].ApplyOrder
	})

	return policies
}

func (g *Generator) detectCNISupport() (bool, string) {
	for _, node := range g.inv.Nodes {
		runtime := strings.ToLower(node.ContainerRuntime)
		if strings.Contains(runtime, "cilium") {
			return true, "cilium"
		}
		if strings.Contains(runtime, "calico") {
			return true, "calico"
		}
	}

	for _, ds := range g.inv.Workloads.DaemonSets {
		name := strings.ToLower(ds.Name)
		if strings.Contains(name, "cilium") {
			return true, "cilium"
		}
		if strings.Contains(name, "calico") {
			return true, "calico"
		}
		if strings.Contains(name, "weave") {
			return true, "weave"
		}
		if strings.Contains(name, "antrea") {
			return true, "antrea"
		}
	}

	for _, pod := range g.inv.Workloads.Pods {
		if pod.Namespace == "kube-system" {
			name := strings.ToLower(pod.Name)
			if strings.Contains(name, "cilium") {
				return true, "cilium"
			}
			if strings.Contains(name, "calico") {
				return true, "calico"
			}
			if strings.Contains(name, "weave") {
				return true, "weave"
			}
			if strings.Contains(name, "flannel") {
				return false, "flannel"
			}
		}
	}

	return true, "unknown"
}

func (g *Generator) findUnprotectedNamespaces() []string {
	hasPolicy := make(map[string]bool)
	for _, np := range g.inv.NetworkPolicies {
		hasPolicy[np.Namespace] = true
	}

	systemNS := map[string]bool{
		"kube-system":     true,
		"kube-public":     true,
		"kube-node-lease": true,
		"calico-system":   true,
		"cilium":          true,
		"tigera-operator": true,
	}

	var unprotected []string
	for _, ns := range g.inv.Namespaces {
		if systemNS[ns.Name] {
			continue
		}
		if hasPolicy[ns.Name] {
			continue
		}

		hasPods := false
		for _, pod := range g.inv.Workloads.Pods {
			if pod.Namespace == ns.Name && pod.Phase == "Running" {
				hasPods = true
				break
			}
		}
		if hasPods {
			unprotected = append(unprotected, ns.Name)
		}
	}

	sort.Strings(unprotected)
	return unprotected
}

func (g *Generator) findExposedServices() []ServiceExposure {
	var exposed []ServiceExposure

	for _, svc := range g.inv.Services {
		if svc.Type == "LoadBalancer" || svc.Type == "NodePort" {
			var ports []int32
			for _, p := range svc.Ports {
				ports = append(ports, p.Port)
			}

			exposedTo := "cluster nodes"
			if svc.Type == "LoadBalancer" {
				exposedTo = "internet (via load balancer)"
			}

			exposed = append(exposed, ServiceExposure{
				Namespace: svc.Namespace,
				Service:   svc.Name,
				Type:      svc.Type,
				Ports:     ports,
				ExposedTo: exposedTo,
			})
		}
	}

	for _, ing := range g.inv.Ingresses {
		var hosts []string
		for _, rule := range ing.Rules {
			if rule.Host != "" {
				hosts = append(hosts, rule.Host)
			}
		}
		exposed = append(exposed, ServiceExposure{
			Namespace: ing.Namespace,
			Service:   ing.Name + " (ingress)",
			Type:      "Ingress",
			ExposedTo: fmt.Sprintf("internet via hosts: %s", strings.Join(hosts, ", ")),
		})
	}

	return exposed
}

func (g *Generator) findCrossNamespaceFlows() []CrossNamespaceFlow {
	return nil
}

func (g *Generator) generateRecommendations(analysis *AnalysisResult) []Recommendation {
	var recs []Recommendation

	if !analysis.CNISupported {
		recs = append(recs, Recommendation{
			Priority:    1,
			Category:    "CNI",
			Description: fmt.Sprintf("CNI '%s' does not support NetworkPolicies", analysis.CNIName),
			Impact:      "NetworkPolicies will have no effect",
			Action:      "Consider migrating to Calico, Cilium, or another CNI that supports NetworkPolicies",
		})
	}

	if len(analysis.UnprotectedNS) > 0 {
		recs = append(recs, Recommendation{
			Priority:    2,
			Category:    "Coverage",
			Description: fmt.Sprintf("%d namespace(s) have no NetworkPolicies: %s", len(analysis.UnprotectedNS), strings.Join(analysis.UnprotectedNS, ", ")),
			Impact:      "All pods in these namespaces can communicate freely with any pod in the cluster",
			Action:      "Apply baseline NetworkPolicies to restrict unnecessary traffic",
		})
	}

	if len(analysis.ExposedServices) > 0 {
		recs = append(recs, Recommendation{
			Priority:    3,
			Category:    "Exposure",
			Description: fmt.Sprintf("%d service(s) are exposed externally", len(analysis.ExposedServices)),
			Impact:      "External traffic can reach these services",
			Action:      "Ensure ingress policies restrict access to expected sources only",
		})
	}

	if len(analysis.CrossNSTraffic) > 0 {
		recs = append(recs, Recommendation{
			Priority:    4,
			Category:    "Segmentation",
			Description: fmt.Sprintf("Detected %d cross-namespace communication pattern(s)", len(analysis.CrossNSTraffic)),
			Impact:      "Applications in different namespaces communicate directly",
			Action:      "Create explicit policies to allow only required cross-namespace traffic",
		})
	}

	return recs
}

func (g *Generator) generateAuditPolicies(analysis *AnalysisResult) []GeneratedPolicy {
	return nil
}

func (g *Generator) generateBaselinePolicies(analysis *AnalysisResult) []GeneratedPolicy {
	var policies []GeneratedPolicy

	for _, ns := range analysis.UnprotectedNS {
		policies = append(policies, g.createDNSEgressPolicy(ns))
	}

	for _, svc := range g.inv.Services {
		if svc.Type == "ClusterIP" {
			if policy := g.createServiceIngressPolicy(svc); policy != nil {
				policies = append(policies, *policy)
			}
		}
	}

	return policies
}

func (g *Generator) generateStrictPolicies(analysis *AnalysisResult) []GeneratedPolicy {
	var policies []GeneratedPolicy

	for _, ns := range analysis.UnprotectedNS {
		policies = append(policies, g.createDefaultDenyIngressPolicy(ns))
		policies = append(policies, g.createDefaultDenyEgressPolicy(ns))
		policies = append(policies, g.createDNSEgressPolicy(ns))
	}

	for _, svc := range g.inv.Services {
		if svc.Type == "ClusterIP" {
			if policy := g.createServiceIngressPolicy(svc); policy != nil {
				policies = append(policies, *policy)
			}
		}
	}

	return policies
}

func (g *Generator) createDefaultDenyIngressPolicy(namespace string) GeneratedPolicy {
	spec := NetworkPolicySpec{
		Name:        "default-deny-ingress",
		Namespace:   namespace,
		PodSelector: map[string]string{},
		Ingress:     []IngressRule{},
		PolicyTypes: []string{"Ingress"},
	}

	policy := GeneratedPolicy{
		Namespace:  namespace,
		Spec:       spec,
		Reason:     "Block all ingress traffic by default (zero-trust baseline)",
		Workloads:  []string{"all pods in " + namespace},
		Impact:     "WARNING: All incoming traffic will be blocked until explicit allow rules are created",
		Risk:       "HIGH - May break existing applications if applied without additional allow policies",
		Recipe:     "DENY all traffic to an application (kubernetes-network-policy-recipes)",
		ApplyOrder: 10,
	}
	policy.YAML = g.toYAML(spec)
	return policy
}

func (g *Generator) createDefaultDenyEgressPolicy(namespace string) GeneratedPolicy {
	spec := NetworkPolicySpec{
		Name:        "default-deny-egress",
		Namespace:   namespace,
		PodSelector: map[string]string{},
		Egress:      []EgressRule{},
		PolicyTypes: []string{"Egress"},
	}

	policy := GeneratedPolicy{
		Namespace:  namespace,
		Spec:       spec,
		Reason:     "Block all egress traffic by default (zero-trust baseline)",
		Workloads:  []string{"all pods in " + namespace},
		Impact:     "WARNING: All outgoing traffic will be blocked until explicit allow rules are created",
		Risk:       "HIGH - Will break DNS resolution and external API calls if applied alone",
		Recipe:     "DENY all egress from an application (kubernetes-network-policy-recipes)",
		ApplyOrder: 11,
	}
	policy.YAML = g.toYAML(spec)
	return policy
}

func (g *Generator) createDNSEgressPolicy(namespace string) GeneratedPolicy {
	spec := NetworkPolicySpec{
		Name:        "allow-dns-egress",
		Namespace:   namespace,
		PodSelector: map[string]string{},
		Egress: []EgressRule{
			{
				To: []PeerSpec{
					{
						NamespaceSelector: map[string]string{
							"kubernetes.io/metadata.name": "kube-system",
						},
						PodSelector: map[string]string{
							"k8s-app": "kube-dns",
						},
					},
				},
				Ports: []PortSpec{
					{Protocol: "UDP", Port: 53},
					{Protocol: "TCP", Port: 53},
				},
			},
		},
		PolicyTypes: []string{"Egress"},
	}

	policy := GeneratedPolicy{
		Namespace:  namespace,
		Spec:       spec,
		Reason:     "Allow DNS resolution to CoreDNS/kube-dns (required for service discovery)",
		Workloads:  []string{"all pods in " + namespace},
		Impact:     "Safe to apply - only allows DNS traffic to kube-system",
		Risk:       "LOW - Required for basic Kubernetes functionality",
		Recipe:     "Allow DNS egress (standard pattern)",
		ApplyOrder: 1,
	}
	policy.YAML = g.toYAML(spec)
	return policy
}

func (g *Generator) createServiceIngressPolicy(svc inventory.ServiceInfo) *GeneratedPolicy {
	if len(svc.Ports) == 0 {
		return nil
	}

	selectorLabels := make(map[string]string)
	if len(svc.Labels) > 0 {
		for k, v := range svc.Labels {
			if k == "app" || k == "app.kubernetes.io/name" || k == "name" {
				selectorLabels[k] = v
				break
			}
		}
	}

	if len(selectorLabels) == 0 {
		return nil
	}

	var ports []PortSpec
	for _, p := range svc.Ports {
		protocol := "TCP"
		if p.Protocol != "" {
			protocol = p.Protocol
		}
		ports = append(ports, PortSpec{
			Protocol: protocol,
			Port:     p.Port,
		})
	}

	ingressFrom := []PeerSpec{
		{
			PodSelector: map[string]string{},
		},
	}

	spec := NetworkPolicySpec{
		Name:        fmt.Sprintf("allow-ingress-to-%s", svc.Name),
		Namespace:   svc.Namespace,
		PodSelector: selectorLabels,
		Ingress: []IngressRule{
			{
				From:  ingressFrom,
				Ports: ports,
			},
		},
		PolicyTypes: []string{"Ingress"},
	}

	policy := GeneratedPolicy{
		Namespace:  svc.Namespace,
		Spec:       spec,
		Reason:     fmt.Sprintf("Allow ingress to service %s on declared ports", svc.Name),
		Workloads:  []string{svc.Name},
		Impact:     "Restricts ingress to specific ports from pods in same namespace",
		Risk:       "MEDIUM - Verify all clients are in the same namespace before applying",
		Recipe:     "LIMIT traffic to an application (kubernetes-network-policy-recipes)",
		ApplyOrder: 5,
	}
	policy.YAML = g.toYAML(spec)
	return &policy
}

func (g *Generator) toYAML(spec NetworkPolicySpec) string {
	var sb strings.Builder

	sb.WriteString("apiVersion: networking.k8s.io/v1\n")
	sb.WriteString("kind: NetworkPolicy\n")
	sb.WriteString("metadata:\n")
	sb.WriteString(fmt.Sprintf("  name: %s\n", spec.Name))
	sb.WriteString(fmt.Sprintf("  namespace: %s\n", spec.Namespace))
	sb.WriteString("spec:\n")

	if len(spec.PodSelector) == 0 {
		sb.WriteString("  podSelector: {}\n")
	} else {
		sb.WriteString("  podSelector:\n")
		sb.WriteString("    matchLabels:\n")
		for k, v := range spec.PodSelector {
			sb.WriteString(fmt.Sprintf("      %s: \"%s\"\n", k, v))
		}
	}

	sb.WriteString("  policyTypes:\n")
	for _, pt := range spec.PolicyTypes {
		sb.WriteString(fmt.Sprintf("    - %s\n", pt))
	}

	hasIngress := false
	for _, pt := range spec.PolicyTypes {
		if pt == "Ingress" {
			hasIngress = true
			break
		}
	}

	if hasIngress {
		if len(spec.Ingress) == 0 {
			sb.WriteString("  ingress: []\n")
		} else {
			sb.WriteString("  ingress:\n")
			for _, rule := range spec.Ingress {
				sb.WriteString("    - ")
				first := true

				if len(rule.From) > 0 {
					sb.WriteString("from:\n")
					first = false
					for _, from := range rule.From {
						g.writePeerSpec(&sb, from, "        ")
					}
				}

				if len(rule.Ports) > 0 {
					if !first {
						sb.WriteString("      ")
					}
					sb.WriteString("ports:\n")
					for _, port := range rule.Ports {
						sb.WriteString(fmt.Sprintf("        - protocol: %s\n", port.Protocol))
						sb.WriteString(fmt.Sprintf("          port: %d\n", port.Port))
					}
				}
			}
		}
	}

	hasEgress := false
	for _, pt := range spec.PolicyTypes {
		if pt == "Egress" {
			hasEgress = true
			break
		}
	}

	if hasEgress {
		if len(spec.Egress) == 0 {
			sb.WriteString("  egress: []\n")
		} else {
			sb.WriteString("  egress:\n")
			for _, rule := range spec.Egress {
				sb.WriteString("    - ")
				first := true

				if len(rule.To) > 0 {
					sb.WriteString("to:\n")
					first = false
					for _, to := range rule.To {
						g.writePeerSpec(&sb, to, "        ")
					}
				}

				if len(rule.Ports) > 0 {
					if !first {
						sb.WriteString("      ")
					}
					sb.WriteString("ports:\n")
					for _, port := range rule.Ports {
						sb.WriteString(fmt.Sprintf("        - protocol: %s\n", port.Protocol))
						sb.WriteString(fmt.Sprintf("          port: %d\n", port.Port))
					}
				}
			}
		}
	}

	return sb.String()
}

func (g *Generator) writePeerSpec(sb *strings.Builder, peer PeerSpec, indent string) {
	sb.WriteString(fmt.Sprintf("%s- ", indent[:len(indent)-2]))

	if len(peer.NamespaceSelector) > 0 && len(peer.PodSelector) > 0 {
		sb.WriteString("namespaceSelector:\n")
		sb.WriteString(fmt.Sprintf("%s  matchLabels:\n", indent))
		for k, v := range peer.NamespaceSelector {
			sb.WriteString(fmt.Sprintf("%s    %s: \"%s\"\n", indent, k, v))
		}
		sb.WriteString(fmt.Sprintf("%spodSelector:\n", indent))
		sb.WriteString(fmt.Sprintf("%s  matchLabels:\n", indent))
		for k, v := range peer.PodSelector {
			sb.WriteString(fmt.Sprintf("%s    %s: \"%s\"\n", indent, k, v))
		}
	} else if len(peer.NamespaceSelector) > 0 {
		sb.WriteString("namespaceSelector:\n")
		sb.WriteString(fmt.Sprintf("%s  matchLabels:\n", indent))
		for k, v := range peer.NamespaceSelector {
			sb.WriteString(fmt.Sprintf("%s    %s: \"%s\"\n", indent, k, v))
		}
	} else if len(peer.PodSelector) > 0 {
		sb.WriteString("podSelector:\n")
		if len(peer.PodSelector) == 0 {
			sb.WriteString(fmt.Sprintf("%s  matchLabels: {}\n", indent))
		} else {
			sb.WriteString(fmt.Sprintf("%s  matchLabels:\n", indent))
			for k, v := range peer.PodSelector {
				sb.WriteString(fmt.Sprintf("%s    %s: \"%s\"\n", indent, k, v))
			}
		}
	} else if peer.IPBlock != nil {
		sb.WriteString("ipBlock:\n")
		sb.WriteString(fmt.Sprintf("%s  cidr: %s\n", indent, peer.IPBlock.CIDR))
		if len(peer.IPBlock.Except) > 0 {
			sb.WriteString(fmt.Sprintf("%s  except:\n", indent))
			for _, ex := range peer.IPBlock.Except {
				sb.WriteString(fmt.Sprintf("%s    - %s\n", indent, ex))
			}
		}
	} else {
		sb.WriteString("podSelector: {}\n")
	}
}

func (g *Generator) GetAnalysisSummary() string {
	analysis := g.Analyze()
	var sb strings.Builder

	sb.WriteString("Network Policy Analysis\n")
	sb.WriteString("=======================\n\n")

	sb.WriteString(fmt.Sprintf("CNI Plugin: %s (NetworkPolicy support: %v)\n", analysis.CNIName, analysis.CNISupported))
	sb.WriteString(fmt.Sprintf("Existing Policies: %d\n", analysis.ExistingPolicies))
	sb.WriteString(fmt.Sprintf("Unprotected Namespaces: %d\n", len(analysis.UnprotectedNS)))
	sb.WriteString(fmt.Sprintf("Externally Exposed Services: %d\n", len(analysis.ExposedServices)))
	sb.WriteString(fmt.Sprintf("Cross-Namespace Flows Detected: %d\n\n", len(analysis.CrossNSTraffic)))

	if len(analysis.Recommendations) > 0 {
		sb.WriteString("Recommendations:\n")
		for i, rec := range analysis.Recommendations {
			sb.WriteString(fmt.Sprintf("\n%d. [%s] %s\n", i+1, rec.Category, rec.Description))
			sb.WriteString(fmt.Sprintf("   Impact: %s\n", rec.Impact))
			sb.WriteString(fmt.Sprintf("   Action: %s\n", rec.Action))
		}
	}

	return sb.String()
}
