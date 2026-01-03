package graph

import (
	"fmt"
	"strings"
	"time"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
)

type Builder struct {
	inv   *inventory.ClusterInventory
	graph *SecurityGraph

	// Lookup maps for relationship building
	podsByNS          map[string][]inventory.PodInfo
	saByNS            map[string]map[string]*inventory.ServiceAccountInfo
	secretsByNS       map[string]map[string]*inventory.SecretInfo
	servicesByNS      map[string]map[string]*inventory.ServiceInfo
	rolesByNS         map[string]map[string]*inventory.RoleInfo
	clusterRoles      map[string]*inventory.ClusterRoleInfo
	roleBindingsByNS  map[string][]inventory.RoleBindingInfo
	clusterRoleBindings []inventory.ClusterRoleBindingInfo
	networkPoliciesByNS map[string][]inventory.NetworkPolicyInfo
}

func NewBuilder(inv *inventory.ClusterInventory) *Builder {
	return &Builder{
		inv:                 inv,
		graph:               NewSecurityGraph(inv.Cluster.Name),
		podsByNS:            make(map[string][]inventory.PodInfo),
		saByNS:              make(map[string]map[string]*inventory.ServiceAccountInfo),
		secretsByNS:         make(map[string]map[string]*inventory.SecretInfo),
		servicesByNS:        make(map[string]map[string]*inventory.ServiceInfo),
		rolesByNS:           make(map[string]map[string]*inventory.RoleInfo),
		clusterRoles:        make(map[string]*inventory.ClusterRoleInfo),
		roleBindingsByNS:    make(map[string][]inventory.RoleBindingInfo),
		networkPoliciesByNS: make(map[string][]inventory.NetworkPolicyInfo),
	}
}

func (b *Builder) Build() *SecurityGraph {
	b.graph.GeneratedAt = time.Now().UTC().Format(time.RFC3339)

	// Build lookup indexes first
	b.buildIndexes()

	// Add all nodes
	b.addNamespaceNodes()
	b.addPodNodes()
	b.addServiceAccountNodes()
	b.addRoleNodes()
	b.addSecretNodes()
	b.addServiceNodes()
	b.addIngressNodes()
	b.addNodeNodes()
	b.addExternalNodes()

	// Add all edges (relationships)
	b.addPodServiceAccountEdges()
	b.addRBACBindingEdges()
	b.addSecretMountEdges()
	b.addServicePodEdges()
	b.addIngressServiceEdges()
	b.addExternalExposureEdges()
	b.addNetworkPolicyEdges()
	b.addContainerEscapeEdges()
	b.addPrivilegeEscalationEdges()
	b.addLateralMovementEdges()

	// Calculate summary
	b.calculateSummary()

	return b.graph
}

func (b *Builder) buildIndexes() {
	// Index pods by namespace
	for _, pod := range b.inv.Workloads.Pods {
		b.podsByNS[pod.Namespace] = append(b.podsByNS[pod.Namespace], pod)
	}

	// Index service accounts
	for i := range b.inv.ServiceAccounts {
		sa := &b.inv.ServiceAccounts[i]
		if b.saByNS[sa.Namespace] == nil {
			b.saByNS[sa.Namespace] = make(map[string]*inventory.ServiceAccountInfo)
		}
		b.saByNS[sa.Namespace][sa.Name] = sa
	}

	// Index secrets
	for i := range b.inv.Secrets {
		secret := &b.inv.Secrets[i]
		if b.secretsByNS[secret.Namespace] == nil {
			b.secretsByNS[secret.Namespace] = make(map[string]*inventory.SecretInfo)
		}
		b.secretsByNS[secret.Namespace][secret.Name] = secret
	}

	// Index services
	for i := range b.inv.Services {
		svc := &b.inv.Services[i]
		if b.servicesByNS[svc.Namespace] == nil {
			b.servicesByNS[svc.Namespace] = make(map[string]*inventory.ServiceInfo)
		}
		b.servicesByNS[svc.Namespace][svc.Name] = svc
	}

	// Index roles
	for i := range b.inv.RBAC.Roles {
		role := &b.inv.RBAC.Roles[i]
		if b.rolesByNS[role.Namespace] == nil {
			b.rolesByNS[role.Namespace] = make(map[string]*inventory.RoleInfo)
		}
		b.rolesByNS[role.Namespace][role.Name] = role
	}

	// Index cluster roles
	for i := range b.inv.RBAC.ClusterRoles {
		cr := &b.inv.RBAC.ClusterRoles[i]
		b.clusterRoles[cr.Name] = cr
	}

	// Index role bindings
	for _, rb := range b.inv.RBAC.RoleBindings {
		b.roleBindingsByNS[rb.Namespace] = append(b.roleBindingsByNS[rb.Namespace], rb)
	}

	// Store cluster role bindings
	b.clusterRoleBindings = b.inv.RBAC.ClusterRoleBindings

	// Index network policies
	for _, np := range b.inv.NetworkPolicies {
		b.networkPoliciesByNS[np.Namespace] = append(b.networkPoliciesByNS[np.Namespace], np)
	}
}

func (b *Builder) addNamespaceNodes() {
	for _, ns := range b.inv.Namespaces {
		risk := b.calculateNamespaceRisk(ns.Name)
		b.graph.AddNode(Node{
			ID:        fmt.Sprintf("namespace/%s", ns.Name),
			Type:      NodeNamespace,
			Name:      ns.Name,
			Risk:      risk,
			RiskScore: riskToScore(risk),
			Labels:    ns.Labels,
		})
	}
}

func (b *Builder) addPodNodes() {
	for _, pod := range b.inv.Workloads.Pods {
		risk, findings := b.calculatePodRisk(pod)
		props := map[string]any{
			"serviceAccount": pod.ServiceAccount,
			"nodeName":       pod.NodeName,
			"hostNetwork":    pod.HostNetwork,
			"hostPID":        pod.HostPID,
			"hostIPC":        pod.HostIPC,
			"phase":          pod.Phase,
		}

		b.graph.AddNode(Node{
			ID:         fmt.Sprintf("pod/%s/%s", pod.Namespace, pod.Name),
			Type:       NodePod,
			Name:       pod.Name,
			Namespace:  pod.Namespace,
			Risk:       risk,
			RiskScore:  riskToScore(risk),
			Labels:     pod.Labels,
			Properties: props,
			Findings:   findings,
		})
	}
}

func (b *Builder) addServiceAccountNodes() {
	for _, sa := range b.inv.ServiceAccounts {
		risk := b.calculateServiceAccountRisk(sa)
		props := map[string]any{
			"automountToken": sa.AutomountServiceAccountToken,
			"secretCount":    len(sa.Secrets),
		}

		b.graph.AddNode(Node{
			ID:         fmt.Sprintf("sa/%s/%s", sa.Namespace, sa.Name),
			Type:       NodeServiceAccount,
			Name:       sa.Name,
			Namespace:  sa.Namespace,
			Risk:       risk,
			RiskScore:  riskToScore(risk),
			Labels:     sa.Labels,
			Properties: props,
		})
	}
}

func (b *Builder) addRoleNodes() {
	// Add Roles
	for _, role := range b.inv.RBAC.Roles {
		risk := b.calculateRoleRisk(role.Rules)
		props := map[string]any{
			"ruleCount": len(role.Rules),
		}

		b.graph.AddNode(Node{
			ID:         fmt.Sprintf("role/%s/%s", role.Namespace, role.Name),
			Type:       NodeRole,
			Name:       role.Name,
			Namespace:  role.Namespace,
			Risk:       risk,
			RiskScore:  riskToScore(risk),
			Labels:     role.Labels,
			Properties: props,
		})
	}

	// Add ClusterRoles
	for _, cr := range b.inv.RBAC.ClusterRoles {
		risk := b.calculateRoleRisk(cr.Rules)
		props := map[string]any{
			"ruleCount": len(cr.Rules),
		}

		b.graph.AddNode(Node{
			ID:         fmt.Sprintf("clusterrole/%s", cr.Name),
			Type:       NodeClusterRole,
			Name:       cr.Name,
			Risk:       risk,
			RiskScore:  riskToScore(risk),
			Labels:     cr.Labels,
			Properties: props,
		})
	}

	// Add RoleBindings
	for _, rb := range b.inv.RBAC.RoleBindings {
		b.graph.AddNode(Node{
			ID:        fmt.Sprintf("rolebinding/%s/%s", rb.Namespace, rb.Name),
			Type:      NodeRoleBinding,
			Name:      rb.Name,
			Namespace: rb.Namespace,
			Risk:      RiskInfo,
			RiskScore: 0,
			Labels:    rb.Labels,
		})
	}

	// Add ClusterRoleBindings
	for _, crb := range b.inv.RBAC.ClusterRoleBindings {
		risk := b.calculateClusterRoleBindingRisk(crb)
		b.graph.AddNode(Node{
			ID:        fmt.Sprintf("clusterrolebinding/%s", crb.Name),
			Type:      NodeClusterRoleBinding,
			Name:      crb.Name,
			Risk:      risk,
			RiskScore: riskToScore(risk),
			Labels:    crb.Labels,
		})
	}
}

func (b *Builder) addSecretNodes() {
	for _, secret := range b.inv.Secrets {
		risk := b.calculateSecretRisk(secret)
		props := map[string]any{
			"type":     secret.Type,
			"keyCount": len(secret.DataKeys),
		}

		b.graph.AddNode(Node{
			ID:         fmt.Sprintf("secret/%s/%s", secret.Namespace, secret.Name),
			Type:       NodeSecret,
			Name:       secret.Name,
			Namespace:  secret.Namespace,
			Risk:       risk,
			RiskScore:  riskToScore(risk),
			Labels:     secret.Labels,
			Properties: props,
		})
	}
}

func (b *Builder) addServiceNodes() {
	for _, svc := range b.inv.Services {
		risk := b.calculateServiceRisk(svc)
		props := map[string]any{
			"type":      svc.Type,
			"clusterIP": svc.ClusterIP,
			"portCount": len(svc.Ports),
		}

		b.graph.AddNode(Node{
			ID:         fmt.Sprintf("service/%s/%s", svc.Namespace, svc.Name),
			Type:       NodeService,
			Name:       svc.Name,
			Namespace:  svc.Namespace,
			Risk:       risk,
			RiskScore:  riskToScore(risk),
			Labels:     svc.Labels,
			Properties: props,
		})
	}
}

func (b *Builder) addIngressNodes() {
	for _, ing := range b.inv.Ingresses {
		risk := b.calculateIngressRisk(ing)
		var hosts []string
		for _, rule := range ing.Rules {
			if rule.Host != "" {
				hosts = append(hosts, rule.Host)
			}
		}
		props := map[string]any{
			"hosts":    hosts,
			"hasTLS":   len(ing.TLS) > 0,
			"ruleCount": len(ing.Rules),
		}

		b.graph.AddNode(Node{
			ID:         fmt.Sprintf("ingress/%s/%s", ing.Namespace, ing.Name),
			Type:       NodeIngress,
			Name:       ing.Name,
			Namespace:  ing.Namespace,
			Risk:       risk,
			RiskScore:  riskToScore(risk),
			Labels:     ing.Labels,
			Properties: props,
		})
	}
}

func (b *Builder) addNodeNodes() {
	for _, node := range b.inv.Nodes {
		risk := RiskInfo
		props := map[string]any{
			"kubeletVersion":   node.KubeletVersion,
			"containerRuntime": node.ContainerRuntime,
			"osImage":          node.OSImage,
			"architecture":     node.Architecture,
		}

		b.graph.AddNode(Node{
			ID:         fmt.Sprintf("node/%s", node.Name),
			Type:       NodeNode,
			Name:       node.Name,
			Risk:       risk,
			RiskScore:  riskToScore(risk),
			Labels:     node.Labels,
			Properties: props,
		})
	}
}

func (b *Builder) addExternalNodes() {
	// Add Internet node
	b.graph.AddNode(Node{
		ID:        "external/internet",
		Type:      NodeExternal,
		Name:      "Internet",
		Risk:      RiskHigh,
		RiskScore: 80,
		Properties: map[string]any{
			"type": "internet",
		},
	})

	// Add Cloud Metadata node (for cloud clusters)
	if b.inv.Cluster.Provider != "" && b.inv.Cluster.Provider != "unknown" {
		b.graph.AddNode(Node{
			ID:        "external/cloud-metadata",
			Type:      NodeExternal,
			Name:      "Cloud Metadata Service",
			Risk:      RiskCritical,
			RiskScore: 95,
			Properties: map[string]any{
				"type":     "cloud-metadata",
				"provider": b.inv.Cluster.Provider,
				"endpoint": "169.254.169.254",
			},
		})
	}
}

func (b *Builder) addPodServiceAccountEdges() {
	for _, pod := range b.inv.Workloads.Pods {
		saID := fmt.Sprintf("sa/%s/%s", pod.Namespace, pod.ServiceAccount)
		podID := fmt.Sprintf("pod/%s/%s", pod.Namespace, pod.Name)

		// Check if automount is enabled
		automount := true
		if pod.AutomountSAToken != nil {
			automount = *pod.AutomountSAToken
		}

		b.graph.AddEdge(Edge{
			Source: podID,
			Target: saID,
			Type:   EdgeUses,
			Label:  "uses",
			Properties: map[string]any{
				"automountToken": automount,
			},
		})

		// Add pod to node edge
		if pod.NodeName != "" {
			nodeID := fmt.Sprintf("node/%s", pod.NodeName)
			b.graph.AddEdge(Edge{
				Source: podID,
				Target: nodeID,
				Type:   EdgeUses,
				Label:  "runs on",
			})
		}

		// Add pod to namespace edge
		nsID := fmt.Sprintf("namespace/%s", pod.Namespace)
		b.graph.AddEdge(Edge{
			Source: podID,
			Target: nsID,
			Type:   EdgeUses,
			Label:  "in namespace",
		})
	}
}

func (b *Builder) addRBACBindingEdges() {
	// Process RoleBindings
	for _, rb := range b.inv.RBAC.RoleBindings {
		rbID := fmt.Sprintf("rolebinding/%s/%s", rb.Namespace, rb.Name)

		// RoleBinding -> Role/ClusterRole
		var roleID string
		if rb.RoleRef.Kind == "Role" {
			roleID = fmt.Sprintf("role/%s/%s", rb.Namespace, rb.RoleRef.Name)
		} else {
			roleID = fmt.Sprintf("clusterrole/%s", rb.RoleRef.Name)
		}

		b.graph.AddEdge(Edge{
			Source: rbID,
			Target: roleID,
			Type:   EdgeBindsTo,
			Label:  "binds to",
		})

		// Subject -> RoleBinding
		for _, subj := range rb.Subjects {
			var subjID string
			switch subj.Kind {
			case "ServiceAccount":
				ns := subj.Namespace
				if ns == "" {
					ns = rb.Namespace
				}
				subjID = fmt.Sprintf("sa/%s/%s", ns, subj.Name)
			case "User":
				subjID = fmt.Sprintf("user/%s", subj.Name)
				b.graph.AddNode(Node{
					ID:   subjID,
					Type: NodeExternal,
					Name: subj.Name,
					Risk: RiskInfo,
					Properties: map[string]any{
						"type": "user",
					},
				})
			case "Group":
				subjID = fmt.Sprintf("group/%s", subj.Name)
				risk := RiskInfo
				if subj.Name == "system:authenticated" || subj.Name == "system:unauthenticated" {
					risk = RiskHigh
				}
				b.graph.AddNode(Node{
					ID:   subjID,
					Type: NodeExternal,
					Name: subj.Name,
					Risk: risk,
					Properties: map[string]any{
						"type": "group",
					},
				})
			}

			if subjID != "" {
				b.graph.AddEdge(Edge{
					Source: subjID,
					Target: rbID,
					Type:   EdgeBindsTo,
					Label:  "bound via",
				})
			}
		}
	}

	// Process ClusterRoleBindings
	for _, crb := range b.inv.RBAC.ClusterRoleBindings {
		crbID := fmt.Sprintf("clusterrolebinding/%s", crb.Name)
		roleID := fmt.Sprintf("clusterrole/%s", crb.RoleRef.Name)

		b.graph.AddEdge(Edge{
			Source: crbID,
			Target: roleID,
			Type:   EdgeBindsTo,
			Label:  "binds to",
		})

		for _, subj := range crb.Subjects {
			var subjID string
			switch subj.Kind {
			case "ServiceAccount":
				subjID = fmt.Sprintf("sa/%s/%s", subj.Namespace, subj.Name)
			case "User":
				subjID = fmt.Sprintf("user/%s", subj.Name)
				b.graph.AddNode(Node{
					ID:   subjID,
					Type: NodeExternal,
					Name: subj.Name,
					Risk: RiskInfo,
					Properties: map[string]any{
						"type": "user",
					},
				})
			case "Group":
				subjID = fmt.Sprintf("group/%s", subj.Name)
				risk := RiskInfo
				if subj.Name == "system:authenticated" || subj.Name == "system:unauthenticated" {
					risk = RiskHigh
				}
				b.graph.AddNode(Node{
					ID:   subjID,
					Type: NodeExternal,
					Name: subj.Name,
					Risk: risk,
					Properties: map[string]any{
						"type": "group",
					},
				})
			}

			if subjID != "" {
				b.graph.AddEdge(Edge{
					Source: subjID,
					Target: crbID,
					Type:   EdgeBindsTo,
					Label:  "bound via",
				})
			}
		}
	}
}

func (b *Builder) addSecretMountEdges() {
	for _, pod := range b.inv.Workloads.Pods {
		podID := fmt.Sprintf("pod/%s/%s", pod.Namespace, pod.Name)

		// Check volume mounts
		for _, vol := range pod.Volumes {
			if vol.Type == "Secret" {
				secretID := fmt.Sprintf("secret/%s/%s", pod.Namespace, vol.Source)
				b.graph.AddEdge(Edge{
					Source: podID,
					Target: secretID,
					Type:   EdgeMounts,
					Label:  "mounts",
				})
			} else if vol.Type == "ConfigMap" {
				cmID := fmt.Sprintf("configmap/%s/%s", pod.Namespace, vol.Source)
				b.graph.AddEdge(Edge{
					Source: podID,
					Target: cmID,
					Type:   EdgeMounts,
					Label:  "mounts",
				})
			}
		}
	}
}

func (b *Builder) addServicePodEdges() {
	for _, svc := range b.inv.Services {
		svcID := fmt.Sprintf("service/%s/%s", svc.Namespace, svc.Name)

		// Find pods matching service selector via labels
		for _, pod := range b.podsByNS[svc.Namespace] {
			if matchesSelector(pod.Labels, svc.Labels) {
				podID := fmt.Sprintf("pod/%s/%s", pod.Namespace, pod.Name)
				b.graph.AddEdge(Edge{
					Source: svcID,
					Target: podID,
					Type:   EdgeExposes,
					Label:  "exposes",
				})
			}
		}
	}
}

func (b *Builder) addIngressServiceEdges() {
	for _, ing := range b.inv.Ingresses {
		ingID := fmt.Sprintf("ingress/%s/%s", ing.Namespace, ing.Name)

		// Connect ingress to services
		for _, rule := range ing.Rules {
			for _, path := range rule.Paths {
				// Backend typically is "service:port"
				parts := strings.Split(path.Backend, ":")
				if len(parts) > 0 {
					svcName := parts[0]
					svcID := fmt.Sprintf("service/%s/%s", ing.Namespace, svcName)
					b.graph.AddEdge(Edge{
						Source: ingID,
						Target: svcID,
						Type:   EdgeExposes,
						Label:  path.Path,
						Properties: map[string]any{
							"host": rule.Host,
							"path": path.Path,
						},
					})
				}
			}
		}
	}
}

func (b *Builder) addExternalExposureEdges() {
	internetID := "external/internet"

	// LoadBalancers exposed to internet
	for _, lb := range b.inv.AttackSurface.LoadBalancers {
		svcID := fmt.Sprintf("service/%s/%s", lb.Namespace, lb.Name)
		b.graph.AddEdge(Edge{
			Source: internetID,
			Target: svcID,
			Type:   EdgeExposedTo,
			Risk:   RiskHigh,
			Label:  "LoadBalancer",
			Properties: map[string]any{
				"ports": lb.Ports,
			},
		})
		b.graph.Summary.ExternalExposures++
	}

	// NodePorts exposed to internet
	for _, np := range b.inv.AttackSurface.NodePorts {
		svcID := fmt.Sprintf("service/%s/%s", np.Namespace, np.Name)
		b.graph.AddEdge(Edge{
			Source: internetID,
			Target: svcID,
			Type:   EdgeExposedTo,
			Risk:   RiskMedium,
			Label:  "NodePort",
			Properties: map[string]any{
				"ports": np.Ports,
			},
		})
		b.graph.Summary.ExternalExposures++
	}

	// Ingresses exposed to internet
	for _, ing := range b.inv.AttackSurface.Ingresses {
		ingID := fmt.Sprintf("ingress/%s/%s", ing.Namespace, ing.Name)
		risk := RiskMedium
		if !ing.TLS {
			risk = RiskHigh
		}
		b.graph.AddEdge(Edge{
			Source: internetID,
			Target: ingID,
			Type:   EdgeExposedTo,
			Risk:   risk,
			Label:  "Ingress",
			Properties: map[string]any{
				"hosts": ing.Hosts,
				"tls":   ing.TLS,
			},
		})
		b.graph.Summary.ExternalExposures++
	}
}

func (b *Builder) addNetworkPolicyEdges() {
	for _, np := range b.inv.NetworkPolicies {
		npID := fmt.Sprintf("networkpolicy/%s/%s", np.Namespace, np.Name)
		b.graph.AddNode(Node{
			ID:        npID,
			Type:      NodeNetworkPolicy,
			Name:      np.Name,
			Namespace: np.Namespace,
			Risk:      RiskInfo,
		})

		// Find pods affected by this policy
		for _, pod := range b.podsByNS[np.Namespace] {
			if matchesSelector(pod.Labels, np.PodSelector) {
				podID := fmt.Sprintf("pod/%s/%s", pod.Namespace, pod.Name)
				b.graph.AddEdge(Edge{
					Source: npID,
					Target: podID,
					Type:   EdgeBlocks,
					Label:  "protects",
				})
			}
		}
	}
}

func (b *Builder) addContainerEscapeEdges() {
	for _, pod := range b.inv.Workloads.Pods {
		podID := fmt.Sprintf("pod/%s/%s", pod.Namespace, pod.Name)
		nodeID := fmt.Sprintf("node/%s", pod.NodeName)

		escapeRisks := b.detectContainerEscapeRisks(pod)
		for _, risk := range escapeRisks {
			b.graph.AddEdge(Edge{
				Source: podID,
				Target: nodeID,
				Type:   EdgeEscapesTo,
				Risk:   RiskCritical,
				Label:  risk,
				Properties: map[string]any{
					"escapeVector": risk,
				},
			})
			b.graph.Summary.ContainerEscapes++
		}
	}
}

func (b *Builder) addPrivilegeEscalationEdges() {
	// Find service accounts with escalation-capable permissions
	escalationRoles := b.findEscalationCapableRoles()

	for saKey, roles := range escalationRoles {
		parts := strings.Split(saKey, "/")
		if len(parts) != 2 {
			continue
		}
		ns, name := parts[0], parts[1]
		saID := fmt.Sprintf("sa/%s/%s", ns, name)

		for _, role := range roles {
			roleID := role
			b.graph.AddEdge(Edge{
				Source: saID,
				Target: roleID,
				Type:   EdgeEscalatesTo,
				Risk:   RiskCritical,
				Label:  "can escalate",
			})
			b.graph.Summary.PrivilegeEscalations++
		}
	}
}

func (b *Builder) addLateralMovementEdges() {
	// Find pods with exec access to other pods
	for _, pod := range b.inv.Workloads.Pods {
		podID := fmt.Sprintf("pod/%s/%s", pod.Namespace, pod.Name)
		saKey := fmt.Sprintf("%s/%s", pod.Namespace, pod.ServiceAccount)

		// Check if this pod's SA can exec into other pods
		if b.canExecIntoPods(saKey) {
			// Add edges to other pods in same namespace
			for _, targetPod := range b.podsByNS[pod.Namespace] {
				if targetPod.Name == pod.Name {
					continue
				}
				targetID := fmt.Sprintf("pod/%s/%s", targetPod.Namespace, targetPod.Name)
				b.graph.AddEdge(Edge{
					Source: podID,
					Target: targetID,
					Type:   EdgeCanExec,
					Risk:   RiskHigh,
					Label:  "can exec",
				})
			}
		}

		// Check for cross-namespace access
		if b.hasCrossNamespaceAccess(saKey) {
			for ns := range b.podsByNS {
				if ns == pod.Namespace {
					continue
				}
				nsID := fmt.Sprintf("namespace/%s", ns)
				b.graph.AddEdge(Edge{
					Source: podID,
					Target: nsID,
					Type:   EdgeCanAccess,
					Risk:   RiskHigh,
					Label:  "cross-namespace access",
				})
			}
		}
	}
}


func (b *Builder) calculateNamespaceRisk(name string) RiskLevel {
	// Check if namespace has network policies
	policies := b.networkPoliciesByNS[name]
	if len(policies) == 0 {
		return RiskMedium
	}
	return RiskLow
}

func (b *Builder) calculatePodRisk(pod inventory.PodInfo) (RiskLevel, []string) {
	var findings []string
	score := 0

	if pod.HostNetwork {
		score += 30
		findings = append(findings, "hostNetwork enabled")
	}
	if pod.HostPID {
		score += 30
		findings = append(findings, "hostPID enabled")
	}
	if pod.HostIPC {
		score += 20
		findings = append(findings, "hostIPC enabled")
	}

	for _, container := range pod.Containers {
		if container.SecurityContext != nil {
			sc := container.SecurityContext
			if sc.Privileged != nil && *sc.Privileged {
				score += 40
				findings = append(findings, fmt.Sprintf("container %s is privileged", container.Name))
			}
			if sc.AllowPrivilegeEscalation != nil && *sc.AllowPrivilegeEscalation {
				score += 20
				findings = append(findings, fmt.Sprintf("container %s allows privilege escalation", container.Name))
			}
			if sc.Capabilities != nil {
				for _, cap := range sc.Capabilities.Add {
					if isDangerousCapability(cap) {
						score += 25
						findings = append(findings, fmt.Sprintf("container %s has dangerous capability %s", container.Name, cap))
					}
				}
			}
		}
	}

	// Check for dangerous volume mounts
	for _, vol := range pod.Volumes {
		if vol.Type == "HostPath" {
			if strings.Contains(vol.Source, "docker.sock") {
				score += 50
				findings = append(findings, "mounts docker.sock")
			} else if vol.Source == "/" || vol.Source == "/etc" || vol.Source == "/var" {
				score += 30
				findings = append(findings, fmt.Sprintf("mounts sensitive host path: %s", vol.Source))
			}
		}
	}

	risk := scoreToRisk(score)
	return risk, findings
}

func (b *Builder) calculateServiceAccountRisk(sa inventory.ServiceAccountInfo) RiskLevel {
	// Check if default SA with permissions
	if sa.Name == "default" {
		// Look up if it has any bindings
		for _, rb := range b.roleBindingsByNS[sa.Namespace] {
			for _, subj := range rb.Subjects {
				if subj.Kind == "ServiceAccount" && subj.Name == "default" {
					return RiskMedium
				}
			}
		}
	}

	// Check automount
	if sa.AutomountServiceAccountToken != nil && *sa.AutomountServiceAccountToken {
		return RiskLow
	}

	return RiskInfo
}

func (b *Builder) calculateRoleRisk(rules []inventory.PolicyRule) RiskLevel {
	score := 0

	for _, rule := range rules {
		// Check for wildcards
		for _, verb := range rule.Verbs {
			if verb == "*" {
				score += 40
			}
		}
		for _, res := range rule.Resources {
			if res == "*" {
				score += 30
			}
		}

		// Check for dangerous permissions
		if containsAny(rule.Resources, "secrets") {
			if containsAny(rule.Verbs, "get", "list", "watch", "*") {
				score += 25
			}
		}
		if containsAny(rule.Verbs, "bind", "escalate", "impersonate") {
			score += 35
		}
		if containsAny(rule.Resources, "pods/exec", "pods/attach") {
			score += 30
		}
	}

	return scoreToRisk(score)
}

func (b *Builder) calculateClusterRoleBindingRisk(crb inventory.ClusterRoleBindingInfo) RiskLevel {
	// Check if binding to cluster-admin
	if crb.RoleRef.Name == "cluster-admin" {
		return RiskCritical
	}

	// Check for system:authenticated or system:unauthenticated
	for _, subj := range crb.Subjects {
		if subj.Kind == "Group" {
			if subj.Name == "system:unauthenticated" {
				return RiskCritical
			}
			if subj.Name == "system:authenticated" {
				return RiskHigh
			}
		}
	}

	return RiskInfo
}

func (b *Builder) calculateSecretRisk(secret inventory.SecretInfo) RiskLevel {
	// High-risk secret types
	if secret.Type == "kubernetes.io/tls" {
		return RiskMedium
	}
	if secret.Type == "kubernetes.io/dockerconfigjson" {
		return RiskMedium
	}
	if strings.Contains(secret.Name, "token") || strings.Contains(secret.Name, "password") {
		return RiskMedium
	}
	return RiskLow
}

func (b *Builder) calculateServiceRisk(svc inventory.ServiceInfo) RiskLevel {
	if svc.Type == "LoadBalancer" {
		return RiskHigh
	}
	if svc.Type == "NodePort" {
		return RiskMedium
	}
	if len(svc.ExternalIPs) > 0 {
		return RiskHigh
	}
	return RiskLow
}

func (b *Builder) calculateIngressRisk(ing inventory.IngressInfo) RiskLevel {
	if len(ing.TLS) == 0 {
		return RiskHigh // No TLS
	}
	return RiskMedium // Exposed but with TLS
}

func (b *Builder) detectContainerEscapeRisks(pod inventory.PodInfo) []string {
	var risks []string

	// Check for docker.sock mount
	for _, vol := range pod.Volumes {
		if vol.Type == "HostPath" && strings.Contains(vol.Source, "docker.sock") {
			risks = append(risks, "docker.sock mount")
		}
		if vol.Type == "HostPath" && (vol.Source == "/" || strings.HasPrefix(vol.Source, "/proc") || strings.HasPrefix(vol.Source, "/sys")) {
			risks = append(risks, "sensitive host path mount")
		}
	}

	// Check for privileged + hostPID
	if pod.HostPID {
		for _, c := range pod.Containers {
			if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				risks = append(risks, "privileged + hostPID")
			}
		}
	}

	// Check for dangerous capabilities
	for _, c := range pod.Containers {
		if c.SecurityContext != nil && c.SecurityContext.Capabilities != nil {
			for _, cap := range c.SecurityContext.Capabilities.Add {
				if cap == "SYS_ADMIN" || cap == "SYS_PTRACE" {
					risks = append(risks, fmt.Sprintf("CAP_%s", cap))
				}
			}
		}
	}

	return risks
}

func (b *Builder) findEscalationCapableRoles() map[string][]string {
	result := make(map[string][]string)

	// Check ClusterRoleBindings
	for _, crb := range b.clusterRoleBindings {
		role := b.clusterRoles[crb.RoleRef.Name]
		if role == nil {
			continue
		}

		canEscalate := false
		for _, rule := range role.Rules {
			if containsAny(rule.Verbs, "bind", "escalate", "impersonate") {
				canEscalate = true
				break
			}
			if containsAny(rule.Resources, "clusterrolebindings", "rolebindings") &&
				containsAny(rule.Verbs, "create", "update", "patch", "*") {
				canEscalate = true
				break
			}
		}

		if canEscalate {
			for _, subj := range crb.Subjects {
				if subj.Kind == "ServiceAccount" {
					key := fmt.Sprintf("%s/%s", subj.Namespace, subj.Name)
					result[key] = append(result[key], fmt.Sprintf("clusterrole/%s", crb.RoleRef.Name))
				}
			}
		}
	}

	return result
}

func (b *Builder) canExecIntoPods(saKey string) bool {
	parts := strings.Split(saKey, "/")
	if len(parts) != 2 {
		return false
	}
	ns, name := parts[0], parts[1]

	// Check RoleBindings in the namespace
	for _, rb := range b.roleBindingsByNS[ns] {
		for _, subj := range rb.Subjects {
			if subj.Kind == "ServiceAccount" && subj.Name == name {
				// Check role permissions
				if rb.RoleRef.Kind == "Role" {
					if role, ok := b.rolesByNS[ns][rb.RoleRef.Name]; ok {
						for _, rule := range role.Rules {
							if containsAny(rule.Resources, "pods/exec", "pods/*", "*") &&
								containsAny(rule.Verbs, "create", "*") {
								return true
							}
						}
					}
				} else {
					if cr := b.clusterRoles[rb.RoleRef.Name]; cr != nil {
						for _, rule := range cr.Rules {
							if containsAny(rule.Resources, "pods/exec", "pods/*", "*") &&
								containsAny(rule.Verbs, "create", "*") {
								return true
							}
						}
					}
				}
			}
		}
	}

	// Check ClusterRoleBindings
	for _, crb := range b.clusterRoleBindings {
		for _, subj := range crb.Subjects {
			if subj.Kind == "ServiceAccount" && subj.Namespace == ns && subj.Name == name {
				if cr := b.clusterRoles[crb.RoleRef.Name]; cr != nil {
					for _, rule := range cr.Rules {
						if containsAny(rule.Resources, "pods/exec", "pods/*", "*") &&
							containsAny(rule.Verbs, "create", "*") {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

func (b *Builder) hasCrossNamespaceAccess(saKey string) bool {
	parts := strings.Split(saKey, "/")
	if len(parts) != 2 {
		return false
	}
	ns, name := parts[0], parts[1]

	// Check ClusterRoleBindings that grant cross-namespace access
	for _, crb := range b.clusterRoleBindings {
		for _, subj := range crb.Subjects {
			if subj.Kind == "ServiceAccount" && subj.Namespace == ns && subj.Name == name {
				if cr := b.clusterRoles[crb.RoleRef.Name]; cr != nil {
					for _, rule := range cr.Rules {
						// Check if the role grants access to cluster-scoped resources
						if containsAny(rule.Resources, "*", "namespaces", "nodes", "persistentvolumes") {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

func (b *Builder) calculateSummary() {
	// Count data exfiltration risks
	for _, pod := range b.inv.Workloads.Pods {
		// Check if pod has unrestricted egress
		policies := b.networkPoliciesByNS[pod.Namespace]
		hasEgressPolicy := false
		for _, np := range policies {
			for _, pt := range np.PolicyTypes {
				if pt == "Egress" {
					hasEgressPolicy = true
					break
				}
			}
		}
		if !hasEgressPolicy {
			b.graph.Summary.DataExfiltrationRisks++
		}
	}
}


func riskToScore(risk RiskLevel) int {
	switch risk {
	case RiskCritical:
		return 95
	case RiskHigh:
		return 75
	case RiskMedium:
		return 50
	case RiskLow:
		return 25
	default:
		return 10
	}
}

func scoreToRisk(score int) RiskLevel {
	if score >= 80 {
		return RiskCritical
	}
	if score >= 50 {
		return RiskHigh
	}
	if score >= 25 {
		return RiskMedium
	}
	if score >= 10 {
		return RiskLow
	}
	return RiskInfo
}

func isDangerousCapability(cap string) bool {
	dangerous := map[string]bool{
		"SYS_ADMIN":      true,
		"SYS_PTRACE":     true,
		"SYS_MODULE":     true,
		"DAC_OVERRIDE":   true,
		"NET_ADMIN":      true,
		"NET_RAW":        true,
		"SYS_RAWIO":      true,
		"MKNOD":          true,
		"SYS_CHROOT":     true,
		"AUDIT_CONTROL":  true,
		"AUDIT_WRITE":    true,
		"BLOCK_SUSPEND":  true,
		"MAC_ADMIN":      true,
		"MAC_OVERRIDE":   true,
		"SETFCAP":        true,
		"SYSLOG":         true,
		"WAKE_ALARM":     true,
	}
	return dangerous[cap]
}

func matchesSelector(labels, selector map[string]string) bool {
	if len(selector) == 0 {
		return true
	}
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

func containsAny(slice []string, items ...string) bool {
	for _, item := range items {
		for _, s := range slice {
			if s == item {
				return true
			}
		}
	}
	return false
}
