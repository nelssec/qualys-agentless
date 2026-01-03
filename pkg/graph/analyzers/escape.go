package analyzers

import (
	"fmt"
	"strings"

	"github.com/nelssec/qualys-agentless/pkg/graph"
	"github.com/nelssec/qualys-agentless/pkg/inventory"
)

type EscapeAnalyzer struct {
	g   *graph.SecurityGraph
	inv *inventory.ClusterInventory
}

type ContainerEscapeVector struct {
	ID            string   `json:"id"`
	PodName       string   `json:"podName"`
	PodNamespace  string   `json:"podNamespace"`
	ContainerName string   `json:"containerName"`
	Vector        string   `json:"vector"`
	Severity      string   `json:"severity"`
	Description   string   `json:"description"`
	Impact        string   `json:"impact"`
	CVE           string   `json:"cve,omitempty"`
	Remediation   []string `json:"remediation"`
}

func NewEscapeAnalyzer(g *graph.SecurityGraph, inv *inventory.ClusterInventory) *EscapeAnalyzer {
	return &EscapeAnalyzer{g: g, inv: inv}
}

func (a *EscapeAnalyzer) Analyze() []ContainerEscapeVector {
	var vectors []ContainerEscapeVector

	for _, pod := range a.inv.Workloads.Pods {
		// Check each container
		for _, container := range pod.Containers {
			containerVectors := a.analyzeContainer(pod, container)
			vectors = append(vectors, containerVectors...)
		}

		// Check init containers too
		for _, container := range pod.InitContainers {
			containerVectors := a.analyzeContainer(pod, container)
			vectors = append(vectors, containerVectors...)
		}

		// Check pod-level escape vectors
		podVectors := a.analyzePodLevel(pod)
		vectors = append(vectors, podVectors...)
	}

	return vectors
}

func (a *EscapeAnalyzer) analyzeContainer(pod inventory.PodInfo, container inventory.ContainerInfo) []ContainerEscapeVector {
	var vectors []ContainerEscapeVector
	baseID := fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)

	sc := container.SecurityContext
	if sc == nil {
		return vectors
	}

	// Check privileged mode
	if sc.Privileged != nil && *sc.Privileged {
		vectors = append(vectors, ContainerEscapeVector{
			ID:            fmt.Sprintf("%s-privileged", baseID),
			PodName:       pod.Name,
			PodNamespace:  pod.Namespace,
			ContainerName: container.Name,
			Vector:        "privileged-container",
			Severity:      "CRITICAL",
			Description:   "Container runs in privileged mode, granting full access to host resources",
			Impact:        "Attacker can escape container and compromise the node with full root access",
			Remediation: []string{
				"Remove privileged: true from security context",
				"Use specific capabilities instead of privileged mode",
				"Implement PodSecurityAdmission with restricted profile",
			},
		})
	}

	// Check dangerous capabilities
	if sc.Capabilities != nil {
		for _, cap := range sc.Capabilities.Add {
			if vector := a.checkCapability(baseID, pod, container, cap); vector != nil {
				vectors = append(vectors, *vector)
			}
		}
	}

	return vectors
}

func (a *EscapeAnalyzer) checkCapability(baseID string, pod inventory.PodInfo, container inventory.ContainerInfo, cap string) *ContainerEscapeVector {
	switch cap {
	case "SYS_ADMIN":
		return &ContainerEscapeVector{
			ID:            fmt.Sprintf("%s-cap-sys-admin", baseID),
			PodName:       pod.Name,
			PodNamespace:  pod.Namespace,
			ContainerName: container.Name,
			Vector:        "CAP_SYS_ADMIN",
			Severity:      "CRITICAL",
			Description:   "CAP_SYS_ADMIN allows mounting filesystems, loading kernel modules, and other admin operations",
			Impact:        "Attacker can mount host filesystem, escape container, and gain root on node",
			CVE:           "CVE-2022-0185",
			Remediation: []string{
				"Remove CAP_SYS_ADMIN capability",
				"Use specific capabilities for required functionality",
				"Implement AppArmor or SELinux policies",
			},
		}

	case "SYS_PTRACE":
		return &ContainerEscapeVector{
			ID:            fmt.Sprintf("%s-cap-sys-ptrace", baseID),
			PodName:       pod.Name,
			PodNamespace:  pod.Namespace,
			ContainerName: container.Name,
			Vector:        "CAP_SYS_PTRACE",
			Severity:      "HIGH",
			Description:   "CAP_SYS_PTRACE allows tracing and controlling other processes",
			Impact:        "Attacker can inject code into other processes, potentially escaping container isolation",
			Remediation: []string{
				"Remove CAP_SYS_PTRACE capability unless required for debugging",
				"Use hostPID: false to limit process visibility",
			},
		}

	case "SYS_MODULE":
		return &ContainerEscapeVector{
			ID:            fmt.Sprintf("%s-cap-sys-module", baseID),
			PodName:       pod.Name,
			PodNamespace:  pod.Namespace,
			ContainerName: container.Name,
			Vector:        "CAP_SYS_MODULE",
			Severity:      "CRITICAL",
			Description:   "CAP_SYS_MODULE allows loading and unloading kernel modules",
			Impact:        "Attacker can load malicious kernel modules, achieving persistent root access to node",
			Remediation: []string{
				"Remove CAP_SYS_MODULE capability",
				"This capability should never be granted in production",
			},
		}

	case "NET_ADMIN":
		return &ContainerEscapeVector{
			ID:            fmt.Sprintf("%s-cap-net-admin", baseID),
			PodName:       pod.Name,
			PodNamespace:  pod.Namespace,
			ContainerName: container.Name,
			Vector:        "CAP_NET_ADMIN",
			Severity:      "MEDIUM",
			Description:   "CAP_NET_ADMIN allows network configuration and packet manipulation",
			Impact:        "Attacker can perform network attacks, intercept traffic, or bypass network policies",
			Remediation: []string{
				"Remove CAP_NET_ADMIN unless required for CNI plugins",
				"Use Network Policies to limit network access",
			},
		}

	case "NET_RAW":
		return &ContainerEscapeVector{
			ID:            fmt.Sprintf("%s-cap-net-raw", baseID),
			PodName:       pod.Name,
			PodNamespace:  pod.Namespace,
			ContainerName: container.Name,
			Vector:        "CAP_NET_RAW",
			Severity:      "MEDIUM",
			Description:   "CAP_NET_RAW allows raw socket access for crafting custom packets",
			Impact:        "Attacker can perform ARP spoofing, DNS poisoning, or other network attacks",
			CVE:           "CVE-2020-14386",
			Remediation: []string{
				"Drop CAP_NET_RAW capability",
				"Ensure securityContext.capabilities.drop includes NET_RAW",
			},
		}

	case "DAC_OVERRIDE":
		return &ContainerEscapeVector{
			ID:            fmt.Sprintf("%s-cap-dac-override", baseID),
			PodName:       pod.Name,
			PodNamespace:  pod.Namespace,
			ContainerName: container.Name,
			Vector:        "CAP_DAC_OVERRIDE",
			Severity:      "HIGH",
			Description:   "CAP_DAC_OVERRIDE bypasses file permission checks",
			Impact:        "Attacker can read/write any file regardless of permissions, useful for escape chains",
			Remediation: []string{
				"Remove CAP_DAC_OVERRIDE capability",
				"Use proper file permissions and ownership",
			},
		}

	case "SETFCAP":
		return &ContainerEscapeVector{
			ID:            fmt.Sprintf("%s-cap-setfcap", baseID),
			PodName:       pod.Name,
			PodNamespace:  pod.Namespace,
			ContainerName: container.Name,
			Vector:        "CAP_SETFCAP",
			Severity:      "HIGH",
			Description:   "CAP_SETFCAP allows setting file capabilities",
			Impact:        "Attacker can grant capabilities to binaries, creating privilege escalation backdoors",
			Remediation: []string{
				"Remove CAP_SETFCAP capability",
			},
		}
	}

	return nil
}

func (a *EscapeAnalyzer) analyzePodLevel(pod inventory.PodInfo) []ContainerEscapeVector {
	var vectors []ContainerEscapeVector
	baseID := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)

	// Check hostPID
	if pod.HostPID {
		vectors = append(vectors, ContainerEscapeVector{
			ID:           fmt.Sprintf("%s-hostpid", baseID),
			PodName:      pod.Name,
			PodNamespace: pod.Namespace,
			Vector:       "hostPID",
			Severity:     "HIGH",
			Description:  "Pod shares process namespace with host, allowing visibility into all host processes",
			Impact:       "Attacker can see and potentially interact with host processes, gather secrets from /proc",
			Remediation: []string{
				"Set hostPID: false in pod spec",
				"Use PodSecurityAdmission restricted profile",
			},
		})

		// Privileged + hostPID is especially dangerous
		for _, c := range pod.Containers {
			if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				vectors = append(vectors, ContainerEscapeVector{
					ID:            fmt.Sprintf("%s-%s-privileged-hostpid", baseID, c.Name),
					PodName:       pod.Name,
					PodNamespace:  pod.Namespace,
					ContainerName: c.Name,
					Vector:        "privileged+hostPID",
					Severity:      "CRITICAL",
					Description:   "Combination of privileged mode and hostPID allows trivial container escape",
					Impact:        "Attacker can escape container by injecting into host processes (nsenter attack)",
					Remediation: []string{
						"Remove privileged: true AND hostPID: true",
						"This combination should never be used in production",
					},
				})
			}
		}
	}

	// Check hostNetwork
	if pod.HostNetwork {
		vectors = append(vectors, ContainerEscapeVector{
			ID:           fmt.Sprintf("%s-hostnetwork", baseID),
			PodName:      pod.Name,
			PodNamespace: pod.Namespace,
			Vector:       "hostNetwork",
			Severity:     "HIGH",
			Description:  "Pod uses host network namespace, bypassing network isolation",
			Impact:       "Attacker can sniff host traffic, access services on localhost, bypass NetworkPolicies",
			Remediation: []string{
				"Set hostNetwork: false in pod spec",
				"Use NetworkPolicies to restrict traffic",
			},
		})
	}

	// Check hostIPC
	if pod.HostIPC {
		vectors = append(vectors, ContainerEscapeVector{
			ID:           fmt.Sprintf("%s-hostipc", baseID),
			PodName:      pod.Name,
			PodNamespace: pod.Namespace,
			Vector:       "hostIPC",
			Severity:     "MEDIUM",
			Description:  "Pod shares IPC namespace with host, allowing shared memory access",
			Impact:       "Attacker can access host shared memory segments, potentially reading sensitive data",
			Remediation: []string{
				"Set hostIPC: false in pod spec",
			},
		})
	}

	// Check volume mounts
	for _, vol := range pod.Volumes {
		if vol.Type == "HostPath" {
			vector := a.analyzeHostPathVolume(pod, vol)
			if vector != nil {
				vectors = append(vectors, *vector)
			}
		}
	}

	return vectors
}

func (a *EscapeAnalyzer) analyzeHostPathVolume(pod inventory.PodInfo, vol inventory.VolumeInfo) *ContainerEscapeVector {
	baseID := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
	source := vol.Source

	// Docker socket mount - most critical
	if strings.Contains(source, "docker.sock") || strings.Contains(source, "containerd.sock") || strings.Contains(source, "cri-o.sock") {
		return &ContainerEscapeVector{
			ID:           fmt.Sprintf("%s-container-socket", baseID),
			PodName:      pod.Name,
			PodNamespace: pod.Namespace,
			Vector:       "container-runtime-socket",
			Severity:     "CRITICAL",
			Description:  fmt.Sprintf("Pod mounts container runtime socket: %s", source),
			Impact:       "Attacker can control container runtime, create privileged containers, and escape to host",
			CVE:          "Multiple: Docker/containerd escape vectors",
			Remediation: []string{
				"Remove container runtime socket mount",
				"Use Kubernetes APIs instead of direct container runtime access",
				"If needed, use a dedicated privileged daemonset with strong RBAC",
			},
		}
	}

	// Root filesystem mount
	if source == "/" {
		return &ContainerEscapeVector{
			ID:           fmt.Sprintf("%s-root-mount", baseID),
			PodName:      pod.Name,
			PodNamespace: pod.Namespace,
			Vector:       "host-root-mount",
			Severity:     "CRITICAL",
			Description:  "Pod mounts host root filesystem /",
			Impact:       "Attacker has full read/write access to entire host filesystem",
			Remediation: []string{
				"Mount only specific required paths",
				"Use readOnly: true for hostPath mounts",
			},
		}
	}

	// /etc mount
	if source == "/etc" || strings.HasPrefix(source, "/etc/") {
		severity := "HIGH"
		if source == "/etc" {
			severity = "CRITICAL"
		}
		return &ContainerEscapeVector{
			ID:           fmt.Sprintf("%s-etc-mount", baseID),
			PodName:      pod.Name,
			PodNamespace: pod.Namespace,
			Vector:       "host-etc-mount",
			Severity:     severity,
			Description:  fmt.Sprintf("Pod mounts host /etc: %s", source),
			Impact:       "Attacker can modify host configuration files (passwd, shadow, crontab, SSH keys)",
			Remediation: []string{
				"Mount only specific config files needed",
				"Use ConfigMaps or Secrets instead",
				"Use readOnly: true",
			},
		}
	}

	// /var mount
	if source == "/var" || strings.HasPrefix(source, "/var/") {
		// Check for specific dangerous paths
		if strings.Contains(source, "/var/run") || strings.Contains(source, "/var/lib/kubelet") {
			return &ContainerEscapeVector{
				ID:           fmt.Sprintf("%s-var-mount", baseID),
				PodName:      pod.Name,
				PodNamespace: pod.Namespace,
				Vector:       "host-var-mount",
				Severity:     "HIGH",
				Description:  fmt.Sprintf("Pod mounts sensitive host path: %s", source),
				Impact:       "Attacker may access kubelet data, container runtime state, or other sensitive data",
				Remediation: []string{
					"Remove or restrict host path mounts",
					"Use emptyDir or PersistentVolumes instead",
				},
			}
		}
	}

	// /proc or /sys mount
	if strings.HasPrefix(source, "/proc") || strings.HasPrefix(source, "/sys") {
		return &ContainerEscapeVector{
			ID:           fmt.Sprintf("%s-procsys-mount", baseID),
			PodName:      pod.Name,
			PodNamespace: pod.Namespace,
			Vector:       "host-procsys-mount",
			Severity:     "CRITICAL",
			Description:  fmt.Sprintf("Pod mounts host %s filesystem", source),
			Impact:       "Attacker can access kernel interfaces, potentially modifying system behavior or escaping",
			CVE:          "CVE-2022-0492",
			Remediation: []string{
				"Remove /proc and /sys mounts",
				"Container already has isolated /proc and /sys",
			},
		}
	}

	return nil
}

func (a *EscapeAnalyzer) GetSummary(vectors []ContainerEscapeVector) map[string]int {
	summary := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}

	for _, v := range vectors {
		summary[v.Severity]++
	}

	return summary
}

func (a *EscapeAnalyzer) GetVectorsByType(vectors []ContainerEscapeVector) map[string][]ContainerEscapeVector {
	byType := make(map[string][]ContainerEscapeVector)

	for _, v := range vectors {
		byType[v.Vector] = append(byType[v.Vector], v)
	}

	return byType
}
