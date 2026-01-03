package docker

import (
	"fmt"
	"strings"
	"time"

	"github.com/nelssec/qualys-agentless/pkg/graph"
)

type GraphBuilder struct {
	inv   *Inventory
	graph *graph.SecurityGraph
}

func NewGraphBuilder(inv *Inventory) *GraphBuilder {
	hostName := inv.Host.Hostname
	if hostName == "" {
		hostName = "docker-host"
	}
	return &GraphBuilder{
		inv:   inv,
		graph: graph.NewSecurityGraph(hostName),
	}
}

func (b *GraphBuilder) Build() *graph.SecurityGraph {
	b.graph.GeneratedAt = time.Now().UTC().Format(time.RFC3339)

	b.addExternalNodes()
	b.addHostNode()
	b.addNetworkNodes()
	b.addVolumeNodes()
	b.addImageNodes()
	b.addContainerNodes()

	b.addContainerImageEdges()
	b.addContainerNetworkEdges()
	b.addContainerVolumeEdges()
	b.addExternalExposureEdges()
	b.addHostEscapeEdges()
	b.addLateralMovementEdges()

	b.calculateSummary()

	return b.graph
}

func (b *GraphBuilder) addExternalNodes() {
	b.graph.AddNode(graph.Node{
		ID:        "external/internet",
		Type:      graph.NodeExternal,
		Name:      "Internet",
		Risk:      graph.RiskHigh,
		RiskScore: 80,
		Properties: map[string]any{
			"type": "internet",
		},
	})
}

func (b *GraphBuilder) addHostNode() {
	risk := graph.RiskInfo
	var findings []string

	if b.inv.Host.CgroupVersion == "1" {
		risk = graph.RiskLow
		findings = append(findings, "Using legacy cgroup v1")
	}

	props := map[string]any{
		"hostname":       b.inv.Host.Hostname,
		"os":             b.inv.Host.OS,
		"architecture":   b.inv.Host.Architecture,
		"kernelVersion":  b.inv.Host.KernelVersion,
		"runtime":        b.inv.Host.Runtime,
		"runtimeVersion": b.inv.Host.RuntimeVersion,
		"storageDriver":  b.inv.Host.StorageDriver,
		"cgroupVersion":  b.inv.Host.CgroupVersion,
	}

	b.graph.AddNode(graph.Node{
		ID:         "host/" + b.inv.Host.Hostname,
		Type:       graph.NodeNode,
		Name:       b.inv.Host.Hostname,
		Risk:       risk,
		RiskScore:  riskToScore(risk),
		Properties: props,
		Findings:   findings,
	})
}

func (b *GraphBuilder) addNetworkNodes() {
	for _, network := range b.inv.Networks {
		risk := graph.RiskInfo
		var findings []string

		if network.Name == "bridge" && len(network.Containers) > 1 {
			risk = graph.RiskMedium
			findings = append(findings, fmt.Sprintf("Default bridge network has %d containers", len(network.Containers)))
		}

		if network.Driver == "host" {
			risk = graph.RiskHigh
			findings = append(findings, "Host network driver allows direct host network access")
		}

		props := map[string]any{
			"driver":     network.Driver,
			"scope":      network.Scope,
			"internal":   network.Internal,
			"containers": len(network.Containers),
		}
		if network.IPAM.Subnet != "" {
			props["subnet"] = network.IPAM.Subnet
		}

		b.graph.AddNode(graph.Node{
			ID:         "network/" + network.Name,
			Type:       graph.NodeNetworkPolicy,
			Name:       network.Name,
			Risk:       risk,
			RiskScore:  riskToScore(risk),
			Properties: props,
			Findings:   findings,
		})
	}
}

func (b *GraphBuilder) addVolumeNodes() {
	usedVolumes := make(map[string]bool)
	for _, c := range b.inv.Containers {
		for _, m := range c.Mounts {
			if m.Type == "volume" {
				usedVolumes[m.Source] = true
			}
		}
	}

	for _, volume := range b.inv.Volumes {
		risk := graph.RiskInfo
		var findings []string

		if !usedVolumes[volume.Name] {
			risk = graph.RiskLow
			findings = append(findings, "Orphaned volume not used by any container")
		}

		b.graph.AddNode(graph.Node{
			ID:   "volume/" + volume.Name,
			Type: graph.NodePersistentVolume,
			Name: volume.Name,
			Risk: risk,
			RiskScore: riskToScore(risk),
			Properties: map[string]any{
				"driver":     volume.Driver,
				"mountpoint": volume.Mountpoint,
				"scope":      volume.Scope,
			},
			Findings: findings,
		})
	}
}

func (b *GraphBuilder) addImageNodes() {
	for _, image := range b.inv.Images {
		risk := graph.RiskInfo
		var findings []string

		name := image.ID[:12]
		if len(image.RepoTags) > 0 && image.RepoTags[0] != "<none>:<none>" {
			name = image.RepoTags[0]
		}

		if len(image.RepoTags) == 0 || (len(image.RepoTags) == 1 && image.RepoTags[0] == "<none>:<none>") {
			risk = graph.RiskLow
			findings = append(findings, "Dangling image with no tags")
		}

		for _, tag := range image.RepoTags {
			if strings.HasSuffix(tag, ":latest") {
				risk = graph.RiskMedium
				findings = append(findings, "Uses 'latest' tag which is mutable")
			}
		}

		if image.User == "" || image.User == "root" || image.User == "0" {
			if risk != graph.RiskMedium {
				risk = graph.RiskMedium
			}
			findings = append(findings, "Image configured to run as root")
		}

		b.graph.AddNode(graph.Node{
			ID:   "image/" + image.ID[:12],
			Type: graph.NodeConfigMap,
			Name: name,
			Risk: risk,
			RiskScore: riskToScore(risk),
			Properties: map[string]any{
				"size":      image.Size,
				"created":   image.Created.Format(time.RFC3339),
				"user":      image.User,
				"usedBy":    len(image.UsedBy),
			},
			Findings: findings,
		})
	}
}

func (b *GraphBuilder) addContainerNodes() {
	for _, container := range b.inv.Containers {
		if container.State != "running" {
			continue
		}

		risk, findings := b.calculateContainerRisk(container)

		props := map[string]any{
			"image":           container.Image,
			"state":           container.State,
			"status":          container.Status,
			"privileged":      container.SecurityContext.Privileged,
			"hostNetwork":     container.SecurityContext.NetworkMode == "host",
			"hostPID":         container.SecurityContext.PidMode == "host",
			"hostIPC":         container.SecurityContext.IpcMode == "host",
			"readonlyRootfs":  container.SecurityContext.ReadonlyRootfs,
			"user":            container.SecurityContext.User,
			"memoryLimit":     container.Resources.Memory,
			"pidsLimit":       container.Resources.PidsLimit,
		}

		if len(container.SecurityContext.CapAdd) > 0 {
			props["capabilities"] = container.SecurityContext.CapAdd
		}

		b.graph.AddNode(graph.Node{
			ID:         "container/" + container.ID[:12],
			Type:       graph.NodePod,
			Name:       container.Name,
			Risk:       risk,
			RiskScore:  riskToScore(risk),
			Properties: props,
			Findings:   findings,
		})
	}
}

func (b *GraphBuilder) calculateContainerRisk(c Container) (graph.RiskLevel, []string) {
	score := 0
	var findings []string

	if c.SecurityContext.Privileged {
		score += 50
		findings = append(findings, "Privileged container - full host access")
	}

	if c.SecurityContext.User == "" || c.SecurityContext.User == "root" || c.SecurityContext.User == "0" {
		score += 15
		findings = append(findings, "Running as root user")
	}

	if c.SecurityContext.PidMode == "host" {
		score += 30
		findings = append(findings, "Host PID namespace - can see host processes")
	}

	if c.SecurityContext.IpcMode == "host" {
		score += 20
		findings = append(findings, "Host IPC namespace - shared memory access")
	}

	if c.SecurityContext.NetworkMode == "host" {
		score += 25
		findings = append(findings, "Host network mode - no network isolation")
	}

	if !c.SecurityContext.ReadonlyRootfs {
		score += 5
		findings = append(findings, "Writable root filesystem")
	}

	dangerousCaps := map[string]int{
		"SYS_ADMIN":    40,
		"NET_ADMIN":    25,
		"SYS_PTRACE":   30,
		"SYS_RAWIO":    35,
		"SYS_MODULE":   40,
		"DAC_OVERRIDE": 20,
	}
	for _, cap := range c.SecurityContext.CapAdd {
		capName := strings.TrimPrefix(strings.ToUpper(cap), "CAP_")
		if points, ok := dangerousCaps[capName]; ok {
			score += points
			findings = append(findings, fmt.Sprintf("Dangerous capability: %s", capName))
		}
	}

	for _, mount := range c.Mounts {
		if mount.Source == "/" {
			score += 50
			findings = append(findings, "Host root filesystem mounted")
		} else if strings.Contains(mount.Source, "docker.sock") || strings.Contains(mount.Source, "containerd.sock") {
			score += 50
			findings = append(findings, fmt.Sprintf("Container runtime socket mounted: %s", mount.Source))
		} else if strings.HasPrefix(mount.Source, "/etc") {
			score += 15
			findings = append(findings, fmt.Sprintf("Sensitive host path mounted: %s", mount.Source))
		} else if strings.HasPrefix(mount.Source, "/var") {
			score += 10
			findings = append(findings, fmt.Sprintf("Host path mounted: %s", mount.Source))
		}
	}

	for _, port := range c.Ports {
		if port.HostPort != 0 && port.HostIP == "0.0.0.0" {
			score += 10
			findings = append(findings, fmt.Sprintf("Port %d exposed on all interfaces", port.HostPort))
		}
	}

	if c.Resources.Memory == 0 {
		score += 5
		findings = append(findings, "No memory limit set")
	}

	if c.Resources.PidsLimit == 0 {
		score += 3
		findings = append(findings, "No PID limit set")
	}

	return scoreToRisk(score), findings
}

func (b *GraphBuilder) addContainerImageEdges() {
	for _, container := range b.inv.Containers {
		if container.State != "running" {
			continue
		}
		containerID := "container/" + container.ID[:12]
		imageID := "image/" + strings.TrimPrefix(container.ImageID, "sha256:")[:12]

		b.graph.AddEdge(graph.Edge{
			Source: containerID,
			Target: imageID,
			Type:   graph.EdgeUses,
			Label:  "uses image",
		})
	}
}

func (b *GraphBuilder) addContainerNetworkEdges() {
	for _, container := range b.inv.Containers {
		if container.State != "running" {
			continue
		}
		containerID := "container/" + container.ID[:12]

		for _, netName := range container.Networks {
			networkID := "network/" + netName
			b.graph.AddEdge(graph.Edge{
				Source: containerID,
				Target: networkID,
				Type:   graph.EdgeCanReach,
				Label:  "connected to",
			})
		}
	}
}

func (b *GraphBuilder) addContainerVolumeEdges() {
	for _, container := range b.inv.Containers {
		if container.State != "running" {
			continue
		}
		containerID := "container/" + container.ID[:12]

		for _, mount := range container.Mounts {
			if mount.Type == "volume" {
				volumeID := "volume/" + mount.Source
				rw := "ro"
				if mount.RW {
					rw = "rw"
				}
				b.graph.AddEdge(graph.Edge{
					Source: containerID,
					Target: volumeID,
					Type:   graph.EdgeMounts,
					Label:  fmt.Sprintf("mounts (%s)", rw),
					Properties: map[string]any{
						"destination": mount.Destination,
						"readWrite":   mount.RW,
					},
				})
			}
		}
	}
}

func (b *GraphBuilder) addExternalExposureEdges() {
	internetID := "external/internet"

	for _, container := range b.inv.Containers {
		if container.State != "running" {
			continue
		}
		containerID := "container/" + container.ID[:12]

		for _, port := range container.Ports {
			if port.HostPort != 0 {
				risk := graph.RiskMedium
				if port.HostIP == "0.0.0.0" {
					risk = graph.RiskHigh
				}

				b.graph.AddEdge(graph.Edge{
					Source: internetID,
					Target: containerID,
					Type:   graph.EdgeExposedTo,
					Risk:   risk,
					Label:  fmt.Sprintf("port %d", port.HostPort),
					Properties: map[string]any{
						"hostPort":      port.HostPort,
						"containerPort": port.ContainerPort,
						"hostIP":        port.HostIP,
						"protocol":      port.Protocol,
					},
				})
				b.graph.Summary.ExternalExposures++
			}
		}
	}
}

func (b *GraphBuilder) addHostEscapeEdges() {
	hostID := "host/" + b.inv.Host.Hostname

	for _, container := range b.inv.Containers {
		if container.State != "running" {
			continue
		}
		containerID := "container/" + container.ID[:12]

		escapeVectors := b.detectEscapeVectors(container)
		for _, vector := range escapeVectors {
			b.graph.AddEdge(graph.Edge{
				Source: containerID,
				Target: hostID,
				Type:   graph.EdgeEscapesTo,
				Risk:   graph.RiskCritical,
				Label:  vector,
				Properties: map[string]any{
					"escapeVector": vector,
				},
			})
			b.graph.Summary.ContainerEscapes++
		}
	}
}

func (b *GraphBuilder) detectEscapeVectors(c Container) []string {
	var vectors []string

	if c.SecurityContext.Privileged {
		vectors = append(vectors, "privileged container")
	}

	for _, mount := range c.Mounts {
		if strings.Contains(mount.Source, "docker.sock") {
			vectors = append(vectors, "docker.sock mount")
		}
		if strings.Contains(mount.Source, "containerd.sock") {
			vectors = append(vectors, "containerd.sock mount")
		}
		if mount.Source == "/" {
			vectors = append(vectors, "host root mount")
		}
	}

	if c.SecurityContext.PidMode == "host" && c.SecurityContext.Privileged {
		vectors = append(vectors, "privileged + hostPID")
	}

	for _, cap := range c.SecurityContext.CapAdd {
		capName := strings.TrimPrefix(strings.ToUpper(cap), "CAP_")
		if capName == "SYS_ADMIN" {
			vectors = append(vectors, "CAP_SYS_ADMIN")
		}
		if capName == "SYS_PTRACE" && c.SecurityContext.PidMode == "host" {
			vectors = append(vectors, "CAP_SYS_PTRACE + hostPID")
		}
	}

	return vectors
}

func (b *GraphBuilder) addLateralMovementEdges() {
	dockerSockContainers := []string{}

	for _, container := range b.inv.Containers {
		if container.State != "running" {
			continue
		}

		for _, mount := range container.Mounts {
			if strings.Contains(mount.Source, "docker.sock") || strings.Contains(mount.Source, "containerd.sock") {
				dockerSockContainers = append(dockerSockContainers, container.ID[:12])
			}
		}
	}

	for _, srcID := range dockerSockContainers {
		srcContainerID := "container/" + srcID
		for _, container := range b.inv.Containers {
			if container.State != "running" {
				continue
			}
			if container.ID[:12] == srcID {
				continue
			}
			targetContainerID := "container/" + container.ID[:12]
			b.graph.AddEdge(graph.Edge{
				Source: srcContainerID,
				Target: targetContainerID,
				Type:   graph.EdgeCanExec,
				Risk:   graph.RiskCritical,
				Label:  "can control via docker.sock",
			})
		}
	}

	networkContainers := make(map[string][]string)
	for _, container := range b.inv.Containers {
		if container.State != "running" {
			continue
		}
		for _, net := range container.Networks {
			networkContainers[net] = append(networkContainers[net], container.ID[:12])
		}
	}

	for netName, containerIDs := range networkContainers {
		if netName == "none" || len(containerIDs) < 2 {
			continue
		}
		for i := 0; i < len(containerIDs); i++ {
			for j := i + 1; j < len(containerIDs); j++ {
				srcID := "container/" + containerIDs[i]
				tgtID := "container/" + containerIDs[j]
				b.graph.AddEdge(graph.Edge{
					Source:        srcID,
					Target:        tgtID,
					Type:          graph.EdgeCanReach,
					Risk:          graph.RiskInfo,
					Label:         "same network",
					Bidirectional: true,
					Properties: map[string]any{
						"network": netName,
					},
				})
			}
		}
	}
}

func (b *GraphBuilder) calculateSummary() {
	for _, container := range b.inv.Containers {
		if container.State != "running" {
			continue
		}

		hasEgressRestriction := false
		for _, net := range container.Networks {
			for _, n := range b.inv.Networks {
				if n.Name == net && n.Internal {
					hasEgressRestriction = true
					break
				}
			}
		}
		if !hasEgressRestriction {
			b.graph.Summary.DataExfiltrationRisks++
		}
	}
}

func riskToScore(risk graph.RiskLevel) int {
	switch risk {
	case graph.RiskCritical:
		return 95
	case graph.RiskHigh:
		return 75
	case graph.RiskMedium:
		return 50
	case graph.RiskLow:
		return 25
	default:
		return 10
	}
}

func scoreToRisk(score int) graph.RiskLevel {
	if score >= 80 {
		return graph.RiskCritical
	}
	if score >= 50 {
		return graph.RiskHigh
	}
	if score >= 25 {
		return graph.RiskMedium
	}
	if score >= 10 {
		return graph.RiskLow
	}
	return graph.RiskInfo
}
