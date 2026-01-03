package docker

import (
	"fmt"
	"strings"
)

type Checker struct {
	inv *Inventory
}

func NewChecker(inv *Inventory) *Checker {
	return &Checker{inv: inv}
}

func (c *Checker) RunAllChecks() []Finding {
	var findings []Finding
	findings = append(findings, c.checkContainers()...)
	findings = append(findings, c.checkImages()...)
	findings = append(findings, c.checkNetworks()...)
	findings = append(findings, c.checkVolumes()...)
	findings = append(findings, c.checkHost()...)
	return findings
}

func (c *Checker) checkContainers() []Finding {
	var findings []Finding

	for _, container := range c.inv.Containers {
		if container.State != "running" {
			continue
		}

		if container.SecurityContext.Privileged {
			findings = append(findings, Finding{
				ID:          "CIS-5.4",
				Name:        "Privileged container",
				Severity:    "CRITICAL",
				Category:    "Container Runtime",
				Resource:    container.Name,
				ResourceID:  container.ID[:12],
				Message:     fmt.Sprintf("Container %s is running in privileged mode", container.Name),
				Remediation: "Run container without --privileged flag. Use specific capabilities instead.",
			})
		}

		if container.SecurityContext.User == "" || container.SecurityContext.User == "root" || container.SecurityContext.User == "0" {
			findings = append(findings, Finding{
				ID:          "CIS-5.7",
				Name:        "Container running as root",
				Severity:    "HIGH",
				Category:    "Container Runtime",
				Resource:    container.Name,
				ResourceID:  container.ID[:12],
				Message:     fmt.Sprintf("Container %s is running as root user", container.Name),
				Remediation: "Run container with --user flag specifying a non-root user.",
			})
		}

		if container.SecurityContext.PidMode == "host" {
			findings = append(findings, Finding{
				ID:          "CIS-5.15",
				Name:        "Host PID namespace",
				Severity:    "HIGH",
				Category:    "Container Runtime",
				Resource:    container.Name,
				ResourceID:  container.ID[:12],
				Message:     fmt.Sprintf("Container %s shares host PID namespace", container.Name),
				Remediation: "Do not use --pid=host unless absolutely necessary.",
			})
		}

		if container.SecurityContext.IpcMode == "host" {
			findings = append(findings, Finding{
				ID:          "CIS-5.16",
				Name:        "Host IPC namespace",
				Severity:    "HIGH",
				Category:    "Container Runtime",
				Resource:    container.Name,
				ResourceID:  container.ID[:12],
				Message:     fmt.Sprintf("Container %s shares host IPC namespace", container.Name),
				Remediation: "Do not use --ipc=host unless absolutely necessary.",
			})
		}

		if container.SecurityContext.NetworkMode == "host" {
			findings = append(findings, Finding{
				ID:          "CIS-5.9",
				Name:        "Host network mode",
				Severity:    "HIGH",
				Category:    "Container Runtime",
				Resource:    container.Name,
				ResourceID:  container.ID[:12],
				Message:     fmt.Sprintf("Container %s uses host network mode", container.Name),
				Remediation: "Do not use --network=host. Use bridge or custom networks.",
			})
		}

		if !container.SecurityContext.ReadonlyRootfs {
			findings = append(findings, Finding{
				ID:          "CIS-5.12",
				Name:        "Writable root filesystem",
				Severity:    "MEDIUM",
				Category:    "Container Runtime",
				Resource:    container.Name,
				ResourceID:  container.ID[:12],
				Message:     fmt.Sprintf("Container %s has writable root filesystem", container.Name),
				Remediation: "Run container with --read-only flag.",
			})
		}

		dangerousCaps := []string{"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_RAWIO", "SYS_MODULE", "DAC_OVERRIDE"}
		for _, cap := range container.SecurityContext.CapAdd {
			for _, dangerous := range dangerousCaps {
				if strings.EqualFold(cap, dangerous) || strings.EqualFold(cap, "CAP_"+dangerous) {
					findings = append(findings, Finding{
						ID:          "CIS-5.3",
						Name:        "Dangerous capability added",
						Severity:    "HIGH",
						Category:    "Container Runtime",
						Resource:    container.Name,
						ResourceID:  container.ID[:12],
						Message:     fmt.Sprintf("Container %s has dangerous capability: %s", container.Name, cap),
						Remediation: fmt.Sprintf("Remove %s capability unless absolutely required.", cap),
					})
				}
			}
		}

		sensitivePaths := []string{
			"/var/run/docker.sock",
			"/run/docker.sock",
			"/var/run/containerd/containerd.sock",
			"/run/containerd/containerd.sock",
			"/var/run/crio/crio.sock",
			"/etc/shadow",
			"/etc/passwd",
			"/etc/kubernetes",
			"/root",
			"/home",
		}
		for _, mount := range container.Mounts {
			for _, sensitive := range sensitivePaths {
				if strings.HasPrefix(mount.Source, sensitive) || mount.Source == sensitive {
					severity := "HIGH"
					if strings.Contains(mount.Source, ".sock") {
						severity = "CRITICAL"
					}
					findings = append(findings, Finding{
						ID:          "CIS-5.5",
						Name:        "Sensitive host path mounted",
						Severity:    severity,
						Category:    "Container Runtime",
						Resource:    container.Name,
						ResourceID:  container.ID[:12],
						Message:     fmt.Sprintf("Container %s mounts sensitive path: %s", container.Name, mount.Source),
						Remediation: fmt.Sprintf("Remove mount of %s from container.", mount.Source),
					})
					break
				}
			}

			if mount.Source == "/" {
				findings = append(findings, Finding{
					ID:          "CIS-5.5",
					Name:        "Host root filesystem mounted",
					Severity:    "CRITICAL",
					Category:    "Container Runtime",
					Resource:    container.Name,
					ResourceID:  container.ID[:12],
					Message:     fmt.Sprintf("Container %s mounts host root filesystem", container.Name),
					Remediation: "Never mount the host root filesystem into a container.",
				})
			}
		}

		for _, port := range container.Ports {
			if port.HostPort != 0 && port.HostIP == "0.0.0.0" {
				findings = append(findings, Finding{
					ID:          "CIS-5.13",
					Name:        "Port exposed on all interfaces",
					Severity:    "MEDIUM",
					Category:    "Container Runtime",
					Resource:    container.Name,
					ResourceID:  container.ID[:12],
					Message:     fmt.Sprintf("Container %s exposes port %d on all interfaces", container.Name, port.HostPort),
					Remediation: "Bind ports to specific interfaces, e.g., -p 127.0.0.1:8080:80",
				})
			}

			if port.HostPort != 0 && port.HostPort < 1024 {
				findings = append(findings, Finding{
					ID:          "CIS-5.14",
					Name:        "Privileged port mapping",
					Severity:    "LOW",
					Category:    "Container Runtime",
					Resource:    container.Name,
					ResourceID:  container.ID[:12],
					Message:     fmt.Sprintf("Container %s uses privileged port %d", container.Name, port.HostPort),
					Remediation: "Use ports above 1024 unless specifically required.",
				})
			}
		}

		if container.Resources.Memory == 0 {
			findings = append(findings, Finding{
				ID:          "CIS-5.10",
				Name:        "No memory limit",
				Severity:    "MEDIUM",
				Category:    "Container Runtime",
				Resource:    container.Name,
				ResourceID:  container.ID[:12],
				Message:     fmt.Sprintf("Container %s has no memory limit set", container.Name),
				Remediation: "Set memory limits with --memory flag.",
			})
		}

		if container.Resources.PidsLimit == 0 {
			findings = append(findings, Finding{
				ID:          "CIS-5.28",
				Name:        "No PID limit",
				Severity:    "LOW",
				Category:    "Container Runtime",
				Resource:    container.Name,
				ResourceID:  container.ID[:12],
				Message:     fmt.Sprintf("Container %s has no PID limit set", container.Name),
				Remediation: "Set PID limits with --pids-limit flag.",
			})
		}

		if container.RestartPolicy == "always" {
			findings = append(findings, Finding{
				ID:          "CIS-5.29",
				Name:        "Unrestricted restart policy",
				Severity:    "LOW",
				Category:    "Container Runtime",
				Resource:    container.Name,
				ResourceID:  container.ID[:12],
				Message:     fmt.Sprintf("Container %s has restart policy 'always'", container.Name),
				Remediation: "Use --restart=on-failure:5 to limit restart attempts.",
			})
		}

		hasAppArmor := false
		hasSeccomp := false
		for _, opt := range container.SecurityContext.SecurityOpt {
			if strings.HasPrefix(opt, "apparmor=") {
				hasAppArmor = true
			}
			if strings.HasPrefix(opt, "seccomp=") {
				hasSeccomp = true
			}
		}

		if !hasAppArmor && c.inv.Host.OS == "linux" {
			findings = append(findings, Finding{
				ID:          "CIS-5.1",
				Name:        "No AppArmor profile",
				Severity:    "LOW",
				Category:    "Container Runtime",
				Resource:    container.Name,
				ResourceID:  container.ID[:12],
				Message:     fmt.Sprintf("Container %s has no AppArmor profile", container.Name),
				Remediation: "Apply AppArmor profile with --security-opt apparmor=docker-default",
			})
		}

		if !hasSeccomp {
			findings = append(findings, Finding{
				ID:          "CIS-5.2",
				Name:        "No Seccomp profile",
				Severity:    "MEDIUM",
				Category:    "Container Runtime",
				Resource:    container.Name,
				ResourceID:  container.ID[:12],
				Message:     fmt.Sprintf("Container %s has no Seccomp profile", container.Name),
				Remediation: "Apply Seccomp profile with --security-opt seccomp=default.json",
			})
		}
	}

	return findings
}

func (c *Checker) checkImages() []Finding {
	var findings []Finding

	for _, image := range c.inv.Images {
		if len(image.RepoTags) == 0 || (len(image.RepoTags) == 1 && image.RepoTags[0] == "<none>:<none>") {
			findings = append(findings, Finding{
				ID:          "CIS-4.1",
				Name:        "Untagged image",
				Severity:    "LOW",
				Category:    "Images",
				Resource:    image.ID[:12],
				ResourceID:  image.ID[:12],
				Message:     "Image has no tags (dangling image)",
				Remediation: "Remove unused dangling images with 'docker image prune'",
			})
			continue
		}

		for _, tag := range image.RepoTags {
			if strings.HasSuffix(tag, ":latest") {
				findings = append(findings, Finding{
					ID:          "CIS-4.7",
					Name:        "Latest tag used",
					Severity:    "MEDIUM",
					Category:    "Images",
					Resource:    tag,
					ResourceID:  image.ID[:12],
					Message:     fmt.Sprintf("Image %s uses 'latest' tag", tag),
					Remediation: "Use specific version tags for reproducible builds.",
				})
			}
		}

		if image.User == "" || image.User == "root" || image.User == "0" {
			name := image.ID[:12]
			if len(image.RepoTags) > 0 {
				name = image.RepoTags[0]
			}
			findings = append(findings, Finding{
				ID:          "CIS-4.1",
				Name:        "Image runs as root",
				Severity:    "MEDIUM",
				Category:    "Images",
				Resource:    name,
				ResourceID:  image.ID[:12],
				Message:     fmt.Sprintf("Image %s is configured to run as root", name),
				Remediation: "Add USER instruction to Dockerfile specifying non-root user.",
			})
		}
	}

	return findings
}

func (c *Checker) checkNetworks() []Finding {
	var findings []Finding

	for _, network := range c.inv.Networks {
		if network.Name == "bridge" && len(network.Containers) > 1 {
			findings = append(findings, Finding{
				ID:          "CIS-5.18",
				Name:        "Default bridge network in use",
				Severity:    "MEDIUM",
				Category:    "Networks",
				Resource:    "bridge",
				ResourceID:  network.ID[:12],
				Message:     fmt.Sprintf("Default bridge network has %d containers", len(network.Containers)),
				Remediation: "Create custom networks for container isolation.",
			})
		}

		if network.Driver == "bridge" && !network.Internal && network.Name != "bridge" {
			if len(network.Containers) > 5 {
				findings = append(findings, Finding{
					ID:          "CIS-5.19",
					Name:        "Large shared network",
					Severity:    "LOW",
					Category:    "Networks",
					Resource:    network.Name,
					ResourceID:  network.ID[:12],
					Message:     fmt.Sprintf("Network %s has %d containers sharing connectivity", network.Name, len(network.Containers)),
					Remediation: "Segment containers into smaller, purpose-specific networks.",
				})
			}
		}
	}

	return findings
}

func (c *Checker) checkVolumes() []Finding {
	var findings []Finding

	usedVolumes := make(map[string]bool)
	for _, container := range c.inv.Containers {
		for _, mount := range container.Mounts {
			if mount.Type == "volume" {
				usedVolumes[mount.Source] = true
			}
		}
	}

	for _, volume := range c.inv.Volumes {
		if !usedVolumes[volume.Name] {
			findings = append(findings, Finding{
				ID:          "CIS-6.3",
				Name:        "Orphaned volume",
				Severity:    "LOW",
				Category:    "Volumes",
				Resource:    volume.Name,
				ResourceID:  volume.Name,
				Message:     fmt.Sprintf("Volume %s is not used by any container", volume.Name),
				Remediation: "Remove unused volumes with 'docker volume prune'",
			})
		}
	}

	return findings
}

func (c *Checker) checkHost() []Finding {
	var findings []Finding

	if c.inv.Host.CgroupVersion == "1" {
		findings = append(findings, Finding{
			ID:          "CIS-1.2",
			Name:        "Legacy cgroup v1",
			Severity:    "LOW",
			Category:    "Host Configuration",
			Resource:    "daemon",
			ResourceID:  "host",
			Message:     "Docker daemon is using cgroup v1 instead of v2",
			Remediation: "Upgrade to cgroup v2 for better resource isolation.",
		})
	}

	return findings
}
