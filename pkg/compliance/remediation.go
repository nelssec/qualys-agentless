package compliance

// FindingMapping maps a finding pattern (keyword) to a control ID
type FindingMapping struct {
	Pattern   string // Keyword to match in finding text
	ControlID string // Control ID to look up
}

// ControlInfo contains the remediation info for a control
type ControlInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Section     string `json:"section"`
	Remediation string `json:"remediation"`
	Framework   string `json:"framework"`
}

// DefaultFindingMappings maps finding patterns to CIS/NSA/MITRE control IDs
var DefaultFindingMappings = []FindingMapping{
	// Pod Security - CIS 5.2.x
	{"privileged", "CIS-5.2.1"},
	{"hostPID", "CIS-5.2.2"},
	{"hostIPC", "CIS-5.2.3"},
	{"hostNetwork", "CIS-5.2.4"},
	{"privilege escalation", "CIS-5.2.5"},
	{"allowPrivilegeEscalation", "CIS-5.2.5"},
	{"root container", "CIS-5.2.6"},
	{"runAsRoot", "CIS-5.2.6"},
	{"runAsUser: 0", "CIS-5.2.6"},
	{"dangerous capability", "CIS-5.2.7"},
	{"CAP_SYS_ADMIN", "CIS-5.2.7"},
	{"SYS_ADMIN", "CIS-5.2.7"},
	{"CAP_SYS_PTRACE", "CIS-5.2.7"},
	{"SYS_PTRACE", "CIS-5.2.7"},
	{"NET_RAW", "CIS-5.2.8"},
	{"CAP_NET_RAW", "CIS-5.2.8"},
	{"NET_ADMIN", "CIS-5.2.9"},
	{"CAP_NET_ADMIN", "CIS-5.2.9"},
	{"added capabilities", "CIS-5.2.9"},
	{"capabilities assigned", "CIS-5.2.10"},
	{"HostProcess", "CIS-5.2.11"},
	{"hostPath", "CIS-5.2.12"},
	{"host path", "CIS-5.2.12"},
	{"sensitive host path", "CIS-5.2.12"},
	{"root filesystem", "CIS-5.2.12"},
	{"docker.sock", "CIS-5.2.12"},
	{"containerd.sock", "CIS-5.2.12"},
	{"hostPort", "CIS-5.2.13"},
	{"host port", "CIS-5.2.13"},

	// RBAC - CIS 5.1.x
	{"cluster-admin", "CIS-5.1.1"},
	{"secrets access", "CIS-5.1.2"},
	{"access to secrets", "CIS-5.1.2"},
	{"wildcard", "CIS-5.1.3"},
	{"create pods", "CIS-5.1.4"},
	{"default service account", "CIS-5.1.5"},
	{"automount", "CIS-5.1.6"},
	{"service account token", "CIS-5.1.6"},
	{"system:masters", "CIS-5.1.7"},
	{"bind permission", "CIS-5.1.8"},
	{"impersonate", "CIS-5.1.8"},
	{"escalate permission", "CIS-5.1.8"},
	{"persistent volume", "CIS-5.1.9"},
	{"nodes/proxy", "CIS-5.1.10"},
	{"webhook", "CIS-5.1.12"},
	{"token creation", "CIS-5.1.13"},

	// Network - CIS 5.3.x
	{"no network policy", "CIS-5.3.2"},
	{"missing network policy", "CIS-5.3.2"},
	{"NetworkPolicy", "CIS-5.3.2"},

	// Secrets - CIS 5.4.x
	{"secret in env", "CIS-5.4.1"},
	{"environment variable", "CIS-5.4.1"},

	// General - CIS 5.7.x
	{"default namespace", "CIS-5.7.4"},
	{"seccomp", "CIS-5.7.2"},
	{"security context", "CIS-5.7.3"},

	// NSA/CISA
	{"non-root", "NSA-1.2"},
	{"immutable filesystem", "NSA-1.3"},
	{"network isolation", "NSA-2.1"},
	{"encrypt traffic", "NSA-2.2"},
	{"mTLS", "NSA-2.2"},
	{"audit log", "NSA-4.1"},

	// MITRE ATT&CK
	{"container escape", "MITRE-T1611"},
	{"escape to host", "MITRE-T1611"},
	{"lateral movement", "MITRE-T1570"},
	{"credential", "MITRE-T1552"},
	{"exec into", "MITRE-T1609"},
	{"kubectl exec", "MITRE-T1609"},
}

// GetRemediationMap returns a map of control IDs to their full info
func (e *Engine) GetRemediationMap() map[string]*ControlInfo {
	result := make(map[string]*ControlInfo)

	for _, ctrl := range e.controls {
		result[ctrl.ID] = &ControlInfo{
			ID:          ctrl.ID,
			Name:        ctrl.Name,
			Severity:    string(ctrl.Severity),
			Section:     ctrl.Section,
			Remediation: ctrl.Remediation,
			Framework:   ctrl.Framework,
		}
	}

	return result
}

// GetFindingMappings returns the default finding-to-control mappings
func GetFindingMappings() []FindingMapping {
	return DefaultFindingMappings
}

// BuildRemediationLookup creates a complete remediation lookup for the topology exporter
// It returns a map of finding patterns to control info
func (e *Engine) BuildRemediationLookup() map[string]*ControlInfo {
	lookup := make(map[string]*ControlInfo)
	controlMap := e.GetRemediationMap()

	for _, mapping := range DefaultFindingMappings {
		if ctrl, ok := controlMap[mapping.ControlID]; ok {
			lookup[mapping.Pattern] = ctrl
		}
	}

	return lookup
}

// GetDefaultRemediationLookup creates a remediation lookup from default controls
// This is a convenience function that doesn't require an engine instance
func GetDefaultRemediationLookup() map[string]*ControlInfo {
	engine := NewEngine()
	engine.RegisterDefaultControls()
	return engine.BuildRemediationLookup()
}
