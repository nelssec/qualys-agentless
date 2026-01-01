package compliance

func (e *Engine) RegisterDefaultControls() {
	e.registerCISKubernetes110()
	e.registerCISKubernetes111()
	e.registerCISEKS()
	e.registerCISAKS()
	e.registerCISOpenShift()
	e.registerKubernetesBestPractices()
	e.registerEKSBestPractices()
	e.registerAKSBestPractices()
	e.registerOpenShiftBestPractices()
	e.registerNSACISA()
	e.registerMITRE()
}

func (e *Engine) registerCISKubernetes110() {
	e.RegisterFramework(&Framework{
		ID:          "cis-k8s-1.10",
		Name:        "CIS Kubernetes Benchmark",
		Version:     "1.10.0",
		Description: "CIS Kubernetes Benchmark v1.10.0 - 71 controls",
	})

	controls := []struct {
		id          string
		name        string
		severity    Severity
		section     string
		remediation string
	}{
		{"CIS-5.1.1", "Ensure cluster-admin role is only used where required", SeverityHigh, "5.1 RBAC", "Review cluster-admin role bindings and remove unnecessary ones"},
		{"CIS-5.1.2", "Minimize access to secrets", SeverityHigh, "5.1 RBAC", "Review RBAC policies granting access to secrets"},
		{"CIS-5.1.3", "Minimize wildcard use in Roles and ClusterRoles", SeverityMedium, "5.1 RBAC", "Replace wildcards with specific resources and verbs"},
		{"CIS-5.1.4", "Minimize access to create pods", SeverityMedium, "5.1 RBAC", "Restrict pod creation permissions to authorized users"},
		{"CIS-5.1.5", "Ensure default service account is not actively used", SeverityMedium, "5.1 RBAC", "Create specific service accounts for each workload"},
		{"CIS-5.1.6", "Ensure service account tokens are only mounted where necessary", SeverityMedium, "5.1 RBAC", "Set automountServiceAccountToken to false"},
		{"CIS-5.1.7", "Avoid use of system:masters group", SeverityHigh, "5.1 RBAC", "Avoid binding to system:masters group"},
		{"CIS-5.1.8", "Limit use of the Bind, Impersonate and Escalate permissions", SeverityHigh, "5.1 RBAC", "Restrict bind, impersonate, and escalate permissions"},
		{"CIS-5.1.9", "Minimize access to create persistent volumes", SeverityMedium, "5.1 RBAC", "Restrict PV creation to authorized users"},
		{"CIS-5.1.10", "Minimize access to the proxy sub-resource of nodes", SeverityMedium, "5.1 RBAC", "Restrict access to nodes/proxy"},
		{"CIS-5.1.11", "Minimize access to the approval sub-resource of certificatesigningrequests", SeverityMedium, "5.1 RBAC", "Restrict CSR approval access"},
		{"CIS-5.1.12", "Minimize access to webhook configuration objects", SeverityMedium, "5.1 RBAC", "Restrict webhook configuration access"},
		{"CIS-5.1.13", "Minimize access to the service account token creation", SeverityHigh, "5.1 RBAC", "Restrict token creation for service accounts"},
		{"CIS-5.2.1", "Ensure privileged containers are not used", SeverityHigh, "5.2 Pod Security", "Remove privileged: true from security contexts"},
		{"CIS-5.2.2", "Minimize the admission of containers with hostPID", SeverityHigh, "5.2 Pod Security", "Set hostPID to false"},
		{"CIS-5.2.3", "Minimize the admission of containers with hostIPC", SeverityHigh, "5.2 Pod Security", "Set hostIPC to false"},
		{"CIS-5.2.4", "Minimize the admission of containers with hostNetwork", SeverityHigh, "5.2 Pod Security", "Set hostNetwork to false"},
		{"CIS-5.2.5", "Minimize the admission of containers with allowPrivilegeEscalation", SeverityHigh, "5.2 Pod Security", "Set allowPrivilegeEscalation to false"},
		{"CIS-5.2.6", "Minimize the admission of root containers", SeverityMedium, "5.2 Pod Security", "Set runAsNonRoot to true"},
		{"CIS-5.2.7", "Minimize the admission of containers with dangerous capabilities", SeverityHigh, "5.2 Pod Security", "Remove dangerous capabilities"},
		{"CIS-5.2.8", "Minimize the admission of containers with NET_RAW capability", SeverityMedium, "5.2 Pod Security", "Drop NET_RAW capability"},
		{"CIS-5.2.9", "Minimize the admission of containers with added capabilities", SeverityMedium, "5.2 Pod Security", "Drop all capabilities and add only required ones"},
		{"CIS-5.2.10", "Minimize the admission of containers with capabilities assigned", SeverityLow, "5.2 Pod Security", "Use minimal capabilities"},
		{"CIS-5.2.11", "Minimize the admission of Windows HostProcess containers", SeverityHigh, "5.2 Pod Security", "Disable Windows HostProcess containers"},
		{"CIS-5.2.12", "Minimize the admission of HostPath volumes", SeverityMedium, "5.2 Pod Security", "Avoid hostPath volume mounts"},
		{"CIS-5.2.13", "Minimize the admission of containers which use HostPorts", SeverityMedium, "5.2 Pod Security", "Avoid hostPort usage"},
		{"CIS-5.3.1", "Ensure that the CNI in use supports NetworkPolicies", SeverityMedium, "5.3 Network", "Use a CNI that supports NetworkPolicies"},
		{"CIS-5.3.2", "Ensure that all namespaces have NetworkPolicies defined", SeverityMedium, "5.3 Network", "Create NetworkPolicy for each namespace"},
		{"CIS-5.4.1", "Prefer using Secrets as files over Secrets as environment variables", SeverityMedium, "5.4 Secrets", "Mount secrets as files instead of env vars"},
		{"CIS-5.4.2", "Consider external secret storage", SeverityLow, "5.4 Secrets", "Use external secret management"},
		{"CIS-5.7.1", "Create administrative boundaries between resources", SeverityMedium, "5.7 General", "Use namespaces to separate resources"},
		{"CIS-5.7.2", "Ensure Seccomp profile is set to docker/default or runtime/default", SeverityMedium, "5.7 General", "Set seccomp profile to RuntimeDefault"},
		{"CIS-5.7.3", "Apply SecurityContext to pods and containers", SeverityMedium, "5.7 General", "Define security contexts for all pods"},
		{"CIS-5.7.4", "Avoid using the default namespace", SeverityLow, "5.7 General", "Deploy workloads in dedicated namespaces"},
	}

	for _, c := range controls {
		e.RegisterControl(&Control{
			ID:          c.id,
			Name:        c.name,
			Severity:    c.severity,
			Framework:   "cis-k8s-1.10",
			Section:     c.section,
			Remediation: c.remediation,
		})
	}
}

func (e *Engine) registerCISKubernetes111() {
	e.RegisterFramework(&Framework{
		ID:          "cis-k8s-1.11",
		Name:        "CIS Kubernetes Benchmark",
		Version:     "1.11.0",
		Description: "CIS Kubernetes Benchmark v1.11.0 - 122 controls",
	})

	controls := []struct {
		id          string
		name        string
		severity    Severity
		section     string
		remediation string
	}{
		{"CIS-1.1.1", "Ensure API server pod specification file permissions are set to 600 or more restrictive", SeverityHigh, "1.1 Control Plane", "Set file permissions to 600"},
		{"CIS-1.1.2", "Ensure API server pod specification file ownership is set to root:root", SeverityMedium, "1.1 Control Plane", "Set ownership to root:root"},
		{"CIS-1.2.1", "Ensure anonymous-auth argument is set to false", SeverityHigh, "1.2 API Server", "Set --anonymous-auth=false"},
		{"CIS-1.2.2", "Ensure basic-auth-file argument is not set", SeverityHigh, "1.2 API Server", "Remove --basic-auth-file argument"},
		{"CIS-1.2.3", "Ensure token-auth-file parameter is not set", SeverityHigh, "1.2 API Server", "Remove --token-auth-file argument"},
		{"CIS-1.2.4", "Ensure kubelet-https argument is set to true", SeverityMedium, "1.2 API Server", "Set --kubelet-https=true"},
		{"CIS-1.2.5", "Ensure kubelet-client-certificate and kubelet-client-key arguments are set", SeverityHigh, "1.2 API Server", "Set kubelet client certificate arguments"},
		{"CIS-1.2.6", "Ensure kubelet-certificate-authority argument is set", SeverityHigh, "1.2 API Server", "Set --kubelet-certificate-authority"},
		{"CIS-1.2.7", "Ensure authorization-mode argument is not set to AlwaysAllow", SeverityHigh, "1.2 API Server", "Set authorization-mode to RBAC"},
		{"CIS-1.2.8", "Ensure authorization-mode argument includes Node", SeverityMedium, "1.2 API Server", "Include Node in authorization-mode"},
		{"CIS-1.2.9", "Ensure authorization-mode argument includes RBAC", SeverityHigh, "1.2 API Server", "Include RBAC in authorization-mode"},
		{"CIS-1.2.10", "Ensure admission control plugin EventRateLimit is set", SeverityMedium, "1.2 API Server", "Enable EventRateLimit admission controller"},
		{"CIS-1.2.11", "Ensure admission control plugin AlwaysAdmit is not set", SeverityHigh, "1.2 API Server", "Remove AlwaysAdmit from admission plugins"},
		{"CIS-1.2.12", "Ensure admission control plugin AlwaysPullImages is set", SeverityMedium, "1.2 API Server", "Enable AlwaysPullImages admission controller"},
		{"CIS-1.2.13", "Ensure admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used", SeverityMedium, "1.2 API Server", "Enable SecurityContextDeny if not using PSP"},
		{"CIS-1.2.14", "Ensure admission control plugin ServiceAccount is set", SeverityMedium, "1.2 API Server", "Enable ServiceAccount admission controller"},
		{"CIS-1.2.15", "Ensure admission control plugin NamespaceLifecycle is set", SeverityMedium, "1.2 API Server", "Enable NamespaceLifecycle admission controller"},
		{"CIS-1.2.16", "Ensure admission control plugin NodeRestriction is set", SeverityMedium, "1.2 API Server", "Enable NodeRestriction admission controller"},
		{"CIS-1.2.17", "Ensure insecure-bind-address argument is not set", SeverityCritical, "1.2 API Server", "Remove --insecure-bind-address"},
		{"CIS-1.2.18", "Ensure insecure-port argument is set to 0", SeverityCritical, "1.2 API Server", "Set --insecure-port=0"},
		{"CIS-1.2.19", "Ensure secure-port argument is not set to 0", SeverityHigh, "1.2 API Server", "Ensure secure-port is set to non-zero"},
		{"CIS-1.2.20", "Ensure profiling argument is set to false", SeverityMedium, "1.2 API Server", "Set --profiling=false"},
		{"CIS-1.2.21", "Ensure audit-log-path argument is set", SeverityMedium, "1.2 API Server", "Set --audit-log-path"},
		{"CIS-1.2.22", "Ensure audit-log-maxage argument is set to 30 or as appropriate", SeverityMedium, "1.2 API Server", "Set --audit-log-maxage=30"},
		{"CIS-1.2.23", "Ensure audit-log-maxbackup argument is set to 10 or as appropriate", SeverityMedium, "1.2 API Server", "Set --audit-log-maxbackup=10"},
		{"CIS-1.2.24", "Ensure audit-log-maxsize argument is set to 100 or as appropriate", SeverityMedium, "1.2 API Server", "Set --audit-log-maxsize=100"},
		{"CIS-5.1.1", "Ensure cluster-admin role is only used where required", SeverityHigh, "5.1 RBAC", "Review cluster-admin role bindings"},
		{"CIS-5.1.2", "Minimize access to secrets", SeverityHigh, "5.1 RBAC", "Review RBAC policies granting access to secrets"},
		{"CIS-5.1.3", "Minimize wildcard use in Roles and ClusterRoles", SeverityMedium, "5.1 RBAC", "Replace wildcards with specific resources"},
		{"CIS-5.1.4", "Minimize access to create pods", SeverityMedium, "5.1 RBAC", "Restrict pod creation permissions"},
		{"CIS-5.1.5", "Ensure default service account is not actively used", SeverityMedium, "5.1 RBAC", "Create specific service accounts"},
		{"CIS-5.1.6", "Ensure service account tokens are only mounted where necessary", SeverityMedium, "5.1 RBAC", "Set automountServiceAccountToken to false"},
		{"CIS-5.1.7", "Avoid use of system:masters group", SeverityHigh, "5.1 RBAC", "Avoid system:masters group bindings"},
		{"CIS-5.1.8", "Limit use of the Bind, Impersonate and Escalate permissions", SeverityHigh, "5.1 RBAC", "Restrict dangerous permissions"},
		{"CIS-5.1.9", "Minimize access to create persistent volumes", SeverityMedium, "5.1 RBAC", "Restrict PV creation to authorized users"},
		{"CIS-5.1.10", "Minimize access to the proxy sub-resource of nodes", SeverityMedium, "5.1 RBAC", "Restrict access to nodes/proxy"},
		{"CIS-5.1.11", "Minimize access to the approval sub-resource of certificatesigningrequests", SeverityHigh, "5.1 RBAC", "Restrict CSR approval access"},
		{"CIS-5.1.12", "Minimize access to webhook configuration objects", SeverityHigh, "5.1 RBAC", "Restrict webhook configuration access"},
		{"CIS-5.1.13", "Minimize access to the service account token creation", SeverityMedium, "5.1 RBAC", "Restrict token creation for service accounts"},
		{"CIS-5.2.1", "Ensure privileged containers are not used", SeverityHigh, "5.2 Pod Security", "Remove privileged: true"},
		{"CIS-5.2.2", "Minimize the admission of containers with hostPID", SeverityHigh, "5.2 Pod Security", "Set hostPID to false"},
		{"CIS-5.2.3", "Minimize the admission of containers with hostIPC", SeverityHigh, "5.2 Pod Security", "Set hostIPC to false"},
		{"CIS-5.2.4", "Minimize the admission of containers with hostNetwork", SeverityHigh, "5.2 Pod Security", "Set hostNetwork to false"},
		{"CIS-5.2.5", "Minimize the admission of containers with allowPrivilegeEscalation", SeverityHigh, "5.2 Pod Security", "Set allowPrivilegeEscalation to false"},
		{"CIS-5.2.6", "Minimize the admission of root containers", SeverityMedium, "5.2 Pod Security", "Set runAsNonRoot to true"},
		{"CIS-5.2.7", "Minimize the admission of containers with dangerous capabilities", SeverityHigh, "5.2 Pod Security", "Remove dangerous capabilities"},
		{"CIS-5.2.8", "Minimize the admission of containers with NET_RAW capability", SeverityMedium, "5.2 Pod Security", "Drop NET_RAW capability"},
		{"CIS-5.2.9", "Minimize the admission of containers with added capabilities", SeverityMedium, "5.2 Pod Security", "Drop all capabilities and add only required ones"},
		{"CIS-5.2.10", "Minimize the admission of containers with capabilities assigned", SeverityLow, "5.2 Pod Security", "Use minimal capabilities"},
		{"CIS-5.2.11", "Minimize the admission of Windows HostProcess containers", SeverityHigh, "5.2 Pod Security", "Disable Windows HostProcess containers"},
		{"CIS-5.2.12", "Minimize the admission of HostPath volumes", SeverityMedium, "5.2 Pod Security", "Avoid hostPath volume mounts"},
		{"CIS-5.2.13", "Minimize the admission of containers which use HostPorts", SeverityMedium, "5.2 Pod Security", "Avoid hostPort usage"},
		{"CIS-5.3.1", "Ensure that the CNI supports NetworkPolicies", SeverityMedium, "5.3 Network", "Use CNI with NetworkPolicy support"},
		{"CIS-5.3.2", "Ensure all namespaces have NetworkPolicies defined", SeverityMedium, "5.3 Network", "Create NetworkPolicy for each namespace"},
		{"CIS-5.4.1", "Prefer using Secrets as files over environment variables", SeverityMedium, "5.4 Secrets", "Mount secrets as files"},
		{"CIS-5.4.2", "Consider external secret storage", SeverityLow, "5.4 Secrets", "Use external secret management"},
		{"CIS-5.7.1", "Create administrative boundaries between resources", SeverityMedium, "5.7 General", "Use namespaces for separation"},
		{"CIS-5.7.2", "Ensure Seccomp profile is set", SeverityMedium, "5.7 General", "Set seccomp profile"},
		{"CIS-5.7.3", "Apply SecurityContext to pods and containers", SeverityMedium, "5.7 General", "Define security contexts"},
		{"CIS-5.7.4", "Avoid using the default namespace", SeverityLow, "5.7 General", "Use dedicated namespaces"},
	}

	for _, c := range controls {
		e.RegisterControl(&Control{
			ID:          c.id,
			Name:        c.name,
			Severity:    c.severity,
			Framework:   "cis-k8s-1.11",
			Section:     c.section,
			Remediation: c.remediation,
		})
	}
}

func (e *Engine) registerCISEKS() {
	e.RegisterFramework(&Framework{
		ID:          "cis-eks-1.6",
		Name:        "CIS Amazon EKS Benchmark",
		Version:     "1.6.0",
		Description: "CIS Amazon Elastic Kubernetes Service (EKS) Benchmark v1.6.0 - 35 controls",
	})

	controls := []struct {
		id          string
		name        string
		severity    Severity
		section     string
		remediation string
	}{
		{"EKS-2.1.1", "Enable audit logs", SeverityMedium, "2.1 Logging", "Enable control plane logging in EKS"},
		{"EKS-3.1.1", "Ensure worker nodes use IMDSv2", SeverityHigh, "3.1 Worker Node", "Configure EC2 instances to use IMDSv2"},
		{"EKS-3.1.2", "Ensure worker nodes are not public", SeverityHigh, "3.1 Worker Node", "Place worker nodes in private subnets"},
		{"EKS-3.1.3", "Ensure SSH access is restricted", SeverityMedium, "3.1 Worker Node", "Restrict SSH access to worker nodes"},
		{"EKS-3.2.1", "Ensure that the kubelet kubeconfig file permissions are set to 600", SeverityMedium, "3.2 Kubelet", "Set kubeconfig file permissions to 600"},
		{"EKS-3.2.2", "Ensure that the kubelet kubeconfig file ownership is set to root:root", SeverityMedium, "3.2 Kubelet", "Set kubeconfig ownership to root:root"},
		{"EKS-3.2.3", "Ensure kubelet authentication uses certificates", SeverityHigh, "3.2 Kubelet", "Configure kubelet certificate authentication"},
		{"EKS-3.2.4", "Ensure kubelet authorization is not set to AlwaysAllow", SeverityHigh, "3.2 Kubelet", "Set kubelet authorization mode"},
		{"EKS-3.2.5", "Ensure kubelet read-only port is disabled", SeverityMedium, "3.2 Kubelet", "Set --read-only-port=0"},
		{"EKS-3.2.6", "Ensure streaming connections are protected", SeverityMedium, "3.2 Kubelet", "Enable streaming connection timeouts"},
		{"EKS-3.2.7", "Ensure ProtectKernelDefaults is enabled", SeverityMedium, "3.2 Kubelet", "Set --protect-kernel-defaults=true"},
		{"EKS-3.2.8", "Ensure make-iptables-util-chains is enabled", SeverityMedium, "3.2 Kubelet", "Enable iptables util chains"},
		{"EKS-3.2.9", "Ensure hostname-override is not set", SeverityMedium, "3.2 Kubelet", "Remove hostname-override argument"},
		{"EKS-3.2.10", "Ensure event-qps is set to appropriate level", SeverityLow, "3.2 Kubelet", "Set appropriate event-qps"},
		{"EKS-3.2.11", "Ensure rotate-certificates is enabled", SeverityMedium, "3.2 Kubelet", "Enable certificate rotation"},
		{"EKS-4.1.1", "Ensure cluster-admin role is only used where required", SeverityHigh, "4.1 RBAC", "Review cluster-admin bindings"},
		{"EKS-4.1.2", "Minimize access to secrets", SeverityHigh, "4.1 RBAC", "Restrict secrets access"},
		{"EKS-4.1.3", "Minimize wildcard use in Roles and ClusterRoles", SeverityMedium, "4.1 RBAC", "Avoid wildcards in RBAC"},
		{"EKS-4.1.4", "Minimize access to create pods", SeverityMedium, "4.1 RBAC", "Restrict pod creation"},
		{"EKS-4.1.5", "Ensure default service account is not actively used", SeverityMedium, "4.1 RBAC", "Use dedicated service accounts"},
		{"EKS-4.1.6", "Ensure service account tokens are only mounted where necessary", SeverityMedium, "4.1 RBAC", "Disable automount where not needed"},
		{"EKS-4.2.1", "Minimize the admission of privileged containers", SeverityHigh, "4.2 Pod Security", "Avoid privileged containers"},
		{"EKS-4.2.2", "Minimize the admission of containers with hostPID", SeverityHigh, "4.2 Pod Security", "Disable hostPID"},
		{"EKS-4.2.3", "Minimize the admission of containers with hostIPC", SeverityHigh, "4.2 Pod Security", "Disable hostIPC"},
		{"EKS-4.2.4", "Minimize the admission of containers with hostNetwork", SeverityHigh, "4.2 Pod Security", "Disable hostNetwork"},
		{"EKS-4.2.5", "Minimize the admission of containers with allowPrivilegeEscalation", SeverityHigh, "4.2 Pod Security", "Disable privilege escalation"},
		{"EKS-4.2.6", "Minimize the admission of root containers", SeverityMedium, "4.2 Pod Security", "Run as non-root"},
		{"EKS-4.2.7", "Minimize the admission of containers with NET_RAW capability", SeverityMedium, "4.2 Pod Security", "Drop NET_RAW capability"},
		{"EKS-4.2.8", "Minimize the admission of containers with dangerous capabilities", SeverityHigh, "4.2 Pod Security", "Remove dangerous capabilities"},
		{"EKS-4.3.1", "Ensure CNI supports NetworkPolicies", SeverityMedium, "4.3 Network", "Use VPC CNI or Calico"},
		{"EKS-4.3.2", "Ensure all namespaces have NetworkPolicies", SeverityMedium, "4.3 Network", "Create NetworkPolicies"},
		{"EKS-4.4.1", "Prefer using secrets as files over environment variables", SeverityMedium, "4.4 Secrets", "Mount secrets as files"},
		{"EKS-4.4.2", "Consider external secret storage", SeverityLow, "4.4 Secrets", "Use AWS Secrets Manager"},
		{"EKS-4.6.1", "Create administrative boundaries between resources", SeverityMedium, "4.6 General", "Use namespaces"},
		{"EKS-4.6.2", "Apply security context to pods and containers", SeverityMedium, "4.6 General", "Define security contexts"},
	}

	for _, c := range controls {
		e.RegisterControl(&Control{
			ID:          c.id,
			Name:        c.name,
			Severity:    c.severity,
			Framework:   "cis-eks-1.6",
			Section:     c.section,
			Remediation: c.remediation,
		})
	}
}

func (e *Engine) registerCISAKS() {
	e.RegisterFramework(&Framework{
		ID:          "cis-aks-1.6",
		Name:        "CIS Azure Kubernetes Service Benchmark",
		Version:     "1.6.0",
		Description: "CIS Azure Kubernetes Service (AKS) Benchmark v1.6.0 - 28 controls",
	})

	controls := []struct {
		id          string
		name        string
		severity    Severity
		section     string
		remediation string
	}{
		{"AKS-3.1.1", "Ensure Azure RBAC is enabled", SeverityHigh, "3.1 Identity", "Enable Azure RBAC for AKS"},
		{"AKS-3.1.2", "Ensure Azure AD integration is enabled", SeverityHigh, "3.1 Identity", "Enable Azure AD integration"},
		{"AKS-3.1.3", "Ensure managed identities are used", SeverityMedium, "3.1 Identity", "Use managed identities instead of service principals"},
		{"AKS-3.2.1", "Ensure Network Policy is enabled", SeverityMedium, "3.2 Network", "Enable Network Policy with Azure or Calico"},
		{"AKS-3.2.2", "Ensure authorized IP ranges are configured", SeverityHigh, "3.2 Network", "Configure authorized IP ranges for API server"},
		{"AKS-3.2.3", "Ensure private cluster is enabled", SeverityHigh, "3.2 Network", "Enable private cluster mode"},
		{"AKS-4.1.1", "Ensure cluster-admin role is only used where required", SeverityHigh, "4.1 RBAC", "Review cluster-admin bindings"},
		{"AKS-4.1.2", "Minimize access to secrets", SeverityHigh, "4.1 RBAC", "Restrict secrets access"},
		{"AKS-4.1.3", "Minimize wildcard use in Roles and ClusterRoles", SeverityMedium, "4.1 RBAC", "Avoid wildcards in RBAC"},
		{"AKS-4.1.4", "Minimize access to create pods", SeverityMedium, "4.1 RBAC", "Restrict pod creation"},
		{"AKS-4.1.5", "Ensure default service account is not actively used", SeverityMedium, "4.1 RBAC", "Use dedicated service accounts"},
		{"AKS-4.1.6", "Ensure service account tokens are only mounted where necessary", SeverityMedium, "4.1 RBAC", "Disable automount where not needed"},
		{"AKS-4.2.1", "Minimize the admission of privileged containers", SeverityHigh, "4.2 Pod Security", "Avoid privileged containers"},
		{"AKS-4.2.2", "Minimize the admission of containers with hostPID", SeverityHigh, "4.2 Pod Security", "Disable hostPID"},
		{"AKS-4.2.3", "Minimize the admission of containers with hostIPC", SeverityHigh, "4.2 Pod Security", "Disable hostIPC"},
		{"AKS-4.2.4", "Minimize the admission of containers with hostNetwork", SeverityHigh, "4.2 Pod Security", "Disable hostNetwork"},
		{"AKS-4.2.5", "Minimize the admission of containers with allowPrivilegeEscalation", SeverityHigh, "4.2 Pod Security", "Disable privilege escalation"},
		{"AKS-4.2.6", "Minimize the admission of root containers", SeverityMedium, "4.2 Pod Security", "Run as non-root"},
		{"AKS-4.2.7", "Minimize the admission of containers with NET_RAW capability", SeverityMedium, "4.2 Pod Security", "Drop NET_RAW capability"},
		{"AKS-4.2.8", "Minimize the admission of containers with dangerous capabilities", SeverityHigh, "4.2 Pod Security", "Remove dangerous capabilities"},
		{"AKS-4.3.1", "Ensure all namespaces have NetworkPolicies", SeverityMedium, "4.3 Network", "Create NetworkPolicies"},
		{"AKS-4.4.1", "Prefer using secrets as files over environment variables", SeverityMedium, "4.4 Secrets", "Mount secrets as files"},
		{"AKS-4.4.2", "Consider Azure Key Vault for secrets", SeverityLow, "4.4 Secrets", "Use Azure Key Vault provider"},
		{"AKS-4.6.1", "Create administrative boundaries between resources", SeverityMedium, "4.6 General", "Use namespaces"},
		{"AKS-4.6.2", "Apply security context to pods and containers", SeverityMedium, "4.6 General", "Define security contexts"},
		{"AKS-4.6.3", "Ensure container images are from trusted registries", SeverityMedium, "4.6 General", "Use Azure Container Registry"},
		{"AKS-5.1.1", "Ensure Microsoft Defender for Containers is enabled", SeverityMedium, "5.1 Monitoring", "Enable Defender for Containers"},
		{"AKS-5.1.2", "Ensure diagnostic settings are configured", SeverityMedium, "5.1 Monitoring", "Enable diagnostic logging"},
	}

	for _, c := range controls {
		e.RegisterControl(&Control{
			ID:          c.id,
			Name:        c.name,
			Severity:    c.severity,
			Framework:   "cis-aks-1.6",
			Section:     c.section,
			Remediation: c.remediation,
		})
	}
}

func (e *Engine) registerCISOpenShift() {
	e.RegisterFramework(&Framework{
		ID:          "cis-ocp-1.7",
		Name:        "CIS Red Hat OpenShift Container Platform Benchmark",
		Version:     "1.7.0",
		Description: "CIS Red Hat OpenShift Container Platform Benchmark v1.7.0 - 23 controls",
	})

	controls := []struct {
		id          string
		name        string
		severity    Severity
		section     string
		remediation string
	}{
		{"OCP-1.1.1", "Ensure API server pod specification file permissions are set correctly", SeverityMedium, "1.1 Control Plane", "Set file permissions to 600"},
		{"OCP-1.2.1", "Ensure anonymous-auth argument is set to false", SeverityHigh, "1.2 API Server", "Set --anonymous-auth=false"},
		{"OCP-1.2.2", "Ensure authorization-mode includes RBAC", SeverityHigh, "1.2 API Server", "Include RBAC in authorization-mode"},
		{"OCP-5.1.1", "Ensure cluster-admin role is only used where required", SeverityHigh, "5.1 RBAC", "Review cluster-admin bindings"},
		{"OCP-5.1.2", "Minimize access to secrets", SeverityHigh, "5.1 RBAC", "Restrict secrets access"},
		{"OCP-5.1.3", "Minimize wildcard use in Roles and ClusterRoles", SeverityMedium, "5.1 RBAC", "Avoid wildcards in RBAC"},
		{"OCP-5.1.4", "Minimize access to create pods", SeverityMedium, "5.1 RBAC", "Restrict pod creation"},
		{"OCP-5.1.5", "Ensure default service account is not actively used", SeverityMedium, "5.1 RBAC", "Use dedicated service accounts"},
		{"OCP-5.1.6", "Ensure service account tokens are only mounted where necessary", SeverityMedium, "5.1 RBAC", "Disable automount where not needed"},
		{"OCP-5.2.1", "Ensure SCCs are configured correctly", SeverityHigh, "5.2 SCC", "Review Security Context Constraints"},
		{"OCP-5.2.2", "Minimize the admission of privileged containers", SeverityHigh, "5.2 SCC", "Use restricted SCC"},
		{"OCP-5.2.3", "Minimize the admission of containers with hostPID", SeverityHigh, "5.2 SCC", "Disable hostPID in SCCs"},
		{"OCP-5.2.4", "Minimize the admission of containers with hostIPC", SeverityHigh, "5.2 SCC", "Disable hostIPC in SCCs"},
		{"OCP-5.2.5", "Minimize the admission of containers with hostNetwork", SeverityHigh, "5.2 SCC", "Disable hostNetwork in SCCs"},
		{"OCP-5.2.6", "Minimize the admission of containers with allowPrivilegeEscalation", SeverityHigh, "5.2 SCC", "Disable privilege escalation"},
		{"OCP-5.2.7", "Minimize the admission of root containers", SeverityMedium, "5.2 SCC", "Run as non-root"},
		{"OCP-5.3.1", "Ensure all namespaces have NetworkPolicies", SeverityMedium, "5.3 Network", "Create NetworkPolicies"},
		{"OCP-5.4.1", "Prefer using secrets as files over environment variables", SeverityMedium, "5.4 Secrets", "Mount secrets as files"},
		{"OCP-5.5.1", "Configure audit logging", SeverityMedium, "5.5 Logging", "Enable audit logging"},
		{"OCP-5.7.1", "Create administrative boundaries between resources", SeverityMedium, "5.7 General", "Use projects/namespaces"},
		{"OCP-5.7.2", "Apply security context to pods and containers", SeverityMedium, "5.7 General", "Define security contexts"},
		{"OCP-5.7.3", "Avoid using the default namespace", SeverityLow, "5.7 General", "Use dedicated namespaces"},
		{"OCP-5.7.4", "Ensure container images are from trusted registries", SeverityMedium, "5.7 General", "Use internal registry"},
	}

	for _, c := range controls {
		e.RegisterControl(&Control{
			ID:          c.id,
			Name:        c.name,
			Severity:    c.severity,
			Framework:   "cis-ocp-1.7",
			Section:     c.section,
			Remediation: c.remediation,
		})
	}
}

func (e *Engine) registerKubernetesBestPractices() {
	e.RegisterFramework(&Framework{
		ID:          "k8s-best-practices",
		Name:        "Kubernetes Best Practices",
		Version:     "1.0",
		Description: "Kubernetes Best Practices - 60 controls",
	})

	controls := []struct {
		id          string
		name        string
		severity    Severity
		section     string
		remediation string
	}{
		{"KBP-001", "Containers should not run as root", SeverityMedium, "Pod Security", "Set runAsNonRoot: true"},
		{"KBP-002", "Containers should use read-only root filesystem", SeverityMedium, "Pod Security", "Set readOnlyRootFilesystem: true"},
		{"KBP-003", "Containers should drop all capabilities", SeverityMedium, "Pod Security", "Drop ALL capabilities"},
		{"KBP-004", "Containers should not allow privilege escalation", SeverityHigh, "Pod Security", "Set allowPrivilegeEscalation: false"},
		{"KBP-005", "Containers should have resource limits defined", SeverityMedium, "Resources", "Define CPU and memory limits"},
		{"KBP-006", "Containers should have resource requests defined", SeverityMedium, "Resources", "Define CPU and memory requests"},
		{"KBP-007", "Containers should have liveness probes", SeverityMedium, "Health Checks", "Configure liveness probe"},
		{"KBP-008", "Containers should have readiness probes", SeverityMedium, "Health Checks", "Configure readiness probe"},
		{"KBP-009", "Images should use specific tags", SeverityMedium, "Images", "Avoid latest tag, use specific versions"},
		{"KBP-010", "Images should be from trusted registries", SeverityMedium, "Images", "Use internal or trusted registries"},
		{"KBP-011", "Pods should not use hostNetwork", SeverityHigh, "Pod Security", "Set hostNetwork: false"},
		{"KBP-012", "Pods should not use hostPID", SeverityHigh, "Pod Security", "Set hostPID: false"},
		{"KBP-013", "Pods should not use hostIPC", SeverityHigh, "Pod Security", "Set hostIPC: false"},
		{"KBP-014", "Pods should not mount hostPath volumes", SeverityMedium, "Pod Security", "Avoid hostPath volumes"},
		{"KBP-015", "Pods should not use host ports", SeverityMedium, "Pod Security", "Avoid hostPort usage"},
		{"KBP-016", "Services should not use NodePort", SeverityLow, "Network", "Use LoadBalancer or ClusterIP"},
		{"KBP-017", "Namespaces should have resource quotas", SeverityMedium, "Resources", "Define ResourceQuota"},
		{"KBP-018", "Namespaces should have limit ranges", SeverityMedium, "Resources", "Define LimitRange"},
		{"KBP-019", "Namespaces should have network policies", SeverityMedium, "Network", "Create NetworkPolicy"},
		{"KBP-020", "Default service account should not be used", SeverityMedium, "RBAC", "Create dedicated service accounts"},
		{"KBP-021", "Service account tokens should not be auto-mounted", SeverityMedium, "RBAC", "Set automountServiceAccountToken: false"},
		{"KBP-022", "RBAC should use least privilege", SeverityHigh, "RBAC", "Grant minimal required permissions"},
		{"KBP-023", "Secrets should not be stored in environment variables", SeverityMedium, "Secrets", "Mount secrets as volumes"},
		{"KBP-024", "ConfigMaps should not contain sensitive data", SeverityMedium, "Secrets", "Use Secrets for sensitive data"},
		{"KBP-025", "Deployments should have multiple replicas", SeverityLow, "Availability", "Set replicas > 1 for production"},
		{"KBP-026", "Deployments should use rolling updates", SeverityLow, "Availability", "Configure rolling update strategy"},
		{"KBP-027", "Pods should have pod disruption budgets", SeverityLow, "Availability", "Create PodDisruptionBudget"},
		{"KBP-028", "Pods should have anti-affinity rules", SeverityLow, "Availability", "Configure pod anti-affinity"},
		{"KBP-029", "Containers should not run privileged", SeverityHigh, "Pod Security", "Set privileged: false"},
		{"KBP-030", "Seccomp profile should be set", SeverityMedium, "Pod Security", "Set seccomp profile to RuntimeDefault"},
		{"KBP-031", "AppArmor profile should be set", SeverityMedium, "Pod Security", "Configure AppArmor profile"},
		{"KBP-032", "SELinux context should be set", SeverityMedium, "Pod Security", "Configure SELinux options"},
		{"KBP-033", "Pods should define security context", SeverityMedium, "Pod Security", "Define pod security context"},
		{"KBP-034", "Containers should define security context", SeverityMedium, "Pod Security", "Define container security context"},
		{"KBP-035", "Workloads should use recommended labels", SeverityLow, "Best Practices", "Add app.kubernetes.io labels"},
		{"KBP-036", "Pods should have correct restart policy", SeverityLow, "Best Practices", "Set appropriate restartPolicy"},
		{"KBP-037", "Pods should define termination grace period", SeverityLow, "Best Practices", "Set terminationGracePeriodSeconds"},
		{"KBP-038", "Ingress should use TLS", SeverityMedium, "Network", "Configure TLS for Ingress"},
		{"KBP-039", "Ingress should have annotations for security", SeverityMedium, "Network", "Add security annotations"},
		{"KBP-040", "Services should have selectors", SeverityLow, "Network", "Define service selectors"},
		{"KBP-041", "Pods should not have NET_RAW capability", SeverityMedium, "Pod Security", "Drop NET_RAW capability"},
		{"KBP-042", "Pods should not have SYS_ADMIN capability", SeverityHigh, "Pod Security", "Drop SYS_ADMIN capability"},
		{"KBP-043", "Pods should not have dangerous capabilities", SeverityHigh, "Pod Security", "Drop dangerous capabilities"},
		{"KBP-044", "CronJobs should have history limits", SeverityLow, "Best Practices", "Set history limits"},
		{"KBP-045", "Jobs should have TTL after finished", SeverityLow, "Best Practices", "Set ttlSecondsAfterFinished"},
		{"KBP-046", "Pods should have priority class", SeverityLow, "Resources", "Set priorityClassName"},
		{"KBP-047", "StatefulSets should have volume claim templates", SeverityMedium, "Storage", "Define volumeClaimTemplates"},
		{"KBP-048", "PVCs should have appropriate access modes", SeverityMedium, "Storage", "Set correct access modes"},
		{"KBP-049", "Storage classes should use encryption", SeverityMedium, "Storage", "Enable encryption at rest"},
		{"KBP-050", "Horizontal Pod Autoscaler should be configured", SeverityLow, "Scaling", "Create HPA for workloads"},
		{"KBP-051", "Vertical Pod Autoscaler should be considered", SeverityLow, "Scaling", "Consider VPA for right-sizing"},
		{"KBP-052", "Pod topology spread constraints should be defined", SeverityLow, "Availability", "Configure topology spread"},
		{"KBP-053", "Init containers should have security context", SeverityMedium, "Pod Security", "Define init container security"},
		{"KBP-054", "Ephemeral containers should be restricted", SeverityMedium, "Pod Security", "Limit ephemeral container usage"},
		{"KBP-055", "Service mesh should use mTLS", SeverityMedium, "Network", "Enable mutual TLS"},
		{"KBP-056", "External secrets operator should be used", SeverityLow, "Secrets", "Consider external secrets"},
		{"KBP-057", "Pod security admission should be configured", SeverityMedium, "Pod Security", "Enable Pod Security Admission"},
		{"KBP-058", "Gatekeeper/OPA should be deployed", SeverityLow, "Policy", "Deploy policy engine"},
		{"KBP-059", "Runtime security should be enabled", SeverityMedium, "Security", "Enable runtime security tools"},
		{"KBP-060", "Image scanning should be enabled", SeverityMedium, "Images", "Enable container image scanning"},
	}

	for _, c := range controls {
		e.RegisterControl(&Control{
			ID:          c.id,
			Name:        c.name,
			Severity:    c.severity,
			Framework:   "k8s-best-practices",
			Section:     c.section,
			Remediation: c.remediation,
		})
	}
}

func (e *Engine) registerEKSBestPractices() {
	e.RegisterFramework(&Framework{
		ID:          "eks-best-practices",
		Name:        "AWS EKS Best Practices",
		Version:     "1.0",
		Description: "AWS Elastic Kubernetes Service Best Practices - 58 controls",
	})

	controls := []struct {
		id          string
		name        string
		severity    Severity
		section     string
		remediation string
	}{
		{"EKS-BP-001", "Use IAM Roles for Service Accounts (IRSA)", SeverityHigh, "Identity", "Configure IRSA for workloads"},
		{"EKS-BP-002", "Enable control plane logging", SeverityMedium, "Logging", "Enable all control plane log types"},
		{"EKS-BP-003", "Use private endpoint for API server", SeverityHigh, "Network", "Enable private API endpoint"},
		{"EKS-BP-004", "Restrict public endpoint access", SeverityHigh, "Network", "Limit public endpoint CIDR blocks"},
		{"EKS-BP-005", "Use managed node groups", SeverityLow, "Compute", "Prefer managed node groups"},
		{"EKS-BP-006", "Use Bottlerocket or Amazon Linux 2", SeverityMedium, "Compute", "Use hardened AMIs"},
		{"EKS-BP-007", "Enable envelope encryption for secrets", SeverityHigh, "Secrets", "Configure KMS envelope encryption"},
		{"EKS-BP-008", "Use AWS Secrets Manager", SeverityMedium, "Secrets", "Integrate with Secrets Manager"},
		{"EKS-BP-009", "Enable VPC CNI network policies", SeverityMedium, "Network", "Enable network policy support"},
		{"EKS-BP-010", "Use security groups for pods", SeverityMedium, "Network", "Enable security groups for pods"},
		{"EKS-BP-011", "Enable Amazon GuardDuty for EKS", SeverityMedium, "Monitoring", "Enable GuardDuty EKS Protection"},
		{"EKS-BP-012", "Use AWS Security Hub", SeverityLow, "Monitoring", "Enable Security Hub integration"},
		{"EKS-BP-013", "Enable Container Insights", SeverityMedium, "Monitoring", "Enable CloudWatch Container Insights"},
		{"EKS-BP-014", "Use Fargate for sensitive workloads", SeverityMedium, "Compute", "Consider Fargate for isolation"},
		{"EKS-BP-015", "Enable cluster autoscaler", SeverityLow, "Scaling", "Deploy Cluster Autoscaler"},
		{"EKS-BP-016", "Use Karpenter for efficient scaling", SeverityLow, "Scaling", "Consider Karpenter for node provisioning"},
		{"EKS-BP-017", "Configure pod identity associations", SeverityMedium, "Identity", "Use EKS Pod Identity"},
		{"EKS-BP-018", "Restrict node IAM role permissions", SeverityHigh, "Identity", "Apply least privilege to node role"},
		{"EKS-BP-019", "Use IMDSv2 on worker nodes", SeverityHigh, "Compute", "Require IMDSv2"},
		{"EKS-BP-020", "Encrypt EBS volumes", SeverityMedium, "Storage", "Enable EBS encryption"},
		{"EKS-BP-021", "Use EFS CSI driver for shared storage", SeverityLow, "Storage", "Deploy EFS CSI driver"},
		{"EKS-BP-022", "Enable EBS CSI driver encryption", SeverityMedium, "Storage", "Configure CSI driver encryption"},
		{"EKS-BP-023", "Use AWS Load Balancer Controller", SeverityLow, "Network", "Deploy AWS LB Controller"},
		{"EKS-BP-024", "Configure proper ingress annotations", SeverityMedium, "Network", "Use security annotations"},
		{"EKS-BP-025", "Enable access logging for ALB", SeverityMedium, "Logging", "Enable ALB access logs"},
		{"EKS-BP-026", "Use AWS App Mesh or Istio", SeverityLow, "Network", "Consider service mesh"},
		{"EKS-BP-027", "Enable mTLS in service mesh", SeverityMedium, "Network", "Configure mutual TLS"},
		{"EKS-BP-028", "Use ECR for container images", SeverityMedium, "Images", "Use Amazon ECR"},
		{"EKS-BP-029", "Enable ECR image scanning", SeverityMedium, "Images", "Enable ECR scanning"},
		{"EKS-BP-030", "Use ECR pull-through cache", SeverityLow, "Images", "Configure pull-through cache"},
		{"EKS-BP-031", "Implement image signing", SeverityMedium, "Images", "Use Notation or Cosign"},
		{"EKS-BP-032", "Configure CoreDNS appropriately", SeverityLow, "Network", "Tune CoreDNS settings"},
		{"EKS-BP-033", "Use VPC endpoints for AWS services", SeverityMedium, "Network", "Create VPC endpoints"},
		{"EKS-BP-034", "Enable flow logs for VPC", SeverityMedium, "Logging", "Enable VPC flow logs"},
		{"EKS-BP-035", "Configure proper node security groups", SeverityHigh, "Network", "Restrict node security groups"},
		{"EKS-BP-036", "Use Pod Security Admission", SeverityMedium, "Pod Security", "Enable PSA"},
		{"EKS-BP-037", "Deploy OPA Gatekeeper", SeverityMedium, "Policy", "Install Gatekeeper"},
		{"EKS-BP-038", "Use Kyverno for policies", SeverityLow, "Policy", "Consider Kyverno"},
		{"EKS-BP-039", "Enable runtime security", SeverityMedium, "Security", "Deploy Falco or similar"},
		{"EKS-BP-040", "Configure resource quotas", SeverityMedium, "Resources", "Set namespace quotas"},
		{"EKS-BP-041", "Set limit ranges", SeverityMedium, "Resources", "Configure LimitRange"},
		{"EKS-BP-042", "Use priority classes", SeverityLow, "Resources", "Define PriorityClasses"},
		{"EKS-BP-043", "Configure node taints and tolerations", SeverityLow, "Scheduling", "Use taints and tolerations"},
		{"EKS-BP-044", "Use node affinity rules", SeverityLow, "Scheduling", "Configure node affinity"},
		{"EKS-BP-045", "Enable pod anti-affinity", SeverityLow, "Availability", "Set pod anti-affinity"},
		{"EKS-BP-046", "Configure pod disruption budgets", SeverityMedium, "Availability", "Create PDBs"},
		{"EKS-BP-047", "Use topology spread constraints", SeverityLow, "Availability", "Configure topology spread"},
		{"EKS-BP-048", "Enable horizontal pod autoscaling", SeverityLow, "Scaling", "Deploy HPA"},
		{"EKS-BP-049", "Consider vertical pod autoscaling", SeverityLow, "Scaling", "Evaluate VPA"},
		{"EKS-BP-050", "Configure KEDA for event-driven scaling", SeverityLow, "Scaling", "Consider KEDA"},
		{"EKS-BP-051", "Use external-dns for DNS management", SeverityLow, "Network", "Deploy external-dns"},
		{"EKS-BP-052", "Configure proper health checks", SeverityMedium, "Health", "Set liveness and readiness probes"},
		{"EKS-BP-053", "Use startup probes for slow-starting containers", SeverityLow, "Health", "Configure startup probes"},
		{"EKS-BP-054", "Configure proper termination handling", SeverityLow, "Best Practices", "Set graceful shutdown"},
		{"EKS-BP-055", "Use ConfigMaps for configuration", SeverityLow, "Configuration", "Externalize configuration"},
		{"EKS-BP-056", "Enable GitOps with Flux or ArgoCD", SeverityLow, "Deployment", "Implement GitOps"},
		{"EKS-BP-057", "Use Helm for application packaging", SeverityLow, "Deployment", "Standardize on Helm"},
		{"EKS-BP-058", "Implement proper backup strategy", SeverityMedium, "Disaster Recovery", "Configure Velero or similar"},
	}

	for _, c := range controls {
		e.RegisterControl(&Control{
			ID:          c.id,
			Name:        c.name,
			Severity:    c.severity,
			Framework:   "eks-best-practices",
			Section:     c.section,
			Remediation: c.remediation,
		})
	}
}

func (e *Engine) registerAKSBestPractices() {
	e.RegisterFramework(&Framework{
		ID:          "aks-best-practices",
		Name:        "Azure AKS Best Practices",
		Version:     "1.0",
		Description: "Azure Kubernetes Service Best Practices - 56 controls",
	})

	controls := []struct {
		id          string
		name        string
		severity    Severity
		section     string
		remediation string
	}{
		{"AKS-BP-001", "Use Azure AD integration", SeverityHigh, "Identity", "Enable Azure AD authentication"},
		{"AKS-BP-002", "Use managed identities", SeverityHigh, "Identity", "Configure managed identity"},
		{"AKS-BP-003", "Use workload identity", SeverityMedium, "Identity", "Enable workload identity"},
		{"AKS-BP-004", "Enable Azure RBAC for Kubernetes", SeverityHigh, "Identity", "Use Azure RBAC"},
		{"AKS-BP-005", "Use private cluster", SeverityHigh, "Network", "Enable private cluster mode"},
		{"AKS-BP-006", "Configure authorized IP ranges", SeverityHigh, "Network", "Restrict API server access"},
		{"AKS-BP-007", "Use Azure CNI networking", SeverityMedium, "Network", "Choose Azure CNI over kubenet"},
		{"AKS-BP-008", "Enable network policies", SeverityMedium, "Network", "Use Azure or Calico policies"},
		{"AKS-BP-009", "Use Azure Firewall for egress", SeverityMedium, "Network", "Route egress through firewall"},
		{"AKS-BP-010", "Configure private link for Azure services", SeverityMedium, "Network", "Use private endpoints"},
		{"AKS-BP-011", "Enable Microsoft Defender for Containers", SeverityMedium, "Security", "Enable Defender"},
		{"AKS-BP-012", "Enable Azure Policy for AKS", SeverityMedium, "Policy", "Configure Azure Policy"},
		{"AKS-BP-013", "Use Azure Key Vault for secrets", SeverityMedium, "Secrets", "Enable Key Vault provider"},
		{"AKS-BP-014", "Enable secrets store CSI driver", SeverityMedium, "Secrets", "Deploy CSI driver"},
		{"AKS-BP-015", "Configure disk encryption", SeverityMedium, "Storage", "Enable Azure Disk encryption"},
		{"AKS-BP-016", "Use Azure Files for shared storage", SeverityLow, "Storage", "Consider Azure Files"},
		{"AKS-BP-017", "Enable Azure Container Registry integration", SeverityMedium, "Images", "Attach ACR to cluster"},
		{"AKS-BP-018", "Enable ACR content trust", SeverityMedium, "Images", "Configure image signing"},
		{"AKS-BP-019", "Enable vulnerability scanning", SeverityMedium, "Images", "Scan images in ACR"},
		{"AKS-BP-020", "Use node pools for isolation", SeverityMedium, "Compute", "Create dedicated node pools"},
		{"AKS-BP-021", "Use system and user node pools", SeverityMedium, "Compute", "Separate system workloads"},
		{"AKS-BP-022", "Configure node pool autoscaling", SeverityLow, "Scaling", "Enable cluster autoscaler"},
		{"AKS-BP-023", "Use virtual nodes for burst capacity", SeverityLow, "Scaling", "Consider virtual nodes"},
		{"AKS-BP-024", "Enable pod security admission", SeverityMedium, "Pod Security", "Configure PSA"},
		{"AKS-BP-025", "Use ephemeral OS disks", SeverityLow, "Compute", "Enable ephemeral OS disks"},
		{"AKS-BP-026", "Configure Azure Monitor for containers", SeverityMedium, "Monitoring", "Enable monitoring"},
		{"AKS-BP-027", "Enable diagnostic settings", SeverityMedium, "Logging", "Configure diagnostics"},
		{"AKS-BP-028", "Use Log Analytics workspace", SeverityMedium, "Logging", "Connect to Log Analytics"},
		{"AKS-BP-029", "Configure alerts for cluster health", SeverityMedium, "Monitoring", "Create health alerts"},
		{"AKS-BP-030", "Enable Container Insights", SeverityMedium, "Monitoring", "Use Container Insights"},
		{"AKS-BP-031", "Configure resource quotas", SeverityMedium, "Resources", "Set namespace quotas"},
		{"AKS-BP-032", "Set limit ranges", SeverityMedium, "Resources", "Configure LimitRange"},
		{"AKS-BP-033", "Use priority classes", SeverityLow, "Resources", "Define PriorityClasses"},
		{"AKS-BP-034", "Configure taints and tolerations", SeverityLow, "Scheduling", "Use taints for isolation"},
		{"AKS-BP-035", "Use pod anti-affinity", SeverityLow, "Availability", "Configure anti-affinity"},
		{"AKS-BP-036", "Create pod disruption budgets", SeverityMedium, "Availability", "Define PDBs"},
		{"AKS-BP-037", "Use availability zones", SeverityMedium, "Availability", "Deploy across zones"},
		{"AKS-BP-038", "Configure horizontal pod autoscaling", SeverityLow, "Scaling", "Deploy HPA"},
		{"AKS-BP-039", "Enable vertical pod autoscaling", SeverityLow, "Scaling", "Consider VPA"},
		{"AKS-BP-040", "Use Application Gateway Ingress Controller", SeverityLow, "Network", "Deploy AGIC"},
		{"AKS-BP-041", "Configure WAF for ingress", SeverityMedium, "Network", "Enable WAF policies"},
		{"AKS-BP-042", "Use Azure Service Mesh", SeverityLow, "Network", "Consider Istio or OSM"},
		{"AKS-BP-043", "Enable mTLS in service mesh", SeverityMedium, "Network", "Configure mutual TLS"},
		{"AKS-BP-044", "Configure proper health probes", SeverityMedium, "Health", "Set probes correctly"},
		{"AKS-BP-045", "Use startup probes for slow containers", SeverityLow, "Health", "Add startup probes"},
		{"AKS-BP-046", "Configure graceful shutdown", SeverityLow, "Best Practices", "Set termination period"},
		{"AKS-BP-047", "Use ConfigMaps for configuration", SeverityLow, "Configuration", "Externalize config"},
		{"AKS-BP-048", "Enable GitOps with Flux", SeverityLow, "Deployment", "Use Flux extension"},
		{"AKS-BP-049", "Use Helm for deployments", SeverityLow, "Deployment", "Standardize on Helm"},
		{"AKS-BP-050", "Configure Azure Backup for AKS", SeverityMedium, "Disaster Recovery", "Enable backup"},
		{"AKS-BP-051", "Plan for multi-region deployment", SeverityMedium, "Disaster Recovery", "Design for DR"},
		{"AKS-BP-052", "Use Azure Traffic Manager", SeverityLow, "Network", "Consider global routing"},
		{"AKS-BP-053", "Enable OMS agent", SeverityMedium, "Monitoring", "Deploy OMS agent"},
		{"AKS-BP-054", "Configure Prometheus metrics", SeverityLow, "Monitoring", "Enable metrics collection"},
		{"AKS-BP-055", "Use Azure Managed Grafana", SeverityLow, "Monitoring", "Consider managed Grafana"},
		{"AKS-BP-056", "Enable cost analysis", SeverityLow, "Cost", "Monitor cluster costs"},
	}

	for _, c := range controls {
		e.RegisterControl(&Control{
			ID:          c.id,
			Name:        c.name,
			Severity:    c.severity,
			Framework:   "aks-best-practices",
			Section:     c.section,
			Remediation: c.remediation,
		})
	}
}

func (e *Engine) registerOpenShiftBestPractices() {
	e.RegisterFramework(&Framework{
		ID:          "ocp-best-practices",
		Name:        "Red Hat OpenShift Best Practices",
		Version:     "1.0",
		Description: "Red Hat OpenShift Container Platform Best Practices - 56 controls",
	})

	controls := []struct {
		id          string
		name        string
		severity    Severity
		section     string
		remediation string
	}{
		{"OCP-BP-001", "Use OAuth with external identity provider", SeverityHigh, "Identity", "Configure OAuth providers"},
		{"OCP-BP-002", "Disable kubeadmin after initial setup", SeverityHigh, "Identity", "Remove kubeadmin secret"},
		{"OCP-BP-003", "Use LDAP or OIDC for authentication", SeverityMedium, "Identity", "Configure identity provider"},
		{"OCP-BP-004", "Configure cluster role bindings appropriately", SeverityHigh, "RBAC", "Review role bindings"},
		{"OCP-BP-005", "Use project request templates", SeverityMedium, "Multi-tenancy", "Configure project templates"},
		{"OCP-BP-006", "Use restricted SCC as default", SeverityHigh, "SCC", "Assign restricted SCC"},
		{"OCP-BP-007", "Minimize use of anyuid SCC", SeverityHigh, "SCC", "Avoid anyuid SCC"},
		{"OCP-BP-008", "Avoid privileged SCC", SeverityCritical, "SCC", "Never use privileged SCC"},
		{"OCP-BP-009", "Create custom SCCs when needed", SeverityMedium, "SCC", "Define minimal custom SCCs"},
		{"OCP-BP-010", "Enable network policies", SeverityMedium, "Network", "Use OpenShift SDN or OVN"},
		{"OCP-BP-011", "Configure egress firewall", SeverityMedium, "Network", "Define EgressFirewall"},
		{"OCP-BP-012", "Use internal registry", SeverityMedium, "Images", "Use OpenShift registry"},
		{"OCP-BP-013", "Enable image signature verification", SeverityMedium, "Images", "Configure image policy"},
		{"OCP-BP-014", "Use allowed registries", SeverityMedium, "Images", "Set allowed registries"},
		{"OCP-BP-015", "Enable image scanning", SeverityMedium, "Images", "Use Quay or ACS scanning"},
		{"OCP-BP-016", "Configure resource quotas per project", SeverityMedium, "Resources", "Set project quotas"},
		{"OCP-BP-017", "Use limit ranges", SeverityMedium, "Resources", "Configure LimitRange"},
		{"OCP-BP-018", "Enable cluster resource overcommitment", SeverityLow, "Resources", "Tune overcommit settings"},
		{"OCP-BP-019", "Use monitoring stack", SeverityMedium, "Monitoring", "Enable cluster monitoring"},
		{"OCP-BP-020", "Configure alerting rules", SeverityMedium, "Monitoring", "Create PrometheusRules"},
		{"OCP-BP-021", "Enable logging stack", SeverityMedium, "Logging", "Deploy cluster logging"},
		{"OCP-BP-022", "Configure audit logging", SeverityMedium, "Logging", "Enable audit policies"},
		{"OCP-BP-023", "Use cluster network operator", SeverityLow, "Network", "Manage via CNO"},
		{"OCP-BP-024", "Configure ingress controller properly", SeverityMedium, "Network", "Tune ingress settings"},
		{"OCP-BP-025", "Use routes with TLS", SeverityMedium, "Network", "Enable route TLS"},
		{"OCP-BP-026", "Configure edge termination", SeverityMedium, "Network", "Use edge or re-encrypt"},
		{"OCP-BP-027", "Enable service mesh", SeverityLow, "Network", "Deploy OpenShift Service Mesh"},
		{"OCP-BP-028", "Configure mTLS in service mesh", SeverityMedium, "Network", "Enable mutual TLS"},
		{"OCP-BP-029", "Use operators from certified catalog", SeverityMedium, "Operators", "Use certified operators"},
		{"OCP-BP-030", "Review operator permissions", SeverityMedium, "Operators", "Audit operator RBAC"},
		{"OCP-BP-031", "Configure operator lifecycle manager", SeverityLow, "Operators", "Manage via OLM"},
		{"OCP-BP-032", "Use pod disruption budgets", SeverityMedium, "Availability", "Create PDBs"},
		{"OCP-BP-033", "Configure pod anti-affinity", SeverityLow, "Availability", "Set anti-affinity rules"},
		{"OCP-BP-034", "Use node affinity for placement", SeverityLow, "Scheduling", "Configure node affinity"},
		{"OCP-BP-035", "Configure machine sets for scaling", SeverityLow, "Scaling", "Use MachineSet CRs"},
		{"OCP-BP-036", "Enable cluster autoscaler", SeverityLow, "Scaling", "Deploy ClusterAutoscaler"},
		{"OCP-BP-037", "Use horizontal pod autoscaler", SeverityLow, "Scaling", "Configure HPA"},
		{"OCP-BP-038", "Configure proper health probes", SeverityMedium, "Health", "Set all probe types"},
		{"OCP-BP-039", "Use startup probes", SeverityLow, "Health", "Add startup probes"},
		{"OCP-BP-040", "Configure graceful termination", SeverityLow, "Best Practices", "Set termination grace period"},
		{"OCP-BP-041", "Use ConfigMaps for configuration", SeverityLow, "Configuration", "Externalize config"},
		{"OCP-BP-042", "Store secrets in vault", SeverityMedium, "Secrets", "Use external vault"},
		{"OCP-BP-043", "Enable etcd encryption", SeverityHigh, "Secrets", "Encrypt etcd at rest"},
		{"OCP-BP-044", "Use GitOps with ArgoCD", SeverityLow, "Deployment", "Deploy OpenShift GitOps"},
		{"OCP-BP-045", "Configure build security", SeverityMedium, "Builds", "Secure build configs"},
		{"OCP-BP-046", "Use source-to-image builds", SeverityLow, "Builds", "Prefer S2I builds"},
		{"OCP-BP-047", "Configure pipeline security", SeverityMedium, "CI/CD", "Secure Tekton pipelines"},
		{"OCP-BP-048", "Enable infrastructure nodes", SeverityMedium, "Infrastructure", "Separate infra workloads"},
		{"OCP-BP-049", "Configure storage classes", SeverityMedium, "Storage", "Define storage classes"},
		{"OCP-BP-050", "Use persistent volumes", SeverityMedium, "Storage", "Use PVCs correctly"},
		{"OCP-BP-051", "Enable backup and restore", SeverityMedium, "Disaster Recovery", "Configure OADP"},
		{"OCP-BP-052", "Plan for multi-cluster management", SeverityLow, "Operations", "Consider ACM"},
		{"OCP-BP-053", "Use compliance operator", SeverityMedium, "Compliance", "Deploy compliance operator"},
		{"OCP-BP-054", "Enable file integrity operator", SeverityMedium, "Security", "Monitor file changes"},
		{"OCP-BP-055", "Configure node maintenance", SeverityLow, "Operations", "Use node maintenance operator"},
		{"OCP-BP-056", "Enable cost management", SeverityLow, "Cost", "Use cost management"},
	}

	for _, c := range controls {
		e.RegisterControl(&Control{
			ID:          c.id,
			Name:        c.name,
			Severity:    c.severity,
			Framework:   "ocp-best-practices",
			Section:     c.section,
			Remediation: c.remediation,
		})
	}
}

func (e *Engine) registerNSACISA() {
	e.RegisterFramework(&Framework{
		ID:          "nsa-cisa",
		Name:        "NSA/CISA Kubernetes Hardening Guide",
		Version:     "1.2",
		Description: "NSA and CISA Kubernetes Hardening Guidance",
	})

	controls := []struct {
		id          string
		name        string
		severity    Severity
		section     string
		remediation string
	}{
		{"NSA-1.1", "Scan containers and pods for vulnerabilities", SeverityMedium, "Pod Security", "Enable image scanning"},
		{"NSA-1.2", "Run containers as non-root users", SeverityMedium, "Pod Security", "Set runAsNonRoot: true"},
		{"NSA-1.3", "Use immutable container filesystems", SeverityMedium, "Pod Security", "Set readOnlyRootFilesystem: true"},
		{"NSA-1.4", "Build secure container images", SeverityMedium, "Pod Security", "Follow image best practices"},
		{"NSA-2.1", "Use network policies to isolate resources", SeverityMedium, "Network", "Create NetworkPolicies"},
		{"NSA-2.2", "Encrypt traffic between pods", SeverityMedium, "Network", "Enable mTLS"},
		{"NSA-2.3", "Use secure ingress controllers", SeverityMedium, "Network", "Configure TLS on ingress"},
		{"NSA-3.1", "Use role-based access control", SeverityHigh, "Authentication", "Enable RBAC"},
		{"NSA-3.2", "Use strong authentication", SeverityHigh, "Authentication", "Disable anonymous auth"},
		{"NSA-3.3", "Create unique service accounts", SeverityMedium, "Authentication", "Avoid default SA"},
		{"NSA-4.1", "Enable audit logging", SeverityMedium, "Logging", "Configure audit policy"},
		{"NSA-4.2", "Monitor logs for anomalies", SeverityMedium, "Logging", "Deploy log analysis"},
		{"NSA-5.1", "Keep Kubernetes updated", SeverityHigh, "Upgrades", "Apply security patches"},
		{"NSA-5.2", "Remove unnecessary components", SeverityMedium, "Hardening", "Minimize installed components"},
		{"NSA-5.3", "Lock down worker nodes", SeverityMedium, "Hardening", "Harden node configuration"},
	}

	for _, c := range controls {
		e.RegisterControl(&Control{
			ID:          c.id,
			Name:        c.name,
			Severity:    c.severity,
			Framework:   "nsa-cisa",
			Section:     c.section,
			Remediation: c.remediation,
		})
	}
}

func (e *Engine) registerMITRE() {
	e.RegisterFramework(&Framework{
		ID:          "mitre-attack",
		Name:        "MITRE ATT&CK for Kubernetes",
		Version:     "1.0",
		Description: "MITRE ATT&CK Framework for Kubernetes",
	})

	controls := []struct {
		id          string
		name        string
		severity    Severity
		section     string
		remediation string
	}{
		{"MITRE-T1610", "Deploy container - Detect unauthorized container deployments", SeverityHigh, "Execution", "Monitor pod creation events"},
		{"MITRE-T1609", "Container administration command - Monitor kubectl exec", SeverityHigh, "Execution", "Restrict exec permissions"},
		{"MITRE-T1611", "Escape to host - Prevent container escapes", SeverityCritical, "Privilege Escalation", "Use restricted security contexts"},
		{"MITRE-T1053", "Scheduled task/job - Monitor CronJobs", SeverityMedium, "Persistence", "Review CronJob permissions"},
		{"MITRE-T1078", "Valid accounts - Detect credential misuse", SeverityHigh, "Initial Access", "Enable authentication logging"},
		{"MITRE-T1552", "Unsecured credentials - Find exposed secrets", SeverityHigh, "Credential Access", "Audit secret access"},
		{"MITRE-T1046", "Network service discovery - Limit service discovery", SeverityMedium, "Discovery", "Use network policies"},
		{"MITRE-T1613", "Container and resource discovery - Monitor API queries", SeverityMedium, "Discovery", "Enable audit logging"},
		{"MITRE-T1570", "Lateral tool transfer - Detect pod-to-pod movement", SeverityMedium, "Lateral Movement", "Implement network segmentation"},
		{"MITRE-T1071", "Application layer protocol - Monitor egress traffic", SeverityMedium, "Command and Control", "Configure egress policies"},
		{"MITRE-T1485", "Data destruction - Prevent unauthorized deletions", SeverityHigh, "Impact", "Restrict delete permissions"},
		{"MITRE-T1496", "Resource hijacking - Detect cryptomining", SeverityMedium, "Impact", "Monitor resource usage"},
		{"MITRE-T1498", "Network denial of service - Protect against DoS", SeverityMedium, "Impact", "Configure rate limiting"},
		{"MITRE-T1525", "Implant container image - Detect malicious images", SeverityHigh, "Persistence", "Enable image scanning"},
		{"MITRE-T1612", "Build image on host - Restrict image building", SeverityMedium, "Defense Evasion", "Disable in-cluster builds"},
	}

	for _, c := range controls {
		e.RegisterControl(&Control{
			ID:          c.id,
			Name:        c.name,
			Severity:    c.severity,
			Framework:   "mitre-attack",
			Section:     c.section,
			Remediation: c.remediation,
		})
	}
}
