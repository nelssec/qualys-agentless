package inventory

import (
	"time"
)

type ClusterInventory struct {
	Cluster             ClusterMetadata       `json:"cluster"`
	CollectedAt         time.Time             `json:"collectedAt"`
	SecurityPosture     SecurityPosture       `json:"securityPosture"`
	RBACRisk            RBACRiskAnalysis      `json:"rbacRisk"`
	AttackSurface       AttackSurface         `json:"attackSurface"`
	NamespaceCompliance NamespaceCompliance   `json:"namespaceCompliance"`
	WorkloadRisk        WorkloadRiskRanking   `json:"workloadRisk"`
	ImageSupplyChain    ImageSupplyChain      `json:"imageSupplyChain"`
	SecretsExposure     SecretsExposure       `json:"secretsExposure"`
	AdmissionGaps       AdmissionControlGaps  `json:"admissionControlGaps"`
	LateralMovement     LateralMovement       `json:"lateralMovement"`
	DeprecatedAPIs      DeprecatedAPIs        `json:"deprecatedApis"`
	Namespaces          []NamespaceInfo       `json:"namespaces"`
	Nodes               []NodeInfo            `json:"nodes"`
	Images              []ImageInfo           `json:"images"`
	AIWorkloads         AIWorkloads           `json:"aiWorkloads"`
	Workloads           WorkloadInventory     `json:"workloads"`
	RBAC                RBACInventory         `json:"rbac"`
	NetworkPolicies     []NetworkPolicyInfo   `json:"networkPolicies"`
	ServiceAccounts     []ServiceAccountInfo  `json:"serviceAccounts"`
	ConfigMaps          []ConfigMapInfo       `json:"configMaps"`
	Secrets             []SecretInfo          `json:"secrets"`
	Services            []ServiceInfo         `json:"services"`
	Ingresses           []IngressInfo         `json:"ingresses"`
	ResourceQuotas      []ResourceQuotaInfo   `json:"resourceQuotas"`
	LimitRanges         []LimitRangeInfo      `json:"limitRanges"`
	Webhooks            WebhookInventory      `json:"webhooks"`
	CRDs                []CRDInfo             `json:"customResourceDefinitions"`
}

type ImageInfo struct {
	Image      string   `json:"image"`
	Registry   string   `json:"registry,omitempty"`
	Repository string   `json:"repository"`
	Tag        string   `json:"tag,omitempty"`
	Digest     string   `json:"digest,omitempty"`
	PodCount   int      `json:"podCount"`
	Namespaces []string `json:"namespaces"`
}

type AIWorkloads struct {
	Summary         AIWorkloadSummary  `json:"summary"`
	GPUWorkloads    []GPUWorkload      `json:"gpuWorkloads,omitempty"`
	MLFrameworks    []MLFrameworkUsage `json:"mlFrameworks,omitempty"`
	LLMInference    []LLMInferenceInfo `json:"llmInference,omitempty"`
	VectorDatabases []VectorDBInfo     `json:"vectorDatabases,omitempty"`
	MLPlatforms     []MLPlatformInfo   `json:"mlPlatforms,omitempty"`
}

type AIWorkloadSummary struct {
	TotalGPUPods       int      `json:"totalGpuPods"`
	TotalGPURequested  int      `json:"totalGpuRequested"`
	GPUTypes           []string `json:"gpuTypes,omitempty"`
	MLFrameworksFound  []string `json:"mlFrameworksFound,omitempty"`
	LLMServersFound    []string `json:"llmServersFound,omitempty"`
	VectorDBsFound     []string `json:"vectorDbsFound,omitempty"`
	MLPlatformsFound   []string `json:"mlPlatformsFound,omitempty"`
	HasAIWorkloads     bool     `json:"hasAiWorkloads"`
}

type SecurityPosture struct {
	PrivilegedWorkloads              int      `json:"privilegedWorkloads"`
	WorkloadsRunningAsRoot           int      `json:"workloadsRunningAsRoot"`
	WorkloadsAllowingPrivEscalation  int      `json:"workloadsAllowingPrivilegeEscalation"`
	WorkloadsWithHostNamespace       int      `json:"workloadsWithHostNamespace"`
	WorkloadsWithoutSecurityContext  int      `json:"workloadsWithoutSecurityContext"`
	WorkloadsWithoutResourceLimits   int      `json:"workloadsWithoutResourceLimits"`
	NamespacesWithoutNetworkPolicies int      `json:"namespacesWithoutNetworkPolicies"`
	ExternallyExposedServices        int      `json:"externallyExposedServices"`
	ImagesWithoutDigest              int      `json:"imagesWithoutDigest"`
	ImagesUsingLatestTag             int      `json:"imagesUsingLatestTag"`
	OverpermissiveRBAC               int      `json:"overpermissiveRbac"`
	ServiceAccountsWithAutoMount     int      `json:"serviceAccountsWithAutoMount"`
	CronJobsEnabled                  int      `json:"cronJobsEnabled"`
	HostPathVolumes                  int      `json:"hostPathVolumes"`
	DangerousCapabilities            []string `json:"dangerousCapabilities,omitempty"`
	RiskScore                        string   `json:"riskScore"`
}

type RBACRiskAnalysis struct {
	RiskScore                 string              `json:"riskScore"`
	ClusterAdminBindings      int                 `json:"clusterAdminBindings"`
	WildcardRoles             int                 `json:"wildcardRoles"`
	SecretsAccessRoles        int                 `json:"secretsAccessRoles"`
	EscalationCapableRoles    int                 `json:"escalationCapableRoles"`
	ExecCapableRoles          int                 `json:"execCapableRoles"`
	DefaultSAWithPermissions  int                 `json:"defaultServiceAccountsWithPermissions"`
	CrossNamespaceBindings    int                 `json:"crossNamespaceBindings"`
	UnauthenticatedAccess     bool                `json:"unauthenticatedAccess"`
	AuthenticatedGroupAccess  bool                `json:"authenticatedGroupAccess"`
	HighRiskBindings          []RBACRiskBinding   `json:"highRiskBindings,omitempty"`
	PrivilegedServiceAccounts []string            `json:"privilegedServiceAccounts,omitempty"`
}

type RBACRiskBinding struct {
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	RoleRef    string   `json:"roleRef"`
	Subjects   []string `json:"subjects"`
	RiskReason string   `json:"riskReason"`
}

type AttackSurface struct {
	ExternalEntryPoints    int                 `json:"externalEntryPoints"`
	LoadBalancers          []ExposedService    `json:"loadBalancers,omitempty"`
	NodePorts              []ExposedService    `json:"nodePorts,omitempty"`
	Ingresses              []ExposedIngress    `json:"ingresses,omitempty"`
	ExternalIPs            []ExposedService    `json:"externalIPs,omitempty"`
	HostNetworkPods        int                 `json:"hostNetworkPods"`
	HostPortPods           int                 `json:"hostPortPods"`
	UnprotectedNamespaces  []string            `json:"unprotectedNamespaces,omitempty"`
	InternetFacingServices int                 `json:"internetFacingServices"`
}

type ExposedService struct {
	Name      string  `json:"name"`
	Namespace string  `json:"namespace"`
	Type      string  `json:"type"`
	Ports     []int32 `json:"ports"`
}

type ExposedIngress struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	Hosts     []string `json:"hosts"`
	TLS       bool     `json:"tls"`
	Paths     int      `json:"paths"`
}

type NamespaceCompliance struct {
	TotalNamespaces     int                          `json:"totalNamespaces"`
	CompliantNamespaces int                          `json:"compliantNamespaces"`
	ComplianceScore     float64                      `json:"complianceScore"`
	NamespaceDetails    []NamespaceComplianceDetail  `json:"namespaceDetails,omitempty"`
}

type NamespaceComplianceDetail struct {
	Name                  string `json:"name"`
	HasPSALabels          bool   `json:"hasPsaLabels"`
	PSAEnforceLevel       string `json:"psaEnforceLevel,omitempty"`
	HasNetworkPolicies    bool   `json:"hasNetworkPolicies"`
	HasDefaultDeny        bool   `json:"hasDefaultDeny"`
	HasResourceQuota      bool   `json:"hasResourceQuota"`
	HasLimitRange         bool   `json:"hasLimitRange"`
	ServiceAccountCount   int    `json:"serviceAccountCount"`
	DefaultSAHasSecrets   bool   `json:"defaultServiceAccountHasSecrets"`
	ComplianceScore       int    `json:"complianceScore"`
	Issues                []string `json:"issues,omitempty"`
}

type WorkloadRiskRanking struct {
	HighRiskCount    int                 `json:"highRiskCount"`
	MediumRiskCount  int                 `json:"mediumRiskCount"`
	LowRiskCount     int                 `json:"lowRiskCount"`
	TopRiskyWorkloads []WorkloadRiskInfo `json:"topRiskyWorkloads,omitempty"`
}

type WorkloadRiskInfo struct {
	Name            string   `json:"name"`
	Namespace       string   `json:"namespace"`
	Kind            string   `json:"kind"`
	RiskScore       int      `json:"riskScore"`
	RiskLevel       string   `json:"riskLevel"`
	RiskFactors     []string `json:"riskFactors"`
	ServiceAccount  string   `json:"serviceAccount,omitempty"`
	HasSecretAccess bool     `json:"hasSecretAccess"`
	HasNetworkAccess bool    `json:"hasNetworkAccess"`
}

type ImageSupplyChain struct {
	TotalImages          int                  `json:"totalImages"`
	TrustedRegistries    int                  `json:"trustedRegistries"`
	UntrustedRegistries  int                  `json:"untrustedRegistries"`
	ImagesWithDigest     int                  `json:"imagesWithDigest"`
	ImagesWithoutDigest  int                  `json:"imagesWithoutDigest"`
	LatestTagImages      int                  `json:"latestTagImages"`
	RegistryBreakdown    []RegistryStats      `json:"registryBreakdown,omitempty"`
	RiskyImages          []ImageRiskInfo      `json:"riskyImages,omitempty"`
}

type RegistryStats struct {
	Registry    string `json:"registry"`
	ImageCount  int    `json:"imageCount"`
	TrustLevel  string `json:"trustLevel"`
}

type ImageRiskInfo struct {
	Image       string   `json:"image"`
	Registry    string   `json:"registry"`
	RiskFactors []string `json:"riskFactors"`
	PodCount    int      `json:"podCount"`
}

type SecretsExposure struct {
	TotalSecrets           int                   `json:"totalSecrets"`
	SecretsInEnvVars       int                   `json:"secretsInEnvVars"`
	SecretsAsMounts        int                   `json:"secretsAsMounts"`
	OrphanedSecrets        int                   `json:"orphanedSecrets"`
	CrossNamespaceAccess   int                   `json:"crossNamespaceAccess"`
	ExternalSecretsManaged int                   `json:"externalSecretsManaged"`
	SealedSecrets          int                   `json:"sealedSecrets"`
	SecretsByType          map[string]int        `json:"secretsByType"`
	ExposedSecrets         []SecretExposureInfo  `json:"exposedSecrets,omitempty"`
}

type SecretExposureInfo struct {
	Name           string   `json:"name"`
	Namespace      string   `json:"namespace"`
	Type           string   `json:"type"`
	ExposureMethod string   `json:"exposureMethod"`
	UsedByPods     []string `json:"usedByPods,omitempty"`
	RiskLevel      string   `json:"riskLevel"`
}

type AdmissionControlGaps struct {
	HasValidatingWebhooks   bool                    `json:"hasValidatingWebhooks"`
	HasMutatingWebhooks     bool                    `json:"hasMutatingWebhooks"`
	FailOpenWebhooks        int                     `json:"failOpenWebhooks"`
	ExemptedNamespaces      []string                `json:"exemptedNamespaces,omitempty"`
	CriticalGaps            []string                `json:"criticalGaps,omitempty"`
	WebhookCoverage         []WebhookCoverageInfo   `json:"webhookCoverage,omitempty"`
	RecommendedWebhooks     []string                `json:"recommendedWebhooks,omitempty"`
}

type WebhookCoverageInfo struct {
	Name           string   `json:"name"`
	Type           string   `json:"type"`
	FailurePolicy  string   `json:"failurePolicy"`
	Covers         []string `json:"covers,omitempty"`
	ExcludedNS     []string `json:"excludedNamespaces,omitempty"`
}

type LateralMovement struct {
	RiskScore              string                  `json:"riskScore"`
	NetworkSegmentation    string                  `json:"networkSegmentation"`
	SATokenExposure        int                     `json:"serviceAccountTokenExposure"`
	PodsWithExecAccess     int                     `json:"podsWithExecAccess"`
	CrossNamespacePaths    int                     `json:"crossNamespacePaths"`
	HighRiskPaths          []LateralMovementPath   `json:"highRiskPaths,omitempty"`
	Recommendations        []string                `json:"recommendations,omitempty"`
}

type LateralMovementPath struct {
	Source          string `json:"source"`
	Target          string `json:"target"`
	AccessMethod    string `json:"accessMethod"`
	RiskLevel       string `json:"riskLevel"`
}

type DeprecatedAPIs struct {
	TotalDeprecated    int                     `json:"totalDeprecated"`
	CriticalCount      int                     `json:"criticalCount"`
	WarningCount       int                     `json:"warningCount"`
	DeprecatedResources []DeprecatedResource   `json:"deprecatedResources,omitempty"`
}

type DeprecatedResource struct {
	Kind            string `json:"kind"`
	Name            string `json:"name"`
	Namespace       string `json:"namespace,omitempty"`
	CurrentAPI      string `json:"currentApi"`
	ReplacementAPI  string `json:"replacementApi"`
	RemovedIn       string `json:"removedIn"`
	Severity        string `json:"severity"`
}

type GPUWorkload struct {
	PodName      string            `json:"podName"`
	Namespace    string            `json:"namespace"`
	GPUType      string            `json:"gpuType"`
	GPURequested int               `json:"gpuRequested"`
	GPULimit     int               `json:"gpuLimit"`
	Images       []string          `json:"images"`
	Labels       map[string]string `json:"labels,omitempty"`
	NodeName     string            `json:"nodeName,omitempty"`
}

type MLFrameworkUsage struct {
	Framework  string   `json:"framework"`
	Image      string   `json:"image"`
	PodCount   int      `json:"podCount"`
	Namespaces []string `json:"namespaces"`
}

type LLMInferenceInfo struct {
	Type       string   `json:"type"`
	Image      string   `json:"image"`
	PodName    string   `json:"podName"`
	Namespace  string   `json:"namespace"`
	HasGPU     bool     `json:"hasGpu"`
	ModelPath  string   `json:"modelPath,omitempty"`
}

type VectorDBInfo struct {
	Type      string `json:"type"`
	Image     string `json:"image"`
	PodName   string `json:"podName"`
	Namespace string `json:"namespace"`
}

type MLPlatformInfo struct {
	Platform  string   `json:"platform"`
	Component string   `json:"component,omitempty"`
	PodName   string   `json:"podName"`
	Namespace string   `json:"namespace"`
	Images    []string `json:"images"`
}

type ClusterMetadata struct {
	Name       string            `json:"name"`
	Provider   string            `json:"provider"`
	Region     string            `json:"region,omitempty"`
	Version    string            `json:"version"`
	Endpoint   string            `json:"endpoint"`
	NodeCount  int               `json:"nodeCount"`
	Tags       map[string]string `json:"tags,omitempty"`
	APIVersion string            `json:"apiVersion"`
}

type NamespaceInfo struct {
	Name        string            `json:"name"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Phase       string            `json:"phase"`
}

type WorkloadInventory struct {
	Pods         []PodInfo         `json:"pods"`
	Deployments  []DeploymentInfo  `json:"deployments"`
	DaemonSets   []DaemonSetInfo   `json:"daemonSets"`
	StatefulSets []StatefulSetInfo `json:"statefulSets"`
	ReplicaSets  []ReplicaSetInfo  `json:"replicaSets"`
	Jobs         []JobInfo         `json:"jobs"`
	CronJobs     []CronJobInfo     `json:"cronJobs"`
}

type PodInfo struct {
	Name           string                `json:"name"`
	Namespace      string                `json:"namespace"`
	Labels         map[string]string     `json:"labels,omitempty"`
	Annotations    map[string]string     `json:"annotations,omitempty"`
	ServiceAccount string                `json:"serviceAccount"`
	NodeName       string                `json:"nodeName"`
	HostNetwork    bool                  `json:"hostNetwork"`
	HostPID        bool                  `json:"hostPID"`
	HostIPC        bool                  `json:"hostIPC"`
	SecurityContext *PodSecurityContext  `json:"securityContext,omitempty"`
	Containers     []ContainerInfo       `json:"containers"`
	InitContainers []ContainerInfo       `json:"initContainers,omitempty"`
	Volumes        []VolumeInfo          `json:"volumes,omitempty"`
	Phase          string                `json:"phase"`
	AutomountSAToken *bool               `json:"automountServiceAccountToken,omitempty"`
	Source         string                `json:"source,omitempty"`
}

type PodSecurityContext struct {
	RunAsUser          *int64  `json:"runAsUser,omitempty"`
	RunAsGroup         *int64  `json:"runAsGroup,omitempty"`
	RunAsNonRoot       *bool   `json:"runAsNonRoot,omitempty"`
	FSGroup            *int64  `json:"fsGroup,omitempty"`
	SeccompProfile     string  `json:"seccompProfile,omitempty"`
	SupplementalGroups []int64 `json:"supplementalGroups,omitempty"`
}

type ContainerInfo struct {
	Name            string                     `json:"name"`
	Image           string                     `json:"image"`
	ImagePullPolicy string                     `json:"imagePullPolicy"`
	Ports           []ContainerPort            `json:"ports,omitempty"`
	SecurityContext *ContainerSecurityContext  `json:"securityContext,omitempty"`
	Resources       ResourceRequirements       `json:"resources,omitempty"`
	VolumeMounts    []VolumeMount              `json:"volumeMounts,omitempty"`
	LivenessProbe   bool                       `json:"livenessProbe"`
	ReadinessProbe  bool                       `json:"readinessProbe"`
	Command         []string                   `json:"command,omitempty"`
	Args            []string                   `json:"args,omitempty"`
}

type ContainerSecurityContext struct {
	Privileged               *bool    `json:"privileged,omitempty"`
	RunAsUser                *int64   `json:"runAsUser,omitempty"`
	RunAsGroup               *int64   `json:"runAsGroup,omitempty"`
	RunAsNonRoot             *bool    `json:"runAsNonRoot,omitempty"`
	ReadOnlyRootFilesystem   *bool    `json:"readOnlyRootFilesystem,omitempty"`
	AllowPrivilegeEscalation *bool    `json:"allowPrivilegeEscalation,omitempty"`
	Capabilities             *Capabilities `json:"capabilities,omitempty"`
	SeccompProfile           string   `json:"seccompProfile,omitempty"`
	SELinuxOptions           string   `json:"seLinuxOptions,omitempty"`
}

type Capabilities struct {
	Add  []string `json:"add,omitempty"`
	Drop []string `json:"drop,omitempty"`
}

type ContainerPort struct {
	Name          string `json:"name,omitempty"`
	ContainerPort int32  `json:"containerPort"`
	Protocol      string `json:"protocol"`
	HostPort      int32  `json:"hostPort,omitempty"`
}

type ResourceRequirements struct {
	Requests map[string]string `json:"requests,omitempty"`
	Limits   map[string]string `json:"limits,omitempty"`
}

type VolumeMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
	ReadOnly  bool   `json:"readOnly"`
	SubPath   string `json:"subPath,omitempty"`
}

type VolumeInfo struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Source string `json:"source,omitempty"`
}

type DeploymentInfo struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	Labels            map[string]string `json:"labels,omitempty"`
	Replicas          int32             `json:"replicas"`
	AvailableReplicas int32             `json:"availableReplicas"`
	PodTemplate       PodTemplateInfo   `json:"podTemplate"`
}

type PodTemplateInfo struct {
	Labels         map[string]string    `json:"labels,omitempty"`
	ServiceAccount string               `json:"serviceAccount"`
	HostNetwork    bool                 `json:"hostNetwork"`
	HostPID        bool                 `json:"hostPID"`
	HostIPC        bool                 `json:"hostIPC"`
	SecurityContext *PodSecurityContext `json:"securityContext,omitempty"`
	Containers     []ContainerInfo      `json:"containers"`
	AutomountSAToken *bool              `json:"automountServiceAccountToken,omitempty"`
}

type DaemonSetInfo struct {
	Name           string          `json:"name"`
	Namespace      string          `json:"namespace"`
	Labels         map[string]string `json:"labels,omitempty"`
	DesiredNumber  int32           `json:"desiredNumber"`
	CurrentNumber  int32           `json:"currentNumber"`
	PodTemplate    PodTemplateInfo `json:"podTemplate"`
}

type StatefulSetInfo struct {
	Name        string          `json:"name"`
	Namespace   string          `json:"namespace"`
	Labels      map[string]string `json:"labels,omitempty"`
	Replicas    int32           `json:"replicas"`
	PodTemplate PodTemplateInfo `json:"podTemplate"`
}

type ReplicaSetInfo struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
	Replicas  int32             `json:"replicas"`
	OwnerRef  string            `json:"ownerRef,omitempty"`
}

type JobInfo struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Labels      map[string]string `json:"labels,omitempty"`
	Completions *int32            `json:"completions,omitempty"`
	PodTemplate PodTemplateInfo   `json:"podTemplate"`
}

type CronJobInfo struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Labels      map[string]string `json:"labels,omitempty"`
	Schedule    string            `json:"schedule"`
	Suspend     bool              `json:"suspend"`
	PodTemplate PodTemplateInfo   `json:"podTemplate"`
}

type RBACInventory struct {
	Roles               []RoleInfo               `json:"roles"`
	ClusterRoles        []ClusterRoleInfo        `json:"clusterRoles"`
	RoleBindings        []RoleBindingInfo        `json:"roleBindings"`
	ClusterRoleBindings []ClusterRoleBindingInfo `json:"clusterRoleBindings"`
}

type RoleInfo struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
	Rules     []PolicyRule      `json:"rules"`
}

type ClusterRoleInfo struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
	Rules  []PolicyRule      `json:"rules"`
}

type PolicyRule struct {
	Verbs           []string `json:"verbs"`
	APIGroups       []string `json:"apiGroups"`
	Resources       []string `json:"resources"`
	ResourceNames   []string `json:"resourceNames,omitempty"`
	NonResourceURLs []string `json:"nonResourceURLs,omitempty"`
}

type RoleBindingInfo struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
	RoleRef   RoleRef           `json:"roleRef"`
	Subjects  []Subject         `json:"subjects"`
}

type ClusterRoleBindingInfo struct {
	Name     string            `json:"name"`
	Labels   map[string]string `json:"labels,omitempty"`
	RoleRef  RoleRef           `json:"roleRef"`
	Subjects []Subject         `json:"subjects"`
}

type RoleRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type Subject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

type NetworkPolicyInfo struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Labels      map[string]string `json:"labels,omitempty"`
	PodSelector map[string]string `json:"podSelector"`
	PolicyTypes []string          `json:"policyTypes"`
	IngressRules int              `json:"ingressRules"`
	EgressRules  int              `json:"egressRules"`
}

type ServiceAccountInfo struct {
	Name                         string            `json:"name"`
	Namespace                    string            `json:"namespace"`
	Labels                       map[string]string `json:"labels,omitempty"`
	AutomountServiceAccountToken *bool             `json:"automountServiceAccountToken,omitempty"`
	Secrets                      []string          `json:"secrets,omitempty"`
}

type ConfigMapInfo struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
	DataKeys  []string          `json:"dataKeys"`
}

type SecretInfo struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
	Type      string            `json:"type"`
	DataKeys  []string          `json:"dataKeys"`
}

type ServiceInfo struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Labels      map[string]string `json:"labels,omitempty"`
	Type        string            `json:"type"`
	ClusterIP   string            `json:"clusterIP"`
	ExternalIPs []string          `json:"externalIPs,omitempty"`
	Ports       []ServicePort     `json:"ports"`
}

type ServicePort struct {
	Name       string `json:"name,omitempty"`
	Port       int32  `json:"port"`
	TargetPort string `json:"targetPort"`
	Protocol   string `json:"protocol"`
	NodePort   int32  `json:"nodePort,omitempty"`
}

type IngressInfo struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Labels      map[string]string `json:"labels,omitempty"`
	IngressClass string           `json:"ingressClass,omitempty"`
	TLS         []IngressTLS      `json:"tls,omitempty"`
	Rules       []IngressRule     `json:"rules"`
}

type IngressTLS struct {
	Hosts      []string `json:"hosts"`
	SecretName string   `json:"secretName"`
}

type IngressRule struct {
	Host  string        `json:"host,omitempty"`
	Paths []IngressPath `json:"paths"`
}

type IngressPath struct {
	Path     string `json:"path"`
	PathType string `json:"pathType"`
	Backend  string `json:"backend"`
}

type NodeInfo struct {
	Name             string            `json:"name"`
	Labels           map[string]string `json:"labels,omitempty"`
	Annotations      map[string]string `json:"annotations,omitempty"`
	Taints           []TaintInfo       `json:"taints,omitempty"`
	Conditions       []NodeCondition   `json:"conditions,omitempty"`
	Capacity         map[string]string `json:"capacity,omitempty"`
	Allocatable      map[string]string `json:"allocatable,omitempty"`
	KubeletVersion   string            `json:"kubeletVersion"`
	ContainerRuntime string            `json:"containerRuntime"`
	OSImage          string            `json:"osImage"`
	Architecture     string            `json:"architecture"`
	KernelVersion    string            `json:"kernelVersion"`
	Unschedulable    bool              `json:"unschedulable"`
	CreatedAt        time.Time         `json:"createdAt"`
}

type TaintInfo struct {
	Key    string `json:"key"`
	Value  string `json:"value,omitempty"`
	Effect string `json:"effect"`
}

type NodeCondition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

type ResourceQuotaInfo struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
	Hard      map[string]string `json:"hard,omitempty"`
	Used      map[string]string `json:"used,omitempty"`
}

type LimitRangeInfo struct {
	Name      string           `json:"name"`
	Namespace string           `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
	Limits    []LimitRangeItem `json:"limits,omitempty"`
}

type LimitRangeItem struct {
	Type           string            `json:"type"`
	Max            map[string]string `json:"max,omitempty"`
	Min            map[string]string `json:"min,omitempty"`
	Default        map[string]string `json:"default,omitempty"`
	DefaultRequest map[string]string `json:"defaultRequest,omitempty"`
}

type WebhookInventory struct {
	ValidatingWebhooks []WebhookInfo `json:"validatingWebhooks"`
	MutatingWebhooks   []WebhookInfo `json:"mutatingWebhooks"`
}

type WebhookInfo struct {
	Name              string           `json:"name"`
	Webhooks          []WebhookConfig  `json:"webhooks"`
}

type WebhookConfig struct {
	Name                    string   `json:"name"`
	ClientConfig            string   `json:"clientConfig"`
	Rules                   []string `json:"rules,omitempty"`
	FailurePolicy           string   `json:"failurePolicy,omitempty"`
	MatchPolicy             string   `json:"matchPolicy,omitempty"`
	SideEffects             string   `json:"sideEffects,omitempty"`
	TimeoutSeconds          *int32   `json:"timeoutSeconds,omitempty"`
	AdmissionReviewVersions []string `json:"admissionReviewVersions,omitempty"`
	NamespaceSelector       string   `json:"namespaceSelector,omitempty"`
}

type CRDInfo struct {
	Name       string            `json:"name"`
	Labels     map[string]string `json:"labels,omitempty"`
	Group      string            `json:"group"`
	Scope      string            `json:"scope"`
	Kind       string            `json:"kind"`
	Versions   []string          `json:"versions"`
	Conditions []CRDCondition    `json:"conditions,omitempty"`
}

type CRDCondition struct {
	Type   string `json:"type"`
	Status string `json:"status"`
}
