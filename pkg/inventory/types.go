package inventory

import (
	"time"
)

type ClusterInventory struct {
	Cluster         ClusterMetadata       `json:"cluster"`
	CollectedAt     time.Time             `json:"collectedAt"`
	Namespaces      []NamespaceInfo       `json:"namespaces"`
	Nodes           []NodeInfo            `json:"nodes"`
	Images          []ImageInfo           `json:"images"`
	AIWorkloads     AIWorkloads           `json:"aiWorkloads"`
	Workloads       WorkloadInventory     `json:"workloads"`
	RBAC            RBACInventory         `json:"rbac"`
	NetworkPolicies []NetworkPolicyInfo   `json:"networkPolicies"`
	ServiceAccounts []ServiceAccountInfo  `json:"serviceAccounts"`
	ConfigMaps      []ConfigMapInfo       `json:"configMaps"`
	Secrets         []SecretInfo          `json:"secrets"`
	Services        []ServiceInfo         `json:"services"`
	Ingresses       []IngressInfo         `json:"ingresses"`
	Events          []EventInfo           `json:"events"`
	ResourceQuotas  []ResourceQuotaInfo   `json:"resourceQuotas"`
	LimitRanges     []LimitRangeInfo      `json:"limitRanges"`
	PDBs            []PDBInfo             `json:"podDisruptionBudgets"`
	HPAs            []HPAInfo             `json:"horizontalPodAutoscalers"`
	Storage         StorageInventory      `json:"storage"`
	Webhooks        WebhookInventory      `json:"webhooks"`
	CRDs            []CRDInfo             `json:"customResourceDefinitions"`
	PriorityClasses []PriorityClassInfo   `json:"priorityClasses"`
	Endpoints       []EndpointInfo        `json:"endpoints"`
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

type EventInfo struct {
	Name           string    `json:"name"`
	Namespace      string    `json:"namespace"`
	Type           string    `json:"type"`
	Reason         string    `json:"reason"`
	Message        string    `json:"message"`
	Count          int32     `json:"count"`
	FirstTimestamp time.Time `json:"firstTimestamp"`
	LastTimestamp  time.Time `json:"lastTimestamp"`
	Source         string    `json:"source"`
	InvolvedObject string    `json:"involvedObject"`
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

type PDBInfo struct {
	Name               string            `json:"name"`
	Namespace          string            `json:"namespace"`
	Labels             map[string]string `json:"labels,omitempty"`
	MinAvailable       string            `json:"minAvailable,omitempty"`
	MaxUnavailable     string            `json:"maxUnavailable,omitempty"`
	CurrentHealthy     int32             `json:"currentHealthy"`
	DesiredHealthy     int32             `json:"desiredHealthy"`
	DisruptionsAllowed int32             `json:"disruptionsAllowed"`
	ExpectedPods       int32             `json:"expectedPods"`
}

type HPAInfo struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	Labels          map[string]string `json:"labels,omitempty"`
	ScaleTargetRef  string            `json:"scaleTargetRef"`
	MinReplicas     *int32            `json:"minReplicas,omitempty"`
	MaxReplicas     int32             `json:"maxReplicas"`
	CurrentReplicas int32             `json:"currentReplicas"`
	DesiredReplicas int32             `json:"desiredReplicas"`
	Metrics         []HPAMetric       `json:"metrics,omitempty"`
}

type HPAMetric struct {
	Type         string `json:"type"`
	Name         string `json:"name,omitempty"`
	TargetType   string `json:"targetType"`
	TargetValue  string `json:"targetValue"`
	CurrentValue string `json:"currentValue,omitempty"`
}

type StorageInventory struct {
	PersistentVolumes      []PersistentVolumeInfo      `json:"persistentVolumes"`
	PersistentVolumeClaims []PersistentVolumeClaimInfo `json:"persistentVolumeClaims"`
	StorageClasses         []StorageClassInfo          `json:"storageClasses"`
}

type PersistentVolumeInfo struct {
	Name                 string            `json:"name"`
	Labels               map[string]string `json:"labels,omitempty"`
	Capacity             string            `json:"capacity"`
	AccessModes          []string          `json:"accessModes"`
	ReclaimPolicy        string            `json:"reclaimPolicy"`
	StorageClass         string            `json:"storageClass,omitempty"`
	VolumeMode           string            `json:"volumeMode"`
	Status               string            `json:"status"`
	ClaimRef             string            `json:"claimRef,omitempty"`
	VolumeType           string            `json:"volumeType"`
	MountOptions         []string          `json:"mountOptions,omitempty"`
}

type PersistentVolumeClaimInfo struct {
	Name             string            `json:"name"`
	Namespace        string            `json:"namespace"`
	Labels           map[string]string `json:"labels,omitempty"`
	StorageClass     string            `json:"storageClass,omitempty"`
	AccessModes      []string          `json:"accessModes"`
	RequestedStorage string            `json:"requestedStorage"`
	ActualStorage    string            `json:"actualStorage,omitempty"`
	VolumeMode       string            `json:"volumeMode"`
	VolumeName       string            `json:"volumeName,omitempty"`
	Status           string            `json:"status"`
}

type StorageClassInfo struct {
	Name                 string            `json:"name"`
	Labels               map[string]string `json:"labels,omitempty"`
	Provisioner          string            `json:"provisioner"`
	ReclaimPolicy        string            `json:"reclaimPolicy,omitempty"`
	VolumeBindingMode    string            `json:"volumeBindingMode,omitempty"`
	AllowVolumeExpansion bool              `json:"allowVolumeExpansion"`
	IsDefault            bool              `json:"isDefault"`
	Parameters           map[string]string `json:"parameters,omitempty"`
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

type PriorityClassInfo struct {
	Name            string            `json:"name"`
	Labels          map[string]string `json:"labels,omitempty"`
	Value           int32             `json:"value"`
	GlobalDefault   bool              `json:"globalDefault"`
	PreemptionPolicy string           `json:"preemptionPolicy,omitempty"`
	Description     string            `json:"description,omitempty"`
}

type EndpointInfo struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
	Subsets   []EndpointSubset  `json:"subsets,omitempty"`
}

type EndpointSubset struct {
	Addresses         int      `json:"addresses"`
	NotReadyAddresses int      `json:"notReadyAddresses"`
	Ports             []string `json:"ports,omitempty"`
}
