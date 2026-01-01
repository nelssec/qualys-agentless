package inventory

import (
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

// ClusterInventory contains all collected resources from a Kubernetes cluster.
type ClusterInventory struct {
	Cluster         ClusterMetadata       `json:"cluster"`
	CollectedAt     time.Time             `json:"collectedAt"`
	Namespaces      []NamespaceInfo       `json:"namespaces"`
	Nodes           []NodeInfo            `json:"nodes"`
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

// ClusterMetadata contains information about the cluster.
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

// NamespaceInfo contains namespace metadata.
type NamespaceInfo struct {
	Name        string            `json:"name"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Phase       string            `json:"phase"`
}

// WorkloadInventory contains all workload resources.
type WorkloadInventory struct {
	Pods         []PodInfo         `json:"pods"`
	Deployments  []DeploymentInfo  `json:"deployments"`
	DaemonSets   []DaemonSetInfo   `json:"daemonSets"`
	StatefulSets []StatefulSetInfo `json:"statefulSets"`
	ReplicaSets  []ReplicaSetInfo  `json:"replicaSets"`
	Jobs         []JobInfo         `json:"jobs"`
	CronJobs     []CronJobInfo     `json:"cronJobs"`
}

// PodInfo contains pod metadata and security context.
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
}

// PodSecurityContext contains pod-level security settings.
type PodSecurityContext struct {
	RunAsUser          *int64  `json:"runAsUser,omitempty"`
	RunAsGroup         *int64  `json:"runAsGroup,omitempty"`
	RunAsNonRoot       *bool   `json:"runAsNonRoot,omitempty"`
	FSGroup            *int64  `json:"fsGroup,omitempty"`
	SeccompProfile     string  `json:"seccompProfile,omitempty"`
	SupplementalGroups []int64 `json:"supplementalGroups,omitempty"`
}

// ContainerInfo contains container metadata and security settings.
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

// ContainerSecurityContext contains container-level security settings.
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

// Capabilities represents Linux capabilities.
type Capabilities struct {
	Add  []string `json:"add,omitempty"`
	Drop []string `json:"drop,omitempty"`
}

// ContainerPort represents a container port.
type ContainerPort struct {
	Name          string `json:"name,omitempty"`
	ContainerPort int32  `json:"containerPort"`
	Protocol      string `json:"protocol"`
	HostPort      int32  `json:"hostPort,omitempty"`
}

// ResourceRequirements represents resource requests and limits.
type ResourceRequirements struct {
	Requests map[string]string `json:"requests,omitempty"`
	Limits   map[string]string `json:"limits,omitempty"`
}

// VolumeMount represents a volume mount.
type VolumeMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
	ReadOnly  bool   `json:"readOnly"`
	SubPath   string `json:"subPath,omitempty"`
}

// VolumeInfo represents a volume.
type VolumeInfo struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Source string `json:"source,omitempty"`
}

// DeploymentInfo contains deployment metadata.
type DeploymentInfo struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	Labels            map[string]string `json:"labels,omitempty"`
	Replicas          int32             `json:"replicas"`
	AvailableReplicas int32             `json:"availableReplicas"`
	PodTemplate       PodTemplateInfo   `json:"podTemplate"`
}

// PodTemplateInfo contains pod template spec information.
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

// DaemonSetInfo contains daemonset metadata.
type DaemonSetInfo struct {
	Name           string          `json:"name"`
	Namespace      string          `json:"namespace"`
	Labels         map[string]string `json:"labels,omitempty"`
	DesiredNumber  int32           `json:"desiredNumber"`
	CurrentNumber  int32           `json:"currentNumber"`
	PodTemplate    PodTemplateInfo `json:"podTemplate"`
}

// StatefulSetInfo contains statefulset metadata.
type StatefulSetInfo struct {
	Name        string          `json:"name"`
	Namespace   string          `json:"namespace"`
	Labels      map[string]string `json:"labels,omitempty"`
	Replicas    int32           `json:"replicas"`
	PodTemplate PodTemplateInfo `json:"podTemplate"`
}

// ReplicaSetInfo contains replicaset metadata.
type ReplicaSetInfo struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
	Replicas  int32             `json:"replicas"`
	OwnerRef  string            `json:"ownerRef,omitempty"`
}

// JobInfo contains job metadata.
type JobInfo struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Labels      map[string]string `json:"labels,omitempty"`
	Completions *int32            `json:"completions,omitempty"`
	PodTemplate PodTemplateInfo   `json:"podTemplate"`
}

// CronJobInfo contains cronjob metadata.
type CronJobInfo struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Labels      map[string]string `json:"labels,omitempty"`
	Schedule    string            `json:"schedule"`
	Suspend     bool              `json:"suspend"`
	PodTemplate PodTemplateInfo   `json:"podTemplate"`
}

// RBACInventory contains RBAC resources.
type RBACInventory struct {
	Roles               []RoleInfo               `json:"roles"`
	ClusterRoles        []ClusterRoleInfo        `json:"clusterRoles"`
	RoleBindings        []RoleBindingInfo        `json:"roleBindings"`
	ClusterRoleBindings []ClusterRoleBindingInfo `json:"clusterRoleBindings"`
}

// RoleInfo contains role metadata.
type RoleInfo struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
	Rules     []PolicyRule      `json:"rules"`
}

// ClusterRoleInfo contains cluster role metadata.
type ClusterRoleInfo struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
	Rules  []PolicyRule      `json:"rules"`
}

// PolicyRule represents an RBAC policy rule.
type PolicyRule struct {
	Verbs           []string `json:"verbs"`
	APIGroups       []string `json:"apiGroups"`
	Resources       []string `json:"resources"`
	ResourceNames   []string `json:"resourceNames,omitempty"`
	NonResourceURLs []string `json:"nonResourceURLs,omitempty"`
}

// RoleBindingInfo contains role binding metadata.
type RoleBindingInfo struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
	RoleRef   RoleRef           `json:"roleRef"`
	Subjects  []Subject         `json:"subjects"`
}

// ClusterRoleBindingInfo contains cluster role binding metadata.
type ClusterRoleBindingInfo struct {
	Name     string            `json:"name"`
	Labels   map[string]string `json:"labels,omitempty"`
	RoleRef  RoleRef           `json:"roleRef"`
	Subjects []Subject         `json:"subjects"`
}

// RoleRef references a role.
type RoleRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// Subject represents an RBAC subject.
type Subject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// NetworkPolicyInfo contains network policy metadata.
type NetworkPolicyInfo struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Labels      map[string]string `json:"labels,omitempty"`
	PodSelector map[string]string `json:"podSelector"`
	PolicyTypes []string          `json:"policyTypes"`
	IngressRules int              `json:"ingressRules"`
	EgressRules  int              `json:"egressRules"`
}

// ServiceAccountInfo contains service account metadata.
type ServiceAccountInfo struct {
	Name                         string            `json:"name"`
	Namespace                    string            `json:"namespace"`
	Labels                       map[string]string `json:"labels,omitempty"`
	AutomountServiceAccountToken *bool             `json:"automountServiceAccountToken,omitempty"`
	Secrets                      []string          `json:"secrets,omitempty"`
}

// ConfigMapInfo contains configmap metadata (no data values).
type ConfigMapInfo struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
	DataKeys  []string          `json:"dataKeys"`
}

// SecretInfo contains secret metadata (no data values).
type SecretInfo struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
	Type      string            `json:"type"`
	DataKeys  []string          `json:"dataKeys"`
}

// ServiceInfo contains service metadata.
type ServiceInfo struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Labels      map[string]string `json:"labels,omitempty"`
	Type        string            `json:"type"`
	ClusterIP   string            `json:"clusterIP"`
	ExternalIPs []string          `json:"externalIPs,omitempty"`
	Ports       []ServicePort     `json:"ports"`
}

// ServicePort represents a service port.
type ServicePort struct {
	Name       string `json:"name,omitempty"`
	Port       int32  `json:"port"`
	TargetPort string `json:"targetPort"`
	Protocol   string `json:"protocol"`
	NodePort   int32  `json:"nodePort,omitempty"`
}

// IngressInfo contains ingress metadata.
type IngressInfo struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Labels      map[string]string `json:"labels,omitempty"`
	IngressClass string           `json:"ingressClass,omitempty"`
	TLS         []IngressTLS      `json:"tls,omitempty"`
	Rules       []IngressRule     `json:"rules"`
}

// IngressTLS contains TLS configuration.
type IngressTLS struct {
	Hosts      []string `json:"hosts"`
	SecretName string   `json:"secretName"`
}

// IngressRule contains ingress rule information.
type IngressRule struct {
	Host  string        `json:"host,omitempty"`
	Paths []IngressPath `json:"paths"`
}

// IngressPath contains ingress path information.
type IngressPath struct {
	Path     string `json:"path"`
	PathType string `json:"pathType"`
	Backend  string `json:"backend"`
}

// NodeInfo contains node metadata.
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

// Keep these for type checking
var (
	_ = corev1.Pod{}
	_ = networkingv1.NetworkPolicy{}
	_ = rbacv1.Role{}
)
