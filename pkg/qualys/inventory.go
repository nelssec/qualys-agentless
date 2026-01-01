package qualys

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
)

type Cluster struct {
	ID           string            `json:"clusterId,omitempty"`
	Name         string            `json:"name"`
	UUID         string            `json:"uuid,omitempty"`
	Provider     string            `json:"provider"`
	Region       string            `json:"region,omitempty"`
	Version      string            `json:"version"`
	NodeCount    int               `json:"nodeCount"`
	Endpoint     string            `json:"endpoint"`
	Status       string            `json:"status,omitempty"`
	LastScanTime *time.Time        `json:"lastScanTime,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
	CreatedAt    *time.Time        `json:"createdAt,omitempty"`
	UpdatedAt    *time.Time        `json:"updatedAt,omitempty"`
}

type ClusterRegistration struct {
	Name      string            `json:"name"`
	Provider  string            `json:"provider"`
	Region    string            `json:"region,omitempty"`
	Version   string            `json:"version"`
	NodeCount int               `json:"nodeCount"`
	Endpoint  string            `json:"endpoint"`
	Tags      map[string]string `json:"tags,omitempty"`
}

type ClusterResponse struct {
	Success bool     `json:"success"`
	Cluster *Cluster `json:"cluster,omitempty"`
	Message string   `json:"message,omitempty"`
}

type ClusterInventorySubmission struct {
	ClusterID   string                `json:"clusterId"`
	CollectedAt time.Time             `json:"collectedAt"`
	Namespaces  []NamespaceRecord     `json:"namespaces"`
	Workloads   WorkloadRecords       `json:"workloads"`
	RBAC        RBACRecords           `json:"rbac"`
	Network     []NetworkPolicyRecord `json:"networkPolicies"`
	Services    []ServiceRecord       `json:"services"`
}

type NamespaceRecord struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
	Status string            `json:"status"`
}

type WorkloadRecords struct {
	Pods         []PodRecord         `json:"pods"`
	Deployments  []DeploymentRecord  `json:"deployments"`
	DaemonSets   []DaemonSetRecord   `json:"daemonSets"`
	StatefulSets []StatefulSetRecord `json:"statefulSets"`
}

type PodRecord struct {
	Name           string            `json:"name"`
	Namespace      string            `json:"namespace"`
	Labels         map[string]string `json:"labels,omitempty"`
	ServiceAccount string            `json:"serviceAccount"`
	NodeName       string            `json:"nodeName"`
	Phase          string            `json:"phase"`
	Containers     []ContainerRecord `json:"containers"`
	HostNetwork    bool              `json:"hostNetwork"`
	HostPID        bool              `json:"hostPID"`
	HostIPC        bool              `json:"hostIPC"`
	Privileged     bool              `json:"privileged"`
}

type ContainerRecord struct {
	Name            string   `json:"name"`
	Image           string   `json:"image"`
	ImageID         string   `json:"imageId,omitempty"`
	Privileged      bool     `json:"privileged"`
	RunAsRoot       bool     `json:"runAsRoot"`
	ReadOnlyFS      bool     `json:"readOnlyRootFilesystem"`
	CapabilitiesAdd []string `json:"capabilitiesAdd,omitempty"`
}

type DeploymentRecord struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
	Replicas  int32             `json:"replicas"`
	Ready     int32             `json:"ready"`
}

type DaemonSetRecord struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
	Desired   int32             `json:"desired"`
	Current   int32             `json:"current"`
}

type StatefulSetRecord struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
	Replicas  int32             `json:"replicas"`
}

type RBACRecords struct {
	ClusterRoles        []ClusterRoleRecord        `json:"clusterRoles"`
	ClusterRoleBindings []ClusterRoleBindingRecord `json:"clusterRoleBindings"`
	Roles               []RoleRecord               `json:"roles"`
	RoleBindings        []RoleBindingRecord        `json:"roleBindings"`
}

type ClusterRoleRecord struct {
	Name       string   `json:"name"`
	RuleCount  int      `json:"ruleCount"`
	Privileged bool     `json:"privileged"`
	Verbs      []string `json:"verbs,omitempty"`
}

type ClusterRoleBindingRecord struct {
	Name         string   `json:"name"`
	RoleRef      string   `json:"roleRef"`
	SubjectCount int      `json:"subjectCount"`
	Subjects     []string `json:"subjects,omitempty"`
}

type RoleRecord struct {
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
	RuleCount  int    `json:"ruleCount"`
	Privileged bool   `json:"privileged"`
}

type RoleBindingRecord struct {
	Name         string   `json:"name"`
	Namespace    string   `json:"namespace"`
	RoleRef      string   `json:"roleRef"`
	SubjectCount int      `json:"subjectCount"`
	Subjects     []string `json:"subjects,omitempty"`
}

type NetworkPolicyRecord struct {
	Name         string   `json:"name"`
	Namespace    string   `json:"namespace"`
	PolicyTypes  []string `json:"policyTypes"`
	IngressRules int      `json:"ingressRules"`
	EgressRules  int      `json:"egressRules"`
}

type ServiceRecord struct {
	Name        string   `json:"name"`
	Namespace   string   `json:"namespace"`
	Type        string   `json:"type"`
	ClusterIP   string   `json:"clusterIP"`
	ExternalIPs []string `json:"externalIPs,omitempty"`
	Ports       []int32  `json:"ports"`
}

func (c *Client) RegisterCluster(ctx context.Context, reg *ClusterRegistration) (*Cluster, error) {
	var resp ClusterResponse
	if err := c.request(ctx, http.MethodPost, "/clusters", reg, &resp); err != nil {
		return nil, err
	}
	return resp.Cluster, nil
}

func (c *Client) GetCluster(ctx context.Context, clusterID string) (*Cluster, error) {
	var resp ClusterResponse
	if err := c.request(ctx, http.MethodGet, fmt.Sprintf("/clusters/%s", clusterID), nil, &resp); err != nil {
		return nil, err
	}
	return resp.Cluster, nil
}

func (c *Client) UpdateCluster(ctx context.Context, clusterID string, update *ClusterRegistration) (*Cluster, error) {
	var resp ClusterResponse
	if err := c.request(ctx, http.MethodPut, fmt.Sprintf("/clusters/%s", clusterID), update, &resp); err != nil {
		return nil, err
	}
	return resp.Cluster, nil
}

func (c *Client) SubmitInventory(ctx context.Context, clusterID string, inv *ClusterInventorySubmission) error {
	return c.request(ctx, http.MethodPost, fmt.Sprintf("/clusters/%s/inventory", clusterID), inv, nil)
}

func ConvertInventory(clusterID string, inv *inventory.ClusterInventory) *ClusterInventorySubmission {
	submission := &ClusterInventorySubmission{
		ClusterID:   clusterID,
		CollectedAt: inv.CollectedAt,
	}

	for _, ns := range inv.Namespaces {
		submission.Namespaces = append(submission.Namespaces, NamespaceRecord{
			Name:   ns.Name,
			Labels: ns.Labels,
			Status: ns.Phase,
		})
	}

	for _, pod := range inv.Workloads.Pods {
		podRecord := PodRecord{
			Name:           pod.Name,
			Namespace:      pod.Namespace,
			Labels:         pod.Labels,
			ServiceAccount: pod.ServiceAccount,
			NodeName:       pod.NodeName,
			Phase:          pod.Phase,
			HostNetwork:    pod.HostNetwork,
			HostPID:        pod.HostPID,
			HostIPC:        pod.HostIPC,
		}

		for _, c := range pod.Containers {
			container := ContainerRecord{
				Name:  c.Name,
				Image: c.Image,
			}
			if c.SecurityContext != nil {
				if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
					container.Privileged = true
					podRecord.Privileged = true
				}
				if c.SecurityContext.RunAsNonRoot != nil && !*c.SecurityContext.RunAsNonRoot {
					container.RunAsRoot = true
				}
				if c.SecurityContext.ReadOnlyRootFilesystem != nil {
					container.ReadOnlyFS = *c.SecurityContext.ReadOnlyRootFilesystem
				}
				if c.SecurityContext.Capabilities != nil {
					container.CapabilitiesAdd = c.SecurityContext.Capabilities.Add
				}
			}
			podRecord.Containers = append(podRecord.Containers, container)
		}

		submission.Workloads.Pods = append(submission.Workloads.Pods, podRecord)
	}

	for _, dep := range inv.Workloads.Deployments {
		submission.Workloads.Deployments = append(submission.Workloads.Deployments, DeploymentRecord{
			Name:      dep.Name,
			Namespace: dep.Namespace,
			Labels:    dep.Labels,
			Replicas:  dep.Replicas,
			Ready:     dep.AvailableReplicas,
		})
	}

	for _, ds := range inv.Workloads.DaemonSets {
		submission.Workloads.DaemonSets = append(submission.Workloads.DaemonSets, DaemonSetRecord{
			Name:      ds.Name,
			Namespace: ds.Namespace,
			Labels:    ds.Labels,
			Desired:   ds.DesiredNumber,
			Current:   ds.CurrentNumber,
		})
	}

	for _, ss := range inv.Workloads.StatefulSets {
		submission.Workloads.StatefulSets = append(submission.Workloads.StatefulSets, StatefulSetRecord{
			Name:      ss.Name,
			Namespace: ss.Namespace,
			Labels:    ss.Labels,
			Replicas:  ss.Replicas,
		})
	}

	for _, cr := range inv.RBAC.ClusterRoles {
		submission.RBAC.ClusterRoles = append(submission.RBAC.ClusterRoles, ClusterRoleRecord{
			Name:      cr.Name,
			RuleCount: len(cr.Rules),
		})
	}

	for _, crb := range inv.RBAC.ClusterRoleBindings {
		subjects := make([]string, len(crb.Subjects))
		for i, s := range crb.Subjects {
			subjects[i] = fmt.Sprintf("%s/%s", s.Kind, s.Name)
		}
		submission.RBAC.ClusterRoleBindings = append(submission.RBAC.ClusterRoleBindings, ClusterRoleBindingRecord{
			Name:         crb.Name,
			RoleRef:      crb.RoleRef.Name,
			SubjectCount: len(crb.Subjects),
			Subjects:     subjects,
		})
	}

	for _, r := range inv.RBAC.Roles {
		submission.RBAC.Roles = append(submission.RBAC.Roles, RoleRecord{
			Name:      r.Name,
			Namespace: r.Namespace,
			RuleCount: len(r.Rules),
		})
	}

	for _, rb := range inv.RBAC.RoleBindings {
		subjects := make([]string, len(rb.Subjects))
		for i, s := range rb.Subjects {
			subjects[i] = fmt.Sprintf("%s/%s", s.Kind, s.Name)
		}
		submission.RBAC.RoleBindings = append(submission.RBAC.RoleBindings, RoleBindingRecord{
			Name:         rb.Name,
			Namespace:    rb.Namespace,
			RoleRef:      rb.RoleRef.Name,
			SubjectCount: len(rb.Subjects),
			Subjects:     subjects,
		})
	}

	for _, np := range inv.NetworkPolicies {
		submission.Network = append(submission.Network, NetworkPolicyRecord{
			Name:         np.Name,
			Namespace:    np.Namespace,
			PolicyTypes:  np.PolicyTypes,
			IngressRules: np.IngressRules,
			EgressRules:  np.EgressRules,
		})
	}

	for _, svc := range inv.Services {
		ports := make([]int32, len(svc.Ports))
		for i, p := range svc.Ports {
			ports[i] = p.Port
		}
		submission.Services = append(submission.Services, ServiceRecord{
			Name:        svc.Name,
			Namespace:   svc.Namespace,
			Type:        svc.Type,
			ClusterIP:   svc.ClusterIP,
			ExternalIPs: svc.ExternalIPs,
			Ports:       ports,
		})
	}

	return submission
}
