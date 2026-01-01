package manifest

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes/scheme"
)

type Parser struct {
	decoder runtime.Decoder
}

func NewParser() *Parser {
	return &Parser{
		decoder: serializer.NewCodecFactory(scheme.Scheme).UniversalDeserializer(),
	}
}

func (p *Parser) ParseFile(path string) (*inventory.ClusterInventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	return p.Parse(data, path)
}

func (p *Parser) ParseDirectory(dir string) (*inventory.ClusterInventory, error) {
	inv := &inventory.ClusterInventory{
		Workloads: inventory.WorkloadInventory{},
		RBAC:      inventory.RBACInventory{},
	}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		fileInv, err := p.ParseFile(path)
		if err != nil {
			return nil
		}
		mergeInventory(inv, fileInv)
		return nil
	})

	return inv, err
}

func (p *Parser) Parse(data []byte, source string) (*inventory.ClusterInventory, error) {
	inv := &inventory.ClusterInventory{
		Workloads: inventory.WorkloadInventory{},
		RBAC:      inventory.RBACInventory{},
	}

	reader := bufio.NewReader(bytes.NewReader(data))
	var currentDoc bytes.Buffer

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil && err != io.EOF {
			return nil, err
		}

		if bytes.Equal(bytes.TrimSpace(line), []byte("---")) || err == io.EOF {
			if currentDoc.Len() > 0 {
				p.parseDocument(currentDoc.Bytes(), source, inv)
				currentDoc.Reset()
			}
			if err == io.EOF {
				break
			}
			continue
		}
		currentDoc.Write(line)
	}

	return inv, nil
}

func (p *Parser) parseDocument(data []byte, source string, inv *inventory.ClusterInventory) {
	obj, _, err := p.decoder.Decode(data, nil, nil)
	if err != nil {
		return
	}

	switch o := obj.(type) {
	case *corev1.Pod:
		inv.Workloads.Pods = append(inv.Workloads.Pods, convertPod(o, source))
	case *appsv1.Deployment:
		inv.Workloads.Deployments = append(inv.Workloads.Deployments, convertDeployment(o, source))
		inv.Workloads.Pods = append(inv.Workloads.Pods, convertPodFromTemplate(o.Spec.Template, o.Namespace, o.Name, source))
	case *appsv1.DaemonSet:
		inv.Workloads.DaemonSets = append(inv.Workloads.DaemonSets, convertDaemonSet(o, source))
		inv.Workloads.Pods = append(inv.Workloads.Pods, convertPodFromTemplate(o.Spec.Template, o.Namespace, o.Name, source))
	case *appsv1.StatefulSet:
		inv.Workloads.StatefulSets = append(inv.Workloads.StatefulSets, convertStatefulSet(o, source))
		inv.Workloads.Pods = append(inv.Workloads.Pods, convertPodFromTemplate(o.Spec.Template, o.Namespace, o.Name, source))
	case *batchv1.Job:
		inv.Workloads.Jobs = append(inv.Workloads.Jobs, convertJob(o, source))
		inv.Workloads.Pods = append(inv.Workloads.Pods, convertPodFromTemplate(o.Spec.Template, o.Namespace, o.Name, source))
	case *batchv1.CronJob:
		inv.Workloads.CronJobs = append(inv.Workloads.CronJobs, convertCronJob(o, source))
		inv.Workloads.Pods = append(inv.Workloads.Pods, convertPodFromTemplate(o.Spec.JobTemplate.Spec.Template, o.Namespace, o.Name, source))
	case *rbacv1.ClusterRole:
		inv.RBAC.ClusterRoles = append(inv.RBAC.ClusterRoles, convertClusterRole(o))
	case *rbacv1.ClusterRoleBinding:
		inv.RBAC.ClusterRoleBindings = append(inv.RBAC.ClusterRoleBindings, convertClusterRoleBinding(o))
	case *rbacv1.Role:
		inv.RBAC.Roles = append(inv.RBAC.Roles, convertRole(o))
	case *rbacv1.RoleBinding:
		inv.RBAC.RoleBindings = append(inv.RBAC.RoleBindings, convertRoleBinding(o))
	case *networkingv1.NetworkPolicy:
		inv.NetworkPolicies = append(inv.NetworkPolicies, convertNetworkPolicy(o))
	case *corev1.ServiceAccount:
		inv.ServiceAccounts = append(inv.ServiceAccounts, convertServiceAccount(o))
	case *corev1.Service:
		inv.Services = append(inv.Services, convertService(o))
	case *corev1.Namespace:
		inv.Namespaces = append(inv.Namespaces, inventory.NamespaceInfo{
			Name:   o.Name,
			Labels: o.Labels,
		})
	}
}

func convertPod(pod *corev1.Pod, source string) inventory.PodInfo {
	return inventory.PodInfo{
		Name:           pod.Name,
		Namespace:      pod.Namespace,
		Labels:         pod.Labels,
		ServiceAccount: pod.Spec.ServiceAccountName,
		HostNetwork:    pod.Spec.HostNetwork,
		HostPID:        pod.Spec.HostPID,
		HostIPC:        pod.Spec.HostIPC,
		Containers:     convertContainers(pod.Spec.Containers),
		Source:         source,
	}
}

func convertPodFromTemplate(template corev1.PodTemplateSpec, namespace, ownerName, source string) inventory.PodInfo {
	name := template.Name
	if name == "" {
		name = ownerName + "-pod"
	}
	ns := template.Namespace
	if ns == "" {
		ns = namespace
	}
	return inventory.PodInfo{
		Name:           name,
		Namespace:      ns,
		Labels:         template.Labels,
		ServiceAccount: template.Spec.ServiceAccountName,
		HostNetwork:    template.Spec.HostNetwork,
		HostPID:        template.Spec.HostPID,
		HostIPC:        template.Spec.HostIPC,
		Containers:     convertContainers(template.Spec.Containers),
		Source:         source,
	}
}

func convertContainers(containers []corev1.Container) []inventory.ContainerInfo {
	result := make([]inventory.ContainerInfo, len(containers))
	for i, c := range containers {
		result[i] = inventory.ContainerInfo{
			Name:  c.Name,
			Image: c.Image,
		}
		if c.SecurityContext != nil {
			result[i].SecurityContext = &inventory.ContainerSecurityContext{}
			if c.SecurityContext.Privileged != nil {
				result[i].SecurityContext.Privileged = c.SecurityContext.Privileged
			}
			if c.SecurityContext.RunAsNonRoot != nil {
				result[i].SecurityContext.RunAsNonRoot = c.SecurityContext.RunAsNonRoot
			}
			if c.SecurityContext.ReadOnlyRootFilesystem != nil {
				result[i].SecurityContext.ReadOnlyRootFilesystem = c.SecurityContext.ReadOnlyRootFilesystem
			}
			if c.SecurityContext.AllowPrivilegeEscalation != nil {
				result[i].SecurityContext.AllowPrivilegeEscalation = c.SecurityContext.AllowPrivilegeEscalation
			}
			if c.SecurityContext.Capabilities != nil {
				if len(c.SecurityContext.Capabilities.Add) > 0 {
					result[i].SecurityContext.Capabilities = &inventory.Capabilities{
						Add: make([]string, len(c.SecurityContext.Capabilities.Add)),
					}
					for j, cap := range c.SecurityContext.Capabilities.Add {
						result[i].SecurityContext.Capabilities.Add[j] = string(cap)
					}
				}
				if len(c.SecurityContext.Capabilities.Drop) > 0 {
					if result[i].SecurityContext.Capabilities == nil {
						result[i].SecurityContext.Capabilities = &inventory.Capabilities{}
					}
					result[i].SecurityContext.Capabilities.Drop = make([]string, len(c.SecurityContext.Capabilities.Drop))
					for j, cap := range c.SecurityContext.Capabilities.Drop {
						result[i].SecurityContext.Capabilities.Drop[j] = string(cap)
					}
				}
			}
		}
		if c.Resources.Limits != nil || c.Resources.Requests != nil {
			if c.Resources.Limits != nil {
				result[i].Resources.Limits = make(map[string]string)
				for k, v := range c.Resources.Limits {
					result[i].Resources.Limits[string(k)] = v.String()
				}
			}
			if c.Resources.Requests != nil {
				result[i].Resources.Requests = make(map[string]string)
				for k, v := range c.Resources.Requests {
					result[i].Resources.Requests[string(k)] = v.String()
				}
			}
		}
		if c.LivenessProbe != nil {
			result[i].LivenessProbe = true
		}
		if c.ReadinessProbe != nil {
			result[i].ReadinessProbe = true
		}
	}
	return result
}

func convertDeployment(d *appsv1.Deployment, source string) inventory.DeploymentInfo {
	return inventory.DeploymentInfo{
		Name:      d.Name,
		Namespace: d.Namespace,
		Labels:    d.Labels,
		Replicas:  *d.Spec.Replicas,
	}
}

func convertDaemonSet(ds *appsv1.DaemonSet, source string) inventory.DaemonSetInfo {
	return inventory.DaemonSetInfo{
		Name:      ds.Name,
		Namespace: ds.Namespace,
		Labels:    ds.Labels,
	}
}

func convertStatefulSet(ss *appsv1.StatefulSet, source string) inventory.StatefulSetInfo {
	replicas := int32(1)
	if ss.Spec.Replicas != nil {
		replicas = *ss.Spec.Replicas
	}
	return inventory.StatefulSetInfo{
		Name:      ss.Name,
		Namespace: ss.Namespace,
		Labels:    ss.Labels,
		Replicas:  replicas,
	}
}

func convertJob(j *batchv1.Job, source string) inventory.JobInfo {
	return inventory.JobInfo{
		Name:      j.Name,
		Namespace: j.Namespace,
		Labels:    j.Labels,
	}
}

func convertCronJob(cj *batchv1.CronJob, source string) inventory.CronJobInfo {
	return inventory.CronJobInfo{
		Name:      cj.Name,
		Namespace: cj.Namespace,
		Labels:    cj.Labels,
		Schedule:  cj.Spec.Schedule,
	}
}

func convertClusterRole(cr *rbacv1.ClusterRole) inventory.ClusterRoleInfo {
	rules := make([]inventory.PolicyRule, len(cr.Rules))
	for i, r := range cr.Rules {
		rules[i] = inventory.PolicyRule{
			Verbs:     r.Verbs,
			Resources: r.Resources,
			APIGroups: r.APIGroups,
		}
	}
	return inventory.ClusterRoleInfo{
		Name:   cr.Name,
		Labels: cr.Labels,
		Rules:  rules,
	}
}

func convertClusterRoleBinding(crb *rbacv1.ClusterRoleBinding) inventory.ClusterRoleBindingInfo {
	subjects := make([]inventory.Subject, len(crb.Subjects))
	for i, s := range crb.Subjects {
		subjects[i] = inventory.Subject{
			Kind:      s.Kind,
			Name:      s.Name,
			Namespace: s.Namespace,
		}
	}
	return inventory.ClusterRoleBindingInfo{
		Name:   crb.Name,
		Labels: crb.Labels,
		RoleRef: inventory.RoleRef{
			Kind: crb.RoleRef.Kind,
			Name: crb.RoleRef.Name,
		},
		Subjects: subjects,
	}
}

func convertRole(r *rbacv1.Role) inventory.RoleInfo {
	rules := make([]inventory.PolicyRule, len(r.Rules))
	for i, rule := range r.Rules {
		rules[i] = inventory.PolicyRule{
			Verbs:     rule.Verbs,
			Resources: rule.Resources,
			APIGroups: rule.APIGroups,
		}
	}
	return inventory.RoleInfo{
		Name:      r.Name,
		Namespace: r.Namespace,
		Labels:    r.Labels,
		Rules:     rules,
	}
}

func convertRoleBinding(rb *rbacv1.RoleBinding) inventory.RoleBindingInfo {
	subjects := make([]inventory.Subject, len(rb.Subjects))
	for i, s := range rb.Subjects {
		subjects[i] = inventory.Subject{
			Kind:      s.Kind,
			Name:      s.Name,
			Namespace: s.Namespace,
		}
	}
	return inventory.RoleBindingInfo{
		Name:      rb.Name,
		Namespace: rb.Namespace,
		Labels:    rb.Labels,
		RoleRef: inventory.RoleRef{
			Kind: rb.RoleRef.Kind,
			Name: rb.RoleRef.Name,
		},
		Subjects: subjects,
	}
}

func convertNetworkPolicy(np *networkingv1.NetworkPolicy) inventory.NetworkPolicyInfo {
	policyTypes := make([]string, len(np.Spec.PolicyTypes))
	for i, pt := range np.Spec.PolicyTypes {
		policyTypes[i] = string(pt)
	}
	return inventory.NetworkPolicyInfo{
		Name:         np.Name,
		Namespace:    np.Namespace,
		Labels:       np.Labels,
		PolicyTypes:  policyTypes,
		IngressRules: len(np.Spec.Ingress),
		EgressRules:  len(np.Spec.Egress),
	}
}

func convertServiceAccount(sa *corev1.ServiceAccount) inventory.ServiceAccountInfo {
	return inventory.ServiceAccountInfo{
		Name:                         sa.Name,
		Namespace:                    sa.Namespace,
		Labels:                       sa.Labels,
		AutomountServiceAccountToken: sa.AutomountServiceAccountToken,
	}
}

func convertService(svc *corev1.Service) inventory.ServiceInfo {
	ports := make([]inventory.ServicePort, len(svc.Spec.Ports))
	for i, p := range svc.Spec.Ports {
		ports[i] = inventory.ServicePort{
			Name:     p.Name,
			Port:     p.Port,
			Protocol: string(p.Protocol),
		}
	}
	return inventory.ServiceInfo{
		Name:        svc.Name,
		Namespace:   svc.Namespace,
		Labels:      svc.Labels,
		Type:        string(svc.Spec.Type),
		ClusterIP:   svc.Spec.ClusterIP,
		ExternalIPs: svc.Spec.ExternalIPs,
		Ports:       ports,
	}
}

func mergeInventory(dst, src *inventory.ClusterInventory) {
	dst.Namespaces = append(dst.Namespaces, src.Namespaces...)
	dst.Workloads.Pods = append(dst.Workloads.Pods, src.Workloads.Pods...)
	dst.Workloads.Deployments = append(dst.Workloads.Deployments, src.Workloads.Deployments...)
	dst.Workloads.DaemonSets = append(dst.Workloads.DaemonSets, src.Workloads.DaemonSets...)
	dst.Workloads.StatefulSets = append(dst.Workloads.StatefulSets, src.Workloads.StatefulSets...)
	dst.Workloads.Jobs = append(dst.Workloads.Jobs, src.Workloads.Jobs...)
	dst.Workloads.CronJobs = append(dst.Workloads.CronJobs, src.Workloads.CronJobs...)
	dst.RBAC.ClusterRoles = append(dst.RBAC.ClusterRoles, src.RBAC.ClusterRoles...)
	dst.RBAC.ClusterRoleBindings = append(dst.RBAC.ClusterRoleBindings, src.RBAC.ClusterRoleBindings...)
	dst.RBAC.Roles = append(dst.RBAC.Roles, src.RBAC.Roles...)
	dst.RBAC.RoleBindings = append(dst.RBAC.RoleBindings, src.RBAC.RoleBindings...)
	dst.NetworkPolicies = append(dst.NetworkPolicies, src.NetworkPolicies...)
	dst.ServiceAccounts = append(dst.ServiceAccounts, src.ServiceAccounts...)
	dst.Services = append(dst.Services, src.Services...)
}
