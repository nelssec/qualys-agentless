package collector

import (
	"context"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// RBACCollector collects RBAC resources.
type RBACCollector struct {
	results inventory.RBACInventory
}

// NewRBACCollector creates a new RBAC collector.
func NewRBACCollector() *RBACCollector {
	return &RBACCollector{}
}

// Name returns the collector name.
func (c *RBACCollector) Name() string {
	return "rbac"
}

// Collect gathers all RBAC resources.
func (c *RBACCollector) Collect(ctx context.Context, clientset *kubernetes.Clientset) error {
	// Collect Roles
	roles, err := clientset.RbacV1().Roles("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, role := range roles.Items {
		c.results.Roles = append(c.results.Roles, convertRole(&role))
	}

	// Collect ClusterRoles
	clusterRoles, err := clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, cr := range clusterRoles.Items {
		c.results.ClusterRoles = append(c.results.ClusterRoles, convertClusterRole(&cr))
	}

	// Collect RoleBindings
	roleBindings, err := clientset.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, rb := range roleBindings.Items {
		c.results.RoleBindings = append(c.results.RoleBindings, convertRoleBinding(&rb))
	}

	// Collect ClusterRoleBindings
	clusterRoleBindings, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, crb := range clusterRoleBindings.Items {
		c.results.ClusterRoleBindings = append(c.results.ClusterRoleBindings, convertClusterRoleBinding(&crb))
	}

	return nil
}

// Results returns the collected RBAC resources.
func (c *RBACCollector) Results() interface{} {
	return c.results
}

// convertRole converts a Kubernetes Role to inventory format.
func convertRole(role *rbacv1.Role) inventory.RoleInfo {
	return inventory.RoleInfo{
		Name:      role.Name,
		Namespace: role.Namespace,
		Labels:    role.Labels,
		Rules:     convertPolicyRules(role.Rules),
	}
}

// convertClusterRole converts a Kubernetes ClusterRole to inventory format.
func convertClusterRole(cr *rbacv1.ClusterRole) inventory.ClusterRoleInfo {
	return inventory.ClusterRoleInfo{
		Name:   cr.Name,
		Labels: cr.Labels,
		Rules:  convertPolicyRules(cr.Rules),
	}
}

// convertRoleBinding converts a Kubernetes RoleBinding to inventory format.
func convertRoleBinding(rb *rbacv1.RoleBinding) inventory.RoleBindingInfo {
	return inventory.RoleBindingInfo{
		Name:      rb.Name,
		Namespace: rb.Namespace,
		Labels:    rb.Labels,
		RoleRef: inventory.RoleRef{
			Kind: rb.RoleRef.Kind,
			Name: rb.RoleRef.Name,
		},
		Subjects: convertSubjects(rb.Subjects),
	}
}

// convertClusterRoleBinding converts a Kubernetes ClusterRoleBinding to inventory format.
func convertClusterRoleBinding(crb *rbacv1.ClusterRoleBinding) inventory.ClusterRoleBindingInfo {
	return inventory.ClusterRoleBindingInfo{
		Name:   crb.Name,
		Labels: crb.Labels,
		RoleRef: inventory.RoleRef{
			Kind: crb.RoleRef.Kind,
			Name: crb.RoleRef.Name,
		},
		Subjects: convertSubjects(crb.Subjects),
	}
}

// convertPolicyRules converts RBAC policy rules.
func convertPolicyRules(rules []rbacv1.PolicyRule) []inventory.PolicyRule {
	result := make([]inventory.PolicyRule, len(rules))
	for i, rule := range rules {
		result[i] = inventory.PolicyRule{
			Verbs:           rule.Verbs,
			APIGroups:       rule.APIGroups,
			Resources:       rule.Resources,
			ResourceNames:   rule.ResourceNames,
			NonResourceURLs: rule.NonResourceURLs,
		}
	}
	return result
}

// convertSubjects converts RBAC subjects.
func convertSubjects(subjects []rbacv1.Subject) []inventory.Subject {
	result := make([]inventory.Subject, len(subjects))
	for i, s := range subjects {
		result[i] = inventory.Subject{
			Kind:      s.Kind,
			Name:      s.Name,
			Namespace: s.Namespace,
		}
	}
	return result
}

// IsPrivilegedRole checks if a role has privileged access.
func IsPrivilegedRole(role *inventory.RoleInfo) bool {
	return hasPrivilegedRules(role.Rules)
}

// IsPrivilegedClusterRole checks if a cluster role has privileged access.
func IsPrivilegedClusterRole(role *inventory.ClusterRoleInfo) bool {
	return hasPrivilegedRules(role.Rules)
}

// hasPrivilegedRules checks if rules grant privileged access.
func hasPrivilegedRules(rules []inventory.PolicyRule) bool {
	for _, rule := range rules {
		// Check for wildcard permissions
		for _, verb := range rule.Verbs {
			if verb == "*" {
				for _, resource := range rule.Resources {
					if resource == "*" {
						return true
					}
				}
			}
		}

		// Check for secrets access
		for _, resource := range rule.Resources {
			if resource == "secrets" {
				for _, verb := range rule.Verbs {
					if verb == "*" || verb == "get" || verb == "list" || verb == "watch" {
						return true
					}
				}
			}
		}

		// Check for pods/exec
		for _, resource := range rule.Resources {
			if resource == "pods/exec" || resource == "pods/attach" {
				return true
			}
		}
	}
	return false
}
