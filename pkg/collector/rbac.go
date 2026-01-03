package collector

import (
	"context"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type RBACCollector struct {
	results inventory.RBACInventory
}

func NewRBACCollector() *RBACCollector {
	return &RBACCollector{}
}

func (c *RBACCollector) Name() string {
	return "rbac"
}

func (c *RBACCollector) Collect(ctx context.Context, clientset *kubernetes.Clientset) error {
	roles, err := clientset.RbacV1().Roles("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, role := range roles.Items {
		c.results.Roles = append(c.results.Roles, convertRole(&role))
	}

	clusterRoles, err := clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, cr := range clusterRoles.Items {
		c.results.ClusterRoles = append(c.results.ClusterRoles, convertClusterRole(&cr))
	}

	roleBindings, err := clientset.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, rb := range roleBindings.Items {
		c.results.RoleBindings = append(c.results.RoleBindings, convertRoleBinding(&rb))
	}

	clusterRoleBindings, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, crb := range clusterRoleBindings.Items {
		c.results.ClusterRoleBindings = append(c.results.ClusterRoleBindings, convertClusterRoleBinding(&crb))
	}

	return nil
}

func (c *RBACCollector) Results() interface{} {
	return c.results
}

func convertRole(role *rbacv1.Role) inventory.RoleInfo {
	return inventory.RoleInfo{
		Name:      role.Name,
		Namespace: role.Namespace,
		Labels:    role.Labels,
		Rules:     convertPolicyRules(role.Rules),
	}
}

func convertClusterRole(cr *rbacv1.ClusterRole) inventory.ClusterRoleInfo {
	return inventory.ClusterRoleInfo{
		Name:   cr.Name,
		Labels: cr.Labels,
		Rules:  convertPolicyRules(cr.Rules),
	}
}

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

