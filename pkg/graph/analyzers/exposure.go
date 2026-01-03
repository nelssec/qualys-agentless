package analyzers

import (
	"fmt"
	"strings"

	"github.com/nelssec/qualys-agentless/pkg/graph"
	"github.com/nelssec/qualys-agentless/pkg/inventory"
)

type ExposureAnalyzer struct {
	g   *graph.SecurityGraph
	inv *inventory.ClusterInventory
}

type ExternalExposure struct {
	ID              string   `json:"id"`
	Type            string   `json:"type"`
	Name            string   `json:"name"`
	Namespace       string   `json:"namespace"`
	ExposureMethod  string   `json:"exposureMethod"`
	Ports           []int32  `json:"ports,omitempty"`
	Hosts           []string `json:"hosts,omitempty"`
	HasTLS          bool     `json:"hasTls"`
	BackendPods     []string `json:"backendPods,omitempty"`
	BackendServices []string `json:"backendServices,omitempty"`
	RiskLevel       string   `json:"riskLevel"`
	AttackPath      []string `json:"attackPath"`
	Recommendations []string `json:"recommendations"`
}

func NewExposureAnalyzer(g *graph.SecurityGraph, inv *inventory.ClusterInventory) *ExposureAnalyzer {
	return &ExposureAnalyzer{g: g, inv: inv}
}

func (a *ExposureAnalyzer) Analyze() []ExternalExposure {
	var exposures []ExternalExposure

	exposures = append(exposures, a.analyzeLoadBalancers()...)
	exposures = append(exposures, a.analyzeNodePorts()...)
	exposures = append(exposures, a.analyzeIngresses()...)
	exposures = append(exposures, a.analyzeExternalIPs()...)
	exposures = append(exposures, a.analyzeHostNetworkPods()...)

	return exposures
}

func (a *ExposureAnalyzer) analyzeLoadBalancers() []ExternalExposure {
	var exposures []ExternalExposure

	for _, lb := range a.inv.AttackSurface.LoadBalancers {
		backendPods := a.findBackendPods(lb.Namespace, lb.Name)
		attackPath := a.buildAttackPath("LoadBalancer", lb.Namespace, lb.Name, backendPods)

		exposure := ExternalExposure{
			ID:             fmt.Sprintf("lb/%s/%s", lb.Namespace, lb.Name),
			Type:           "LoadBalancer",
			Name:           lb.Name,
			Namespace:      lb.Namespace,
			ExposureMethod: "Cloud Load Balancer",
			Ports:          lb.Ports,
			BackendPods:    backendPods,
			RiskLevel:      "HIGH",
			AttackPath:     attackPath,
			Recommendations: []string{
				"Use NetworkPolicies to restrict ingress traffic",
				"Implement WAF in front of load balancer",
				"Use private load balancer if internal-only access needed",
				"Enable access logging",
			},
		}
		exposures = append(exposures, exposure)
	}

	return exposures
}

func (a *ExposureAnalyzer) analyzeNodePorts() []ExternalExposure {
	var exposures []ExternalExposure

	for _, np := range a.inv.AttackSurface.NodePorts {
		backendPods := a.findBackendPods(np.Namespace, np.Name)
		attackPath := a.buildAttackPath("NodePort", np.Namespace, np.Name, backendPods)

		exposure := ExternalExposure{
			ID:             fmt.Sprintf("np/%s/%s", np.Namespace, np.Name),
			Type:           "NodePort",
			Name:           np.Name,
			Namespace:      np.Namespace,
			ExposureMethod: "Node Port (30000-32767)",
			Ports:          np.Ports,
			BackendPods:    backendPods,
			RiskLevel:      "MEDIUM",
			AttackPath:     attackPath,
			Recommendations: []string{
				"Consider using LoadBalancer or Ingress instead",
				"Restrict node network access with security groups/firewall",
				"Use NetworkPolicies for pod-level restriction",
			},
		}
		exposures = append(exposures, exposure)
	}

	return exposures
}

func (a *ExposureAnalyzer) analyzeIngresses() []ExternalExposure {
	var exposures []ExternalExposure

	for _, ing := range a.inv.AttackSurface.Ingresses {
		backendServices := a.findIngressBackends(ing.Namespace, ing.Name)
		backendPods := []string{}
		for _, svc := range backendServices {
			parts := strings.Split(svc, "/")
			if len(parts) == 2 {
				pods := a.findBackendPods(parts[0], parts[1])
				backendPods = append(backendPods, pods...)
			}
		}

		riskLevel := "MEDIUM"
		recommendations := []string{
			"Implement rate limiting",
			"Use ingress annotations for security headers",
			"Configure proper CORS policies",
		}

		if !ing.TLS {
			riskLevel = "HIGH"
			recommendations = append([]string{"Enable TLS encryption (HTTPS)"}, recommendations...)
		}

		exposure := ExternalExposure{
			ID:              fmt.Sprintf("ing/%s/%s", ing.Namespace, ing.Name),
			Type:            "Ingress",
			Name:            ing.Name,
			Namespace:       ing.Namespace,
			ExposureMethod:  "HTTP(S) Ingress",
			Hosts:           ing.Hosts,
			HasTLS:          ing.TLS,
			BackendServices: backendServices,
			BackendPods:     backendPods,
			RiskLevel:       riskLevel,
			AttackPath:      a.buildIngressAttackPath(ing, backendServices, backendPods),
			Recommendations: recommendations,
		}
		exposures = append(exposures, exposure)
	}

	return exposures
}

func (a *ExposureAnalyzer) analyzeExternalIPs() []ExternalExposure {
	var exposures []ExternalExposure

	for _, svc := range a.inv.Services {
		if len(svc.ExternalIPs) == 0 {
			continue
		}

		backendPods := a.findBackendPods(svc.Namespace, svc.Name)
		var ports []int32
		for _, p := range svc.Ports {
			ports = append(ports, p.Port)
		}

		exposure := ExternalExposure{
			ID:             fmt.Sprintf("extip/%s/%s", svc.Namespace, svc.Name),
			Type:           "ExternalIP",
			Name:           svc.Name,
			Namespace:      svc.Namespace,
			ExposureMethod: "External IP Address",
			Hosts:          svc.ExternalIPs,
			Ports:          ports,
			BackendPods:    backendPods,
			RiskLevel:      "HIGH",
			AttackPath:     a.buildAttackPath("ExternalIP", svc.Namespace, svc.Name, backendPods),
			Recommendations: []string{
				"Consider using LoadBalancer type instead",
				"Ensure external IPs are properly firewalled",
				"Use NetworkPolicies to restrict traffic",
			},
		}
		exposures = append(exposures, exposure)
	}

	return exposures
}

func (a *ExposureAnalyzer) analyzeHostNetworkPods() []ExternalExposure {
	var exposures []ExternalExposure

	for _, pod := range a.inv.Workloads.Pods {
		if !pod.HostNetwork {
			continue
		}

		var ports []int32
		for _, c := range pod.Containers {
			for _, p := range c.Ports {
				ports = append(ports, p.ContainerPort)
			}
		}

		if len(ports) == 0 {
			continue
		}

		exposure := ExternalExposure{
			ID:             fmt.Sprintf("hostnet/%s/%s", pod.Namespace, pod.Name),
			Type:           "HostNetwork",
			Name:           pod.Name,
			Namespace:      pod.Namespace,
			ExposureMethod: "Host Network (node IP)",
			Ports:          ports,
			BackendPods:    []string{fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)},
			RiskLevel:      "HIGH",
			AttackPath: []string{
				fmt.Sprintf("Internet → Node %s → Pod %s (hostNetwork)", pod.NodeName, pod.Name),
			},
			Recommendations: []string{
				"Remove hostNetwork: true unless absolutely required",
				"Use NetworkPolicies (note: may not work with hostNetwork)",
				"Restrict node network with security groups",
			},
		}
		exposures = append(exposures, exposure)
	}

	return exposures
}

func (a *ExposureAnalyzer) findBackendPods(namespace, serviceName string) []string {
	var pods []string

	var targetService *inventory.ServiceInfo
	for i := range a.inv.Services {
		svc := &a.inv.Services[i]
		if svc.Namespace == namespace && svc.Name == serviceName {
			targetService = svc
			break
		}
	}

	if targetService == nil {
		return pods
	}

	for _, pod := range a.inv.Workloads.Pods {
		if pod.Namespace != namespace {
			continue
		}
		if matchesLabels(pod.Labels, targetService.Labels) {
			pods = append(pods, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name))
		}
	}

	return pods
}

func (a *ExposureAnalyzer) findIngressBackends(namespace, ingressName string) []string {
	var services []string

	for _, ing := range a.inv.Ingresses {
		if ing.Namespace != namespace || ing.Name != ingressName {
			continue
		}

		for _, rule := range ing.Rules {
			for _, path := range rule.Paths {
				parts := strings.Split(path.Backend, ":")
				if len(parts) > 0 {
					services = append(services, fmt.Sprintf("%s/%s", namespace, parts[0]))
				}
			}
		}
	}

	return services
}

func (a *ExposureAnalyzer) buildAttackPath(expType, namespace, name string, backendPods []string) []string {
	path := []string{
		fmt.Sprintf("Internet → %s %s/%s", expType, namespace, name),
	}

	if len(backendPods) > 0 {
		path = append(path, fmt.Sprintf("→ Backend Pods: %s", strings.Join(backendPods, ", ")))
	}

	for _, podRef := range backendPods {
		parts := strings.Split(podRef, "/")
		if len(parts) != 2 {
			continue
		}
		for _, pod := range a.inv.Workloads.Pods {
			if pod.Namespace == parts[0] && pod.Name == parts[1] {
				path = append(path, fmt.Sprintf("→ ServiceAccount: %s/%s", pod.Namespace, pod.ServiceAccount))
				break
			}
		}
	}

	return path
}

func (a *ExposureAnalyzer) buildIngressAttackPath(ing inventory.ExposedIngress, services, pods []string) []string {
	protocol := "HTTPS"
	if !ing.TLS {
		protocol = "HTTP (unencrypted!)"
	}

	path := []string{
		fmt.Sprintf("Internet → %s → Ingress %s/%s", protocol, ing.Namespace, ing.Name),
	}

	if len(ing.Hosts) > 0 {
		path = append(path, fmt.Sprintf("→ Hosts: %s", strings.Join(ing.Hosts, ", ")))
	}

	if len(services) > 0 {
		path = append(path, fmt.Sprintf("→ Services: %s", strings.Join(services, ", ")))
	}

	if len(pods) > 0 {
		path = append(path, fmt.Sprintf("→ Pods: %s", strings.Join(pods, ", ")))
	}

	return path
}

func matchesLabels(podLabels, serviceSelector map[string]string) bool {
	if len(serviceSelector) == 0 {
		return false
	}
	for k, v := range serviceSelector {
		if podLabels[k] != v {
			return false
		}
	}
	return true
}

func (a *ExposureAnalyzer) GetSummary(exposures []ExternalExposure) map[string]interface{} {
	summary := map[string]interface{}{
		"totalExposures":    len(exposures),
		"loadBalancers":     0,
		"nodePorts":         0,
		"ingresses":         0,
		"externalIPs":       0,
		"hostNetworkPods":   0,
		"highRisk":          0,
		"mediumRisk":        0,
		"ingressesWithoutTLS": 0,
	}

	for _, e := range exposures {
		switch e.Type {
		case "LoadBalancer":
			summary["loadBalancers"] = summary["loadBalancers"].(int) + 1
		case "NodePort":
			summary["nodePorts"] = summary["nodePorts"].(int) + 1
		case "Ingress":
			summary["ingresses"] = summary["ingresses"].(int) + 1
			if !e.HasTLS {
				summary["ingressesWithoutTLS"] = summary["ingressesWithoutTLS"].(int) + 1
			}
		case "ExternalIP":
			summary["externalIPs"] = summary["externalIPs"].(int) + 1
		case "HostNetwork":
			summary["hostNetworkPods"] = summary["hostNetworkPods"].(int) + 1
		}

		switch e.RiskLevel {
		case "HIGH", "CRITICAL":
			summary["highRisk"] = summary["highRisk"].(int) + 1
		case "MEDIUM":
			summary["mediumRisk"] = summary["mediumRisk"].(int) + 1
		}
	}

	return summary
}
