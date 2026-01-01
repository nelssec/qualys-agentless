package collector

import (
	"context"
	"fmt"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ServiceCollector collects Service resources.
type ServiceCollector struct {
	include []string
	exclude []string
	results []inventory.ServiceInfo
}

// NewServiceCollector creates a new service collector.
func NewServiceCollector(include, exclude []string) *ServiceCollector {
	return &ServiceCollector{
		include: include,
		exclude: exclude,
	}
}

// Name returns the collector name.
func (c *ServiceCollector) Name() string {
	return "service"
}

// Collect gathers all Service resources.
func (c *ServiceCollector) Collect(ctx context.Context, clientset *kubernetes.Clientset) error {
	services, err := clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	c.results = make([]inventory.ServiceInfo, 0, len(services.Items))

	for _, svc := range services.Items {
		if !shouldIncludeNamespace(svc.Namespace, c.include, c.exclude) {
			continue
		}

		ports := make([]inventory.ServicePort, len(svc.Spec.Ports))
		for i, p := range svc.Spec.Ports {
			ports[i] = inventory.ServicePort{
				Name:       p.Name,
				Port:       p.Port,
				TargetPort: p.TargetPort.String(),
				Protocol:   string(p.Protocol),
				NodePort:   p.NodePort,
			}
		}

		c.results = append(c.results, inventory.ServiceInfo{
			Name:        svc.Name,
			Namespace:   svc.Namespace,
			Labels:      svc.Labels,
			Type:        string(svc.Spec.Type),
			ClusterIP:   svc.Spec.ClusterIP,
			ExternalIPs: svc.Spec.ExternalIPs,
			Ports:       ports,
		})
	}

	return nil
}

// Results returns the collected services.
func (c *ServiceCollector) Results() interface{} {
	return c.results
}

// IngressCollector collects Ingress resources.
type IngressCollector struct {
	include []string
	exclude []string
	results []inventory.IngressInfo
}

// NewIngressCollector creates a new ingress collector.
func NewIngressCollector(include, exclude []string) *IngressCollector {
	return &IngressCollector{
		include: include,
		exclude: exclude,
	}
}

// Name returns the collector name.
func (c *IngressCollector) Name() string {
	return "ingress"
}

// Collect gathers all Ingress resources.
func (c *IngressCollector) Collect(ctx context.Context, clientset *kubernetes.Clientset) error {
	ingresses, err := clientset.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	c.results = make([]inventory.IngressInfo, 0, len(ingresses.Items))

	for _, ing := range ingresses.Items {
		if !shouldIncludeNamespace(ing.Namespace, c.include, c.exclude) {
			continue
		}

		// Convert TLS configuration
		tls := make([]inventory.IngressTLS, len(ing.Spec.TLS))
		for i, t := range ing.Spec.TLS {
			tls[i] = inventory.IngressTLS{
				Hosts:      t.Hosts,
				SecretName: t.SecretName,
			}
		}

		// Convert rules
		rules := make([]inventory.IngressRule, len(ing.Spec.Rules))
		for i, r := range ing.Spec.Rules {
			paths := make([]inventory.IngressPath, 0)
			if r.HTTP != nil {
				for _, p := range r.HTTP.Paths {
					pathType := "Prefix"
					if p.PathType != nil {
						pathType = string(*p.PathType)
					}

					backend := ""
					if p.Backend.Service != nil {
						backend = fmt.Sprintf("%s:%d", p.Backend.Service.Name, p.Backend.Service.Port.Number)
					}

					paths = append(paths, inventory.IngressPath{
						Path:     p.Path,
						PathType: pathType,
						Backend:  backend,
					})
				}
			}

			rules[i] = inventory.IngressRule{
				Host:  r.Host,
				Paths: paths,
			}
		}

		ingressClass := ""
		if ing.Spec.IngressClassName != nil {
			ingressClass = *ing.Spec.IngressClassName
		}

		c.results = append(c.results, inventory.IngressInfo{
			Name:         ing.Name,
			Namespace:    ing.Namespace,
			Labels:       ing.Labels,
			IngressClass: ingressClass,
			TLS:          tls,
			Rules:        rules,
		})
	}

	return nil
}

// Results returns the collected ingresses.
func (c *IngressCollector) Results() interface{} {
	return c.results
}
