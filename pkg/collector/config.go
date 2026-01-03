package collector

import (
	"context"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type ConfigResults struct {
	ConfigMaps []inventory.ConfigMapInfo
	Secrets    []inventory.SecretInfo
}

type ConfigCollector struct {
	include         []string
	exclude         []string
	collectSecretKeys bool
	results         ConfigResults
}

func NewConfigCollector(include, exclude []string) *ConfigCollector {
	return &ConfigCollector{
		include:         include,
		exclude:         exclude,
		collectSecretKeys: false,
	}
}

func (c *ConfigCollector) Name() string {
	return "config"
}

func (c *ConfigCollector) Collect(ctx context.Context, clientset *kubernetes.Clientset) error {
	configMaps, err := clientset.CoreV1().ConfigMaps("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	c.results.ConfigMaps = make([]inventory.ConfigMapInfo, 0, len(configMaps.Items))
	for _, cm := range configMaps.Items {
		if !shouldIncludeNamespace(cm.Namespace, c.include, c.exclude) {
			continue
		}

		dataKeys := make([]string, 0, len(cm.Data))
		for k := range cm.Data {
			dataKeys = append(dataKeys, k)
		}

		c.results.ConfigMaps = append(c.results.ConfigMaps, inventory.ConfigMapInfo{
			Name:      cm.Name,
			Namespace: cm.Namespace,
			Labels:    cm.Labels,
			DataKeys:  dataKeys,
		})
	}

	secrets, err := clientset.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	c.results.Secrets = make([]inventory.SecretInfo, 0, len(secrets.Items))
	for _, secret := range secrets.Items {
		if !shouldIncludeNamespace(secret.Namespace, c.include, c.exclude) {
			continue
		}

		var dataKeys []string
		if c.collectSecretKeys {
			dataKeys = make([]string, 0, len(secret.Data))
			for k := range secret.Data {
				dataKeys = append(dataKeys, k)
			}
		}

		c.results.Secrets = append(c.results.Secrets, inventory.SecretInfo{
			Name:      secret.Name,
			Namespace: secret.Namespace,
			Labels:    secret.Labels,
			Type:      string(secret.Type),
			DataKeys:  dataKeys,
		})
	}

	return nil
}

func (c *ConfigCollector) Results() interface{} {
	return c.results
}
