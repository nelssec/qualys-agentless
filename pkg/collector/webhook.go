package collector

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type WebhookCollector struct {
	results inventory.WebhookInventory
}

func NewWebhookCollector() *WebhookCollector {
	return &WebhookCollector{}
}

func (c *WebhookCollector) Name() string {
	return "webhook"
}

func (c *WebhookCollector) Collect(ctx context.Context, clientset *kubernetes.Clientset) error {
	validating, err := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	c.results.ValidatingWebhooks = make([]inventory.WebhookInfo, 0, len(validating.Items))
	for _, vwc := range validating.Items {
		webhooks := make([]inventory.WebhookConfig, 0, len(vwc.Webhooks))
		for _, wh := range vwc.Webhooks {
			var clientConfig string
			if wh.ClientConfig.Service != nil {
				clientConfig = fmt.Sprintf("%s/%s:%d", wh.ClientConfig.Service.Namespace, wh.ClientConfig.Service.Name, *wh.ClientConfig.Service.Port)
			} else if wh.ClientConfig.URL != nil {
				clientConfig = *wh.ClientConfig.URL
			}

			rules := make([]string, 0, len(wh.Rules))
			for _, r := range wh.Rules {
				ruleStr, _ := json.Marshal(r)
				rules = append(rules, string(ruleStr))
			}

			var failurePolicy string
			if wh.FailurePolicy != nil {
				failurePolicy = string(*wh.FailurePolicy)
			}

			var matchPolicy string
			if wh.MatchPolicy != nil {
				matchPolicy = string(*wh.MatchPolicy)
			}

			var sideEffects string
			if wh.SideEffects != nil {
				sideEffects = string(*wh.SideEffects)
			}

			var nsSelector string
			if wh.NamespaceSelector != nil {
				sel, _ := json.Marshal(wh.NamespaceSelector)
				nsSelector = string(sel)
			}

			webhooks = append(webhooks, inventory.WebhookConfig{
				Name:                    wh.Name,
				ClientConfig:            clientConfig,
				Rules:                   rules,
				FailurePolicy:           failurePolicy,
				MatchPolicy:             matchPolicy,
				SideEffects:             sideEffects,
				TimeoutSeconds:          wh.TimeoutSeconds,
				AdmissionReviewVersions: wh.AdmissionReviewVersions,
				NamespaceSelector:       nsSelector,
			})
		}

		c.results.ValidatingWebhooks = append(c.results.ValidatingWebhooks, inventory.WebhookInfo{
			Name:     vwc.Name,
			Webhooks: webhooks,
		})
	}

	mutating, err := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	c.results.MutatingWebhooks = make([]inventory.WebhookInfo, 0, len(mutating.Items))
	for _, mwc := range mutating.Items {
		webhooks := make([]inventory.WebhookConfig, 0, len(mwc.Webhooks))
		for _, wh := range mwc.Webhooks {
			var clientConfig string
			if wh.ClientConfig.Service != nil {
				clientConfig = fmt.Sprintf("%s/%s:%d", wh.ClientConfig.Service.Namespace, wh.ClientConfig.Service.Name, *wh.ClientConfig.Service.Port)
			} else if wh.ClientConfig.URL != nil {
				clientConfig = *wh.ClientConfig.URL
			}

			rules := make([]string, 0, len(wh.Rules))
			for _, r := range wh.Rules {
				ruleStr, _ := json.Marshal(r)
				rules = append(rules, string(ruleStr))
			}

			var failurePolicy string
			if wh.FailurePolicy != nil {
				failurePolicy = string(*wh.FailurePolicy)
			}

			var matchPolicy string
			if wh.MatchPolicy != nil {
				matchPolicy = string(*wh.MatchPolicy)
			}

			var sideEffects string
			if wh.SideEffects != nil {
				sideEffects = string(*wh.SideEffects)
			}

			var nsSelector string
			if wh.NamespaceSelector != nil {
				sel, _ := json.Marshal(wh.NamespaceSelector)
				nsSelector = string(sel)
			}

			webhooks = append(webhooks, inventory.WebhookConfig{
				Name:                    wh.Name,
				ClientConfig:            clientConfig,
				Rules:                   rules,
				FailurePolicy:           failurePolicy,
				MatchPolicy:             matchPolicy,
				SideEffects:             sideEffects,
				TimeoutSeconds:          wh.TimeoutSeconds,
				AdmissionReviewVersions: wh.AdmissionReviewVersions,
				NamespaceSelector:       nsSelector,
			})
		}

		c.results.MutatingWebhooks = append(c.results.MutatingWebhooks, inventory.WebhookInfo{
			Name:     mwc.Name,
			Webhooks: webhooks,
		})
	}

	return nil
}

func (c *WebhookCollector) Results() interface{} {
	return c.results
}
