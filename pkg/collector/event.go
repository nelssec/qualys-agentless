package collector

import (
	"context"
	"fmt"
	"time"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type EventCollector struct {
	maxAge  time.Duration
	results []inventory.EventInfo
}

func NewEventCollector(maxAge time.Duration) *EventCollector {
	if maxAge == 0 {
		maxAge = 1 * time.Hour
	}
	return &EventCollector{maxAge: maxAge}
}

func (c *EventCollector) Name() string {
	return "event"
}

func (c *EventCollector) Collect(ctx context.Context, clientset *kubernetes.Clientset) error {
	events, err := clientset.CoreV1().Events("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	cutoff := time.Now().Add(-c.maxAge)
	c.results = make([]inventory.EventInfo, 0)

	for _, event := range events.Items {
		lastTime := event.LastTimestamp.Time
		if lastTime.IsZero() {
			lastTime = event.EventTime.Time
		}
		if lastTime.Before(cutoff) {
			continue
		}

		firstTime := event.FirstTimestamp.Time
		if firstTime.IsZero() {
			firstTime = event.EventTime.Time
		}

		involvedObj := fmt.Sprintf("%s/%s", event.InvolvedObject.Kind, event.InvolvedObject.Name)
		if event.InvolvedObject.Namespace != "" {
			involvedObj = fmt.Sprintf("%s/%s/%s", event.InvolvedObject.Kind, event.InvolvedObject.Namespace, event.InvolvedObject.Name)
		}

		c.results = append(c.results, inventory.EventInfo{
			Name:           event.Name,
			Namespace:      event.Namespace,
			Type:           event.Type,
			Reason:         event.Reason,
			Message:        event.Message,
			Count:          event.Count,
			FirstTimestamp: firstTime,
			LastTimestamp:  lastTime,
			Source:         event.Source.Component,
			InvolvedObject: involvedObj,
		})
	}

	return nil
}

func (c *EventCollector) Results() interface{} {
	return c.results
}
