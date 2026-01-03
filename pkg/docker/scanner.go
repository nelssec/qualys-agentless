package docker

import (
	"context"
	"time"
)

type Scanner struct {
	client *Client
}

func NewScanner(opts ...ClientOption) (*Scanner, error) {
	client, err := NewClient(opts...)
	if err != nil {
		return nil, err
	}
	return &Scanner{client: client}, nil
}

func (s *Scanner) Scan(ctx context.Context) (*ScanResult, error) {
	inv, err := s.CollectInventory(ctx)
	if err != nil {
		return nil, err
	}

	checker := NewChecker(inv)
	findings := checker.RunAllChecks()

	summary := Summary{
		TotalContainers: len(inv.Containers),
		TotalImages:     len(inv.Images),
		TotalFindings:   len(findings),
		BySeverity:      make(map[string]int),
		ByCategory:      make(map[string]int),
	}

	for _, c := range inv.Containers {
		if c.State == "running" {
			summary.RunningContainers++
		}
	}

	for _, f := range findings {
		summary.BySeverity[f.Severity]++
		summary.ByCategory[f.Category]++
	}

	return &ScanResult{
		Inventory: inv,
		Findings:  findings,
		Summary:   summary,
		ScanTime:  time.Now().UTC(),
	}, nil
}

func (s *Scanner) CollectInventory(ctx context.Context) (*Inventory, error) {
	if err := s.client.Ping(ctx); err != nil {
		return nil, err
	}

	hostInfo, err := s.client.Info(ctx)
	if err != nil {
		return nil, err
	}

	images, err := s.client.ListImages(ctx)
	if err != nil {
		return nil, err
	}

	containers, err := s.client.ListContainers(ctx, true)
	if err != nil {
		return nil, err
	}

	imageUsage := make(map[string][]string)
	for _, c := range containers {
		imageUsage[c.ImageID] = append(imageUsage[c.ImageID], c.Name)
	}
	for i := range images {
		if users, ok := imageUsage[images[i].ID]; ok {
			images[i].UsedBy = users
		}
	}

	networks, err := s.client.ListNetworks(ctx)
	if err != nil {
		return nil, err
	}

	volumes, err := s.client.ListVolumes(ctx)
	if err != nil {
		return nil, err
	}

	volumeUsage := make(map[string][]string)
	for _, c := range containers {
		for _, m := range c.Mounts {
			if m.Type == "volume" {
				volumeUsage[m.Source] = append(volumeUsage[m.Source], c.Name)
			}
		}
	}
	for i := range volumes {
		if users, ok := volumeUsage[volumes[i].Name]; ok {
			volumes[i].UsedBy = users
		}
	}

	return &Inventory{
		Host:        *hostInfo,
		Images:      images,
		Containers:  containers,
		Networks:    networks,
		Volumes:     volumes,
		CollectedAt: time.Now().UTC(),
	}, nil
}
