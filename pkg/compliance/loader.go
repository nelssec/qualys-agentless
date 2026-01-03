package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/rego"
)

type ControlSource string

const (
	SourceEmbedded ControlSource = "embedded"

	SourceLocal ControlSource = "local"

	SourceKubescape ControlSource = "kubescape"
)

type ControlLoader struct {
	source      ControlSource
	localPath   string
	kubescapeURL string
	httpClient  *http.Client
}

type ControlLoaderOption func(*ControlLoader)

func NewControlLoader(source ControlSource, opts ...ControlLoaderOption) *ControlLoader {
	loader := &ControlLoader{
		source:      source,
		httpClient:  http.DefaultClient,
		kubescapeURL: "https://raw.githubusercontent.com/kubescape/regolibrary/master",
	}

	for _, opt := range opts {
		opt(loader)
	}

	return loader
}

func WithLocalPath(path string) ControlLoaderOption {
	return func(l *ControlLoader) {
		l.localPath = path
	}
}

func WithKubescapeURL(url string) ControlLoaderOption {
	return func(l *ControlLoader) {
		l.kubescapeURL = url
	}
}

func (l *ControlLoader) LoadControls(ctx context.Context, engine *Engine, frameworks []string) error {
	switch l.source {
	case SourceEmbedded:
		return l.loadEmbeddedControls(engine, frameworks)
	case SourceLocal:
		return l.loadLocalControls(engine, frameworks)
	case SourceKubescape:
		return l.loadKubescapeControls(ctx, engine, frameworks)
	default:
		return fmt.Errorf("unknown control source: %s", l.source)
	}
}

func (l *ControlLoader) loadEmbeddedControls(engine *Engine, frameworks []string) error {
	engine.RegisterDefaultControls()
	return nil
}

func (l *ControlLoader) loadLocalControls(engine *Engine, frameworks []string) error {
	if l.localPath == "" {
		return fmt.Errorf("local path not specified")
	}

	return filepath.WalkDir(l.localPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		ext := filepath.Ext(path)
		if ext != ".rego" {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

		ctrl, query, err := parseRegoControl(path, string(content))
		if err != nil {
			fmt.Printf("Warning: failed to parse %s: %v\n", path, err)
			return nil
		}

		if ctrl != nil {
			engine.RegisterControl(ctrl)
			engine.policies[ctrl.ID] = query
		}

		return nil
	})
}

func (l *ControlLoader) loadKubescapeControls(ctx context.Context, engine *Engine, frameworks []string) error {
	for _, fw := range frameworks {
		frameworkURL := fmt.Sprintf("%s/frameworks/%s.json", l.kubescapeURL, fw)

		resp, err := l.httpClient.Get(frameworkURL)
		if err != nil {
			fmt.Printf("Warning: failed to fetch framework %s: %v\n", fw, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			fmt.Printf("Warning: framework %s not found (status %d)\n", fw, resp.StatusCode)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		var kubescapeFW KubescapeFramework
		if err := json.Unmarshal(body, &kubescapeFW); err != nil {
			fmt.Printf("Warning: failed to parse framework %s: %v\n", fw, err)
			continue
		}

		engine.RegisterFramework(&Framework{
			ID:          kubescapeFW.Name,
			Name:        kubescapeFW.Name,
			Description: kubescapeFW.Description,
			ControlIDs:  kubescapeFW.ControlIDs,
		})

		for _, controlID := range kubescapeFW.ControlIDs {
			if err := l.fetchKubescapeControl(ctx, engine, controlID); err != nil {
				fmt.Printf("Warning: failed to fetch control %s: %v\n", controlID, err)
			}
		}
	}

	return nil
}

type KubescapeFramework struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	ControlIDs  []string `json:"controlIDs"`
}

type KubescapeControl struct {
	ControlID   string   `json:"controlID"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	Rules       []string `json:"rules"`
	Severity    string   `json:"baseScore,omitempty"`
}

func (l *ControlLoader) fetchKubescapeControl(ctx context.Context, engine *Engine, controlID string) error {
	controlURL := fmt.Sprintf("%s/controls/%s.json", l.kubescapeURL, controlID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, controlURL, nil)
	if err != nil {
		return err
	}

	resp, err := l.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("control not found (status %d)", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var ksControl KubescapeControl
	if err := json.Unmarshal(body, &ksControl); err != nil {
		return err
	}

	severity := SeverityMedium
	switch strings.ToLower(ksControl.Severity) {
	case "critical":
		severity = SeverityCritical
	case "high":
		severity = SeverityHigh
	case "low":
		severity = SeverityLow
	}

	ctrl := &Control{
		ID:          ksControl.ControlID,
		Name:        ksControl.Name,
		Description: ksControl.Description,
		Remediation: ksControl.Remediation,
		Severity:    severity,
	}

	engine.RegisterControl(ctrl)

	for _, ruleID := range ksControl.Rules {
		ruleURL := fmt.Sprintf("%s/rules/%s/raw.rego", l.kubescapeURL, ruleID)
		ruleResp, err := l.httpClient.Get(ruleURL)
		if err != nil {
			continue
		}
		defer ruleResp.Body.Close()

		if ruleResp.StatusCode != http.StatusOK {
			continue
		}

		ruleBody, err := io.ReadAll(ruleResp.Body)
		if err != nil {
			continue
		}

		query, err := rego.New(
			rego.Query("data.armo_builtins.deny"),
			rego.Module(ruleID+".rego", string(ruleBody)),
		).PrepareForEval(ctx)
		if err != nil {
			fmt.Printf("Warning: failed to compile rule %s: %v\n", ruleID, err)
			continue
		}

		engine.policies[ctrl.ID] = &query
	}

	return nil
}

func parseRegoControl(path, content string) (*Control, *rego.PreparedEvalQuery, error) {
	controlID := ""
	name := ""
	description := ""
	severity := SeverityMedium
	framework := ""

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "# control_id:") {
			controlID = strings.TrimSpace(strings.TrimPrefix(line, "# control_id:"))
		} else if strings.HasPrefix(line, "# name:") {
			name = strings.TrimSpace(strings.TrimPrefix(line, "# name:"))
		} else if strings.HasPrefix(line, "# description:") {
			description = strings.TrimSpace(strings.TrimPrefix(line, "# description:"))
		} else if strings.HasPrefix(line, "# severity:") {
			sevStr := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(line, "# severity:")))
			severity = Severity(sevStr)
		} else if strings.HasPrefix(line, "# framework:") {
			framework = strings.TrimSpace(strings.TrimPrefix(line, "# framework:"))
		}
	}

	if controlID == "" {
		return nil, nil, fmt.Errorf("no control_id found in %s", path)
	}

	query := "data.qualys.controls.deny"
	if strings.Contains(content, "package armo_builtins") {
		query = "data.armo_builtins.deny"
	}

	preparedQuery, err := rego.New(
		rego.Query(query),
		rego.Module(path, content),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, nil, err
	}

	ctrl := &Control{
		ID:          controlID,
		Name:        name,
		Description: description,
		Severity:    severity,
		Framework:   framework,
	}

	return ctrl, &preparedQuery, nil
}
