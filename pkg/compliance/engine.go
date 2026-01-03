package compliance

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
	"github.com/open-policy-agent/opa/rego"
)

type Engine struct {
	frameworks map[string]*Framework
	controls   map[string]*Control
	policies   map[string]*rego.PreparedEvalQuery
}

type Framework struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	ControlIDs  []string `json:"controlIds"`
}

type Control struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Description   string            `json:"description"`
	Severity      Severity          `json:"severity"`
	Framework     string            `json:"framework"`
	Section       string            `json:"section"`
	Remediation   string            `json:"remediation"`
	References    []string          `json:"references,omitempty"`
	QualysMapping *QualysMapping    `json:"qualysMapping,omitempty"`
	Tags          map[string]string `json:"tags,omitempty"`
	RegoPolicy    string            `json:"-"` // The Rego policy code
}

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

type QualysMapping struct {
	QID         int    `json:"qid"`
	Title       string `json:"title"`
	Category    string `json:"category"`
	SubCategory string `json:"subCategory"`
}

type Finding struct {
	ControlID   string                 `json:"controlId"`
	ControlName string                 `json:"controlName"`
	Framework   string                 `json:"framework"`
	Severity    Severity               `json:"severity"`
	Status      FindingStatus          `json:"status"`
	Resource    ResourceRef            `json:"resource"`
	Message     string                 `json:"message"`
	Remediation string                 `json:"remediation,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type FindingStatus string

const (
	StatusPass    FindingStatus = "PASS"
	StatusFail    FindingStatus = "FAIL"
	StatusWarning FindingStatus = "WARNING"
	StatusSkipped FindingStatus = "SKIPPED"
	StatusError   FindingStatus = "ERROR"
)

type ResourceRef struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	APIGroup  string `json:"apiGroup,omitempty"`
}

type ScanResult struct {
	ClusterName  string    `json:"clusterName"`
	ScanTime     time.Time `json:"scanTime"`
	Frameworks   []string  `json:"frameworks"`
	TotalChecks  int       `json:"totalChecks"`
	PassedChecks int       `json:"passedChecks"`
	FailedChecks int       `json:"failedChecks"`
	Findings     []Finding `json:"findings"`
	Summary      Summary   `json:"summary"`
}

type Summary struct {
	BySeverity  map[Severity]int `json:"bySeverity"`
	ByFramework map[string]int   `json:"byFramework"`
	ByStatus    map[FindingStatus]int `json:"byStatus"`
	ComplianceScore float64       `json:"complianceScore"`
}

func NewEngine() *Engine {
	return &Engine{
		frameworks: make(map[string]*Framework),
		controls:   make(map[string]*Control),
		policies:   make(map[string]*rego.PreparedEvalQuery),
	}
}

func (e *Engine) LoadEmbeddedPolicies(fsys embed.FS, root string) error {
	return fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		ext := filepath.Ext(path)
		if ext == ".rego" {
			content, err := fs.ReadFile(fsys, path)
			if err != nil {
				return fmt.Errorf("failed to read %s: %w", path, err)
			}
			return e.loadRegoPolicy(path, string(content))
		} else if ext == ".json" && strings.Contains(path, "framework") {
			content, err := fs.ReadFile(fsys, path)
			if err != nil {
				return fmt.Errorf("failed to read %s: %w", path, err)
			}
			return e.loadFramework(content)
		}

		return nil
	})
}

func (e *Engine) LoadPoliciesFromDir(dir string) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if filepath.Ext(path) != ".rego" {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

		return e.loadRegoPolicy(path, string(content))
	})
}

func (e *Engine) loadRegoPolicy(path, content string) error {
	controlID := extractControlID(content)
	if controlID == "" {
		return nil
	}

	packageName := extractPackageName(content)
	if packageName == "" {
		return nil
	}

	queryStr := fmt.Sprintf("data.%s.deny", packageName)

	ctx := context.Background()
	query, err := rego.New(
		rego.Query(queryStr),
		rego.Module(path, content),
	).PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("failed to prepare policy %s: %w", path, err)
	}

	e.policies[controlID] = &query
	return nil
}

func extractPackageName(content string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package ") {
			return strings.TrimPrefix(line, "package ")
		}
	}
	return ""
}

func (e *Engine) loadFramework(content []byte) error {
	var fw Framework
	if err := json.Unmarshal(content, &fw); err != nil {
		return err
	}
	e.frameworks[fw.ID] = &fw
	return nil
}

func (e *Engine) RegisterControl(ctrl *Control) {
	e.controls[ctrl.ID] = ctrl
}

func (e *Engine) RegisterFramework(fw *Framework) {
	e.frameworks[fw.ID] = fw
}

func (e *Engine) PolicyCount() int {
	return len(e.policies)
}

func (e *Engine) HasPolicy(controlID string) bool {
	_, ok := e.policies[controlID]
	return ok
}

func (e *Engine) Evaluate(ctx context.Context, inv *inventory.ClusterInventory, frameworks []string) (*ScanResult, error) {
	result := &ScanResult{
		ClusterName: inv.Cluster.Name,
		ScanTime:    time.Now().UTC(),
		Frameworks:  frameworks,
		Findings:    make([]Finding, 0),
		Summary: Summary{
			BySeverity:  make(map[Severity]int),
			ByFramework: make(map[string]int),
			ByStatus:    make(map[FindingStatus]int),
		},
	}

	input, err := e.buildOPAInput(inv)
	if err != nil {
		return nil, fmt.Errorf("failed to build OPA input: %w", err)
	}

	for controlID, query := range e.policies {
		ctrl, ok := e.controls[controlID]
		if !ok {
			continue
		}

		if !e.isControlInFrameworks(ctrl, frameworks) {
			continue
		}

		result.TotalChecks++

		findings, err := e.evaluateControl(ctx, query, ctrl, input)
		if err != nil {
			fmt.Printf("Warning: failed to evaluate control %s: %v\n", controlID, err)
			result.Summary.ByStatus[StatusError]++
			continue
		}

		for _, f := range findings {
			result.Findings = append(result.Findings, f)
			result.Summary.BySeverity[f.Severity]++
			result.Summary.ByFramework[f.Framework]++
			result.Summary.ByStatus[f.Status]++

			if f.Status == StatusPass {
				result.PassedChecks++
			} else if f.Status == StatusFail {
				result.FailedChecks++
			}
		}
	}

	if result.TotalChecks > 0 {
		result.Summary.ComplianceScore = float64(result.PassedChecks) / float64(result.TotalChecks) * 100
	}

	return result, nil
}

func (e *Engine) evaluateControl(ctx context.Context, query *rego.PreparedEvalQuery, ctrl *Control, input map[string]interface{}) ([]Finding, error) {
	results, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, err
	}

	findings := make([]Finding, 0)

	if len(results) == 0 || len(results[0].Expressions) == 0 {
		findings = append(findings, Finding{
			ControlID:   ctrl.ID,
			ControlName: ctrl.Name,
			Framework:   ctrl.Framework,
			Severity:    ctrl.Severity,
			Status:      StatusPass,
			Message:     "Control passed",
			Timestamp:   time.Now().UTC(),
		})
		return findings, nil
	}

	violations, ok := results[0].Expressions[0].Value.([]interface{})
	if !ok {
		return findings, nil
	}

	for _, v := range violations {
		violation, ok := v.(map[string]interface{})
		if !ok {
			continue
		}

		finding := Finding{
			ControlID:   ctrl.ID,
			ControlName: ctrl.Name,
			Framework:   ctrl.Framework,
			Severity:    ctrl.Severity,
			Status:      StatusFail,
			Remediation: ctrl.Remediation,
			Timestamp:   time.Now().UTC(),
			Metadata:    violation,
		}

		if msg, ok := violation["message"].(string); ok {
			finding.Message = msg
		} else {
			finding.Message = fmt.Sprintf("Violation of control %s", ctrl.ID)
		}

		if resource, ok := violation["resource"].(map[string]interface{}); ok {
			finding.Resource = ResourceRef{
				Kind:      getString(resource, "kind"),
				Name:      getString(resource, "name"),
				Namespace: getString(resource, "namespace"),
			}
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

func (e *Engine) buildOPAInput(inv *inventory.ClusterInventory) (map[string]interface{}, error) {
	data, err := json.Marshal(inv)
	if err != nil {
		return nil, err
	}

	var input map[string]interface{}
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, err
	}

	return input, nil
}

func (e *Engine) isControlInFrameworks(ctrl *Control, frameworks []string) bool {
	if len(frameworks) == 0 {
		return true // No filter, include all
	}

	for _, fwID := range frameworks {
		if strings.EqualFold(ctrl.Framework, fwID) {
			return true
		}

		if fw, ok := e.frameworks[fwID]; ok {
			for _, cid := range fw.ControlIDs {
				if cid == ctrl.ID {
					return true
				}
			}
		}
	}

	return false
}

func (e *Engine) ListFrameworks() []*Framework {
	fws := make([]*Framework, 0, len(e.frameworks))
	for _, fw := range e.frameworks {
		fws = append(fws, fw)
	}
	return fws
}

func (e *Engine) ListControls(framework string) []*Control {
	ctrls := make([]*Control, 0, len(e.controls))
	for _, ctrl := range e.controls {
		if framework == "" || strings.EqualFold(ctrl.Framework, framework) {
			ctrls = append(ctrls, ctrl)
		}
	}
	return ctrls
}


func extractControlID(content string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# control_id:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "# control_id:"))
		}
		if strings.HasPrefix(line, "package ") && strings.Contains(line, "controls") {
			parts := strings.Split(line, ".")
			if len(parts) > 2 {
				return strings.ReplaceAll(parts[len(parts)-1], "_", ".")
			}
		}
	}
	return ""
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
