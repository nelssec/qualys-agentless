package qualys

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/nelssec/qualys-agentless/pkg/compliance"
)

type FindingsSubmission struct {
	ClusterID       string          `json:"clusterId"`
	ScanTime        time.Time       `json:"scanTime"`
	Framework       string          `json:"framework"`
	TotalControls   int             `json:"totalControls"`
	PassedControls  int             `json:"passedControls"`
	FailedControls  int             `json:"failedControls"`
	ComplianceScore float64         `json:"complianceScore"`
	Findings        []FindingRecord `json:"findings"`
}

type FindingRecord struct {
	ControlID    string                 `json:"controlId"`
	ControlName  string                 `json:"controlName"`
	QID          int                    `json:"qid,omitempty"`
	Severity     string                 `json:"severity"`
	Status       string                 `json:"status"`
	ResourceKind string                 `json:"resourceKind"`
	ResourceName string                 `json:"resourceName"`
	Namespace    string                 `json:"namespace,omitempty"`
	Message      string                 `json:"message"`
	Remediation  string                 `json:"remediation,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
	Details      map[string]interface{} `json:"details,omitempty"`
}

func (c *Client) SubmitFindings(ctx context.Context, submission *FindingsSubmission) error {
	return c.request(ctx, http.MethodPost, fmt.Sprintf("/clusters/%s/posture/findings", submission.ClusterID), submission, nil)
}

func ConvertFindings(clusterID string, result *compliance.ScanResult, qidMapping map[string]int) *FindingsSubmission {
	submission := &FindingsSubmission{
		ClusterID:       clusterID,
		ScanTime:        result.ScanTime,
		TotalControls:   result.TotalChecks,
		PassedControls:  result.PassedChecks,
		FailedControls:  result.FailedChecks,
		ComplianceScore: result.Summary.ComplianceScore,
		Findings:        make([]FindingRecord, 0, len(result.Findings)),
	}

	if len(result.Frameworks) > 0 {
		submission.Framework = result.Frameworks[0]
	}

	for _, f := range result.Findings {
		record := FindingRecord{
			ControlID:    f.ControlID,
			ControlName:  f.ControlName,
			Severity:     string(f.Severity),
			Status:       string(f.Status),
			ResourceKind: f.Resource.Kind,
			ResourceName: f.Resource.Name,
			Namespace:    f.Resource.Namespace,
			Message:      f.Message,
			Remediation:  f.Remediation,
			Timestamp:    f.Timestamp,
			Details:      f.Metadata,
		}

		if qid, ok := qidMapping[f.ControlID]; ok {
			record.QID = qid
		}

		submission.Findings = append(submission.Findings, record)
	}

	return submission
}

var QIDMappings = map[string]int{}

func (c *Client) GetPostureReport(ctx context.Context, clusterID string) (*PostureReport, error) {
	var report PostureReport
	if err := c.request(ctx, http.MethodGet, fmt.Sprintf("/clusters/%s/posture", clusterID), nil, &report); err != nil {
		return nil, err
	}
	return &report, nil
}

type PostureReport struct {
	ClusterID       string         `json:"clusterId"`
	ClusterName     string         `json:"clusterName"`
	LastScanTime    time.Time      `json:"lastScanTime"`
	ComplianceScore float64        `json:"complianceScore"`
	TotalControls   int            `json:"totalControls"`
	PassedControls  int            `json:"passedControls"`
	FailedControls  int            `json:"failedControls"`
	BySeverity      map[string]int `json:"bySeverity"`
	ByFramework     map[string]int `json:"byFramework"`
}
