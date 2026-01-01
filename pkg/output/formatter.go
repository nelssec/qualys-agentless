package output

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/nelssec/qualys-agentless/pkg/compliance"
)

type Formatter interface {
	Format([]*compliance.ScanResult) ([]byte, error)
}

type JSONFormatter struct{}

func NewJSONFormatter() *JSONFormatter {
	return &JSONFormatter{}
}

func (f *JSONFormatter) Format(results []*compliance.ScanResult) ([]byte, error) {
	return json.MarshalIndent(results, "", "  ")
}

type ConsoleFormatter struct{}

func NewConsoleFormatter() *ConsoleFormatter {
	return &ConsoleFormatter{}
}

func (f *ConsoleFormatter) Format(results []*compliance.ScanResult) ([]byte, error) {
	var buf bytes.Buffer

	for _, result := range results {
		buf.WriteString(fmt.Sprintf("\n=== Scan Results: %s ===\n", result.ClusterName))
		buf.WriteString(fmt.Sprintf("Scan Time: %s\n", result.ScanTime.Format("2006-01-02 15:04:05 UTC")))
		buf.WriteString(fmt.Sprintf("Frameworks: %s\n", strings.Join(result.Frameworks, ", ")))
		buf.WriteString(fmt.Sprintf("\nCompliance Score: %.1f%%\n", result.Summary.ComplianceScore))
		buf.WriteString(fmt.Sprintf("Total Checks: %d | Passed: %d | Failed: %d\n\n",
			result.TotalChecks, result.PassedChecks, result.FailedChecks))

		if len(result.Summary.BySeverity) > 0 {
			buf.WriteString("By Severity:\n")
			for sev, count := range result.Summary.BySeverity {
				buf.WriteString(fmt.Sprintf("  %s: %d\n", sev, count))
			}
			buf.WriteString("\n")
		}

		failedFindings := make([]compliance.Finding, 0)
		for _, finding := range result.Findings {
			if finding.Status == compliance.StatusFail {
				failedFindings = append(failedFindings, finding)
			}
		}

		if len(failedFindings) > 0 {
			buf.WriteString("Failed Controls:\n")
			buf.WriteString(strings.Repeat("-", 80) + "\n")

			for _, finding := range failedFindings {
				buf.WriteString(fmt.Sprintf("[%s] %s\n", finding.Severity, finding.ControlID))
				buf.WriteString(fmt.Sprintf("  %s\n", finding.ControlName))
				if finding.Resource.Name != "" {
					ns := finding.Resource.Namespace
					if ns == "" {
						ns = "cluster-scoped"
					}
					buf.WriteString(fmt.Sprintf("  Resource: %s/%s (%s)\n",
						finding.Resource.Kind, finding.Resource.Name, ns))
				}
				buf.WriteString(fmt.Sprintf("  Message: %s\n", finding.Message))
				if finding.Remediation != "" {
					buf.WriteString(fmt.Sprintf("  Remediation: %s\n", finding.Remediation))
				}
				buf.WriteString("\n")
			}
		}
	}

	return buf.Bytes(), nil
}

type SARIFFormatter struct{}

func NewSARIFFormatter() *SARIFFormatter {
	return &SARIFFormatter{}
}

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifMessage   `json:"shortDescription"`
	FullDescription  sarifMessage   `json:"fullDescription,omitempty"`
	DefaultConfig    sarifConfig    `json:"defaultConfiguration"`
	HelpURI          string         `json:"helpUri,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   sarifMessage     `json:"message"`
	Locations []sarifLocation  `json:"locations,omitempty"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

func (f *SARIFFormatter) Format(results []*compliance.ScanResult) ([]byte, error) {
	report := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs:    make([]sarifRun, 0),
	}

	for _, result := range results {
		rules := make(map[string]sarifRule)
		sarifResults := make([]sarifResult, 0)

		for _, finding := range result.Findings {
			if finding.Status != compliance.StatusFail {
				continue
			}

			if _, exists := rules[finding.ControlID]; !exists {
				rules[finding.ControlID] = sarifRule{
					ID:               finding.ControlID,
					Name:             finding.ControlName,
					ShortDescription: sarifMessage{Text: finding.ControlName},
					DefaultConfig:    sarifConfig{Level: severityToSARIF(finding.Severity)},
				}
			}

			sr := sarifResult{
				RuleID:  finding.ControlID,
				Level:   severityToSARIF(finding.Severity),
				Message: sarifMessage{Text: finding.Message},
			}

			if finding.Resource.Name != "" {
				sr.Locations = []sarifLocation{{
					LogicalLocations: []sarifLogicalLocation{{
						Name:               finding.Resource.Name,
						FullyQualifiedName: fmt.Sprintf("%s/%s/%s", finding.Resource.Namespace, finding.Resource.Kind, finding.Resource.Name),
						Kind:               finding.Resource.Kind,
					}},
				}}
			}

			sarifResults = append(sarifResults, sr)
		}

		rulesList := make([]sarifRule, 0, len(rules))
		for _, r := range rules {
			rulesList = append(rulesList, r)
		}

		run := sarifRun{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "qualys-k8s",
					Version:        "0.1.0",
					InformationURI: "https://www.qualys.com/apps/container-security/",
					Rules:          rulesList,
				},
			},
			Results: sarifResults,
		}

		report.Runs = append(report.Runs, run)
	}

	return json.MarshalIndent(report, "", "  ")
}

func severityToSARIF(s compliance.Severity) string {
	switch s {
	case compliance.SeverityCritical, compliance.SeverityHigh:
		return "error"
	case compliance.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

type JUnitFormatter struct{}

func NewJUnitFormatter() *JUnitFormatter {
	return &JUnitFormatter{}
}

type junitTestSuites struct {
	XMLName    string           `xml:"testsuites"`
	Tests      int              `xml:"tests,attr"`
	Failures   int              `xml:"failures,attr"`
	Time       float64          `xml:"time,attr"`
	TestSuites []junitTestSuite `xml:"testsuite"`
}

type junitTestSuite struct {
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Errors    int             `xml:"errors,attr"`
	Time      float64         `xml:"time,attr"`
	TestCases []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      float64       `xml:"time,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

func (f *JUnitFormatter) Format(results []*compliance.ScanResult) ([]byte, error) {
	suites := junitTestSuites{
		TestSuites: make([]junitTestSuite, 0),
	}

	for _, result := range results {
		suite := junitTestSuite{
			Name:      result.ClusterName,
			Tests:     result.TotalChecks,
			Failures:  result.FailedChecks,
			Errors:    0,
			Time:      0,
			TestCases: make([]junitTestCase, 0),
		}

		for _, finding := range result.Findings {
			tc := junitTestCase{
				Name:      finding.ControlID + ": " + finding.ControlName,
				ClassName: finding.Framework,
				Time:      0,
			}

			if finding.Status == compliance.StatusFail {
				resource := ""
				if finding.Resource.Name != "" {
					resource = fmt.Sprintf("%s/%s in %s", finding.Resource.Kind, finding.Resource.Name, finding.Resource.Namespace)
				}
				tc.Failure = &junitFailure{
					Message: finding.Message,
					Type:    string(finding.Severity),
					Content: fmt.Sprintf("Resource: %s\nRemediation: %s", resource, finding.Remediation),
				}
			}

			suite.TestCases = append(suite.TestCases, tc)
		}

		suites.Tests += suite.Tests
		suites.Failures += suite.Failures
		suites.TestSuites = append(suites.TestSuites, suite)
	}

	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")

	encoder := xml.NewEncoder(&buf)
	encoder.Indent("", "  ")
	if err := encoder.Encode(suites); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
