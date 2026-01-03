package analyzers

import (
	"fmt"
	"strings"

	"github.com/nelssec/qualys-agentless/pkg/graph"
	"github.com/nelssec/qualys-agentless/pkg/inventory"
)

type CloudMetadataAnalyzer struct {
	g        *graph.SecurityGraph
	inv      *inventory.ClusterInventory
	provider string
}

type CloudMetadataRisk struct {
	ID                string   `json:"id"`
	PodName           string   `json:"podName"`
	PodNamespace      string   `json:"podNamespace"`
	CanAccessIMDS     bool     `json:"canAccessImds"`
	IMDSVersion       string   `json:"imdsVersion"`
	HasCloudCreds     bool     `json:"hasCloudCredentials"`
	CloudCredVars     []string `json:"cloudCredentialVars,omitempty"`
	RiskLevel         string   `json:"riskLevel"`
	Provider          string   `json:"provider"`
	PotentialImpact   []string `json:"potentialImpact"`
	Recommendations   []string `json:"recommendations"`
}

func NewCloudMetadataAnalyzer(g *graph.SecurityGraph, inv *inventory.ClusterInventory) *CloudMetadataAnalyzer {
	return &CloudMetadataAnalyzer{
		g:        g,
		inv:      inv,
		provider: inv.Cluster.Provider,
	}
}

func (a *CloudMetadataAnalyzer) Analyze() []CloudMetadataRisk {
	var risks []CloudMetadataRisk

	for _, pod := range a.inv.Workloads.Pods {
		risk := a.analyzePod(pod)
		if risk != nil {
			risks = append(risks, *risk)
		}
	}

	return risks
}

func (a *CloudMetadataAnalyzer) analyzePod(pod inventory.PodInfo) *CloudMetadataRisk {
	canAccessIMDS := a.canAccessIMDS(pod)
	cloudCreds := a.findCloudCredentials(pod)

	if !canAccessIMDS && len(cloudCreds) == 0 {
		return nil
	}

	riskLevel := "LOW"
	if canAccessIMDS && len(cloudCreds) > 0 {
		riskLevel = "CRITICAL"
	} else if canAccessIMDS {
		riskLevel = "HIGH"
	} else if len(cloudCreds) > 0 {
		riskLevel = "MEDIUM"
	}

	impact := a.assessImpact(canAccessIMDS, cloudCreds)
	recommendations := a.getRecommendations(canAccessIMDS, cloudCreds)

	imdsVersion := "unknown"
	if a.provider == "aws" {
		imdsVersion = "v1 (vulnerable)"
	}

	return &CloudMetadataRisk{
		ID:              fmt.Sprintf("cloudmeta/%s/%s", pod.Namespace, pod.Name),
		PodName:         pod.Name,
		PodNamespace:    pod.Namespace,
		CanAccessIMDS:   canAccessIMDS,
		IMDSVersion:     imdsVersion,
		HasCloudCreds:   len(cloudCreds) > 0,
		CloudCredVars:   cloudCreds,
		RiskLevel:       riskLevel,
		Provider:        a.provider,
		PotentialImpact: impact,
		Recommendations: recommendations,
	}
}

func (a *CloudMetadataAnalyzer) canAccessIMDS(pod inventory.PodInfo) bool {
	if pod.HostNetwork {
		return true
	}

	hasEgressPolicy := false
	for _, np := range a.inv.NetworkPolicies {
		if np.Namespace != pod.Namespace {
			continue
		}

		if matchesPodSelector(pod.Labels, np.PodSelector) {
			for _, policyType := range np.PolicyTypes {
				if policyType == "Egress" {
					hasEgressPolicy = true
					break
				}
			}
		}
	}

	return !hasEgressPolicy
}

func (a *CloudMetadataAnalyzer) findCloudCredentials(pod inventory.PodInfo) []string {
	var creds []string

	awsVars := []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"AWS_SECURITY_TOKEN",
		"AWS_DEFAULT_REGION",
		"AWS_ROLE_ARN",
		"AWS_WEB_IDENTITY_TOKEN_FILE",
	}

	azureVars := []string{
		"AZURE_CLIENT_ID",
		"AZURE_CLIENT_SECRET",
		"AZURE_TENANT_ID",
		"AZURE_SUBSCRIPTION_ID",
		"ARM_CLIENT_ID",
		"ARM_CLIENT_SECRET",
		"ARM_TENANT_ID",
		"ARM_SUBSCRIPTION_ID",
		"MSI_ENDPOINT",
		"MSI_SECRET",
	}

	gcpVars := []string{
		"GOOGLE_APPLICATION_CREDENTIALS",
		"GOOGLE_CLOUD_PROJECT",
		"GCLOUD_PROJECT",
		"GCP_PROJECT",
		"CLOUDSDK_CORE_PROJECT",
		"GOOGLE_CREDENTIALS",
	}

	allVars := append(awsVars, azureVars...)
	allVars = append(allVars, gcpVars...)

	for _, container := range pod.Containers {
		for _, mount := range container.VolumeMounts {
			mountLower := strings.ToLower(mount.MountPath)
			if strings.Contains(mountLower, "credentials") ||
				strings.Contains(mountLower, ".aws") ||
				strings.Contains(mountLower, ".azure") ||
				strings.Contains(mountLower, ".gcloud") ||
				strings.Contains(mountLower, ".config/gcloud") {
				creds = append(creds, fmt.Sprintf("mount:%s", mount.MountPath))
			}
		}
	}

	for _, vol := range pod.Volumes {
		if vol.Type == "Secret" {
			secretLower := strings.ToLower(vol.Source)
			if strings.Contains(secretLower, "aws") ||
				strings.Contains(secretLower, "azure") ||
				strings.Contains(secretLower, "gcp") ||
				strings.Contains(secretLower, "google") ||
				strings.Contains(secretLower, "cloud") {
				creds = append(creds, fmt.Sprintf("secret:%s", vol.Source))
			}
		}
	}

	_ = allVars

	return creds
}

func (a *CloudMetadataAnalyzer) assessImpact(canAccessIMDS bool, cloudCreds []string) []string {
	var impact []string

	if canAccessIMDS {
		switch a.provider {
		case "aws", "eks":
			impact = append(impact,
				"Can retrieve IAM role credentials from IMDS",
				"Can access EC2 instance metadata (hostname, network config)",
				"Can potentially pivot to other AWS services",
				"May access secrets stored in SSM Parameter Store",
			)
		case "azure", "aks":
			impact = append(impact,
				"Can retrieve managed identity tokens from IMDS",
				"Can access Azure instance metadata",
				"Can potentially access Azure Key Vault",
				"May pivot to other Azure resources",
			)
		case "gcp", "gke":
			impact = append(impact,
				"Can retrieve service account tokens from metadata server",
				"Can access GCE instance metadata",
				"Can potentially access Secret Manager",
				"May pivot to other GCP services",
			)
		default:
			impact = append(impact,
				"Can access cloud instance metadata service",
				"May retrieve cloud credentials",
			)
		}
	}

	if len(cloudCreds) > 0 {
		impact = append(impact,
			fmt.Sprintf("Has %d cloud credential sources mounted/referenced", len(cloudCreds)),
			"Credentials could be exfiltrated if pod is compromised",
		)
	}

	return impact
}

func (a *CloudMetadataAnalyzer) getRecommendations(canAccessIMDS bool, cloudCreds []string) []string {
	var recs []string

	if canAccessIMDS {
		switch a.provider {
		case "aws", "eks":
			recs = append(recs,
				"Enable IMDSv2 and disable IMDSv1 on nodes",
				"Use IRSA (IAM Roles for Service Accounts) instead of node roles",
				"Set HttpPutResponseHopLimit to 1 to prevent IMDS access from pods",
				"Implement NetworkPolicy to block egress to 169.254.169.254",
			)
		case "azure", "aks":
			recs = append(recs,
				"Use Azure Workload Identity instead of pod managed identity",
				"Restrict IMDS access using NetworkPolicy",
				"Use AAD Pod Identity v2 with restrictive bindings",
			)
		case "gcp", "gke":
			recs = append(recs,
				"Use Workload Identity instead of node service account",
				"Disable legacy metadata API endpoints",
				"Implement NetworkPolicy to restrict metadata access",
			)
		default:
			recs = append(recs,
				"Implement NetworkPolicy to block metadata service access",
				"Use cloud-native workload identity solutions",
			)
		}
	}

	if len(cloudCreds) > 0 {
		recs = append(recs,
			"Use cloud-native identity federation (IRSA, Workload Identity)",
			"Remove static cloud credentials from pods",
			"Use external-secrets or sealed-secrets for credential management",
			"Rotate any exposed credentials immediately",
		)
	}

	return recs
}

func matchesPodSelector(podLabels, selector map[string]string) bool {
	if len(selector) == 0 {
		return true
	}
	for k, v := range selector {
		if podLabels[k] != v {
			return false
		}
	}
	return true
}

func (a *CloudMetadataAnalyzer) GetSummary(risks []CloudMetadataRisk) map[string]interface{} {
	summary := map[string]interface{}{
		"totalPodsAnalyzed":    len(a.inv.Workloads.Pods),
		"podsWithIMDSAccess":   0,
		"podsWithCloudCreds":   0,
		"criticalRisks":        0,
		"highRisks":            0,
		"provider":             a.provider,
	}

	for _, r := range risks {
		if r.CanAccessIMDS {
			summary["podsWithIMDSAccess"] = summary["podsWithIMDSAccess"].(int) + 1
		}
		if r.HasCloudCreds {
			summary["podsWithCloudCreds"] = summary["podsWithCloudCreds"].(int) + 1
		}
		switch r.RiskLevel {
		case "CRITICAL":
			summary["criticalRisks"] = summary["criticalRisks"].(int) + 1
		case "HIGH":
			summary["highRisks"] = summary["highRisks"].(int) + 1
		}
	}

	return summary
}
