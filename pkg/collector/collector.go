package collector

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Collector interface {
	Name() string
	Collect(ctx context.Context, clientset *kubernetes.Clientset) error
	Results() interface{}
}

type Manager struct {
	clientset  *kubernetes.Clientset
	config     *rest.Config
	collectors []Collector
	options    ManagerOptions
	mu         sync.Mutex
}

type ManagerOptions struct {
	Namespaces        []string
	NamespacesExclude []string
	Parallel          int
	Timeout           time.Duration
}

func NewManager(config *rest.Config, opts ManagerOptions) (*Manager, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	if opts.Parallel <= 0 {
		opts.Parallel = 5
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Minute
	}

	return &Manager{
		clientset:  clientset,
		config:     config,
		collectors: make([]Collector, 0),
		options:    opts,
	}, nil
}

func (m *Manager) RegisterCollector(c Collector) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.collectors = append(m.collectors, c)
}

func (m *Manager) RegisterDefaultCollectors() {
	m.RegisterCollector(NewNamespaceCollector(m.options.Namespaces, m.options.NamespacesExclude))
	m.RegisterCollector(NewNodeCollector())
	m.RegisterCollector(NewWorkloadCollector(m.options.Namespaces, m.options.NamespacesExclude))
	m.RegisterCollector(NewRBACCollector())
	m.RegisterCollector(NewNetworkPolicyCollector(m.options.Namespaces, m.options.NamespacesExclude))
	m.RegisterCollector(NewServiceAccountCollector(m.options.Namespaces, m.options.NamespacesExclude))
	m.RegisterCollector(NewConfigCollector(m.options.Namespaces, m.options.NamespacesExclude))
	m.RegisterCollector(NewServiceCollector(m.options.Namespaces, m.options.NamespacesExclude))
	m.RegisterCollector(NewIngressCollector(m.options.Namespaces, m.options.NamespacesExclude))
	m.RegisterCollector(NewQuotaCollector(m.options.Namespaces, m.options.NamespacesExclude))
	m.RegisterCollector(NewWebhookCollector())
	m.RegisterCollector(NewCRDCollector())
}

func (m *Manager) Collect(ctx context.Context) (*inventory.ClusterInventory, error) {
	ctx, cancel := context.WithTimeout(ctx, m.options.Timeout)
	defer cancel()

	clusterMeta, err := m.getClusterMetadata(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster metadata: %w", err)
	}

	sem := make(chan struct{}, m.options.Parallel)
	errChan := make(chan error, len(m.collectors))
	var wg sync.WaitGroup

	for _, collector := range m.collectors {
		wg.Add(1)
		go func(c Collector) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if err := c.Collect(ctx, m.clientset); err != nil {
				errChan <- fmt.Errorf("%s collector: %w", c.Name(), err)
			}
		}(collector)
	}

	wg.Wait()
	close(errChan)

	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		for _, err := range errs {
			fmt.Printf("Warning: %v\n", err)
		}
	}

	inv := &inventory.ClusterInventory{
		Cluster:     *clusterMeta,
		CollectedAt: time.Now().UTC(),
	}

	for _, c := range m.collectors {
		m.mergeResults(inv, c)
	}

	inv.Images = extractImages(inv.Workloads.Pods)
	inv.AIWorkloads = detectAIWorkloads(inv.Workloads.Pods)
	inv.SecurityPosture = computeSecurityPosture(inv)
	inv.RBACRisk = computeRBACRisk(inv)
	inv.AttackSurface = computeAttackSurface(inv)
	inv.NamespaceCompliance = computeNamespaceCompliance(inv)
	inv.WorkloadRisk = computeWorkloadRisk(inv)
	inv.ImageSupplyChain = computeImageSupplyChain(inv)
	inv.SecretsExposure = computeSecretsExposure(inv)
	inv.AdmissionGaps = computeAdmissionGaps(inv)
	inv.LateralMovement = computeLateralMovement(inv)
	inv.DeprecatedAPIs = computeDeprecatedAPIs(inv)

	return inv, nil
}

func (m *Manager) getClusterMetadata(ctx context.Context) (*inventory.ClusterMetadata, error) {
	version, err := m.clientset.Discovery().ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to get server version: %w", err)
	}

	nodes, err := m.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	return &inventory.ClusterMetadata{
		Version:    version.String(),
		NodeCount:  len(nodes.Items),
		APIVersion: version.GitVersion,
		Endpoint:   m.config.Host,
	}, nil
}

func (m *Manager) mergeResults(inv *inventory.ClusterInventory, c Collector) {
	switch c.Name() {
	case "namespace":
		if nc, ok := c.(*NamespaceCollector); ok {
			inv.Namespaces = nc.Results().([]inventory.NamespaceInfo)
		}
	case "node":
		if nc, ok := c.(*NodeCollector); ok {
			inv.Nodes = nc.Results().([]inventory.NodeInfo)
		}
	case "workload":
		if wc, ok := c.(*WorkloadCollector); ok {
			inv.Workloads = wc.Results().(inventory.WorkloadInventory)
		}
	case "rbac":
		if rc, ok := c.(*RBACCollector); ok {
			inv.RBAC = rc.Results().(inventory.RBACInventory)
		}
	case "networkpolicy":
		if npc, ok := c.(*NetworkPolicyCollector); ok {
			inv.NetworkPolicies = npc.Results().([]inventory.NetworkPolicyInfo)
		}
	case "serviceaccount":
		if sac, ok := c.(*ServiceAccountCollector); ok {
			inv.ServiceAccounts = sac.Results().([]inventory.ServiceAccountInfo)
		}
	case "config":
		if cc, ok := c.(*ConfigCollector); ok {
			results := cc.Results().(ConfigResults)
			inv.ConfigMaps = results.ConfigMaps
			inv.Secrets = results.Secrets
		}
	case "service":
		if sc, ok := c.(*ServiceCollector); ok {
			inv.Services = sc.Results().([]inventory.ServiceInfo)
		}
	case "ingress":
		if ic, ok := c.(*IngressCollector); ok {
			inv.Ingresses = ic.Results().([]inventory.IngressInfo)
		}
	case "quota":
		if qc, ok := c.(*QuotaCollector); ok {
			inv.ResourceQuotas = qc.ResourceQuotas()
			inv.LimitRanges = qc.LimitRanges()
		}
	case "webhook":
		if wc, ok := c.(*WebhookCollector); ok {
			inv.Webhooks = wc.Results().(inventory.WebhookInventory)
		}
	case "crd":
		if cc, ok := c.(*CRDCollector); ok {
			inv.CRDs = cc.Results().([]inventory.CRDInfo)
		}
	}
}

func shouldIncludeNamespace(ns string, include, exclude []string) bool {
	for _, excluded := range exclude {
		if ns == excluded {
			return false
		}
	}

	if len(include) > 0 {
		for _, included := range include {
			if ns == included {
				return true
			}
		}
		return false
	}

	return true
}

func extractImages(pods []inventory.PodInfo) []inventory.ImageInfo {
	type imageUsage struct {
		namespaces map[string]struct{}
		podCount   int
	}

	imageMap := make(map[string]*imageUsage)

	for _, pod := range pods {
		seenInPod := make(map[string]struct{})

		for _, container := range pod.Containers {
			if _, seen := seenInPod[container.Image]; !seen {
				seenInPod[container.Image] = struct{}{}
				if usage, exists := imageMap[container.Image]; exists {
					usage.podCount++
					usage.namespaces[pod.Namespace] = struct{}{}
				} else {
					imageMap[container.Image] = &imageUsage{
						namespaces: map[string]struct{}{pod.Namespace: {}},
						podCount:   1,
					}
				}
			}
		}

		for _, container := range pod.InitContainers {
			if _, seen := seenInPod[container.Image]; !seen {
				seenInPod[container.Image] = struct{}{}
				if usage, exists := imageMap[container.Image]; exists {
					usage.podCount++
					usage.namespaces[pod.Namespace] = struct{}{}
				} else {
					imageMap[container.Image] = &imageUsage{
						namespaces: map[string]struct{}{pod.Namespace: {}},
						podCount:   1,
					}
				}
			}
		}
	}

	images := make([]inventory.ImageInfo, 0, len(imageMap))
	for imageRef, usage := range imageMap {
		registry, repo, tag, digest := parseImageRef(imageRef)

		namespaces := make([]string, 0, len(usage.namespaces))
		for ns := range usage.namespaces {
			namespaces = append(namespaces, ns)
		}
		sort.Strings(namespaces)

		images = append(images, inventory.ImageInfo{
			Image:      imageRef,
			Registry:   registry,
			Repository: repo,
			Tag:        tag,
			Digest:     digest,
			PodCount:   usage.podCount,
			Namespaces: namespaces,
		})
	}

	sort.Slice(images, func(i, j int) bool {
		if images[i].PodCount != images[j].PodCount {
			return images[i].PodCount > images[j].PodCount
		}
		return images[i].Image < images[j].Image
	})

	return images
}

func parseImageRef(imageRef string) (registry, repository, tag, digest string) {
	ref := imageRef

	if idx := strings.Index(ref, "@"); idx != -1 {
		digest = ref[idx+1:]
		ref = ref[:idx]
	}

	if idx := strings.LastIndex(ref, ":"); idx != -1 {
		slashIdx := strings.LastIndex(ref, "/")
		if slashIdx == -1 || idx > slashIdx {
			tag = ref[idx+1:]
			ref = ref[:idx]
		}
	}

	if tag == "" && digest == "" {
		tag = "latest"
	}

	parts := strings.Split(ref, "/")
	if len(parts) == 1 {
		registry = "docker.io"
		repository = "library/" + parts[0]
	} else if len(parts) == 2 {
		if strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") || parts[0] == "localhost" {
			registry = parts[0]
			repository = parts[1]
		} else {
			registry = "docker.io"
			repository = ref
		}
	} else {
		registry = parts[0]
		repository = strings.Join(parts[1:], "/")
	}

	return
}

var gpuResourceTypes = []string{
	"nvidia.com/gpu",
	"amd.com/gpu",
	"intel.com/gpu",
	"habana.ai/gaudi",
	"aws.amazon.com/neuron",
	"google.com/tpu",
}

var mlFrameworkPatterns = map[string][]string{
	"tensorflow":   {"tensorflow", "tf-serving", "tfserving"},
	"pytorch":      {"pytorch", "torch"},
	"huggingface":  {"huggingface", "transformers", "hf-"},
	"jax":          {"jax", "flax"},
	"onnx":         {"onnx", "onnxruntime"},
	"mxnet":        {"mxnet"},
	"keras":        {"keras"},
	"scikit-learn": {"sklearn", "scikit"},
	"xgboost":      {"xgboost"},
	"lightgbm":     {"lightgbm"},
}

var llmServerPatterns = map[string][]string{
	"ollama":                 {"ollama"},
	"vllm":                   {"vllm"},
	"text-generation-inference": {"text-generation-inference", "tgi", "huggingface/text-generation"},
	"triton":                 {"tritonserver", "triton-inference"},
	"localai":                {"localai", "local-ai"},
	"llamacpp":               {"llama.cpp", "llama-cpp", "llamacpp"},
	"openllm":                {"openllm"},
	"ray-serve":              {"ray-serve", "rayserve"},
	"lmdeploy":               {"lmdeploy"},
	"tensorrt-llm":           {"tensorrt-llm", "trt-llm"},
}

var vectorDBPatterns = map[string][]string{
	"milvus":    {"milvus"},
	"weaviate":  {"weaviate"},
	"qdrant":    {"qdrant"},
	"chroma":    {"chroma"},
	"pinecone":  {"pinecone"},
	"pgvector":  {"pgvector"},
	"elasticsearch-vector": {"elasticsearch"},
	"opensearch": {"opensearch"},
	"redis-vector": {"redis-stack", "redisearch"},
	"vespa":     {"vespa"},
	"zilliz":    {"zilliz"},
}

var mlPlatformPatterns = map[string][]string{
	"kubeflow":    {"kubeflow", "ml-pipeline", "katib", "kfserving", "kserve"},
	"mlflow":      {"mlflow"},
	"ray":         {"rayproject", "ray-head", "ray-worker", "kuberay"},
	"seldon":      {"seldon", "seldon-core"},
	"bentoml":     {"bentoml", "bento"},
	"feast":       {"feast"},
	"airflow":     {"airflow"},
	"prefect":     {"prefect"},
	"argo":        {"argo-workflows", "argoproj"},
	"metaflow":    {"metaflow"},
	"clearml":     {"clearml"},
	"determined":  {"determined-ai", "determined"},
	"polyaxon":    {"polyaxon"},
	"pachyderm":   {"pachyderm"},
	"dvc":         {"dvc", "iterative"},
}

func detectAIWorkloads(pods []inventory.PodInfo) inventory.AIWorkloads {
	result := inventory.AIWorkloads{}

	gpuTypesSet := make(map[string]struct{})
	frameworksSet := make(map[string]struct{})
	llmServersSet := make(map[string]struct{})
	vectorDBsSet := make(map[string]struct{})
	platformsSet := make(map[string]struct{})

	frameworkUsage := make(map[string]map[string]map[string]struct{})

	for _, pod := range pods {
		allImages := getAllPodImages(pod)
		hasGPU, gpuType, gpuReq, gpuLim := detectGPUUsage(pod)

		if hasGPU {
			result.GPUWorkloads = append(result.GPUWorkloads, inventory.GPUWorkload{
				PodName:      pod.Name,
				Namespace:    pod.Namespace,
				GPUType:      gpuType,
				GPURequested: gpuReq,
				GPULimit:     gpuLim,
				Images:       allImages,
				Labels:       pod.Labels,
				NodeName:     pod.NodeName,
			})
			gpuTypesSet[gpuType] = struct{}{}
		}

		for _, image := range allImages {
			imageLower := strings.ToLower(image)

			for framework, patterns := range mlFrameworkPatterns {
				if matchesAny(imageLower, patterns) {
					frameworksSet[framework] = struct{}{}
					if frameworkUsage[framework] == nil {
						frameworkUsage[framework] = make(map[string]map[string]struct{})
					}
					if frameworkUsage[framework][image] == nil {
						frameworkUsage[framework][image] = make(map[string]struct{})
					}
					frameworkUsage[framework][image][pod.Namespace] = struct{}{}
				}
			}

			for serverType, patterns := range llmServerPatterns {
				if matchesAny(imageLower, patterns) {
					llmServersSet[serverType] = struct{}{}
					result.LLMInference = append(result.LLMInference, inventory.LLMInferenceInfo{
						Type:      serverType,
						Image:     image,
						PodName:   pod.Name,
						Namespace: pod.Namespace,
						HasGPU:    hasGPU,
					})
				}
			}

			for dbType, patterns := range vectorDBPatterns {
				if matchesAny(imageLower, patterns) {
					vectorDBsSet[dbType] = struct{}{}
					result.VectorDatabases = append(result.VectorDatabases, inventory.VectorDBInfo{
						Type:      dbType,
						Image:     image,
						PodName:   pod.Name,
						Namespace: pod.Namespace,
					})
				}
			}

			for platform, patterns := range mlPlatformPatterns {
				if matchesAny(imageLower, patterns) {
					platformsSet[platform] = struct{}{}
					result.MLPlatforms = append(result.MLPlatforms, inventory.MLPlatformInfo{
						Platform:  platform,
						PodName:   pod.Name,
						Namespace: pod.Namespace,
						Images:    allImages,
					})
				}
			}
		}
	}

	for framework, images := range frameworkUsage {
		for image, namespaces := range images {
			nsList := make([]string, 0, len(namespaces))
			for ns := range namespaces {
				nsList = append(nsList, ns)
			}
			sort.Strings(nsList)
			result.MLFrameworks = append(result.MLFrameworks, inventory.MLFrameworkUsage{
				Framework:  framework,
				Image:      image,
				PodCount:   len(namespaces),
				Namespaces: nsList,
			})
		}
	}

	result.Summary = buildAISummary(result, gpuTypesSet, frameworksSet, llmServersSet, vectorDBsSet, platformsSet)

	return result
}

func getAllPodImages(pod inventory.PodInfo) []string {
	images := make([]string, 0)
	seen := make(map[string]struct{})

	for _, c := range pod.Containers {
		if _, ok := seen[c.Image]; !ok {
			images = append(images, c.Image)
			seen[c.Image] = struct{}{}
		}
	}
	for _, c := range pod.InitContainers {
		if _, ok := seen[c.Image]; !ok {
			images = append(images, c.Image)
			seen[c.Image] = struct{}{}
		}
	}
	return images
}

func detectGPUUsage(pod inventory.PodInfo) (hasGPU bool, gpuType string, requested, limit int) {
	for _, container := range pod.Containers {
		for _, gpuRes := range gpuResourceTypes {
			if val, ok := container.Resources.Requests[gpuRes]; ok {
				hasGPU = true
				gpuType = gpuRes
				requested += parseResourceQuantity(val)
			}
			if val, ok := container.Resources.Limits[gpuRes]; ok {
				hasGPU = true
				if gpuType == "" {
					gpuType = gpuRes
				}
				limit += parseResourceQuantity(val)
			}
		}
	}
	return
}

func parseResourceQuantity(val string) int {
	var count int
	_, _ = fmt.Sscanf(val, "%d", &count)
	return count
}

func matchesAny(str string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(str, p) {
			return true
		}
	}
	return false
}

func buildAISummary(ai inventory.AIWorkloads, gpuTypes, frameworks, llmServers, vectorDBs, platforms map[string]struct{}) inventory.AIWorkloadSummary {
	summary := inventory.AIWorkloadSummary{
		TotalGPUPods: len(ai.GPUWorkloads),
	}

	for _, gpu := range ai.GPUWorkloads {
		summary.TotalGPURequested += gpu.GPURequested
	}

	summary.GPUTypes = setToSortedSlice(gpuTypes)
	summary.MLFrameworksFound = setToSortedSlice(frameworks)
	summary.LLMServersFound = setToSortedSlice(llmServers)
	summary.VectorDBsFound = setToSortedSlice(vectorDBs)
	summary.MLPlatformsFound = setToSortedSlice(platforms)

	summary.HasAIWorkloads = summary.TotalGPUPods > 0 ||
		len(summary.MLFrameworksFound) > 0 ||
		len(summary.LLMServersFound) > 0 ||
		len(summary.VectorDBsFound) > 0 ||
		len(summary.MLPlatformsFound) > 0

	return summary
}

func setToSortedSlice(set map[string]struct{}) []string {
	slice := make([]string, 0, len(set))
	for k := range set {
		slice = append(slice, k)
	}
	sort.Strings(slice)
	return slice
}

var dangerousCapsList = []string{
	"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH",
	"NET_ADMIN", "NET_RAW", "SYS_RAWIO", "MKNOD",
}

func computeSecurityPosture(inv *inventory.ClusterInventory) inventory.SecurityPosture {
	posture := inventory.SecurityPosture{}
	dangerousCapsFound := make(map[string]struct{})

	userNamespaces := make(map[string]bool)
	for _, ns := range inv.Namespaces {
		if ns.Name != "kube-system" && ns.Name != "kube-public" && ns.Name != "kube-node-lease" && ns.Name != "default" {
			userNamespaces[ns.Name] = true
		}
	}

	nsPolicies := make(map[string]bool)
	for _, np := range inv.NetworkPolicies {
		nsPolicies[np.Namespace] = true
	}

	for ns := range userNamespaces {
		if !nsPolicies[ns] {
			posture.NamespacesWithoutNetworkPolicies++
		}
	}

	for _, pod := range inv.Workloads.Pods {
		if pod.Namespace == "kube-system" || pod.Namespace == "kube-public" {
			continue
		}

		hasSecurityContext := false
		hasResourceLimits := true
		hasHostPath := false

		for _, vol := range pod.Volumes {
			if vol.Type == "hostPath" {
				hasHostPath = true
				break
			}
		}
		if hasHostPath {
			posture.HostPathVolumes++
		}

		if pod.HostNetwork || pod.HostPID || pod.HostIPC {
			posture.WorkloadsWithHostNamespace++
		}

		for _, container := range pod.Containers {
			if container.SecurityContext != nil {
				hasSecurityContext = true

				if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
					posture.PrivilegedWorkloads++
				}

				if container.SecurityContext.RunAsUser != nil && *container.SecurityContext.RunAsUser == 0 {
					posture.WorkloadsRunningAsRoot++
				} else if container.SecurityContext.RunAsNonRoot == nil || !*container.SecurityContext.RunAsNonRoot {
					if pod.SecurityContext == nil || pod.SecurityContext.RunAsNonRoot == nil || !*pod.SecurityContext.RunAsNonRoot {
						posture.WorkloadsRunningAsRoot++
					}
				}

				if container.SecurityContext.AllowPrivilegeEscalation == nil || *container.SecurityContext.AllowPrivilegeEscalation {
					posture.WorkloadsAllowingPrivEscalation++
				}

				if container.SecurityContext.Capabilities != nil {
					for _, cap := range container.SecurityContext.Capabilities.Add {
						for _, dangerous := range dangerousCapsList {
							if cap == dangerous {
								dangerousCapsFound[cap] = struct{}{}
							}
						}
					}
				}
			}

			if len(container.Resources.Limits) == 0 {
				hasResourceLimits = false
			}
		}

		if !hasSecurityContext {
			posture.WorkloadsWithoutSecurityContext++
		}
		if !hasResourceLimits {
			posture.WorkloadsWithoutResourceLimits++
		}
	}

	for _, img := range inv.Images {
		if img.Digest == "" {
			posture.ImagesWithoutDigest++
		}
		if img.Tag == "latest" {
			posture.ImagesUsingLatestTag++
		}
	}

	for _, svc := range inv.Services {
		if svc.Type == "LoadBalancer" || svc.Type == "NodePort" {
			posture.ExternallyExposedServices++
		}
	}
	posture.ExternallyExposedServices += len(inv.Ingresses)

	for _, sa := range inv.ServiceAccounts {
		if sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
			posture.ServiceAccountsWithAutoMount++
		}
	}

	for _, cj := range inv.Workloads.CronJobs {
		if !cj.Suspend {
			posture.CronJobsEnabled++
		}
	}

	wildcardVerbs := []string{"*"}
	dangerousResources := []string{"secrets", "pods", "deployments", "*"}
	for _, cr := range inv.RBAC.ClusterRoles {
		for _, rule := range cr.Rules {
			isWildcard := false
			for _, verb := range rule.Verbs {
				for _, wv := range wildcardVerbs {
					if verb == wv {
						isWildcard = true
						break
					}
				}
			}
			if isWildcard {
				for _, res := range rule.Resources {
					for _, dr := range dangerousResources {
						if res == dr {
							posture.OverpermissiveRBAC++
							break
						}
					}
				}
			}
		}
	}

	posture.DangerousCapabilities = setToSortedSlice(dangerousCapsFound)

	riskCount := posture.PrivilegedWorkloads*10 +
		posture.WorkloadsRunningAsRoot*3 +
		posture.WorkloadsWithHostNamespace*5 +
		posture.OverpermissiveRBAC*5 +
		posture.ExternallyExposedServices*2 +
		len(posture.DangerousCapabilities)*4

	if riskCount == 0 {
		posture.RiskScore = "low"
	} else if riskCount < 20 {
		posture.RiskScore = "medium"
	} else if riskCount < 50 {
		posture.RiskScore = "high"
	} else {
		posture.RiskScore = "critical"
	}

	return posture
}

func computeRBACRisk(inv *inventory.ClusterInventory) inventory.RBACRiskAnalysis {
	analysis := inventory.RBACRiskAnalysis{}

	clusterRoleRules := make(map[string][]inventory.PolicyRule)
	for _, cr := range inv.RBAC.ClusterRoles {
		clusterRoleRules[cr.Name] = cr.Rules
	}

	roleRules := make(map[string][]inventory.PolicyRule)
	for _, r := range inv.RBAC.Roles {
		key := r.Namespace + "/" + r.Name
		roleRules[key] = r.Rules
	}

	// Safe default roles that legitimately allow unauthenticated access
	safeUnauthRoles := map[string]bool{
		"system:public-info-viewer": true, // Only /healthz, /version - needed for LB health checks
		"system:discovery":          true, // API discovery, common default
	}

	for _, crb := range inv.RBAC.ClusterRoleBindings {
		isClusterAdmin := crb.RoleRef.Name == "cluster-admin"
		if isClusterAdmin {
			analysis.ClusterAdminBindings++
		}

		for _, subject := range crb.Subjects {
			if subject.Kind == "Group" && subject.Name == "system:unauthenticated" {
				// Skip safe default roles
				if !safeUnauthRoles[crb.RoleRef.Name] {
					analysis.UnauthenticatedAccess = true
					analysis.HighRiskBindings = append(analysis.HighRiskBindings, inventory.RBACRiskBinding{
						Name:       crb.Name,
						Kind:       "ClusterRoleBinding",
						RoleRef:    crb.RoleRef.Name,
						Subjects:   []string{"system:unauthenticated"},
						RiskReason: "Grants access to unauthenticated users",
					})
				}
			}
			if subject.Kind == "Group" && subject.Name == "system:authenticated" {
				analysis.AuthenticatedGroupAccess = true
				if isClusterAdmin {
					analysis.HighRiskBindings = append(analysis.HighRiskBindings, inventory.RBACRiskBinding{
						Name:       crb.Name,
						Kind:       "ClusterRoleBinding",
						RoleRef:    crb.RoleRef.Name,
						Subjects:   []string{"system:authenticated"},
						RiskReason: "Grants cluster-admin to all authenticated users",
					})
				}
			}
			if subject.Kind == "ServiceAccount" && subject.Name == "default" {
				analysis.DefaultSAWithPermissions++
			}
		}

		rules := clusterRoleRules[crb.RoleRef.Name]
		if hasWildcardAccess(rules) {
			analysis.WildcardRoles++
		}
		if hasSecretsAccess(rules) {
			analysis.SecretsAccessRoles++
			for _, subject := range crb.Subjects {
				if subject.Kind == "ServiceAccount" {
					saName := subject.Namespace + "/" + subject.Name
					found := false
					for _, existing := range analysis.PrivilegedServiceAccounts {
						if existing == saName {
							found = true
							break
						}
					}
					if !found {
						analysis.PrivilegedServiceAccounts = append(analysis.PrivilegedServiceAccounts, saName)
					}
				}
			}
		}
		if hasEscalationPerms(rules) {
			analysis.EscalationCapableRoles++
		}
		if hasExecAccess(rules) {
			analysis.ExecCapableRoles++
		}
	}

	for _, rb := range inv.RBAC.RoleBindings {
		for _, subject := range rb.Subjects {
			if subject.Kind == "ServiceAccount" && subject.Namespace != "" && subject.Namespace != rb.Namespace {
				analysis.CrossNamespaceBindings++
			}
			if subject.Kind == "ServiceAccount" && subject.Name == "default" {
				analysis.DefaultSAWithPermissions++
			}
		}
	}

	riskScore := analysis.ClusterAdminBindings*20 +
		analysis.WildcardRoles*10 +
		analysis.EscalationCapableRoles*15 +
		analysis.DefaultSAWithPermissions*5

	if analysis.UnauthenticatedAccess {
		riskScore += 50
	}
	if analysis.AuthenticatedGroupAccess && analysis.ClusterAdminBindings > 0 {
		riskScore += 30
	}

	if riskScore == 0 {
		analysis.RiskScore = "low"
	} else if riskScore < 20 {
		analysis.RiskScore = "medium"
	} else if riskScore < 50 {
		analysis.RiskScore = "high"
	} else {
		analysis.RiskScore = "critical"
	}

	return analysis
}

func hasWildcardAccess(rules []inventory.PolicyRule) bool {
	for _, rule := range rules {
		for _, verb := range rule.Verbs {
			if verb == "*" {
				for _, res := range rule.Resources {
					if res == "*" {
						return true
					}
				}
			}
		}
	}
	return false
}

func hasSecretsAccess(rules []inventory.PolicyRule) bool {
	for _, rule := range rules {
		for _, res := range rule.Resources {
			if res == "secrets" || res == "*" {
				for _, verb := range rule.Verbs {
					if verb == "get" || verb == "list" || verb == "watch" || verb == "*" {
						return true
					}
				}
			}
		}
	}
	return false
}

func hasEscalationPerms(rules []inventory.PolicyRule) bool {
	escalationVerbs := map[string]bool{"bind": true, "escalate": true, "impersonate": true}
	for _, rule := range rules {
		for _, verb := range rule.Verbs {
			if escalationVerbs[verb] || verb == "*" {
				return true
			}
		}
	}
	return false
}

func hasExecAccess(rules []inventory.PolicyRule) bool {
	for _, rule := range rules {
		for _, res := range rule.Resources {
			if res == "pods/exec" || res == "*" {
				for _, verb := range rule.Verbs {
					if verb == "create" || verb == "*" {
						return true
					}
				}
			}
		}
	}
	return false
}

func computeAttackSurface(inv *inventory.ClusterInventory) inventory.AttackSurface {
	surface := inventory.AttackSurface{}

	nsPolicies := make(map[string]bool)
	for _, np := range inv.NetworkPolicies {
		nsPolicies[np.Namespace] = true
	}

	for _, svc := range inv.Services {
		ports := make([]int32, 0)
		for _, p := range svc.Ports {
			ports = append(ports, p.Port)
		}

		switch svc.Type {
		case "LoadBalancer":
			surface.LoadBalancers = append(surface.LoadBalancers, inventory.ExposedService{
				Name:      svc.Name,
				Namespace: svc.Namespace,
				Type:      svc.Type,
				Ports:     ports,
			})
			surface.ExternalEntryPoints++
			surface.InternetFacingServices++
		case "NodePort":
			nodePorts := make([]int32, 0)
			for _, p := range svc.Ports {
				if p.NodePort > 0 {
					nodePorts = append(nodePorts, p.NodePort)
				}
			}
			surface.NodePorts = append(surface.NodePorts, inventory.ExposedService{
				Name:      svc.Name,
				Namespace: svc.Namespace,
				Type:      svc.Type,
				Ports:     nodePorts,
			})
			surface.ExternalEntryPoints++
		}

		if len(svc.ExternalIPs) > 0 {
			surface.ExternalIPs = append(surface.ExternalIPs, inventory.ExposedService{
				Name:      svc.Name,
				Namespace: svc.Namespace,
				Type:      "ExternalIP",
				Ports:     ports,
			})
			surface.ExternalEntryPoints++
		}
	}

	for _, ing := range inv.Ingresses {
		hosts := make([]string, 0)
		pathCount := 0
		for _, rule := range ing.Rules {
			if rule.Host != "" {
				hosts = append(hosts, rule.Host)
			}
			pathCount += len(rule.Paths)
		}

		hasTLS := len(ing.TLS) > 0
		surface.Ingresses = append(surface.Ingresses, inventory.ExposedIngress{
			Name:      ing.Name,
			Namespace: ing.Namespace,
			Hosts:     hosts,
			TLS:       hasTLS,
			Paths:     pathCount,
		})
		surface.ExternalEntryPoints++
		surface.InternetFacingServices++
	}

	for _, pod := range inv.Workloads.Pods {
		if pod.Namespace == "kube-system" {
			continue
		}

		if pod.HostNetwork {
			surface.HostNetworkPods++
		}

		for _, container := range pod.Containers {
			for _, port := range container.Ports {
				if port.HostPort > 0 {
					surface.HostPortPods++
					break
				}
			}
		}
	}

	for _, ns := range inv.Namespaces {
		if isSystemNamespace(ns.Name) {
			continue
		}
		if !nsPolicies[ns.Name] {
			surface.UnprotectedNamespaces = append(surface.UnprotectedNamespaces, ns.Name)
		}
	}

	return surface
}

func computeNamespaceCompliance(inv *inventory.ClusterInventory) inventory.NamespaceCompliance {
	compliance := inventory.NamespaceCompliance{}

	nsNetPolicies := make(map[string][]inventory.NetworkPolicyInfo)
	for _, np := range inv.NetworkPolicies {
		nsNetPolicies[np.Namespace] = append(nsNetPolicies[np.Namespace], np)
	}

	nsQuotas := make(map[string]bool)
	for _, q := range inv.ResourceQuotas {
		nsQuotas[q.Namespace] = true
	}

	nsLimitRanges := make(map[string]bool)
	for _, lr := range inv.LimitRanges {
		nsLimitRanges[lr.Namespace] = true
	}

	nsSAs := make(map[string][]inventory.ServiceAccountInfo)
	for _, sa := range inv.ServiceAccounts {
		nsSAs[sa.Namespace] = append(nsSAs[sa.Namespace], sa)
	}

	for _, ns := range inv.Namespaces {
		if isSystemNamespace(ns.Name) {
			continue
		}

		compliance.TotalNamespaces++

		detail := inventory.NamespaceComplianceDetail{
			Name: ns.Name,
		}

		score := 0
		maxScore := 6

		if enforceLevel, ok := ns.Labels["pod-security.kubernetes.io/enforce"]; ok {
			detail.HasPSALabels = true
			detail.PSAEnforceLevel = enforceLevel
			if enforceLevel == "restricted" {
				score += 2
			} else if enforceLevel == "baseline" {
				score++
			}
		} else {
			detail.Issues = append(detail.Issues, "No PSA enforce label")
		}

		policies := nsNetPolicies[ns.Name]
		if len(policies) > 0 {
			detail.HasNetworkPolicies = true
			score++

			for _, policy := range policies {
				if len(policy.PodSelector) == 0 && policy.IngressRules == 0 {
					detail.HasDefaultDeny = true
					score++
					break
				}
				if len(policy.PodSelector) == 0 && policy.EgressRules == 0 {
					detail.HasDefaultDeny = true
					score++
					break
				}
			}
		} else {
			detail.Issues = append(detail.Issues, "No NetworkPolicies")
		}

		if nsQuotas[ns.Name] {
			detail.HasResourceQuota = true
			score++
		} else {
			detail.Issues = append(detail.Issues, "No ResourceQuota")
		}

		if nsLimitRanges[ns.Name] {
			detail.HasLimitRange = true
			score++
		}

		sas := nsSAs[ns.Name]
		detail.ServiceAccountCount = len(sas)
		for _, sa := range sas {
			if sa.Name == "default" && len(sa.Secrets) > 0 {
				detail.DefaultSAHasSecrets = true
				detail.Issues = append(detail.Issues, "Default SA has secrets")
			}
		}

		detail.ComplianceScore = int(float64(score) / float64(maxScore) * 100)

		if detail.ComplianceScore >= 80 {
			compliance.CompliantNamespaces++
		}

		compliance.NamespaceDetails = append(compliance.NamespaceDetails, detail)
	}

	if compliance.TotalNamespaces > 0 {
		compliance.ComplianceScore = float64(compliance.CompliantNamespaces) / float64(compliance.TotalNamespaces) * 100
	}

	return compliance
}

func isSystemNamespace(name string) bool {
	return name == "kube-system" || name == "kube-public" || name == "kube-node-lease" || name == "default" || name == "qualys"
}

func computeWorkloadRisk(inv *inventory.ClusterInventory) inventory.WorkloadRiskRanking {
	ranking := inventory.WorkloadRiskRanking{}

	saSecretAccess := make(map[string]bool)
	for _, crb := range inv.RBAC.ClusterRoleBindings {
		for _, subject := range crb.Subjects {
			if subject.Kind == "ServiceAccount" {
				key := subject.Namespace + "/" + subject.Name
				saSecretAccess[key] = true
			}
		}
	}

	var workloads []inventory.WorkloadRiskInfo

	for _, pod := range inv.Workloads.Pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}

		risk := inventory.WorkloadRiskInfo{
			Name:           pod.Name,
			Namespace:      pod.Namespace,
			Kind:           "Pod",
			ServiceAccount: pod.ServiceAccount,
			RiskFactors:    []string{},
		}

		score := 0

		if pod.HostNetwork {
			score += 20
			risk.RiskFactors = append(risk.RiskFactors, "hostNetwork")
			risk.HasNetworkAccess = true
		}
		if pod.HostPID {
			score += 15
			risk.RiskFactors = append(risk.RiskFactors, "hostPID")
		}
		if pod.HostIPC {
			score += 10
			risk.RiskFactors = append(risk.RiskFactors, "hostIPC")
		}

		saKey := pod.Namespace + "/" + pod.ServiceAccount
		if saSecretAccess[saKey] {
			score += 15
			risk.RiskFactors = append(risk.RiskFactors, "serviceAccountHasClusterAccess")
			risk.HasSecretAccess = true
		}

		for _, container := range pod.Containers {
			if container.SecurityContext != nil {
				if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
					score += 25
					risk.RiskFactors = append(risk.RiskFactors, "privileged")
				}
				if container.SecurityContext.Capabilities != nil {
					for _, cap := range container.SecurityContext.Capabilities.Add {
						if cap == "SYS_ADMIN" || cap == "SYS_PTRACE" {
							score += 20
							risk.RiskFactors = append(risk.RiskFactors, "dangerousCapability:"+cap)
						}
					}
				}
			}
		}

		for _, vol := range pod.Volumes {
			if vol.Type == "hostPath" {
				score += 15
				risk.RiskFactors = append(risk.RiskFactors, "hostPath:"+vol.Source)
			}
			if vol.Type == "secret" {
				risk.HasSecretAccess = true
			}
		}

		risk.RiskScore = score
		if score >= 50 {
			risk.RiskLevel = "critical"
			ranking.HighRiskCount++
		} else if score >= 25 {
			risk.RiskLevel = "high"
			ranking.HighRiskCount++
		} else if score >= 10 {
			risk.RiskLevel = "medium"
			ranking.MediumRiskCount++
		} else {
			risk.RiskLevel = "low"
			ranking.LowRiskCount++
		}

		if score >= 10 {
			workloads = append(workloads, risk)
		}
	}

	sort.Slice(workloads, func(i, j int) bool {
		return workloads[i].RiskScore > workloads[j].RiskScore
	})

	if len(workloads) > 10 {
		ranking.TopRiskyWorkloads = workloads[:10]
	} else {
		ranking.TopRiskyWorkloads = workloads
	}

	return ranking
}

var trustedRegistries = map[string]bool{
	"gcr.io":                      true,
	"us.gcr.io":                   true,
	"eu.gcr.io":                   true,
	"asia.gcr.io":                 true,
	"registry.k8s.io":             true,
	"k8s.gcr.io":                  true,
	"quay.io":                     true,
	"ghcr.io":                     true,
	"mcr.microsoft.com":           true,
	"docker.io":                   true,
	"public.ecr.aws":              true,
	"gallery.ecr.aws":             true,
}

func computeImageSupplyChain(inv *inventory.ClusterInventory) inventory.ImageSupplyChain {
	chain := inventory.ImageSupplyChain{
		TotalImages: len(inv.Images),
	}

	registryCount := make(map[string]int)

	for _, img := range inv.Images {
		registryCount[img.Registry]++

		if img.Digest != "" {
			chain.ImagesWithDigest++
		} else {
			chain.ImagesWithoutDigest++
		}

		if img.Tag == "latest" {
			chain.LatestTagImages++
		}

		if trustedRegistries[img.Registry] {
			chain.TrustedRegistries++
		} else {
			chain.UntrustedRegistries++
		}

		var riskFactors []string
		if img.Digest == "" {
			riskFactors = append(riskFactors, "noDigest")
		}
		if img.Tag == "latest" {
			riskFactors = append(riskFactors, "latestTag")
		}
		if !trustedRegistries[img.Registry] {
			riskFactors = append(riskFactors, "untrustedRegistry")
		}

		if len(riskFactors) >= 2 {
			chain.RiskyImages = append(chain.RiskyImages, inventory.ImageRiskInfo{
				Image:       img.Image,
				Registry:    img.Registry,
				RiskFactors: riskFactors,
				PodCount:    img.PodCount,
			})
		}
	}

	for registry, count := range registryCount {
		trustLevel := "untrusted"
		if trustedRegistries[registry] {
			trustLevel = "trusted"
		}
		chain.RegistryBreakdown = append(chain.RegistryBreakdown, inventory.RegistryStats{
			Registry:   registry,
			ImageCount: count,
			TrustLevel: trustLevel,
		})
	}

	sort.Slice(chain.RegistryBreakdown, func(i, j int) bool {
		return chain.RegistryBreakdown[i].ImageCount > chain.RegistryBreakdown[j].ImageCount
	})

	return chain
}

func computeSecretsExposure(inv *inventory.ClusterInventory) inventory.SecretsExposure {
	exposure := inventory.SecretsExposure{
		TotalSecrets:  len(inv.Secrets),
		SecretsByType: make(map[string]int),
	}

	secretUsage := make(map[string][]string)

	for _, secret := range inv.Secrets {
		exposure.SecretsByType[secret.Type]++

		if secret.Type == "kubernetes.io/dockerconfigjson" || secret.Type == "kubernetes.io/dockercfg" {
			continue
		}

		for _, label := range []string{"sealedsecrets.bitnami.com/sealed-secrets-key"} {
			if _, ok := secret.Labels[label]; ok {
				exposure.SealedSecrets++
			}
		}

		if _, ok := secret.Labels["externalsecrets.kubernetes-client.io/owned-by"]; ok {
			exposure.ExternalSecretsManaged++
		}
	}

	for _, pod := range inv.Workloads.Pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}

		for _, vol := range pod.Volumes {
			if vol.Type == "secret" {
				key := pod.Namespace + "/" + vol.Source
				secretUsage[key] = append(secretUsage[key], pod.Name)
				exposure.SecretsAsMounts++
			}
		}
	}

	usedSecrets := make(map[string]bool)
	for key := range secretUsage {
		usedSecrets[key] = true
	}

	for _, secret := range inv.Secrets {
		if isSystemNamespace(secret.Namespace) {
			continue
		}
		key := secret.Namespace + "/" + secret.Name
		if !usedSecrets[key] {
			if secret.Type != "kubernetes.io/service-account-token" {
				exposure.OrphanedSecrets++
			}
		}
	}

	return exposure
}

func computeAdmissionGaps(inv *inventory.ClusterInventory) inventory.AdmissionControlGaps {
	gaps := inventory.AdmissionControlGaps{}

	if len(inv.Webhooks.ValidatingWebhooks) > 0 {
		gaps.HasValidatingWebhooks = true
	}
	if len(inv.Webhooks.MutatingWebhooks) > 0 {
		gaps.HasMutatingWebhooks = true
	}

	exemptedNS := make(map[string]bool)

	for _, vwh := range inv.Webhooks.ValidatingWebhooks {
		for _, wh := range vwh.Webhooks {
			coverage := inventory.WebhookCoverageInfo{
				Name:          wh.Name,
				Type:          "validating",
				FailurePolicy: wh.FailurePolicy,
				Covers:        wh.Rules,
			}

			if wh.FailurePolicy == "Ignore" {
				gaps.FailOpenWebhooks++
			}

			if wh.NamespaceSelector != "" && strings.Contains(wh.NamespaceSelector, "exclude") {
				exemptedNS["detected-exemptions"] = true
			}

			gaps.WebhookCoverage = append(gaps.WebhookCoverage, coverage)
		}
	}

	for _, mwh := range inv.Webhooks.MutatingWebhooks {
		for _, wh := range mwh.Webhooks {
			coverage := inventory.WebhookCoverageInfo{
				Name:          wh.Name,
				Type:          "mutating",
				FailurePolicy: wh.FailurePolicy,
				Covers:        wh.Rules,
			}

			if wh.FailurePolicy == "Ignore" {
				gaps.FailOpenWebhooks++
			}

			gaps.WebhookCoverage = append(gaps.WebhookCoverage, coverage)
		}
	}

	for ns := range exemptedNS {
		gaps.ExemptedNamespaces = append(gaps.ExemptedNamespaces, ns)
	}

	if !gaps.HasValidatingWebhooks {
		gaps.CriticalGaps = append(gaps.CriticalGaps, "No validating admission webhooks")
		gaps.RecommendedWebhooks = append(gaps.RecommendedWebhooks, "Pod Security Admission", "OPA Gatekeeper", "Kyverno")
	}

	if gaps.FailOpenWebhooks > 0 {
		gaps.CriticalGaps = append(gaps.CriticalGaps, fmt.Sprintf("%d webhooks have fail-open policy", gaps.FailOpenWebhooks))
	}

	return gaps
}

func computeLateralMovement(inv *inventory.ClusterInventory) inventory.LateralMovement {
	lateral := inventory.LateralMovement{}

	nsPolicies := make(map[string]bool)
	nsDefaultDeny := make(map[string]bool)
	for _, np := range inv.NetworkPolicies {
		nsPolicies[np.Namespace] = true
		if len(np.PodSelector) == 0 && (np.IngressRules == 0 || np.EgressRules == 0) {
			nsDefaultDeny[np.Namespace] = true
		}
	}

	userNS := 0
	protectedNS := 0
	for _, ns := range inv.Namespaces {
		if !isSystemNamespace(ns.Name) {
			userNS++
			if nsDefaultDeny[ns.Name] {
				protectedNS++
			}
		}
	}

	if userNS > 0 {
		coverage := float64(protectedNS) / float64(userNS) * 100
		if coverage >= 80 {
			lateral.NetworkSegmentation = "strong"
		} else if coverage >= 50 {
			lateral.NetworkSegmentation = "partial"
		} else if coverage > 0 {
			lateral.NetworkSegmentation = "weak"
		} else {
			lateral.NetworkSegmentation = "none"
		}
	} else {
		lateral.NetworkSegmentation = "n/a"
	}

	for _, sa := range inv.ServiceAccounts {
		if sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
			lateral.SATokenExposure++
		}
	}

	saExecAccess := make(map[string]bool)
	for _, crb := range inv.RBAC.ClusterRoleBindings {
		for _, subject := range crb.Subjects {
			if subject.Kind == "ServiceAccount" {
				saExecAccess[subject.Namespace+"/"+subject.Name] = true
			}
		}
	}

	for _, pod := range inv.Workloads.Pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		saKey := pod.Namespace + "/" + pod.ServiceAccount
		if saExecAccess[saKey] {
			lateral.PodsWithExecAccess++
		}
	}

	for _, rb := range inv.RBAC.RoleBindings {
		for _, subject := range rb.Subjects {
			if subject.Kind == "ServiceAccount" && subject.Namespace != "" && subject.Namespace != rb.Namespace {
				lateral.CrossNamespacePaths++
				lateral.HighRiskPaths = append(lateral.HighRiskPaths, inventory.LateralMovementPath{
					Source:       subject.Namespace + "/" + subject.Name,
					Target:       rb.Namespace,
					AccessMethod: "RoleBinding",
					RiskLevel:    "high",
				})
			}
		}
	}

	riskScore := 0
	if lateral.NetworkSegmentation == "none" {
		riskScore += 30
		lateral.Recommendations = append(lateral.Recommendations, "Implement network policies with default-deny")
	} else if lateral.NetworkSegmentation == "weak" {
		riskScore += 15
		lateral.Recommendations = append(lateral.Recommendations, "Expand network policy coverage")
	}

	if lateral.SATokenExposure > 10 {
		riskScore += 20
		lateral.Recommendations = append(lateral.Recommendations, "Disable automountServiceAccountToken where not needed")
	}

	if lateral.CrossNamespacePaths > 0 {
		riskScore += 15
		lateral.Recommendations = append(lateral.Recommendations, "Review cross-namespace RBAC bindings")
	}

	if riskScore >= 40 {
		lateral.RiskScore = "critical"
	} else if riskScore >= 25 {
		lateral.RiskScore = "high"
	} else if riskScore >= 10 {
		lateral.RiskScore = "medium"
	} else {
		lateral.RiskScore = "low"
	}

	return lateral
}

func computeDeprecatedAPIs(inv *inventory.ClusterInventory) inventory.DeprecatedAPIs {
	deprecated := inventory.DeprecatedAPIs{}

	for _, ing := range inv.Ingresses {
		if ing.IngressClass == "" {
			deprecated.WarningCount++
			deprecated.TotalDeprecated++
			deprecated.DeprecatedResources = append(deprecated.DeprecatedResources, inventory.DeprecatedResource{
				Kind:           "Ingress",
				Name:           ing.Name,
				Namespace:      ing.Namespace,
				CurrentAPI:     "networking.k8s.io/v1",
				ReplacementAPI: "networking.k8s.io/v1 with ingressClassName",
				RemovedIn:      "n/a",
				Severity:       "warning",
			})
		}
	}

	for _, crd := range inv.CRDs {
		hasV1Beta1 := false
		for _, v := range crd.Versions {
			if strings.Contains(v, "v1beta1") || strings.Contains(v, "v1alpha1") {
				hasV1Beta1 = true
				break
			}
		}
		if hasV1Beta1 {
			deprecated.WarningCount++
			deprecated.TotalDeprecated++
		}
	}

	return deprecated
}
