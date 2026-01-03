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
	m.RegisterCollector(NewEventCollector(time.Hour))
	m.RegisterCollector(NewQuotaCollector(m.options.Namespaces, m.options.NamespacesExclude))
	m.RegisterCollector(NewAutoscalingCollector(m.options.Namespaces, m.options.NamespacesExclude))
	m.RegisterCollector(NewStorageCollector(m.options.Namespaces, m.options.NamespacesExclude))
	m.RegisterCollector(NewWebhookCollector())
	m.RegisterCollector(NewClusterResourceCollector())
	m.RegisterCollector(NewCRDCollector())
	m.RegisterCollector(NewEndpointCollector(m.options.Namespaces, m.options.NamespacesExclude))
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
	case "event":
		if ec, ok := c.(*EventCollector); ok {
			inv.Events = ec.Results().([]inventory.EventInfo)
		}
	case "quota":
		if qc, ok := c.(*QuotaCollector); ok {
			inv.ResourceQuotas = qc.ResourceQuotas()
			inv.LimitRanges = qc.LimitRanges()
		}
	case "autoscaling":
		if ac, ok := c.(*AutoscalingCollector); ok {
			inv.PDBs = ac.PDBs()
			inv.HPAs = ac.HPAs()
		}
	case "storage":
		if sc, ok := c.(*StorageCollector); ok {
			inv.Storage = sc.Results().(inventory.StorageInventory)
		}
	case "webhook":
		if wc, ok := c.(*WebhookCollector); ok {
			inv.Webhooks = wc.Results().(inventory.WebhookInventory)
		}
	case "clusterresource":
		if crc, ok := c.(*ClusterResourceCollector); ok {
			inv.PriorityClasses = crc.PriorityClasses()
		}
	case "crd":
		if cc, ok := c.(*CRDCollector); ok {
			inv.CRDs = cc.Results().([]inventory.CRDInfo)
		}
	case "endpoint":
		if ec, ok := c.(*EndpointCollector); ok {
			inv.Endpoints = ec.Results().([]inventory.EndpointInfo)
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
	fmt.Sscanf(val, "%d", &count)
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
