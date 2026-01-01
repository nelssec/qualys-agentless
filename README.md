# Qualys Kubernetes Agentless Scanner

Agentless security scanner for any Kubernetes cluster. Connects via the Kubernetes API to collect inventory and evaluate compliance against CIS benchmarks, NSA-CISA guidelines, and MITRE ATT&CK frameworks.

**Supported Platforms:** EKS, AKS, GKE, OpenShift, Rancher, k3s, k0s, MicroK8s, Kind, Minikube, on-prem, any CNCF-conformant Kubernetes

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/nelssec/qualys-agentless/main/install.sh | sh
```

Homebrew (macOS/Linux):

```bash
brew tap nelssec/tap
brew install qualys-k8s
```

Or download directly:

```bash
curl -fsSL https://github.com/nelssec/qualys-agentless/releases/latest/download/qualys-k8s-linux-amd64 -o qualys-k8s
chmod +x qualys-k8s
```

## Usage

```bash
# Scan live cluster
qualys-k8s scan
qualys-k8s scan --output json --output-file results.json

# Scan YAML manifests (shift-left)
qualys-k8s scan-manifest deployment.yaml
qualys-k8s scan-manifest ./manifests/
qualys-k8s scan-manifest deployment.yaml --output sarif

# Scan Helm charts
qualys-k8s scan-helm ./my-chart
qualys-k8s scan-helm ./my-chart -f values-prod.yaml
qualys-k8s scan-helm ./my-chart --set image.tag=v1.0.0
qualys-k8s scan-helm nginx-15.0.0.tgz

# Cloud providers
qualys-k8s scan --provider aws --cluster my-cluster --region us-west-2
qualys-k8s scan --provider azure --subscription XXX --cluster rg/cluster
qualys-k8s scan --provider gcp --project my-project --cluster projects/x/locations/y/clusters/z

# List frameworks and controls
qualys-k8s frameworks list
qualys-k8s controls list --framework cis-k8s-1.11

# CI/CD with thresholds
qualys-k8s scan --compliance-threshold 80           # Fail if score < 80%
qualys-k8s scan --severity-threshold high           # Fail if any high/critical findings
qualys-k8s scan-manifest ./manifests --output junit # JUnit for CI test reporting
```

## Authentication

| Platform | Credentials |
|----------|-------------|
| Any K8s (kubeconfig) | `~/.kube/config` or `--kubeconfig` |
| OpenShift | `oc login` then use kubeconfig |
| Rancher | Download kubeconfig from Rancher UI |
| k3s | `/etc/rancher/k3s/k3s.yaml` |
| AWS EKS | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` |
| Azure AKS | `AZURE_CLIENT_ID` + `AZURE_TENANT_ID` + `AZURE_CLIENT_SECRET` |
| GCP GKE | `GOOGLE_APPLICATION_CREDENTIALS` |

## Data Collection

17 collectors gather metadata from the Kubernetes API:

| Category | Resources |
|----------|-----------|
| Cluster | Version, API endpoint, node count |
| Nodes | Labels, taints, conditions, capacity |
| Workloads | Pods, Deployments, DaemonSets, StatefulSets, Jobs, CronJobs |
| RBAC | Roles, ClusterRoles, RoleBindings, ClusterRoleBindings |
| Network | Services, Ingresses, NetworkPolicies, Endpoints |
| Identity | ServiceAccounts |
| Config | ConfigMaps (keys only), Secrets (metadata only) |
| Events | Recent cluster events |
| Quotas | ResourceQuotas, LimitRanges |
| Autoscaling | HPAs, PodDisruptionBudgets |
| Storage | PVs, PVCs, StorageClasses |
| Admission | ValidatingWebhooks, MutatingWebhooks |
| Extensions | CRDs, PriorityClasses |

Secret values and ConfigMap values are never collected.

## Frameworks

| Framework | ID |
|-----------|---------|
| CIS Kubernetes Benchmark v1.10 | cis-k8s-1.10 |
| CIS Kubernetes Benchmark v1.11 | cis-k8s-1.11 |
| CIS Amazon EKS Benchmark v1.6 | cis-eks-1.6 |
| CIS Azure AKS Benchmark v1.6 | cis-aks-1.6 |
| CIS Red Hat OpenShift v1.7 | cis-ocp-1.7 |
| Kubernetes Best Practices | k8s-best-practices |
| AWS EKS Best Practices | eks-best-practices |
| Azure AKS Best Practices | aks-best-practices |
| Red Hat OpenShift Best Practices | ocp-best-practices |
| NSA/CISA Kubernetes Hardening | nsa-cisa |
| MITRE ATT&CK for Kubernetes | mitre-attack |

## Build

```bash
make build              # Local dev build (~70MB, native platform)
make build-linux        # Full build + UPX compression (~13MB)
make build-nohelm       # Without Helm SDK + UPX (~11MB)
make build-minimal      # Kubeconfig-only + UPX (~10MB)
make build-aws-only     # EKS auth only + UPX
make build-azure-only   # AKS auth only + UPX
make build-gcp-only     # GKE auth only + UPX
make build-all          # Cross-compile all platforms
```

The minimal build works with any Kubernetes cluster via kubeconfig. The cloud SDKs (AWS/Azure/GCP) are only needed for automatic credential fetching from managed services.

## Limitations

Agentless scanning covers controls accessible via the Kubernetes API. Host-level checks (kubelet configuration, file permissions, container runtime settings) require node access and are not supported.

## License

Apache License 2.0
