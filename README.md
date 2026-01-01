# Qualys Kubernetes Agentless Scanner

Agentless security scanner for Kubernetes clusters. Connects via the Kubernetes API to collect inventory and evaluate compliance against CIS benchmarks, NSA-CISA guidelines, and MITRE ATT&CK frameworks.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/nelssec/qualys-agentless/main/install.sh | sh
```

Or download directly:

```bash
curl -fsSL https://github.com/nelssec/qualys-agentless/releases/latest/download/qualys-k8s-linux-amd64 -o qualys-k8s
chmod +x qualys-k8s
```

## Usage

```bash
qualys-k8s scan
qualys-k8s scan --output json --output-file results.json
qualys-k8s scan --provider aws --cluster my-cluster --region us-west-2
qualys-k8s scan --provider azure --subscription XXX --cluster rg/cluster
qualys-k8s scan --provider gcp --project my-project --cluster projects/x/locations/y/clusters/z
qualys-k8s frameworks list
qualys-k8s controls list --framework cis-k8s-1.11
```

## Authentication

| Provider | Credentials |
|----------|-------------|
| Kubeconfig | `~/.kube/config` or `--kubeconfig` |
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
make build              # Full build (~58MB)
make build-small        # Linux + UPX compression (~11MB)
make build-minimal      # No cloud SDKs + UPX (~10MB)
make build-aws-only     # AWS/EKS only
make build-azure-only   # Azure/AKS only
make build-gcp-only     # GCP/GKE only
```

## Limitations

Agentless scanning covers controls accessible via the Kubernetes API. Host-level checks (kubelet configuration, file permissions, container runtime settings) require node access and are not supported.

## License

Apache License 2.0
