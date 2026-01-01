# Agentless Kubernetes Security Scanning

## Problem

Traditional Kubernetes security tools deploy agents into every cluster. For organizations with hundreds of clusters across cloud providers, this creates operational overhead: agent maintenance, resource consumption, and additional attack surface.

## Approach

This scanner connects remotely via the Kubernetes API. No pods, daemonsets, or sidecars are deployed to target clusters.

```mermaid
flowchart LR
    subgraph External
        SCANNER[Scanner]
    end

    subgraph Kubernetes
        API[API Server]
        PODS[Pods]
        RBAC[RBAC]
        NP[NetworkPolicies]
    end

    SCANNER -->|HTTPS| API
    API --> PODS
    API --> RBAC
    API --> NP
```

The scanner makes read-only API calls to collect inventory, then evaluates against security policies locally.

## Authentication

All authentication uses short-lived tokens.

### AWS EKS

```mermaid
sequenceDiagram
    participant S as Scanner
    participant STS as AWS STS
    participant EKS as EKS API

    S->>STS: AssumeRole
    STS-->>S: Temporary credentials
    S->>STS: Presign GetCallerIdentity
    STS-->>S: Presigned URL
    S->>EKS: API request + bearer token
    EKS-->>S: Resources
```

Uses the same token mechanism as aws-iam-authenticator. Creates a presigned STS GetCallerIdentity request encoded as a Kubernetes bearer token.

### Azure AKS

```mermaid
sequenceDiagram
    participant S as Scanner
    participant AAD as Azure AD
    participant AKS as AKS API

    S->>AAD: Get token via Workload Identity
    AAD-->>S: OAuth token
    S->>AKS: API request + token
    AKS-->>S: Resources
```

Uses Azure AD tokens from Managed Identity or Workload Identity.

### GCP GKE

```mermaid
sequenceDiagram
    participant S as Scanner
    participant GCP as GCP IAM
    participant GKE as GKE API

    S->>GCP: Get access token
    GCP-->>S: OAuth2 token
    S->>GKE: API request + token
    GKE-->>S: Resources
```

Uses OAuth2 tokens from Application Default Credentials or Workload Identity Federation.

## Data Collection

| Collected | Not Collected |
|-----------|---------------|
| Pods, Deployments | Secret values |
| RBAC rules | ConfigMap values |
| NetworkPolicies | Pod logs |
| ServiceAccounts | Pod exec |
| Secret metadata | Environment values |

## Compliance Evaluation

OPA/Rego policies evaluate collected resources against security frameworks.

```mermaid
flowchart LR
    INV[Inventory] --> OPA[OPA Engine]
    CIS[CIS] --> OPA
    NSA[NSA-CISA] --> OPA
    MITRE[MITRE] --> OPA
    OPA --> FINDINGS[Findings]
```

### Policy Example

```rego
deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    container.securityContext.privileged == true

    result := {
        "message": "Container runs in privileged mode",
        "resource": {"kind": "Pod", "name": pod.name}
    }
}
```

### Frameworks

- CIS Kubernetes Benchmark v1.10.0, v1.11.0
- CIS EKS Benchmark v1.6.0
- CIS AKS Benchmark v1.6.0
- CIS OpenShift Benchmark v1.7.0
- Kubernetes/EKS/AKS/OpenShift Best Practices
- NSA/CISA Kubernetes Hardening Guide
- MITRE ATT&CK for Kubernetes

## RBAC

ClusterRole grants only get and list verbs:

```mermaid
flowchart TB
    subgraph Granted
        GET[get]
        LIST[list]
    end

    subgraph Denied
        CREATE[create]
        UPDATE[update]
        DELETE[delete]
        EXEC[pods/exec]
    end

    style GET fill:#90EE90
    style LIST fill:#90EE90
    style CREATE fill:#FFB6C1
    style UPDATE fill:#FFB6C1
    style DELETE fill:#FFB6C1
    style EXEC fill:#FFB6C1
```

## Deployment

```mermaid
flowchart LR
    subgraph CLI
        LAPTOP[Workstation] --> CLUSTER1[Cluster]
    end

    subgraph CICD
        PIPELINE[Pipeline] --> CLUSTER2[Staging]
    end

    subgraph Daemon
        SERVER[Server] --> CLUSTER3[Production]
    end
```

1. CLI: On-demand scans
2. CI/CD: Pre-deployment checks
3. Daemon: Scheduled scanning

## Security Controls

| Control | Implementation |
|---------|----------------|
| Zero credential storage | IAM roles, Workload Identity |
| Read-only access | get/list verbs only |
| Minimal data collection | No secret values |
| Network encryption | TLS 1.2+ |
| Credentials | Environment variables only |
