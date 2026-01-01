# CIS Kubernetes Benchmark v1.11 - Controls Reference

## Agentless Coverage

**Sections 1-4**: Require host/node access (file permissions, kubelet args, etcd config)
**Section 5**: Accessible via Kubernetes API ✅

---

## Section 5: Policies (API-Accessible)

### 5.1 RBAC and Service Accounts

| ID | Control | Status | Type |
|----|---------|--------|------|
| 5.1.1 | Ensure cluster-admin role is only used where required | Manual | RBAC |
| 5.1.2 | Minimize access to secrets | Manual | RBAC |
| 5.1.3 | Minimize wildcard use in Roles and ClusterRoles | Manual | RBAC |
| 5.1.4 | Minimize access to create pods | Manual | RBAC |
| 5.1.5 | Ensure default service accounts are not actively used | Manual | SA |
| 5.1.6 | Ensure Service Account Tokens are only mounted where necessary | Manual | SA |
| 5.1.7 | Avoid use of system:masters group | Manual | RBAC |
| 5.1.8 | Limit use of Bind, Impersonate and Escalate permissions | Manual | RBAC |
| 5.1.9 | Minimize access to create persistent volumes | Manual | RBAC |
| 5.1.10 | Minimize access to proxy sub-resource of nodes | Manual | RBAC |
| 5.1.11 | Minimize access to approval sub-resource of CSRs | Manual | RBAC |
| 5.1.12 | Minimize access to webhook configuration objects | Manual | RBAC |
| 5.1.13 | Minimize access to service account token creation | Manual | RBAC |

### 5.2 Pod Security Standards

| ID | Control | Status | Type |
|----|---------|--------|------|
| 5.2.1 | Ensure cluster has at least one active policy control mechanism | Manual | PSS |
| 5.2.2 | Minimize admission of privileged containers | Manual | Pod |
| 5.2.3 | Minimize admission of containers sharing host PID namespace | Manual | Pod |
| 5.2.4 | Minimize admission of containers sharing host IPC namespace | Manual | Pod |
| 5.2.5 | Minimize admission of containers sharing host network namespace | Manual | Pod |
| 5.2.6 | Minimize admission of containers with allowPrivilegeEscalation | Manual | Pod |
| 5.2.7 | Minimize admission of root containers | Manual | Pod |
| 5.2.8 | Minimize admission of containers with NET_RAW capability | Manual | Pod |
| 5.2.9 | Minimize admission of containers with added capabilities | Manual | Pod |
| 5.2.10 | Minimize admission of containers with capabilities assigned | Manual | Pod |
| 5.2.11 | Minimize admission of Windows HostProcess containers | Manual | Pod |
| 5.2.12 | Minimize admission of HostPath volumes | Manual | Pod |
| 5.2.13 | Minimize admission of containers using HostPorts | Manual | Pod |

### 5.3 Network Policies and CNI

| ID | Control | Status | Type |
|----|---------|--------|------|
| 5.3.1 | Ensure CNI in use supports Network Policies | Manual | Net |
| 5.3.2 | Ensure all Namespaces have Network Policies defined | Manual | Net |

### 5.4 Secrets Management

| ID | Control | Status | Type |
|----|---------|--------|------|
| 5.4.1 | Prefer using secrets as files over environment variables | Manual | Secrets |
| 5.4.2 | Consider external secret storage | Manual | Secrets |

### 5.5 Extensible Admission Control

| ID | Control | Status | Type |
|----|---------|--------|------|
| 5.5.1 | Configure Image Provenance using ImagePolicyWebhook | Manual | Admission |

### 5.7 General Policies

| ID | Control | Status | Type |
|----|---------|--------|------|
| 5.7.1 | Create administrative boundaries using namespaces | Manual | NS |
| 5.7.2 | Ensure seccomp profile is set to docker/default | Manual | Pod |
| 5.7.3 | Apply SecurityContext to Pods and Containers | Manual | Pod |
| 5.7.4 | The default namespace should not be used | Manual | NS |

---

## Summary

| Section | Total | Agentless | Notes |
|---------|-------|-----------|-------|
| 1.1 Control Plane Files | 21 | 0 | Requires host access |
| 1.2 API Server | 30 | 0 | Requires process args |
| 1.3 Controller Manager | 7 | 0 | Requires process args |
| 1.4 Scheduler | 2 | 0 | Requires process args |
| 2 etcd | 8 | 0 | Requires host access |
| 3 Control Plane Config | 5 | 0 | Requires audit logs |
| 4.1 Worker Files | 10 | 0 | Requires host access |
| 4.2 Kubelet | 15 | 0 | Requires host access |
| 4.3 kube-proxy | 1 | 0 | Requires host access |
| 5.x Policies | 32 | 32 | **All via K8s API** |

**Total**: ~131 controls, 32 (24%) accessible agentlessly
