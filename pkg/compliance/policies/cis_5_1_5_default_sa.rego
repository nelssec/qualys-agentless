# control_id: CIS-5.1.5
# framework: cis-k8s-1.11
# severity: MEDIUM
package qualys.controls.cis_5_1_5

deny[result] {
    pod := input.workloads.pods[_]
    pod.serviceAccount == "default"
    not is_system_namespace(pod.namespace)

    result := {
        "message": sprintf("Pod '%s/%s' uses the default service account", [pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "failedPath": "spec.serviceAccountName"
    }
}

deny[result] {
    pod := input.workloads.pods[_]
    not pod.serviceAccount
    not is_system_namespace(pod.namespace)

    result := {
        "message": sprintf("Pod '%s/%s' does not specify a service account (uses default)", [pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "failedPath": "spec.serviceAccountName"
    }
}

is_system_namespace(ns) {
    ns == "kube-system"
}

is_system_namespace(ns) {
    ns == "kube-public"
}

is_system_namespace(ns) {
    ns == "kube-node-lease"
}
