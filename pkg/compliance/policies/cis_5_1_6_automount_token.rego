# control_id: CIS-5.1.6
# framework: cis-k8s-1.11
# severity: MEDIUM
package qualys.controls.cis_5_1_6

deny[result] {
    pod := input.workloads.pods[_]
    pod.automountServiceAccountToken == true
    not is_system_namespace(pod.namespace)

    result := {
        "message": sprintf("Pod '%s/%s' automounts service account token", [pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "serviceAccount": object.get(pod, "serviceAccount", "default"),
        "failedPath": "spec.automountServiceAccountToken"
    }
}

deny[result] {
    sa := input.serviceAccounts[_]
    sa.automountServiceAccountToken == true
    not is_system_namespace(sa.namespace)

    result := {
        "message": sprintf("ServiceAccount '%s/%s' has automountServiceAccountToken enabled", [sa.namespace, sa.name]),
        "resource": {
            "kind": "ServiceAccount",
            "name": sa.name,
            "namespace": sa.namespace
        },
        "failedPath": "automountServiceAccountToken"
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
