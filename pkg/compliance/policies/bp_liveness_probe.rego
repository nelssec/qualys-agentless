# control_id: KBP-007
# framework: k8s-best-practices
# severity: MEDIUM
package qualys.controls.kbp_007

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    not container.livenessProbe
    not is_system_namespace(pod.namespace)

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' has no liveness probe defined", [container.name, pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "container": container.name,
        "failedPath": "spec.containers[].livenessProbe"
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
