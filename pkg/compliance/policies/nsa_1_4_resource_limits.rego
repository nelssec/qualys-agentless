# control_id: NSA-1.4
# framework: nsa-cisa
# severity: MEDIUM
package qualys.controls.nsa_1_4

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    not has_resource_limits(container)
    not is_system_namespace(pod.namespace)

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' has no resource limits", [container.name, pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "container": container.name,
        "failedPath": "spec.containers[].resources.limits"
    }
}

has_resource_limits(container) {
    container.resources.limits.cpu
}

has_resource_limits(container) {
    container.resources.limits.memory
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
