# control_id: KBP-005
# framework: k8s-best-practices
# severity: MEDIUM
package qualys.controls.kbp_005

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    not container.resources.limits.cpu
    not is_system_namespace(pod.namespace)

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' has no CPU limit defined", [container.name, pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "container": container.name,
        "failedPath": "spec.containers[].resources.limits.cpu"
    }
}

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    not container.resources.limits.memory
    not is_system_namespace(pod.namespace)

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' has no memory limit defined", [container.name, pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "container": container.name,
        "failedPath": "spec.containers[].resources.limits.memory"
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
