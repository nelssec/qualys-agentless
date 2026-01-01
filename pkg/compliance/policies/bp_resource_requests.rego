# control_id: KBP-006
# framework: k8s-best-practices
# severity: MEDIUM
package qualys.controls.kbp_006

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    not container.resources.requests.cpu
    not is_system_namespace(pod.namespace)

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' has no CPU request defined", [container.name, pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "container": container.name,
        "failedPath": "spec.containers[].resources.requests.cpu"
    }
}

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    not container.resources.requests.memory
    not is_system_namespace(pod.namespace)

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' has no memory request defined", [container.name, pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "container": container.name,
        "failedPath": "spec.containers[].resources.requests.memory"
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
