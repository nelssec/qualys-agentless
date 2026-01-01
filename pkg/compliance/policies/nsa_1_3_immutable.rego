# control_id: NSA-1.3
# framework: nsa-cisa
# severity: MEDIUM
package qualys.controls.nsa_1_3

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    not container.securityContext.readOnlyRootFilesystem == true
    not is_system_namespace(pod.namespace)

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' does not use immutable (read-only) root filesystem", [container.name, pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "container": container.name,
        "failedPath": "spec.containers[].securityContext.readOnlyRootFilesystem"
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
