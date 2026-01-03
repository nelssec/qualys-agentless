# control_id: NSA-4.3
# framework: nsa-cisa
# severity: MEDIUM
package qualys.controls.nsa_4_3

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    not drops_all_capabilities(container)
    not is_system_namespace(pod.namespace)

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' does not drop all capabilities", [container.name, pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "container": container.name,
        "failedPath": "spec.containers[].securityContext.capabilities.drop"
    }
}

drops_all_capabilities(container) {
    container.securityContext.capabilities.drop[_] == "ALL"
}

drops_all_capabilities(container) {
    container.securityContext.capabilities.drop[_] == "all"
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
