# control_id: NSA-1.2
# framework: nsa-cisa
# severity: MEDIUM
package qualys.controls.nsa_1_2

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    not runs_as_non_root(pod, container)
    not is_system_namespace(pod.namespace)

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' may run as root", [container.name, pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "container": container.name,
        "failedPath": "spec.containers[].securityContext.runAsNonRoot"
    }
}

runs_as_non_root(pod, container) {
    container.securityContext.runAsNonRoot == true
}

runs_as_non_root(pod, container) {
    pod.securityContext.runAsNonRoot == true
    not container.securityContext.runAsNonRoot == false
}

runs_as_non_root(pod, container) {
    container.securityContext.runAsUser > 0
}

runs_as_non_root(pod, container) {
    pod.securityContext.runAsUser > 0
    not container.securityContext.runAsUser == 0
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
