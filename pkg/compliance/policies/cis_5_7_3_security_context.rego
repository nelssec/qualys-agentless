# control_id: CIS-5.7.3
# framework: cis-k8s-1.11
# severity: MEDIUM
package qualys.controls.cis_5_7_3

deny[result] {
    pod := input.workloads.pods[_]
    not pod.securityContext
    not is_system_namespace(pod.namespace)

    result := {
        "message": sprintf("Pod '%s/%s' does not define a pod security context", [pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "failedPath": "spec.securityContext"
    }
}

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    not container.securityContext
    not is_system_namespace(pod.namespace)

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' does not define a security context", [container.name, pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "container": container.name,
        "failedPath": "spec.containers[].securityContext"
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
