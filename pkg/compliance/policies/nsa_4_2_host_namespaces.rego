# control_id: NSA-4.2
# framework: nsa-cisa
# severity: HIGH
package qualys.controls.nsa_4_2

deny[result] {
    pod := input.workloads.pods[_]
    pod.hostNetwork == true
    not is_system_namespace(pod.namespace)

    result := {
        "message": sprintf("Pod '%s/%s' uses hostNetwork", [pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "failedPath": "spec.hostNetwork"
    }
}

deny[result] {
    pod := input.workloads.pods[_]
    pod.hostPID == true
    not is_system_namespace(pod.namespace)

    result := {
        "message": sprintf("Pod '%s/%s' uses hostPID", [pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "failedPath": "spec.hostPID"
    }
}

deny[result] {
    pod := input.workloads.pods[_]
    pod.hostIPC == true
    not is_system_namespace(pod.namespace)

    result := {
        "message": sprintf("Pod '%s/%s' uses hostIPC", [pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "failedPath": "spec.hostIPC"
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
