# control_id: NSA-4.4
# framework: nsa-cisa
# severity: HIGH
package qualys.controls.nsa_4_4

deny[result] {
    pod := input.workloads.pods[_]
    volume := pod.volumes[_]
    volume.type == "hostPath"
    not is_system_namespace(pod.namespace)

    result := {
        "message": sprintf("Pod '%s/%s' uses hostPath volume '%s'", [pod.namespace, pod.name, volume.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "volume": volume.name,
        "failedPath": "spec.volumes[].hostPath"
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
