# control_id: CIS-5.2.8
# framework: cis-k8s-1.11
# severity: MEDIUM
package qualys.controls.cis_5_2_8

import future.keywords.in

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    cap := container.securityContext.capabilities.add[_]
    cap == "NET_RAW"

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' adds NET_RAW capability", [container.name, pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "container": container.name,
        "failedPath": "spec.containers[].securityContext.capabilities.add"
    }
}

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    container.securityContext.capabilities
    not drops_net_raw(container)
    not drops_all(container)

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' does not drop NET_RAW capability", [container.name, pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "container": container.name,
        "failedPath": "spec.containers[].securityContext.capabilities.drop"
    }
}

drops_net_raw(container) {
    drop := container.securityContext.capabilities.drop[_]
    drop == "NET_RAW"
}

drops_all(container) {
    drop := container.securityContext.capabilities.drop[_]
    lower(drop) == "all"
}
