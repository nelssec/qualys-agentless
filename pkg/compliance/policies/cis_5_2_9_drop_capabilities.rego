# control_id: CIS-5.2.9
# framework: cis-k8s-1.11
# severity: MEDIUM
package qualys.controls.cis_5_2_9

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    count(container.securityContext.capabilities.add) > 0
    not drops_all(container)

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' adds capabilities without dropping all first", [container.name, pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "container": container.name,
        "failedPath": "spec.containers[].securityContext.capabilities"
    }
}

drops_all(container) {
    drop := container.securityContext.capabilities.drop[_]
    lower(drop) == "all"
}
