# control_id: CIS-5.2.1
# framework: cis-k8s-1.11
# severity: HIGH
package qualys.controls.cis_5_2_1

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    container.securityContext.privileged == true

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' runs in privileged mode", [container.name, pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "container": container.name,
        "failedPath": "spec.containers[].securityContext.privileged"
    }
}

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.initContainers[_]
    container.securityContext.privileged == true

    result := {
        "message": sprintf("Init container '%s' in pod '%s/%s' runs in privileged mode", [container.name, pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "container": container.name,
        "failedPath": "spec.initContainers[].securityContext.privileged"
    }
}
