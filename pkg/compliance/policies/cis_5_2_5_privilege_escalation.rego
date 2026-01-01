# control_id: CIS-5.2.5
# framework: cis-k8s-1.11
# severity: HIGH
package qualys.controls.cis_5_2_5

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    container.securityContext.allowPrivilegeEscalation == true

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' allows privilege escalation", [container.name, pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "container": container.name,
        "failedPath": "spec.containers[].securityContext.allowPrivilegeEscalation"
    }
}

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    not container.securityContext

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' has no security context defined", [container.name, pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "container": container.name,
        "failedPath": "spec.containers[].securityContext"
    }
}
