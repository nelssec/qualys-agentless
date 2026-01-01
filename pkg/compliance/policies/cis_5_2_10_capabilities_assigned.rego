# control_id: CIS-5.2.10
# framework: cis-k8s-1.11
# severity: MEDIUM
package qualys.controls.cis_5_2_10

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    container.securityContext.capabilities
    has_any_capabilities(container.securityContext.capabilities)

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' has capabilities assigned", [container.name, pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "failedPath": "spec.containers[].securityContext.capabilities"
    }
}

has_any_capabilities(caps) {
    count(caps.add) > 0
}

has_any_capabilities(caps) {
    count(caps.drop) < 1
    not drops_all(caps)
}

drops_all(caps) {
    caps.drop[_] == "ALL"
}

drops_all(caps) {
    caps.drop[_] == "all"
}
