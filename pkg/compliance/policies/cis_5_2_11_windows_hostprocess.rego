# control_id: CIS-5.2.11
# framework: cis-k8s-1.11
# severity: HIGH
package qualys.controls.cis_5_2_11

deny[result] {
    pod := input.workloads.pods[_]
    pod.securityContext.windowsOptions.hostProcess == true

    result := {
        "message": sprintf("Pod '%s/%s' has Windows HostProcess enabled at pod level", [pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "failedPath": "spec.securityContext.windowsOptions.hostProcess"
    }
}

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    container.securityContext.windowsOptions.hostProcess == true

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' has Windows HostProcess enabled", [container.name, pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "failedPath": "spec.containers[].securityContext.windowsOptions.hostProcess"
    }
}
