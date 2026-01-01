# control_id: CIS-5.2.13
# framework: cis-k8s-1.11
# severity: MEDIUM
package qualys.controls.cis_5_2_13

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    port := container.ports[_]
    port.hostPort > 0

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' uses hostPort %d", [container.name, pod.namespace, pod.name, port.hostPort]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "container": container.name,
        "hostPort": port.hostPort,
        "failedPath": "spec.containers[].ports[].hostPort"
    }
}
