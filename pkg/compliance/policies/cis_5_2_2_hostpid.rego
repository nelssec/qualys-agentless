# control_id: CIS-5.2.2
# framework: cis-k8s-1.11
# severity: HIGH
package qualys.controls.cis_5_2_2

deny[result] {
    pod := input.workloads.pods[_]
    pod.hostPID == true

    result := {
        "message": sprintf("Pod '%s/%s' shares the host PID namespace", [pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "failedPath": "spec.hostPID"
    }
}
