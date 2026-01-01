# control_id: CIS-5.2.3
# framework: cis-k8s-1.11
# severity: HIGH
package qualys.controls.cis_5_2_3

deny[result] {
    pod := input.workloads.pods[_]
    pod.hostIPC == true

    result := {
        "message": sprintf("Pod '%s/%s' shares the host IPC namespace", [pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "failedPath": "spec.hostIPC"
    }
}
