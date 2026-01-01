# control_id: CIS-5.2.4
# framework: cis-k8s-1.11
# severity: HIGH
package qualys.controls.cis_5_2_4

deny[result] {
    pod := input.workloads.pods[_]
    pod.hostNetwork == true

    result := {
        "message": sprintf("Pod '%s/%s' shares the host network namespace", [pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "failedPath": "spec.hostNetwork"
    }
}
