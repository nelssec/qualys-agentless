# control_id: CIS-5.2.12
# framework: cis-k8s-1.11
# severity: MEDIUM
package qualys.controls.cis_5_2_12

deny[result] {
    pod := input.workloads.pods[_]
    volume := pod.volumes[_]
    volume.hostPath

    result := {
        "message": sprintf("Pod '%s/%s' mounts hostPath volume '%s' at '%s'", [pod.namespace, pod.name, volume.name, volume.hostPath.path]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "volume": volume.name,
        "hostPath": volume.hostPath.path,
        "failedPath": "spec.volumes[].hostPath"
    }
}
