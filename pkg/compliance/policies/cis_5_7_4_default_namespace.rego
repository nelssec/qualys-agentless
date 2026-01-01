# control_id: CIS-5.7.4
# framework: cis-k8s-1.11
# severity: LOW
package qualys.controls.cis_5_7_4

deny[result] {
    pod := input.workloads.pods[_]
    pod.namespace == "default"

    result := {
        "message": sprintf("Pod '%s' is deployed in the default namespace", [pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": "default"
        },
        "failedPath": "metadata.namespace"
    }
}

deny[result] {
    svc := input.services[_]
    svc.namespace == "default"
    svc.name != "kubernetes"

    result := {
        "message": sprintf("Service '%s' is deployed in the default namespace", [svc.name]),
        "resource": {
            "kind": "Service",
            "name": svc.name,
            "namespace": "default"
        },
        "failedPath": "metadata.namespace"
    }
}
