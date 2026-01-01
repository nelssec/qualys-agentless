# control_id: MITRE-T1611
# framework: mitre-attack
# severity: CRITICAL
package qualys.controls.mitre_t1611

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    container.securityContext.privileged == true

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' is privileged (container escape risk)", [container.name, pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "container": container.name,
        "tactic": "Privilege Escalation",
        "failedPath": "spec.containers[].securityContext.privileged"
    }
}

deny[result] {
    pod := input.workloads.pods[_]
    pod.hostPID == true

    result := {
        "message": sprintf("Pod '%s/%s' shares host PID namespace (container escape risk)", [pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "tactic": "Privilege Escalation",
        "failedPath": "spec.hostPID"
    }
}

deny[result] {
    pod := input.workloads.pods[_]
    pod.hostNetwork == true

    result := {
        "message": sprintf("Pod '%s/%s' shares host network namespace (container escape risk)", [pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "tactic": "Privilege Escalation",
        "failedPath": "spec.hostNetwork"
    }
}
