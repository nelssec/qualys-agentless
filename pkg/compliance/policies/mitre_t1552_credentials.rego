# control_id: MITRE-T1552
# framework: mitre-attack
# severity: HIGH
package qualys.controls.mitre_t1552

deny[result] {
    pod := input.workloads.pods[_]
    pod.automountServiceAccountToken == true
    not is_system_namespace(pod.namespace)

    result := {
        "message": sprintf("Pod '%s/%s' automounts service account token (credential exposure risk)", [pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "tactic": "Credential Access",
        "failedPath": "spec.automountServiceAccountToken"
    }
}

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    env := container.env[_]
    env.valueFrom.secretKeyRef
    not is_system_namespace(pod.namespace)

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' exposes secret as environment variable (credential exposure risk)", [container.name, pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "container": container.name,
        "secret": env.valueFrom.secretKeyRef.name,
        "tactic": "Credential Access",
        "failedPath": "spec.containers[].env[].valueFrom.secretKeyRef"
    }
}

is_system_namespace(ns) {
    ns == "kube-system"
}

is_system_namespace(ns) {
    ns == "kube-public"
}

is_system_namespace(ns) {
    ns == "kube-node-lease"
}
