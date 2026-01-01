# control_id: CIS-5.4.1
# framework: cis-k8s-1.11
# severity: MEDIUM
package qualys.controls.cis_5_4_1

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    env := container.env[_]
    env.valueFrom.secretKeyRef

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' uses secret '%s' as environment variable", [container.name, pod.namespace, pod.name, env.valueFrom.secretKeyRef.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "container": container.name,
        "secret": env.valueFrom.secretKeyRef.name,
        "envVar": env.name,
        "failedPath": "spec.containers[].env[].valueFrom.secretKeyRef"
    }
}

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    envFrom := container.envFrom[_]
    envFrom.secretRef

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' uses secret '%s' as envFrom", [container.name, pod.namespace, pod.name, envFrom.secretRef.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "container": container.name,
        "secret": envFrom.secretRef.name,
        "failedPath": "spec.containers[].envFrom[].secretRef"
    }
}
