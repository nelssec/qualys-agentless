# control_id: CIS-5.7.2
# framework: cis-k8s-1.11
# severity: MEDIUM
package qualys.controls.cis_5_7_2

deny[result] {
    pod := input.workloads.pods[_]
    not has_seccomp_profile(pod)

    result := {
        "message": sprintf("Pod '%s/%s' does not have a seccomp profile set", [pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "failedPath": "spec.securityContext.seccompProfile"
    }
}

has_seccomp_profile(pod) {
    pod.securityContext.seccompProfile.type
}

has_seccomp_profile(pod) {
    pod.annotations["seccomp.security.alpha.kubernetes.io/pod"]
}

has_seccomp_profile(pod) {
    container := pod.containers[_]
    container.securityContext.seccompProfile.type
}
