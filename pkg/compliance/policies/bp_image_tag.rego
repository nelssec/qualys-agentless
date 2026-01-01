# control_id: KBP-009
# framework: k8s-best-practices
# severity: MEDIUM
package qualys.controls.kbp_009

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    uses_latest_tag(container.image)

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' uses latest tag or no tag", [container.name, pod.namespace, pod.name]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "container": container.name,
        "image": container.image,
        "failedPath": "spec.containers[].image"
    }
}

uses_latest_tag(image) {
    endswith(image, ":latest")
}

uses_latest_tag(image) {
    not contains(image, ":")
}

uses_latest_tag(image) {
    parts := split(image, ":")
    count(parts) == 2
    parts[1] == ""
}
