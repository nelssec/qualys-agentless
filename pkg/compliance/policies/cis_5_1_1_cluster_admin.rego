# control_id: CIS-5.1.1
# framework: cis-k8s-1.11
# severity: HIGH
package qualys.controls.cis_5_1_1

deny[result] {
    binding := input.rbac.clusterRoleBindings[_]
    binding.roleRef.name == "cluster-admin"
    subject := binding.subjects[_]
    not is_system_subject(subject)

    result := {
        "message": sprintf("ClusterRoleBinding '%s' grants cluster-admin to '%s/%s'", [binding.name, subject.kind, subject.name]),
        "resource": {
            "kind": "ClusterRoleBinding",
            "name": binding.name
        },
        "subject": {
            "kind": subject.kind,
            "name": subject.name,
            "namespace": object.get(subject, "namespace", "")
        },
        "failedPath": "subjects"
    }
}

is_system_subject(subject) {
    startswith(subject.name, "system:")
}

is_system_subject(subject) {
    subject.namespace == "kube-system"
}
