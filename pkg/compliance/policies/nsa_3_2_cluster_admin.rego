# control_id: NSA-3.2
# framework: nsa-cisa
# severity: HIGH
package qualys.controls.nsa_3_2

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
            "name": subject.name
        },
        "failedPath": "subjects"
    }
}

is_system_subject(subject) {
    subject.namespace == "kube-system"
}

is_system_subject(subject) {
    startswith(subject.name, "system:")
}
