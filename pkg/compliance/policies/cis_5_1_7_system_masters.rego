# control_id: CIS-5.1.7
# framework: cis-k8s-1.11
# severity: HIGH
package qualys.controls.cis_5_1_7

deny[result] {
    binding := input.rbac.clusterRoleBindings[_]
    subject := binding.subjects[_]
    subject.kind == "Group"
    subject.name == "system:masters"
    not is_default_binding(binding.name)

    result := {
        "message": sprintf("ClusterRoleBinding '%s' binds to system:masters group", [binding.name]),
        "resource": {
            "kind": "ClusterRoleBinding",
            "name": binding.name
        },
        "roleRef": binding.roleRef.name,
        "failedPath": "subjects"
    }
}

is_default_binding(name) {
    name == "cluster-admin"
}
