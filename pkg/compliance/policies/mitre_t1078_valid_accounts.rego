# control_id: MITRE-T1078.004
# framework: mitre-attack
# severity: HIGH
package qualys.controls.mitre_t1078

deny[result] {
    binding := input.rbac.clusterRoleBindings[_]
    subject := binding.subjects[_]
    subject.kind == "Group"
    is_default_authenticated_group(subject.name)

    result := {
        "message": sprintf("ClusterRoleBinding '%s' grants access to all authenticated users", [binding.name]),
        "resource": {
            "kind": "ClusterRoleBinding",
            "name": binding.name
        },
        "roleRef": binding.roleRef.name,
        "tactic": "Initial Access",
        "technique": "Valid Accounts: Cloud Accounts",
        "failedPath": "subjects"
    }
}

deny[result] {
    binding := input.rbac.clusterRoleBindings[_]
    subject := binding.subjects[_]
    subject.kind == "Group"
    subject.name == "system:unauthenticated"

    result := {
        "message": sprintf("ClusterRoleBinding '%s' grants access to unauthenticated users", [binding.name]),
        "resource": {
            "kind": "ClusterRoleBinding",
            "name": binding.name
        },
        "roleRef": binding.roleRef.name,
        "tactic": "Initial Access",
        "technique": "Valid Accounts: Default Accounts",
        "failedPath": "subjects"
    }
}

is_default_authenticated_group(name) {
    name == "system:authenticated"
}
