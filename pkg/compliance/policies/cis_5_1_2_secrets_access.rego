# control_id: CIS-5.1.2
# framework: cis-k8s-1.11
# severity: HIGH
package qualys.controls.cis_5_1_2

import future.keywords.in

deny[result] {
    role := input.rbac.roles[_]
    rule := role.rules[_]
    "secrets" in rule.resources
    has_broad_access(rule.verbs)

    result := {
        "message": sprintf("Role '%s/%s' has broad access to secrets", [role.namespace, role.name]),
        "resource": {
            "kind": "Role",
            "name": role.name,
            "namespace": role.namespace
        },
        "verbs": rule.verbs,
        "failedPath": "rules[].resources"
    }
}

deny[result] {
    role := input.rbac.clusterRoles[_]
    rule := role.rules[_]
    "secrets" in rule.resources
    has_broad_access(rule.verbs)
    not is_system_role(role.name)

    result := {
        "message": sprintf("ClusterRole '%s' has broad access to secrets", [role.name]),
        "resource": {
            "kind": "ClusterRole",
            "name": role.name
        },
        "verbs": rule.verbs,
        "failedPath": "rules[].resources"
    }
}

has_broad_access(verbs) {
    "*" in verbs
}

has_broad_access(verbs) {
    "get" in verbs
    "list" in verbs
}

is_system_role(name) {
    startswith(name, "system:")
}
