# control_id: CIS-5.1.9
# framework: cis-k8s-1.11
# severity: MEDIUM
package qualys.controls.cis_5_1_9

import future.keywords.in

deny[result] {
    role := input.rbac.roles[_]
    rule := role.rules[_]
    can_create_pv(rule)

    result := {
        "message": sprintf("Role '%s/%s' can create persistent volumes", [role.namespace, role.name]),
        "resource": {
            "kind": "Role",
            "name": role.name,
            "namespace": role.namespace
        },
        "failedPath": "rules[]"
    }
}

deny[result] {
    role := input.rbac.clusterRoles[_]
    rule := role.rules[_]
    can_create_pv(rule)
    not is_system_role(role.name)

    result := {
        "message": sprintf("ClusterRole '%s' can create persistent volumes", [role.name]),
        "resource": {
            "kind": "ClusterRole",
            "name": role.name
        },
        "failedPath": "rules[]"
    }
}

can_create_pv(rule) {
    "persistentvolumes" in rule.resources
    "create" in rule.verbs
}

can_create_pv(rule) {
    "*" in rule.resources
    "create" in rule.verbs
}

can_create_pv(rule) {
    "persistentvolumes" in rule.resources
    "*" in rule.verbs
}

can_create_pv(rule) {
    "*" in rule.resources
    "*" in rule.verbs
}

is_system_role(name) {
    startswith(name, "system:")
}

is_system_role(name) {
    name == "cluster-admin"
}
