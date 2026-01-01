# control_id: CIS-5.1.3
# framework: cis-k8s-1.11
# severity: MEDIUM
package qualys.controls.cis_5_1_3

import future.keywords.in

deny[result] {
    role := input.rbac.roles[_]
    rule := role.rules[_]
    "*" in rule.verbs
    "*" in rule.resources

    result := {
        "message": sprintf("Role '%s/%s' uses wildcards for both verbs and resources", [role.namespace, role.name]),
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
    "*" in rule.verbs
    "*" in rule.resources
    not is_system_role(role.name)

    result := {
        "message": sprintf("ClusterRole '%s' uses wildcards for both verbs and resources", [role.name]),
        "resource": {
            "kind": "ClusterRole",
            "name": role.name
        },
        "failedPath": "rules[]"
    }
}

is_system_role(name) {
    startswith(name, "system:")
}

is_system_role(name) {
    name == "cluster-admin"
}

is_system_role(name) {
    name == "admin"
}

is_system_role(name) {
    name == "edit"
}

is_system_role(name) {
    name == "view"
}
