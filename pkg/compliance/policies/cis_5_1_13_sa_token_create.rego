# control_id: CIS-5.1.13
# framework: cis-k8s-1.11
# severity: MEDIUM
package qualys.controls.cis_5_1_13

import future.keywords.in

deny[result] {
    role := input.rbac.roles[_]
    rule := role.rules[_]
    can_create_sa_token(rule)

    result := {
        "message": sprintf("Role '%s/%s' can create service account tokens", [role.namespace, role.name]),
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
    can_create_sa_token(rule)
    not is_system_role(role.name)

    result := {
        "message": sprintf("ClusterRole '%s' can create service account tokens", [role.name]),
        "resource": {
            "kind": "ClusterRole",
            "name": role.name
        },
        "failedPath": "rules[]"
    }
}

can_create_sa_token(rule) {
    "serviceaccounts/token" in rule.resources
    "create" in rule.verbs
}

can_create_sa_token(rule) {
    "serviceaccounts/token" in rule.resources
    "*" in rule.verbs
}

can_create_sa_token(rule) {
    "*" in rule.resources
    "*" in rule.verbs
}

is_system_role(name) {
    startswith(name, "system:")
}

is_system_role(name) {
    name == "cluster-admin"
}
