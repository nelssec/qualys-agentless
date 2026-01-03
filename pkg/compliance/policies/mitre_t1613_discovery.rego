# control_id: MITRE-T1613
# framework: mitre-attack
# severity: MEDIUM
package qualys.controls.mitre_t1613

deny[result] {
    role := input.rbac.clusterRoles[_]
    rule := role.rules[_]
    has_broad_list_permissions(rule)

    result := {
        "message": sprintf("ClusterRole '%s' has broad list/watch permissions (container discovery risk)", [role.name]),
        "resource": {
            "kind": "ClusterRole",
            "name": role.name
        },
        "tactic": "Discovery",
        "technique": "Container and Resource Discovery",
        "failedPath": "rules[].verbs"
    }
}

has_broad_list_permissions(rule) {
    rule.resources[_] == "*"
    rule.verbs[_] == "list"
}

has_broad_list_permissions(rule) {
    rule.resources[_] == "*"
    rule.verbs[_] == "watch"
}

has_broad_list_permissions(rule) {
    rule.resources[_] == "*"
    rule.verbs[_] == "*"
}

has_broad_list_permissions(rule) {
    rule.resources[_] == "secrets"
    rule.verbs[_] == "list"
}

has_broad_list_permissions(rule) {
    rule.resources[_] == "configmaps"
    rule.verbs[_] == "list"
    rule.resources[_] == "secrets"
}
