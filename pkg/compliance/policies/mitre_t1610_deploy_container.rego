# control_id: MITRE-T1610
# framework: mitre-attack
# severity: HIGH
package qualys.controls.mitre_t1610

deny[result] {
    role := input.rbac.clusterRoles[_]
    rule := role.rules[_]
    can_create_pods(rule)

    result := {
        "message": sprintf("ClusterRole '%s' can create pods (potential malicious container deployment)", [role.name]),
        "resource": {
            "kind": "ClusterRole",
            "name": role.name
        },
        "tactic": "Execution",
        "failedPath": "rules[].verbs"
    }
}

deny[result] {
    role := input.rbac.roles[_]
    rule := role.rules[_]
    can_create_pods(rule)
    not is_system_namespace(role.namespace)

    result := {
        "message": sprintf("Role '%s/%s' can create pods (potential malicious container deployment)", [role.namespace, role.name]),
        "resource": {
            "kind": "Role",
            "name": role.name,
            "namespace": role.namespace
        },
        "tactic": "Execution",
        "failedPath": "rules[].verbs"
    }
}

can_create_pods(rule) {
    rule.resources[_] == "pods"
    rule.verbs[_] == "create"
}

can_create_pods(rule) {
    rule.resources[_] == "pods"
    rule.verbs[_] == "*"
}

can_create_pods(rule) {
    rule.resources[_] == "*"
    rule.verbs[_] == "create"
}

can_create_pods(rule) {
    rule.resources[_] == "*"
    rule.verbs[_] == "*"
}

is_system_namespace(ns) {
    ns == "kube-system"
}

is_system_namespace(ns) {
    ns == "kube-public"
}

is_system_namespace(ns) {
    ns == "kube-node-lease"
}
