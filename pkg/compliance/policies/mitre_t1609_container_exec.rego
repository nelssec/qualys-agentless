# control_id: MITRE-T1609
# framework: mitre-attack
# severity: HIGH
package qualys.controls.mitre_t1609

deny[result] {
    role := input.rbac.clusterRoles[_]
    rule := role.rules[_]
    can_exec_pods(rule)

    result := {
        "message": sprintf("ClusterRole '%s' can exec into pods (container administration command)", [role.name]),
        "resource": {
            "kind": "ClusterRole",
            "name": role.name
        },
        "tactic": "Execution",
        "technique": "Container Administration Command",
        "failedPath": "rules[].resources"
    }
}

deny[result] {
    role := input.rbac.roles[_]
    rule := role.rules[_]
    can_exec_pods(rule)
    not is_system_namespace(role.namespace)

    result := {
        "message": sprintf("Role '%s/%s' can exec into pods (container administration command)", [role.namespace, role.name]),
        "resource": {
            "kind": "Role",
            "name": role.name,
            "namespace": role.namespace
        },
        "tactic": "Execution",
        "technique": "Container Administration Command",
        "failedPath": "rules[].resources"
    }
}

can_exec_pods(rule) {
    rule.resources[_] == "pods/exec"
    rule.verbs[_] == "create"
}

can_exec_pods(rule) {
    rule.resources[_] == "pods/exec"
    rule.verbs[_] == "*"
}

can_exec_pods(rule) {
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
