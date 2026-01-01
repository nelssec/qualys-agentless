# control_id: CIS-5.1.11
# framework: cis-k8s-1.11
# severity: HIGH
package qualys.controls.cis_5_1_11

import future.keywords.in

deny[result] {
    role := input.rbac.clusterRoles[_]
    rule := role.rules[_]
    can_approve_csr(rule)
    not is_system_role(role.name)

    result := {
        "message": sprintf("ClusterRole '%s' can approve certificate signing requests", [role.name]),
        "resource": {
            "kind": "ClusterRole",
            "name": role.name
        },
        "failedPath": "rules[]"
    }
}

can_approve_csr(rule) {
    "certificatesigningrequests/approval" in rule.resources
}

can_approve_csr(rule) {
    "certificatesigningrequests" in rule.resources
    "approve" in rule.verbs
}

can_approve_csr(rule) {
    "*" in rule.resources
    "*" in rule.verbs
}

is_system_role(name) {
    startswith(name, "system:")
}

is_system_role(name) {
    name == "cluster-admin"
}
