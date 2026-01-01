# control_id: CIS-5.1.10
# framework: cis-k8s-1.11
# severity: MEDIUM
package qualys.controls.cis_5_1_10

import future.keywords.in

deny[result] {
    role := input.rbac.clusterRoles[_]
    rule := role.rules[_]
    can_proxy_nodes(rule)
    not is_system_role(role.name)

    result := {
        "message": sprintf("ClusterRole '%s' can access proxy sub-resource of nodes", [role.name]),
        "resource": {
            "kind": "ClusterRole",
            "name": role.name
        },
        "failedPath": "rules[]"
    }
}

can_proxy_nodes(rule) {
    "nodes" in rule.resources
    "proxy" in rule.resources
}

can_proxy_nodes(rule) {
    "nodes/proxy" in rule.resources
}

can_proxy_nodes(rule) {
    "*" in rule.resources
}

is_system_role(name) {
    startswith(name, "system:")
}

is_system_role(name) {
    name == "cluster-admin"
}
