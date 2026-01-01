# control_id: CIS-5.1.8
# framework: cis-k8s-1.11
# severity: HIGH
package qualys.controls.cis_5_1_8

import future.keywords.in

dangerous_verbs := {"bind", "escalate", "impersonate"}

deny[result] {
    role := input.rbac.clusterRoles[_]
    rule := role.rules[_]
    verb := rule.verbs[_]
    lower(verb) in dangerous_verbs
    not is_system_role(role.name)

    result := {
        "message": sprintf("ClusterRole '%s' has dangerous verb '%s'", [role.name, verb]),
        "resource": {
            "kind": "ClusterRole",
            "name": role.name
        },
        "verb": verb,
        "failedPath": "rules[].verbs"
    }
}

deny[result] {
    role := input.rbac.roles[_]
    rule := role.rules[_]
    verb := rule.verbs[_]
    lower(verb) in dangerous_verbs

    result := {
        "message": sprintf("Role '%s/%s' has dangerous verb '%s'", [role.namespace, role.name, verb]),
        "resource": {
            "kind": "Role",
            "name": role.name,
            "namespace": role.namespace
        },
        "verb": verb,
        "failedPath": "rules[].verbs"
    }
}

is_system_role(name) {
    startswith(name, "system:")
}
