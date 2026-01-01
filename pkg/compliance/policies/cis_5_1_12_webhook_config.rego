# control_id: CIS-5.1.12
# framework: cis-k8s-1.11
# severity: HIGH
package qualys.controls.cis_5_1_12

import future.keywords.in

deny[result] {
    role := input.rbac.clusterRoles[_]
    rule := role.rules[_]
    can_modify_webhooks(rule)
    not is_system_role(role.name)

    result := {
        "message": sprintf("ClusterRole '%s' can modify webhook configurations", [role.name]),
        "resource": {
            "kind": "ClusterRole",
            "name": role.name
        },
        "failedPath": "rules[]"
    }
}

can_modify_webhooks(rule) {
    webhook_resource(rule)
    modify_verb(rule)
}

webhook_resource(rule) {
    "validatingwebhookconfigurations" in rule.resources
}

webhook_resource(rule) {
    "mutatingwebhookconfigurations" in rule.resources
}

webhook_resource(rule) {
    "*" in rule.resources
}

modify_verb(rule) {
    "create" in rule.verbs
}

modify_verb(rule) {
    "update" in rule.verbs
}

modify_verb(rule) {
    "patch" in rule.verbs
}

modify_verb(rule) {
    "delete" in rule.verbs
}

modify_verb(rule) {
    "*" in rule.verbs
}

is_system_role(name) {
    startswith(name, "system:")
}

is_system_role(name) {
    name == "cluster-admin"
}
