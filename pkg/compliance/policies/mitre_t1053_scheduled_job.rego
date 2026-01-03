# control_id: MITRE-T1053.007
# framework: mitre-attack
# severity: MEDIUM
package qualys.controls.mitre_t1053

deny[result] {
    cronjob := input.workloads.cronJobs[_]
    cronjob.suspend == false
    not is_system_namespace(cronjob.namespace)

    result := {
        "message": sprintf("CronJob '%s/%s' is active (scheduled execution risk)", [cronjob.namespace, cronjob.name]),
        "resource": {
            "kind": "CronJob",
            "name": cronjob.name,
            "namespace": cronjob.namespace
        },
        "schedule": cronjob.schedule,
        "tactic": "Execution",
        "technique": "Scheduled Task/Job: Container Orchestration Job",
        "failedPath": "spec.suspend"
    }
}

deny[result] {
    role := input.rbac.clusterRoles[_]
    rule := role.rules[_]
    can_create_cronjobs(rule)

    result := {
        "message": sprintf("ClusterRole '%s' can create CronJobs (persistence risk)", [role.name]),
        "resource": {
            "kind": "ClusterRole",
            "name": role.name
        },
        "tactic": "Persistence",
        "technique": "Scheduled Task/Job: Container Orchestration Job",
        "failedPath": "rules[].verbs"
    }
}

can_create_cronjobs(rule) {
    rule.resources[_] == "cronjobs"
    rule.verbs[_] == "create"
}

can_create_cronjobs(rule) {
    rule.resources[_] == "cronjobs"
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
