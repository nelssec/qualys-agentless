# control_id: MITRE-T1046
# framework: mitre-attack
# severity: MEDIUM
package qualys.controls.mitre_t1046

import future.keywords.in

target_namespaces[ns] {
    namespace := input.namespaces[_]
    ns := namespace.name
    not is_system_namespace(ns)
}

namespaces_with_default_deny[ns] {
    policy := input.networkPolicies[_]
    ns := policy.namespace
    is_default_deny(policy)
}

deny[result] {
    ns := target_namespaces[_]
    not ns in namespaces_with_default_deny

    result := {
        "message": sprintf("Namespace '%s' lacks default-deny network policy (network scanning risk)", [ns]),
        "resource": {
            "kind": "Namespace",
            "name": ns
        },
        "tactic": "Discovery",
        "technique": "Network Service Discovery",
        "failedPath": "NetworkPolicy"
    }
}

is_default_deny(policy) {
    count(policy.podSelector) == 0
    policy.ingressRules == 0
}

is_default_deny(policy) {
    count(policy.podSelector) == 0
    policy.egressRules == 0
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

is_system_namespace(ns) {
    ns == "default"
}
