# control_id: NSA-2.1
# framework: nsa-cisa
# severity: MEDIUM
package qualys.controls.nsa_2_1

import future.keywords.in

target_namespaces[ns] {
    namespace := input.namespaces[_]
    ns := namespace.name
    not is_system_namespace(ns)
}

namespaces_with_policies[ns] {
    policy := input.networkPolicies[_]
    ns := policy.namespace
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

deny[result] {
    ns := target_namespaces[_]
    not ns in namespaces_with_policies

    result := {
        "message": sprintf("Namespace '%s' has no NetworkPolicy to isolate resources", [ns]),
        "resource": {
            "kind": "Namespace",
            "name": ns
        },
        "failedPath": "NetworkPolicy"
    }
}
