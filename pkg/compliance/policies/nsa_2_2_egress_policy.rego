# control_id: NSA-2.2
# framework: nsa-cisa
# severity: HIGH
package qualys.controls.nsa_2_2

import future.keywords.in

target_namespaces[ns] {
    namespace := input.namespaces[_]
    ns := namespace.name
    not is_system_namespace(ns)
}

namespaces_with_egress[ns] {
    policy := input.networkPolicies[_]
    ns := policy.namespace
    "Egress" in policy.policyTypes
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
    not ns in namespaces_with_egress

    result := {
        "message": sprintf("Namespace '%s' has no egress NetworkPolicy to restrict outbound traffic", [ns]),
        "resource": {
            "kind": "Namespace",
            "name": ns
        },
        "failedPath": "NetworkPolicy.spec.policyTypes"
    }
}
