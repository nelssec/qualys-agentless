# control_id: NSA-3.1
# framework: nsa-cisa
# severity: MEDIUM
package qualys.controls.nsa_3_1

deny[result] {
    sa := input.serviceAccounts[_]
    automount_enabled(sa)
    not is_system_namespace(sa.namespace)

    result := {
        "message": sprintf("ServiceAccount '%s/%s' has automountServiceAccountToken enabled", [sa.namespace, sa.name]),
        "resource": {
            "kind": "ServiceAccount",
            "name": sa.name,
            "namespace": sa.namespace
        },
        "failedPath": "automountServiceAccountToken"
    }
}

automount_enabled(sa) {
    sa.automountServiceAccountToken == true
}

automount_enabled(sa) {
    not sa.automountServiceAccountToken
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
