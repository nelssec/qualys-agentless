# control_id: CIS-5.7.1
# framework: cis-k8s-1.11
# severity: LOW
package qualys.controls.cis_5_7_1

deny[result] {
    count(input.namespaces) < 2

    result := {
        "message": "Cluster has fewer than 2 namespaces; consider using namespaces to create administrative boundaries",
        "resource": {
            "kind": "Cluster",
            "name": "cluster"
        },
        "failedPath": "namespaces"
    }
}

deny[result] {
    pods_in_default := [p | p := input.workloads.pods[_]; p.namespace == "default"]
    count(pods_in_default) > 0
    count(input.namespaces) < 3

    result := {
        "message": sprintf("Only %d namespaces exist and pods are running in default namespace; create dedicated namespaces for workloads", [count(input.namespaces)]),
        "resource": {
            "kind": "Cluster",
            "name": "cluster"
        },
        "failedPath": "namespaces"
    }
}
