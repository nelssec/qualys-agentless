# control_id: CIS-5.2.7
# framework: cis-k8s-1.11
# severity: HIGH
package qualys.controls.cis_5_2_7

import future.keywords.in

dangerous_caps := {
    "NET_ADMIN",
    "SYS_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "DAC_READ_SEARCH",
    "SYS_RAWIO",
    "SYS_BOOT",
    "SYS_TIME",
    "MKNOD",
    "SETUID",
    "SETGID",
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "FSETID",
    "KILL",
    "SETPCAP",
    "LINUX_IMMUTABLE",
    "IPC_LOCK",
    "IPC_OWNER",
    "SYS_CHROOT",
    "SYS_NICE",
    "SYS_RESOURCE",
    "SYS_TTY_CONFIG",
    "LEASE",
    "AUDIT_WRITE",
    "AUDIT_CONTROL",
    "SETFCAP",
    "MAC_OVERRIDE",
    "MAC_ADMIN",
    "SYSLOG",
    "WAKE_ALARM",
    "BLOCK_SUSPEND"
}

deny[result] {
    pod := input.workloads.pods[_]
    container := pod.containers[_]
    cap := container.securityContext.capabilities.add[_]
    cap in dangerous_caps

    result := {
        "message": sprintf("Container '%s' in pod '%s/%s' adds dangerous capability '%s'", [container.name, pod.namespace, pod.name, cap]),
        "resource": {
            "kind": "Pod",
            "name": pod.name,
            "namespace": pod.namespace
        },
        "container": container.name,
        "capability": cap,
        "failedPath": "spec.containers[].securityContext.capabilities.add"
    }
}
