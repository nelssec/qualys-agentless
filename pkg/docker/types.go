package docker

import "time"

type Inventory struct {
	Host       HostInfo     `json:"host"`
	Images     []Image      `json:"images"`
	Containers []Container  `json:"containers"`
	Networks   []Network    `json:"networks"`
	Volumes    []Volume     `json:"volumes"`
	CollectedAt time.Time   `json:"collectedAt"`
}

type HostInfo struct {
	Hostname       string `json:"hostname"`
	OS             string `json:"os"`
	Architecture   string `json:"architecture"`
	KernelVersion  string `json:"kernelVersion"`
	Runtime        string `json:"runtime"`
	RuntimeVersion string `json:"runtimeVersion"`
	APIVersion     string `json:"apiVersion"`
	RootDir        string `json:"rootDir"`
	StorageDriver  string `json:"storageDriver"`
	CgroupDriver   string `json:"cgroupDriver"`
	CgroupVersion  string `json:"cgroupVersion"`
	Registries     []string `json:"registries,omitempty"`
}

type Image struct {
	ID          string            `json:"id"`
	RepoTags    []string          `json:"repoTags"`
	RepoDigests []string          `json:"repoDigests,omitempty"`
	Created     time.Time         `json:"created"`
	Size        int64             `json:"size"`
	Labels      map[string]string `json:"labels,omitempty"`
	User        string            `json:"user,omitempty"`
	ExposedPorts []string         `json:"exposedPorts,omitempty"`
	Entrypoint  []string          `json:"entrypoint,omitempty"`
	Cmd         []string          `json:"cmd,omitempty"`
	Env         []string          `json:"env,omitempty"`
	Volumes     []string          `json:"volumes,omitempty"`
	UsedBy      []string          `json:"usedBy,omitempty"`
}

type Container struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Image           string            `json:"image"`
	ImageID         string            `json:"imageId"`
	Created         time.Time         `json:"created"`
	State           string            `json:"state"`
	Status          string            `json:"status"`
	Labels          map[string]string `json:"labels,omitempty"`
	Ports           []PortBinding     `json:"ports,omitempty"`
	Mounts          []Mount           `json:"mounts,omitempty"`
	Networks        []string          `json:"networks,omitempty"`
	SecurityContext SecurityContext   `json:"securityContext"`
	Resources       Resources         `json:"resources,omitempty"`
	RestartPolicy   string            `json:"restartPolicy,omitempty"`
	RestartCount    int               `json:"restartCount"`
	Pid             int               `json:"pid,omitempty"`
	ExitCode        int               `json:"exitCode,omitempty"`
}

type PortBinding struct {
	ContainerPort int    `json:"containerPort"`
	HostPort      int    `json:"hostPort,omitempty"`
	HostIP        string `json:"hostIp,omitempty"`
	Protocol      string `json:"protocol"`
}

type Mount struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Mode        string `json:"mode,omitempty"`
	RW          bool   `json:"rw"`
	Propagation string `json:"propagation,omitempty"`
}

type SecurityContext struct {
	Privileged     bool     `json:"privileged"`
	User           string   `json:"user,omitempty"`
	CapAdd         []string `json:"capAdd,omitempty"`
	CapDrop        []string `json:"capDrop,omitempty"`
	SecurityOpt    []string `json:"securityOpt,omitempty"`
	ReadonlyRootfs bool     `json:"readonlyRootfs"`
	PidMode        string   `json:"pidMode,omitempty"`
	IpcMode        string   `json:"ipcMode,omitempty"`
	NetworkMode    string   `json:"networkMode,omitempty"`
	UsernsMode     string   `json:"usernsMode,omitempty"`
	AppArmor       string   `json:"appArmor,omitempty"`
	Seccomp        string   `json:"seccomp,omitempty"`
}

type Resources struct {
	CPUShares  int64 `json:"cpuShares,omitempty"`
	CPUQuota   int64 `json:"cpuQuota,omitempty"`
	CPUPeriod  int64 `json:"cpuPeriod,omitempty"`
	Memory     int64 `json:"memory,omitempty"`
	MemorySwap int64 `json:"memorySwap,omitempty"`
	PidsLimit  int64 `json:"pidsLimit,omitempty"`
}

type Network struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Scope      string            `json:"scope"`
	Internal   bool              `json:"internal"`
	IPAM       IPAM              `json:"ipam,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Containers []string          `json:"containers,omitempty"`
}

type IPAM struct {
	Driver string   `json:"driver"`
	Subnet string   `json:"subnet,omitempty"`
	Gateway string  `json:"gateway,omitempty"`
}

type Volume struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Mountpoint string            `json:"mountpoint"`
	Labels     map[string]string `json:"labels,omitempty"`
	Scope      string            `json:"scope"`
	UsedBy     []string          `json:"usedBy,omitempty"`
}

type Finding struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Resource    string   `json:"resource"`
	ResourceID  string   `json:"resourceId"`
	Message     string   `json:"message"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references,omitempty"`
}

type ScanResult struct {
	Inventory    *Inventory `json:"inventory"`
	Findings     []Finding  `json:"findings"`
	Summary      Summary    `json:"summary"`
	ScanTime     time.Time  `json:"scanTime"`
}

type Summary struct {
	TotalContainers   int            `json:"totalContainers"`
	RunningContainers int            `json:"runningContainers"`
	TotalImages       int            `json:"totalImages"`
	TotalFindings     int            `json:"totalFindings"`
	BySeverity        map[string]int `json:"bySeverity"`
	ByCategory        map[string]int `json:"byCategory"`
}
