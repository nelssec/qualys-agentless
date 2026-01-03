package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

type Client struct {
	httpClient *http.Client
	host       string
	apiVersion string
}

type ClientOption func(*Client)

func WithHost(host string) ClientOption {
	return func(c *Client) {
		c.host = host
	}
}

func WithAPIVersion(version string) ClientOption {
	return func(c *Client) {
		c.apiVersion = version
	}
}

func NewClient(opts ...ClientOption) (*Client, error) {
	c := &Client{
		apiVersion: "v1.43",
	}

	for _, opt := range opts {
		opt(c)
	}

	if c.host == "" {
		c.host = detectSocket()
	}

	transport := &http.Transport{}

	if strings.HasPrefix(c.host, "unix://") {
		socketPath := strings.TrimPrefix(c.host, "unix://")
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		}
		c.host = "http://localhost"
	} else if strings.HasPrefix(c.host, "tcp://") {
		c.host = "http://" + strings.TrimPrefix(c.host, "tcp://")
	} else if !strings.HasPrefix(c.host, "http://") && !strings.HasPrefix(c.host, "https://") {
		if strings.HasPrefix(c.host, "/") {
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", c.host)
			}
			c.host = "http://localhost"
		}
	}

	c.httpClient = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	return c, nil
}

func detectSocket() string {
	if host := os.Getenv("DOCKER_HOST"); host != "" {
		return host
	}

	if runtime.GOOS == "windows" {
		return "npipe:////./pipe/docker_engine"
	}

	podmanSocket := fmt.Sprintf("/run/user/%d/podman/podman.sock", os.Getuid())
	if _, err := os.Stat(podmanSocket); err == nil {
		return "unix://" + podmanSocket
	}

	if _, err := os.Stat("/run/podman/podman.sock"); err == nil {
		return "unix:///run/podman/podman.sock"
	}

	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		return "unix:///var/run/docker.sock"
	}

	return "unix:///var/run/docker.sock"
}

func (c *Client) Ping(ctx context.Context) error {
	resp, err := c.get(ctx, "/_ping")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (c *Client) Info(ctx context.Context) (*HostInfo, error) {
	resp, err := c.get(ctx, "/info")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var info struct {
		Name            string `json:"Name"`
		OperatingSystem string `json:"OperatingSystem"`
		Architecture    string `json:"Architecture"`
		KernelVersion   string `json:"KernelVersion"`
		ServerVersion   string `json:"ServerVersion"`
		Driver          string `json:"Driver"`
		DockerRootDir   string `json:"DockerRootDir"`
		CgroupDriver    string `json:"CgroupDriver"`
		CgroupVersion   string `json:"CgroupVersion"`
		RegistryConfig  struct {
			IndexConfigs map[string]interface{} `json:"IndexConfigs"`
		} `json:"RegistryConfig"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}

	runtime := "docker"
	if strings.Contains(strings.ToLower(info.ServerVersion), "podman") {
		runtime = "podman"
	}

	registries := []string{}
	for reg := range info.RegistryConfig.IndexConfigs {
		registries = append(registries, reg)
	}

	return &HostInfo{
		Hostname:       info.Name,
		OS:             info.OperatingSystem,
		Architecture:   info.Architecture,
		KernelVersion:  info.KernelVersion,
		Runtime:        runtime,
		RuntimeVersion: info.ServerVersion,
		APIVersion:     c.apiVersion,
		RootDir:        info.DockerRootDir,
		StorageDriver:  info.Driver,
		CgroupDriver:   info.CgroupDriver,
		CgroupVersion:  info.CgroupVersion,
		Registries:     registries,
	}, nil
}

func (c *Client) ListImages(ctx context.Context) ([]Image, error) {
	resp, err := c.get(ctx, "/images/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var rawImages []struct {
		ID          string            `json:"Id"`
		RepoTags    []string          `json:"RepoTags"`
		RepoDigests []string          `json:"RepoDigests"`
		Created     int64             `json:"Created"`
		Size        int64             `json:"Size"`
		Labels      map[string]string `json:"Labels"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rawImages); err != nil {
		return nil, err
	}

	images := make([]Image, 0, len(rawImages))
	for _, raw := range rawImages {
		img := Image{
			ID:          raw.ID,
			RepoTags:    raw.RepoTags,
			RepoDigests: raw.RepoDigests,
			Created:     time.Unix(raw.Created, 0),
			Size:        raw.Size,
			Labels:      raw.Labels,
		}

		if details, err := c.InspectImage(ctx, raw.ID); err == nil {
			img.User = details.User
			img.ExposedPorts = details.ExposedPorts
			img.Entrypoint = details.Entrypoint
			img.Cmd = details.Cmd
			img.Env = details.Env
			img.Volumes = details.Volumes
		}

		images = append(images, img)
	}

	return images, nil
}

func (c *Client) InspectImage(ctx context.Context, id string) (*Image, error) {
	resp, err := c.get(ctx, "/images/"+id+"/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var raw struct {
		Config struct {
			User         string              `json:"User"`
			ExposedPorts map[string]struct{} `json:"ExposedPorts"`
			Entrypoint   []string            `json:"Entrypoint"`
			Cmd          []string            `json:"Cmd"`
			Env          []string            `json:"Env"`
			Volumes      map[string]struct{} `json:"Volumes"`
		} `json:"Config"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}

	ports := make([]string, 0, len(raw.Config.ExposedPorts))
	for p := range raw.Config.ExposedPorts {
		ports = append(ports, p)
	}

	volumes := make([]string, 0, len(raw.Config.Volumes))
	for v := range raw.Config.Volumes {
		volumes = append(volumes, v)
	}

	return &Image{
		User:         raw.Config.User,
		ExposedPorts: ports,
		Entrypoint:   raw.Config.Entrypoint,
		Cmd:          raw.Config.Cmd,
		Env:          raw.Config.Env,
		Volumes:      volumes,
	}, nil
}

func (c *Client) ListContainers(ctx context.Context, all bool) ([]Container, error) {
	url := "/containers/json"
	if all {
		url += "?all=true"
	}

	resp, err := c.get(ctx, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var rawContainers []struct {
		ID      string `json:"Id"`
		Names   []string `json:"Names"`
		Image   string `json:"Image"`
		ImageID string `json:"ImageID"`
		Created int64  `json:"Created"`
		State   string `json:"State"`
		Status  string `json:"Status"`
		Ports   []struct {
			PrivatePort int    `json:"PrivatePort"`
			PublicPort  int    `json:"PublicPort"`
			IP          string `json:"IP"`
			Type        string `json:"Type"`
		} `json:"Ports"`
		Labels  map[string]string `json:"Labels"`
		Mounts  []struct {
			Type        string `json:"Type"`
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
			Mode        string `json:"Mode"`
			RW          bool   `json:"RW"`
			Propagation string `json:"Propagation"`
		} `json:"Mounts"`
		NetworkSettings struct {
			Networks map[string]interface{} `json:"Networks"`
		} `json:"NetworkSettings"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rawContainers); err != nil {
		return nil, err
	}

	containers := make([]Container, 0, len(rawContainers))
	for _, raw := range rawContainers {
		name := ""
		if len(raw.Names) > 0 {
			name = strings.TrimPrefix(raw.Names[0], "/")
		}

		ports := make([]PortBinding, 0, len(raw.Ports))
		for _, p := range raw.Ports {
			ports = append(ports, PortBinding{
				ContainerPort: p.PrivatePort,
				HostPort:      p.PublicPort,
				HostIP:        p.IP,
				Protocol:      p.Type,
			})
		}

		mounts := make([]Mount, 0, len(raw.Mounts))
		for _, m := range raw.Mounts {
			mounts = append(mounts, Mount{
				Type:        m.Type,
				Source:      m.Source,
				Destination: m.Destination,
				Mode:        m.Mode,
				RW:          m.RW,
				Propagation: m.Propagation,
			})
		}

		networks := make([]string, 0, len(raw.NetworkSettings.Networks))
		for n := range raw.NetworkSettings.Networks {
			networks = append(networks, n)
		}

		container := Container{
			ID:       raw.ID,
			Name:     name,
			Image:    raw.Image,
			ImageID:  raw.ImageID,
			Created:  time.Unix(raw.Created, 0),
			State:    raw.State,
			Status:   raw.Status,
			Labels:   raw.Labels,
			Ports:    ports,
			Mounts:   mounts,
			Networks: networks,
		}

		if details, err := c.InspectContainer(ctx, raw.ID); err == nil {
			container.SecurityContext = details.SecurityContext
			container.Resources = details.Resources
			container.RestartPolicy = details.RestartPolicy
			container.RestartCount = details.RestartCount
			container.Pid = details.Pid
			container.ExitCode = details.ExitCode
		}

		containers = append(containers, container)
	}

	return containers, nil
}

func (c *Client) InspectContainer(ctx context.Context, id string) (*Container, error) {
	resp, err := c.get(ctx, "/containers/"+id+"/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var raw struct {
		State struct {
			Pid      int `json:"Pid"`
			ExitCode int `json:"ExitCode"`
		} `json:"State"`
		RestartCount int `json:"RestartCount"`
		HostConfig   struct {
			Privileged     bool     `json:"Privileged"`
			CapAdd         []string `json:"CapAdd"`
			CapDrop        []string `json:"CapDrop"`
			SecurityOpt    []string `json:"SecurityOpt"`
			ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
			PidMode        string   `json:"PidMode"`
			IpcMode        string   `json:"IpcMode"`
			NetworkMode    string   `json:"NetworkMode"`
			UsernsMode     string   `json:"UsernsMode"`
			RestartPolicy  struct {
				Name string `json:"Name"`
			} `json:"RestartPolicy"`
			CPUShares  int64 `json:"CpuShares"`
			CPUQuota   int64 `json:"CpuQuota"`
			CPUPeriod  int64 `json:"CpuPeriod"`
			Memory     int64 `json:"Memory"`
			MemorySwap int64 `json:"MemorySwap"`
			PidsLimit  int64 `json:"PidsLimit"`
		} `json:"HostConfig"`
		Config struct {
			User string `json:"User"`
		} `json:"Config"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}

	return &Container{
		SecurityContext: SecurityContext{
			Privileged:     raw.HostConfig.Privileged,
			User:           raw.Config.User,
			CapAdd:         raw.HostConfig.CapAdd,
			CapDrop:        raw.HostConfig.CapDrop,
			SecurityOpt:    raw.HostConfig.SecurityOpt,
			ReadonlyRootfs: raw.HostConfig.ReadonlyRootfs,
			PidMode:        raw.HostConfig.PidMode,
			IpcMode:        raw.HostConfig.IpcMode,
			NetworkMode:    raw.HostConfig.NetworkMode,
			UsernsMode:     raw.HostConfig.UsernsMode,
		},
		Resources: Resources{
			CPUShares:  raw.HostConfig.CPUShares,
			CPUQuota:   raw.HostConfig.CPUQuota,
			CPUPeriod:  raw.HostConfig.CPUPeriod,
			Memory:     raw.HostConfig.Memory,
			MemorySwap: raw.HostConfig.MemorySwap,
			PidsLimit:  raw.HostConfig.PidsLimit,
		},
		RestartPolicy: raw.HostConfig.RestartPolicy.Name,
		RestartCount:  raw.RestartCount,
		Pid:           raw.State.Pid,
		ExitCode:      raw.State.ExitCode,
	}, nil
}

func (c *Client) ListNetworks(ctx context.Context) ([]Network, error) {
	resp, err := c.get(ctx, "/networks")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var rawNetworks []struct {
		ID         string            `json:"Id"`
		Name       string            `json:"Name"`
		Driver     string            `json:"Driver"`
		Scope      string            `json:"Scope"`
		Internal   bool              `json:"Internal"`
		Labels     map[string]string `json:"Labels"`
		IPAM       struct {
			Driver string `json:"Driver"`
			Config []struct {
				Subnet  string `json:"Subnet"`
				Gateway string `json:"Gateway"`
			} `json:"Config"`
		} `json:"IPAM"`
		Containers map[string]interface{} `json:"Containers"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rawNetworks); err != nil {
		return nil, err
	}

	networks := make([]Network, 0, len(rawNetworks))
	for _, raw := range rawNetworks {
		ipam := IPAM{Driver: raw.IPAM.Driver}
		if len(raw.IPAM.Config) > 0 {
			ipam.Subnet = raw.IPAM.Config[0].Subnet
			ipam.Gateway = raw.IPAM.Config[0].Gateway
		}

		containers := make([]string, 0, len(raw.Containers))
		for id := range raw.Containers {
			containers = append(containers, id[:12])
		}

		networks = append(networks, Network{
			ID:         raw.ID,
			Name:       raw.Name,
			Driver:     raw.Driver,
			Scope:      raw.Scope,
			Internal:   raw.Internal,
			IPAM:       ipam,
			Labels:     raw.Labels,
			Containers: containers,
		})
	}

	return networks, nil
}

func (c *Client) ListVolumes(ctx context.Context) ([]Volume, error) {
	resp, err := c.get(ctx, "/volumes")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var rawVolumes struct {
		Volumes []struct {
			Name       string            `json:"Name"`
			Driver     string            `json:"Driver"`
			Mountpoint string            `json:"Mountpoint"`
			Labels     map[string]string `json:"Labels"`
			Scope      string            `json:"Scope"`
		} `json:"Volumes"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rawVolumes); err != nil {
		return nil, err
	}

	volumes := make([]Volume, 0, len(rawVolumes.Volumes))
	for _, raw := range rawVolumes.Volumes {
		volumes = append(volumes, Volume{
			Name:       raw.Name,
			Driver:     raw.Driver,
			Mountpoint: raw.Mountpoint,
			Labels:     raw.Labels,
			Scope:      raw.Scope,
		})
	}

	return volumes, nil
}

func (c *Client) get(ctx context.Context, path string) (*http.Response, error) {
	url := c.host + "/" + c.apiVersion + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("docker API error %d: %s", resp.StatusCode, string(body))
	}

	return resp, nil
}
