package enricher

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
)

var (
	// Matches container 64-hex and 12-hex IDs
	containerID64Regex = regexp.MustCompile(`([0-9a-fA-F]{64})`)
	containerID12Regex = regexp.MustCompile(`([0-9a-fA-F]{12})`)
	// Matches Kubernetes pod UUID patterns
	kubePodRegex = regexp.MustCompile(`pod([0-9a-fA-F-_]{36})`)
)

func extractContainerID(path string) string {
	if m := containerID64Regex.FindStringSubmatch(path); len(m) > 1 {
		return m[1]
	}
	if m := containerID12Regex.FindStringSubmatch(path); len(m) > 1 {
		return m[1]
	}
	return ""
}

// ContainerInfo captures container and orchestration details.
type ContainerInfo struct {
	IsContainer bool
	Runtime     string
	ContainerID string
	PodUID      string
	CgroupPath  string
}

// ContainerResolver inspects /proc/<pid>/cgroup to identify container boundaries.
type ContainerResolver struct {
	cache sync.Map // map[uint32]*ContainerInfo
}

// NewContainerResolver creates a new container context resolver.
func NewContainerResolver() *ContainerResolver {
	return &ContainerResolver{}
}

// Resolve reads cgroup information for the given PID and determines if it is containerized.
func (cr *ContainerResolver) Resolve(pid uint32) *ContainerInfo {
	if val, ok := cr.cache.Load(pid); ok {
		return val.(*ContainerInfo)
	}

	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		// Non-containerized or process terminated
		info := &ContainerInfo{IsContainer: false}
		return info
	}

	info := ParseCgroupContent(string(data))
	cr.cache.Store(pid, info)
	return info
}

// ParseCgroupContent parses raw /proc/<pid>/cgroup content (v1 or v2).
func ParseCgroupContent(content string) *ContainerInfo {
	info := &ContainerInfo{
		IsContainer: false,
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		path := parts[2]
		info.CgroupPath = path

		// 1. Kubernetes
		if strings.Contains(path, "kubepods") {
			info.IsContainer = true
			info.Runtime = "kubernetes"
			if match := kubePodRegex.FindStringSubmatch(path); len(match) > 1 {
				info.PodUID = match[1]
			}
			info.ContainerID = extractContainerID(path)
			return info
		}

		// 2. Docker
		if strings.Contains(path, "docker") {
			info.IsContainer = true
			info.Runtime = "docker"
			info.ContainerID = extractContainerID(path)
			return info
		}

		// 3. Podman / Libpod
		if strings.Contains(path, "libpod") || strings.Contains(path, "podman") {
			info.IsContainer = true
			info.Runtime = "podman"
			info.ContainerID = extractContainerID(path)
			return info
		}

		// 4. containerd / cri-o standalone
		if strings.Contains(path, "containerd") || strings.Contains(path, "crio") {
			info.IsContainer = true
			info.Runtime = "containerd"
			info.ContainerID = extractContainerID(path)
			return info
		}

		// 5. LXC
		if strings.Contains(path, "/lxc/") {
			info.IsContainer = true
			info.Runtime = "lxc"
			return info
		}
	}

	return info
}
