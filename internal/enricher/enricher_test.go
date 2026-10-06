package enricher

import (
	"testing"
)

func TestParseCgroupContent_Kubernetes(t *testing.T) {
	cgroupV2 := `0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod8c7b8c8d-4f1a-4d9b-a3d5-e3d8f1e9b2c3.slice/cri-containerd-a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef.scope`

	info := ParseCgroupContent(cgroupV2)
	if !info.IsContainer {
		t.Fatal("expected container detection to be true for kubernetes cgroup")
	}
	if info.Runtime != "kubernetes" {
		t.Errorf("expected runtime 'kubernetes', got '%s'", info.Runtime)
	}
	if info.PodUID != "8c7b8c8d-4f1a-4d9b-a3d5-e3d8f1e9b2c3" {
		t.Errorf("expected pod UID, got '%s'", info.PodUID)
	}
	if info.ContainerID != "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef" {
		t.Errorf("expected container ID, got '%s'", info.ContainerID)
	}
}

func TestParseCgroupContent_Docker(t *testing.T) {
	cgroupV1 := `1:name=systemd:/docker/7b2e9a1f5c6d3e8b4a0f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f`

	info := ParseCgroupContent(cgroupV1)
	if !info.IsContainer {
		t.Fatal("expected container detection to be true for docker cgroup")
	}
	if info.Runtime != "docker" {
		t.Errorf("expected runtime 'docker', got '%s'", info.Runtime)
	}
	if info.ContainerID != "7b2e9a1f5c6d3e8b4a0f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f" {
		t.Errorf("expected container ID, got '%s'", info.ContainerID)
	}
}

func TestParseCgroupContent_Host(t *testing.T) {
	cgroupHost := `0::/user.slice/user-1000.slice/session-1.scope`

	info := ParseCgroupContent(cgroupHost)
	if info.IsContainer {
		t.Error("host session should not be marked as container")
	}
}

func TestParseProcStatus(t *testing.T) {
	status := `Name:	kshield
Umask:	0022
State:	S (sleeping)
Tgid:	12345
Ngid:	0
Pid:	12345
PPid:	6789
TracerPid:	0
Uid:	0	0	0	0
Gid:	0	0	0	0`

	ppid, comm := ParseProcStatus(status)
	if ppid != 6789 {
		t.Errorf("expected PPID 6789, got %d", ppid)
	}
	if comm != "kshield" {
		t.Errorf("expected comm 'kshield', got '%s'", comm)
	}
}

func TestUserResolver(t *testing.T) {
	ur := NewUserResolver()
	nameRoot := ur.Resolve(0)
	if nameRoot != "root" {
		t.Errorf("expected UID 0 to resolve to 'root', got '%s'", nameRoot)
	}
}
