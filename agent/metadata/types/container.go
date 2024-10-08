package types

import (
	"encoding/json"
	"strings"
)

type Container struct {
	Id     string
	Name   string
	Labels map[string]string

	RootPid          int
	PidNamespace     int64
	MountNamespace   int64
	NetworkNamespace int64

	Image       string
	ImageDigest string

	p Pod
}

func (c *Container) IsNull() bool {
	if c == nil {
		return true
	}
	return c.Id == ""
}

func (c Container) TidyName() string {
	return strings.TrimLeft(c.Name, "/")
}

func (c Container) FormatLabels() string {
	if len(c.Labels) == 0 {
		return "{}"
	}
	b, _ := json.Marshal(c.Labels)
	return string(b)
}

func (c Container) IsSandbox() bool {
	if len(c.Labels) == 0 {
		return false
	}
	return c.Labels["io.cri-containerd.kind"] == "sandbox" ||
		c.Labels["io.kubernetes.docker.type"] == "sandbox" ||
		c.Labels["io.kubernetes.docker.type"] == "podsandbox"
}

func (c *Container) Pod() Pod {
	if c.p.Name != "" {
		return c.p
	}
	p := Pod{}
	p.LoadFromContainer(*c)
	c.p = p
	return p
}

func (c Container) EmptyNS() bool {
	return c.PidNamespace == 0 && c.MountNamespace == 0 && c.NetworkNamespace == 0
}

func ParseContainerLabels(s string) map[string]string {
	labels := make(map[string]string)
	json.Unmarshal([]byte(s), &labels)
	return labels
}
