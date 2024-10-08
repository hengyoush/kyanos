package types

import (
	"encoding/json"
)

const (
	ContainerLabelKeyPodName      = "io.kubernetes.pod.name"
	ContainerLabelKeyPodNamespace = "io.kubernetes.pod.namespace"
	ContainerLabelKeyPodUid       = "io.kubernetes.pod.uid"
)

type Pod struct {
	Name        string
	Namespace   string
	Uid         string
	Labels      map[string]string
	Annotations map[string]string
}

func (p *Pod) LoadFromContainer(c Container) {
	labels := c.Labels
	if len(labels) == 0 {
		return
	}
	p.Name = labels[ContainerLabelKeyPodName]
	p.Namespace = labels[ContainerLabelKeyPodNamespace]
	p.Uid = labels[ContainerLabelKeyPodUid]
}

func (p Pod) FormatLabels() string {
	if len(p.Labels) == 0 {
		return "{}"
	}
	b, _ := json.Marshal(p.Labels)
	return string(b)
}

func ParsePodLabels(s string) map[string]string {
	labels := make(map[string]string)
	json.Unmarshal([]byte(s), &labels)
	return labels
}

func (p Pod) FormatAnnotations() string {
	if len(p.Annotations) == 0 {
		return "{}"
	}
	b, _ := json.Marshal(p.Annotations)
	return string(b)
}

func ParsePodAnnotations(s string) map[string]string {
	annotations := make(map[string]string)
	json.Unmarshal([]byte(s), &annotations)
	return annotations
}
