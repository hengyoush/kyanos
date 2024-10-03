package metadata

import (
	"context"
	"kyanos/agent/metadata/container"
	"kyanos/agent/metadata/k8s"
	"kyanos/agent/metadata/types"
)

type ContainerCache struct {
	d   container.MetaData
	k8s *k8s.MetaData
}

func NewContainerCache(ctx context.Context,
	dockerEndpoint, containerdEndpoint, criRuntimeEndpoint string) (*ContainerCache, error, error) {
	d := container.NewMultipleEngineMetaData(dockerEndpoint, containerdEndpoint)

	if err := d.Start(ctx); err != nil {
		return nil, err, nil
	}

	k8sd, k8sErr := k8s.NewMetaData(criRuntimeEndpoint)
	return &ContainerCache{
		d:   d,
		k8s: k8sd,
	}, nil, k8sErr
}

func (c *ContainerCache) GetById(containerId string) types.Container {
	return c.d.GetById(containerId)
}

func (c *ContainerCache) GetByMntNs(mntNs int64) types.Container {
	return c.d.GetByMntNs(mntNs)
}

func (c *ContainerCache) GetByNetNs(ns int64) types.Container {
	return c.d.GetByNetNs(ns)
}

func (c *ContainerCache) GetByPid(pid int) types.Container {
	return c.d.GetByPid(pid)
}

func (c *ContainerCache) GetByName(containerName string) []types.Container {
	return c.d.GetByName(containerName)
}

func (c *ContainerCache) GetPodByContainer(cr types.Container) types.Pod {
	return c.k8s.GetPodByContainer(cr)
}

func (c *ContainerCache) GetByPodName(name, namespace string) []types.Container {
	return c.d.GetByPod(name, namespace)
}
