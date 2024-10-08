package container

import (
	"context"
	"kyanos/agent/metadata/container/containerd"
	"kyanos/agent/metadata/container/docker"
	"kyanos/agent/metadata/types"
	"kyanos/common"
)

type MultipleEngineMetaData struct {
	engines []MetaData
}

func NewMultipleEngineMetaData(dockerEndpoint, containerdEndpoint string) *MultipleEngineMetaData {
	var m MultipleEngineMetaData

	dr, err := docker.NewMetaData(dockerEndpoint)
	if err != nil {
		common.DefaultLog.Infof(err.Error())
		common.DefaultLog.Warnf("skip Docker Engine integration due to %s", err.Error())
	} else {
		m.engines = append(m.engines, dr)
	}

	cd, err := containerd.NewMultipleNamespacesMetaData(containerdEndpoint, "")
	if err != nil {
		common.DefaultLog.Infof(err.Error())
		common.DefaultLog.Warnf("skip containerd integration due to %s", err.Error())
	} else {
		for _, c := range cd {
			c := c
			m.engines = append(m.engines, c)
		}
	}

	return &m
}

func (m *MultipleEngineMetaData) Start(ctx context.Context) error {
	for _, e := range m.engines {
		if err := e.Start(ctx); err != nil {
			common.DefaultLog.Error(err.Error())
		}
	}

	return nil
}

func (m *MultipleEngineMetaData) GetById(containerId string) types.Container {
	var c types.Container
	for _, e := range m.engines {
		c = e.GetById(containerId)
		if c.Id != "" {
			return c
		}
	}
	return c
}
func (m *MultipleEngineMetaData) GetByMntNs(mntNs int64) types.Container {
	var c types.Container
	for _, e := range m.engines {
		c = e.GetByMntNs(mntNs)
		if c.Id != "" {
			return c
		}
	}
	return c
}
func (m *MultipleEngineMetaData) GetByNetNs(netNs int64) types.Container {
	var c types.Container
	for _, e := range m.engines {
		c = e.GetByNetNs(netNs)
		if c.Id != "" {
			return c
		}
	}
	return c
}
func (m *MultipleEngineMetaData) GetByPid(pid int) types.Container {
	var c types.Container
	for _, e := range m.engines {
		c = e.GetByPid(pid)
		if c.Id != "" {
			return c
		}
	}
	return c
}

func (m *MultipleEngineMetaData) GetByName(name string) []types.Container {
	var cs []types.Container
	for _, e := range m.engines {
		cs = e.GetByName(name)
		if len(cs) > 0 {
			return cs
		}
	}

	return cs
}

func (m *MultipleEngineMetaData) GetByPod(name, namespace string) []types.Container {
	var cs []types.Container
	for _, e := range m.engines {
		cs = e.GetByPod(name, namespace)
		if len(cs) > 0 {
			return cs
		}
	}

	return cs
}
