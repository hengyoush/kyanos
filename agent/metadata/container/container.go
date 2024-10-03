package container

import (
	"context"
	"kyanos/agent/metadata/types"
)

type MetaData interface {
	Start(ctx context.Context) error
	GetById(containerId string) types.Container
	GetByMntNs(mntNs int64) types.Container
	GetByNetNs(netNs int64) types.Container
	GetByPid(pid int) types.Container
	GetByName(name string) []types.Container
	GetByPod(name, namespace string) []types.Container
}
