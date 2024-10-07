package loader

import (
	"context"
	ac "kyanos/agent/common"
	"kyanos/agent/metadata"
	"kyanos/agent/metadata/types"
	"kyanos/bpf"
	"kyanos/common"
	"log"

	"github.com/cilium/ebpf"
)

type containerFilterResult struct {
	mntnsIds []uint32
	netnsIds []uint32
	pidnsIds []uint32
}

func applyContainerFilter(ctx context.Context, options *ac.AgentOptions) (*metadata.ContainerCache, *containerFilterResult, error) {
	cc, err, k8sErr := metadata.NewContainerCache(ctx, options.DockerEndpoint, options.ContainerdEndpoint, options.CriRuntimeEndpoint)
	if err != nil {
		if options.FilterByContainer() {
			common.DefaultLog.Fatalf("find container failed: %s", err)
		} else {
			common.DefaultLog.Warnf("find container failed: %s", err)
			return nil, nil, nil
		}
	}
	if k8sErr != nil {
		if options.FilterByK8s() {
			common.DefaultLog.Fatalf("find pod failed: %s", k8sErr)
		} else {
			common.DefaultLog.Infof("find pod failed: %s", k8sErr)
		}
	}
	if !options.FilterByContainer() {
		return cc, nil, nil
	}

	var containers []types.Container

	switch {
	case options.ContainerId != "":
		container := cc.GetById(options.ContainerId)
		if container.EmptyNS() {
			log.Fatalf("can not find any running container by id %s", options.ContainerId)
		}
		containers = append(containers, container)
	case options.ContainerName != "":
		cs := cc.GetByName(options.ContainerName)
		cs = removeNonFilterAbleContainers(cs)
		if len(cs) > 1 {
			log.Fatalf("found more than one containers by name %s", options.ContainerName)
		}
		if len(cs) == 0 {
			log.Fatalf("can not find any running container by name %s", options.ContainerName)
		}
		container := cs[0]
		containers = append(containers, container)
	case options.PodName != "":
		cs := cc.GetByPodName(options.PodName, options.PodNameSpace)
		cs = removeNonFilterAbleContainers(cs)
		if len(cs) == 0 {
			log.Fatalf("can not find any running pod by name %s in namespace %s", options.PodName, options.PodNameSpace)
		}
		containers = append(containers, cs...)
	}
	result := containerFilterResult{
		pidnsIds: make([]uint32, 0),
		mntnsIds: make([]uint32, 0),
		netnsIds: make([]uint32, 0),
	}
	for _, container := range containers {
		if container.IsSandbox() {
			common.DefaultLog.Infof("skip sandbox container: %#v", container)
			continue
		}
		common.DefaultLog.Infof("filter by container %#v", container)
		if container.PidNamespace > 0 && container.PidNamespace != metadata.HostPidNs {
			result.pidnsIds = append(result.pidnsIds, uint32(container.PidNamespace))
		}
		if container.MountNamespace > 0 && container.MountNamespace != metadata.HostMntNs {
			result.mntnsIds = append(result.mntnsIds, uint32(container.MountNamespace))
		}
		if container.NetworkNamespace > 0 && container.NetworkNamespace != metadata.HostNetNs {
			result.netnsIds = append(result.netnsIds, uint32(container.NetworkNamespace))
		}
	}
	return cc, &result, nil
}

func writeFilterNsIdsToMap(r *containerFilterResult, objs any) {
	pidnsMap := bpf.GetMapFromObjs(objs, "FilterPidnsMap")
	mntnsMap := bpf.GetMapFromObjs(objs, "FilterMntnsMap")
	netnsMap := bpf.GetMapFromObjs(objs, "FilterNetnsMap")
	value := uint8(0)
	for _, id := range r.pidnsIds {
		pidnsMap.Update(id, value, ebpf.UpdateAny)
	}
	for _, id := range r.mntnsIds {
		mntnsMap.Update(id, value, ebpf.UpdateAny)
	}
	for _, id := range r.netnsIds {
		netnsMap.Update(id, value, ebpf.UpdateAny)
	}
}

func removeNonFilterAbleContainers(containers []types.Container) []types.Container {
	var final []types.Container
	for _, c := range containers {
		if c.IsSandbox() || c.EmptyNS() {
			continue
		}
		if c.PidNamespace == metadata.HostPidNs &&
			c.MountNamespace == metadata.HostMntNs &&
			c.NetworkNamespace == metadata.HostNetNs {
			continue
		}
		final = append(final, c)
	}
	return final
}

func initProcExitEventChannel(ctx context.Context) chan *bpf.AgentProcessExitEvent {
	ch := make(chan *bpf.AgentProcessExitEvent, 10)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case evt := <-ch:
				common.DeleteIfIdxToNameEntry(int(evt.Pid))
			}
		}
	}()
	return ch
}
