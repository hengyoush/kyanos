package docker

import (
	"context"
	"errors"
	"fmt"
	"kyanos/agent/metadata/types"
	"kyanos/common"
	"regexp"
	"strings"
	"sync"
	"time"

	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

const (
	DefaultSocket          = "/var/run/docker.sock"
	shortContainerIdLength = 12
)

type MetaData struct {
	client *client.Client

	containerById map[string]types.Container
	mux           sync.RWMutex

	hostPidNs int64
	hostMntNs int64
	hostNetNs int64
}

func NewMetaData(host string) (*MetaData, error) {
	common.DefaultLog.Infof("init docker metadata with host=%s", host)
	opts := []client.Opt{
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	}
	if host != "" {
		opts = append(opts, client.WithHost(host))
	}
	c, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second*5)
	defer cancel()
	if _, err := c.Info(ctx); err != nil {
		return nil, err
	}

	m := MetaData{
		client:        c,
		containerById: make(map[string]types.Container),
		mux:           sync.RWMutex{},
	}
	return &m, nil
}

func (d *MetaData) Start(ctx context.Context) error {
	if err := d.init(ctx); err != nil {
		return err
	}

	go func() {
		d.watchContainerEventsWithRetry(ctx)
	}()
	return nil
}

func (d *MetaData) GetById(containerId string) types.Container {
	d.mux.RLock()
	defer d.mux.RUnlock()

	id := getDockerContainerId(containerId)

	if len(id) == shortContainerIdLength {
		return d.getByShortId(id)
	}

	return d.containerById[id]
}

func (d *MetaData) GetByNetNs(netNs int64) types.Container {
	if netNs == 0 || netNs == d.hostNetNs {
		return types.Container{}
	}

	d.mux.RLock()
	defer d.mux.RUnlock()

	var containers []types.Container
	for _, c := range d.containerById {
		if c.NetworkNamespace > 0 && c.NetworkNamespace == d.hostNetNs {
			continue
		}
		if c.NetworkNamespace > 0 && c.NetworkNamespace == netNs {
			containers = append(containers, c)
		}
	}
	if len(containers) == 1 {
		return containers[0]
	}
	for _, c := range containers {
		if !c.IsSandbox() {
			return c
		}
	}

	return types.Container{}
}

func (d *MetaData) GetByMntNs(mntNs int64) types.Container {
	if mntNs == 0 || mntNs == d.hostMntNs {
		return types.Container{}
	}

	d.mux.RLock()
	defer d.mux.RUnlock()

	var containers []types.Container
	for _, c := range d.containerById {
		if c.MountNamespace > 0 && c.MountNamespace == d.hostMntNs {
			continue
		}
		if c.MountNamespace > 0 && c.MountNamespace == mntNs {
			containers = append(containers, c)
		}
	}
	if len(containers) == 1 {
		return containers[0]
	}
	for _, c := range containers {
		if !c.IsSandbox() {
			return c
		}
	}

	return types.Container{}
}

func (d *MetaData) GetByPid(pid int) types.Container {
	if pid == 0 {
		return types.Container{}
	}

	d.mux.RLock()
	defer d.mux.RUnlock()

	for _, c := range d.containerById {
		if c.RootPid > 0 && c.RootPid == pid {
			return c
		}
	}

	return types.Container{}
}

func (d *MetaData) GetByName(name string) []types.Container {
	d.mux.RLock()
	defer d.mux.RUnlock()

	var cs []types.Container
	for _, c := range d.containerById {
		if c.TidyName() == name {
			cs = append(cs, c)
		}
	}

	return cs
}

func (d *MetaData) GetByPod(name, namespace string) []types.Container {
	d.mux.RLock()
	defer d.mux.RUnlock()

	var cs []types.Container
	for _, c := range d.containerById {
		p := c.Pod()
		if p.Name == name && p.Namespace == namespace {
			cs = append(cs, c)
		}
	}

	return cs
}

func (d *MetaData) getByShortId(shortId string) types.Container {
	for _, c := range d.containerById {
		if strings.HasPrefix(c.Id, shortId) {
			return c
		}
	}

	return types.Container{}
}

func (d *MetaData) init(ctx context.Context) error {
	d.hostPidNs = common.GetPidNamespaceFromPid(1)
	d.hostMntNs = common.GetMountNamespaceFromPid(1)
	d.hostNetNs = common.GetNetworkNamespaceFromPid(1)

	c := d.client
	containers, err := c.ContainerList(ctx, container.ListOptions{
		Filters: filters.NewArgs(filters.Arg("status", "running")),
	})
	if err != nil {
		return fmt.Errorf("list containers: %w", err)
	}
	for _, cr := range containers {
		d.handleContainerEvent(ctx, cr.ID)
	}
	return nil
}

func (d *MetaData) watchContainerEventsWithRetry(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		d.watchContainerEvents(ctx)

		time.Sleep(time.Second * 15)
	}
}

func (d *MetaData) watchContainerEvents(ctx context.Context) {
	c := d.client

	var chMsg <-chan events.Message
	var chErr <-chan error
	var msg events.Message

	chMsg, chErr = c.Events(ctx, dockertypes.EventsOptions{
		// Filters: filters.NewArgs(
		// 	filters.Arg("type", "container"),
		// 	filters.Arg("event", "exec_create"),
		// 	filters.Arg("event", "exec_start"),
		// ),
	})

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-chErr:
			if errors.Is(err, context.Canceled) {
				return
			}
			common.DefaultLog.Errorf("docker events failed: %s", err)
			return
		case msg = <-chMsg:
		}

		if msg.Type != events.ContainerEventType {
			continue
		}
		if string(msg.Action) == string(ActionStart) ||
			strings.HasPrefix(string(msg.Action), string(ActionExecCreate)+": ") ||
			strings.HasPrefix(string(msg.Action), string(ActionExecStart)+": ") {
			d.handleContainerEvent(ctx, msg.Actor.ID)
		}
	}
}

func (d *MetaData) handleContainerEvent(ctx context.Context, containerId string) {
	cr, err := d.inspectContainer(ctx, containerId)
	if err != nil {
		common.DefaultLog.Errorf("inspect container failed: %s", err)
		return
	}

	d.setContainer(*cr)
}

func (d *MetaData) setContainer(c types.Container) {
	d.mux.Lock()
	defer d.mux.Unlock()

	common.DefaultLog.Debugf("new container: %#v", c)

	d.containerById[c.Id] = c
}

func (d *MetaData) inspectContainer(ctx context.Context, containerId string) (*types.Container, error) {
	c := d.client

	data, err := c.ContainerInspect(ctx, containerId)
	if err != nil {
		return nil, fmt.Errorf("inspect container %s: %w", containerId, err)
	}

	cr := &types.Container{
		Id:          containerId,
		Name:        data.Name,
		ImageDigest: data.Image,
	}
	if conf := data.Config; conf != nil {
		cr.Image = conf.Image
		cr.Labels = conf.Labels
	}
	if state := data.State; state != nil && state.Pid != 0 {
		cr.RootPid = state.Pid
		cr.PidNamespace = common.GetPidNamespaceFromPid(cr.RootPid)
		cr.MountNamespace = common.GetMountNamespaceFromPid(cr.RootPid)
		cr.NetworkNamespace = common.GetNetworkNamespaceFromPid(cr.RootPid)
	}

	return cr, nil
}

func (d *MetaData) Close() error {
	return d.client.Close()
}

// cgroupName: docker-40fad6778feaab1bd6ed7bfa0d43a2d5338267204f30cd8203e4d06de871c577.scope
var regexDockerCgroupV2Name = regexp.MustCompilePOSIX(`[^\-]+-([a-z0-9]{64}).scope`)

func getDockerContainerId(id string) string {
	parts := regexDockerCgroupV2Name.FindAllStringSubmatch(id, -1)
	if len(parts) < 1 {
		return id
	}
	part := parts[0]
	if len(part) < 2 {
		return id
	}
	return part[1]
}
