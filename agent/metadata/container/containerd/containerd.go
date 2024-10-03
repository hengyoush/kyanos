package containerd

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

	"github.com/containerd/containerd"
	apievents "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/events"
	"github.com/containerd/errdefs"
	"github.com/containerd/typeurl/v2"
)

const (
	DefaultSocket          = "/run/containerd/containerd.sock"
	defaultNamespace       = "default"
	shortContainerIdLength = 12
)

var containerNameLabels = []string{
	"nerdctl/name",
	"io.kubernetes.container.name",
}

type MetaData struct {
	client *containerd.Client

	containerById map[string]types.Container
	mux           sync.RWMutex

	hostPidNs int64
	hostMntNs int64
	hostNetNs int64
}

func NewMetaData(host string, namespace string) (*MetaData, error) {
	if namespace == "" {
		namespace = defaultNamespace
	}
	if host == "" {
		host = DefaultSocket
	}

	common.DefaultLog.Infof("init containerd metadata with host=%s, namespace=%s", host, namespace)
	opts := []containerd.ClientOpt{
		containerd.WithDefaultNamespace(namespace),
		containerd.WithTimeout(time.Second * 2),
	}
	c, err := containerd.New(host, opts...)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second*5)
	defer cancel()
	if _, err := c.Server(ctx); err != nil {
		return nil, err
	}

	m := MetaData{
		client:        c,
		containerById: make(map[string]types.Container),
		mux:           sync.RWMutex{},
	}
	return &m, nil
}

func NewMultipleNamespacesMetaData(host, namespace string) ([]*MetaData, error) {
	var instances []*MetaData

	cd, err := NewMetaData(host, namespace)
	if err != nil {
		return nil, err
	}
	instances = append(instances, cd)
	if namespace != "" {
		return instances, nil
	}

	nsList, err := cd.ListNamespace(context.TODO())
	if err != nil {
		return instances, err
	}

	for _, ns := range nsList {
		if ns == defaultNamespace {
			continue
		}
		cd, err := NewMetaData(host, ns)
		if err != nil {
			return instances, err
		}
		instances = append(instances, cd)
	}

	return instances, nil
}

func (d *MetaData) ListNamespace(ctx context.Context) ([]string, error) {
	return d.client.NamespaceService().List(ctx)
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

	id := getContainerId(containerId)
	common.DefaultLog.Debugf("get by id, id: %s", id)

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
	containers, err := c.Containers(ctx)
	if err != nil {
		return fmt.Errorf("list containers: %w", err)
	}
	for _, cr := range containers {
		d.saveContainer(ctx, cr)
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

	var chMsg <-chan *events.Envelope
	var chErr <-chan error
	var msg *events.Envelope

	chMsg, chErr = c.Subscribe(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-chErr:
			if errors.Is(err, context.Canceled) {
				return
			}
			common.DefaultLog.Errorf("containerd events failed: %s", err)
			return
		case msg = <-chMsg:
		}

		event, err := typeurl.UnmarshalAny(msg.Event)
		if err != nil {
			common.DefaultLog.Errorf("parse containerd event failed: %s", err)
			continue
		}

		common.DefaultLog.Debugf("new event: %#v", event)
		switch ev := event.(type) {
		case *apievents.ContainerCreate:
			d.handleContainerEvent(ctx, ev.ID)
		case *apievents.TaskCreate:
			d.handleContainerEvent(ctx, ev.ContainerID)
		case *apievents.TaskStart:
			d.handleContainerEvent(ctx, ev.ContainerID)
		}
	}
}

func (d *MetaData) handleContainerEvent(ctx context.Context, containerId string) {
	c := d.client
	containers, err := c.Containers(ctx)
	if err != nil {
		common.DefaultLog.Error(err.Error())
		return
	}
	for _, container := range containers {
		if container.ID() == containerId {
			d.saveContainer(ctx, container)
		}
	}
}

func (d *MetaData) saveContainer(ctx context.Context, container containerd.Container) {
	cr, err := d.inspectContainer(ctx, container)
	if err != nil {
		common.DefaultLog.Errorf(err.Error())
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

func (d *MetaData) inspectContainer(ctx context.Context, container containerd.Container) (*types.Container, error) {
	info, err := container.Info(ctx)
	if err != nil {
		return nil, err
	}
	task, err := container.Task(ctx, nil)
	if err != nil {
		if errors.Is(err, errdefs.ErrNotFound) ||
			strings.Contains(err.Error(), "no running task found") {
			common.DefaultLog.Debugf("get task failed: %s", err)
		} else {
			common.DefaultLog.Infof("get task failed: %s", err)
		}
		// return nil, err
	}

	name := getContainerName(info.Labels)
	cr := &types.Container{
		Id:     container.ID(),
		Name:   name,
		Image:  info.Image,
		Labels: info.Labels,
	}

	if task != nil {
		cr.RootPid = int(task.Pid())
		cr.PidNamespace = common.GetPidNamespaceFromPid(cr.RootPid)
		cr.MountNamespace = common.GetMountNamespaceFromPid(cr.RootPid)
		cr.NetworkNamespace = common.GetNetworkNamespaceFromPid(cr.RootPid)
	}

	return cr, nil
}

func (d *MetaData) Close() error {
	return d.client.Close()
}

// cgroupName: nerdctl-d3d7bc0de8fc3c1ccffc3b870f57ce5f82982b3b494df21f9722a68cc75cd4cd.scope
var regexContainerCgroupV2Name = regexp.MustCompilePOSIX(`[^\-]+-([a-z0-9]{64}).scope`)

func getContainerId(id string) string {
	parts := regexContainerCgroupV2Name.FindAllStringSubmatch(id, -1)
	if len(parts) < 1 {
		return id
	}
	part := parts[0]
	if len(part) < 2 {
		return id
	}
	return part[1]
}

func getContainerName(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	for _, key := range containerNameLabels {
		v := labels[key]
		if v != "" {
			return v
		}
	}
	return ""
}
