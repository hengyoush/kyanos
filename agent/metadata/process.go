package metadata

import "kyanos/common"

const defaultProcDir = "/proc"

var (
	HostMntNs int64
	HostPidNs int64
	HostNetNs int64
)

func init() {
	HostPidNs = common.GetPidNamespaceFromPid(1)
	HostMntNs = common.GetMountNamespaceFromPid(1)
	HostNetNs = common.GetNetworkNamespaceFromPid(1)
}
