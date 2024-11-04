package uprobe

import (
	"kyanos/bpf"

	"github.com/cilium/ebpf"
)

func getMapReplacementsForOpenssl() map[string]*ebpf.Map {
	return map[string]*ebpf.Map{
		"active_ssl_read_args_map":  bpf.GetMapFromObjs(bpf.Objs, "ActiveSslReadArgsMap"),
		"active_ssl_write_args_map": bpf.GetMapFromObjs(bpf.Objs, "ActiveSslWriteArgsMap"),
		"conn_evt_rb":               bpf.GetMapFromObjs(bpf.Objs, "ConnEvtRb"),
		"conn_info_map":             bpf.GetMapFromObjs(bpf.Objs, "ConnInfoMap"),
		"rb":                        bpf.GetMapFromObjs(bpf.Objs, "Rb"),
		"ssl_data_map":              bpf.GetMapFromObjs(bpf.Objs, "SslDataMap"),
		"ssl_rb":                    bpf.GetMapFromObjs(bpf.Objs, "SslRb"),
		"ssl_user_space_call_map":   bpf.GetMapFromObjs(bpf.Objs, "SslUserSpaceCallMap"),
		"syscall_data_map":          bpf.GetMapFromObjs(bpf.Objs, "SyscallDataMap"),
		"syscall_rb":                bpf.GetMapFromObjs(bpf.Objs, "SyscallRb"),
		"filter_mntns_map":          bpf.GetMapFromObjs(bpf.Objs, "FilterMntnsMap"),
		"filter_netns_map":          bpf.GetMapFromObjs(bpf.Objs, "FilterNetnsMap"),
		"filter_pid_map":            bpf.GetMapFromObjs(bpf.Objs, "FilterPidMap"),
		"filter_pidns_map":          bpf.GetMapFromObjs(bpf.Objs, "FilterPidnsMap"),
	}
}

func getMapReplacementsForGoTls() map[string]*ebpf.Map {
	m := getMapReplacementsForOpenssl()
	m["go_common_symaddrs_map"] = bpf.GetMapFromObjs(bpf.Objs, "GoCommonSymaddrsMap")
	m["go_ssl_user_space_call_map"] = bpf.GetMapFromObjs(bpf.Objs, "GoSslUserSpaceCallMap")
	return m
}
