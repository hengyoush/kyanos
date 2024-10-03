package common

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func GetPidNamespaceFromPid(pid int) int64 {
	raw, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
	if err != nil {
		return 0
	}
	return getNamespaceId(raw)
}

func GetMountNamespaceFromPid(pid int) int64 {
	raw, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", pid))
	if err != nil {
		return 0
	}
	return getNamespaceId(raw)
}

func GetNetworkNamespaceFromPid(pid int) int64 {
	raw, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		return 0
	}
	return getNamespaceId(raw)
}

func getNamespaceId(raw string) int64 {
	parts := strings.Split(raw, "[")
	if len(parts) > 1 {
		n := strings.Trim(parts[1], "[]")
		id, err := strconv.ParseInt(n, 10, 64)
		if err != nil {
			return 0
		}
		return id
	}
	return 0
}
