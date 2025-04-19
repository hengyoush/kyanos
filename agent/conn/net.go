package conn

import (
	"kyanos/agent/metadata"
	"kyanos/common"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

var ifIdxToName map[string]map[string]string = make(map[string]map[string]string)
var netnsIDMap map[string]string = make(map[string]string)
var lock *sync.Mutex = &sync.Mutex{}

func init() {
	nicsFromAllNs, err := GetAllNICs()
	if err != nil {
		return
	}
	ifIdxToName = nicsFromAllNs
	netnsIDMap, _ = getNetnsIDMap()
}

func getInterfaceNameByIndex(index int, pid int) (string, error) {
	var netnsId int64
	pidInfo := metadata.GetPidInfo(pid)
	if pidInfo.NetNS != -1 {
		netnsId = pidInfo.NetNS
	} else {
		netnsId = common.GetNetworkNamespaceFromPid(pid)
		pidInfo.NetNS = netnsId
	}
	netnsName, found := netnsIDMap[strconv.FormatInt(netnsId, 10)]
	if !found {
		netnsName = "default"
	}
	exist, found := ifIdxToName[netnsName]
	if found {
		ifName, found := exist[strconv.Itoa(index)]
		if found {
			return ifName, nil
		}
	}
	return strconv.Itoa(index), nil
}

func parseIpCmdLine(line string) (int, string, bool) {
	// Use regular expressions to match interface index and interface name
	// Assume the interface index starts with a number, followed by a colon and the interface name
	re := regexp.MustCompile(`^(\d+):\s*([^:]+)`)
	match := re.FindStringSubmatch(line)
	if len(match) < 3 {
		return 0, "", false // No match found
	}

	index, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, "", false // Failed to convert index
	}

	interfaceName := match[2]
	return index, interfaceName, true // Successfully extracted
}

var (
	hostNetNs int64
)

func init() {
	hostNetNs = common.GetNetworkNamespaceFromPid(1)
}

func GetAllNICs() (map[string]map[string]string, error) {
	result := make(map[string]map[string]string)

	// Default namespace
	defaultNS, err := exec.Command("ip", "link", "show").Output()
	if err != nil {
		return nil, err
	}
	result["default"] = parseLinkOutput(string(defaultNS))

	// Custom network namespaces
	nsList, err := exec.Command("ip", "netns", "list").Output()
	if err != nil {
		// If the command fails, there may be no custom network namespaces
		return result, nil
	}
	namespaces := strings.Split(strings.TrimSpace(string(nsList)), "\n")

	for _, ns := range namespaces {
		parts := strings.Fields(ns)
		if len(parts) == 0 {
			continue
		}
		nsName := parts[0]
		nsOutput, err := exec.Command("ip", "netns", "exec", nsName, "ip", "link", "show").Output()
		if err != nil {
			// Ignore errors for this namespace
			continue
		}
		result[nsName] = parseLinkOutput(string(nsOutput))
	}

	return result, nil
}

func parseLinkOutput(output string) map[string]string {
	interfaces := make(map[string]string)
	re := regexp.MustCompile(`^(\d+):\s+([^:]+):`)
	for _, line := range strings.Split(output, "\n") {
		match := re.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) == 3 {
			interfaces[match[1]] = match[2]
		}
	}
	return interfaces
}

func getNetnsIDMap() (map[string]string, error) {
	nsMap := make(map[string]string)

	dir, err := os.Open("/var/run/netns")
	if err != nil {
		return nil, err
	}
	defer dir.Close()

	files, err := dir.Readdirnames(0)
	if err != nil {
		return nil, err
	}

	for _, f := range files {
		info, err := os.Stat("/var/run/netns/" + f)
		if err != nil {
			continue
		}
		statT, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		inode := strconv.FormatUint(statT.Ino, 10)
		nsMap[inode] = f
	}

	return nsMap, nil
}
