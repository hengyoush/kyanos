package conn

import (
	"errors"
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
	netnsName, found := netnsIDMap[strconv.FormatInt(common.GetNetworkNamespaceFromPid(pid), 10)]
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
	return "", errors.New("interface not found")
}

func parseIpCmdLine(line string) (int, string, bool) {
	// 使用正则表达式匹配接口索引和接口名称
	// 假设接口索引是以数字开头，后面跟着冒号和接口名称
	re := regexp.MustCompile(`^(\d+):\s*([^:]+)`)
	match := re.FindStringSubmatch(line)
	if len(match) < 3 {
		return 0, "", false // 没有匹配到
	}

	index, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, "", false // 转换索引失败
	}

	interfaceName := match[2]
	return index, interfaceName, true // 成功提取
}

var (
	hostNetNs int64
)

func init() {
	hostNetNs = common.GetNetworkNamespaceFromPid(1)
}

func GetAllNICs() (map[string]map[string]string, error) {
	result := make(map[string]map[string]string)

	// 默认命名空间
	defaultNS, err := exec.Command("ip", "link", "show").Output()
	if err != nil {
		return nil, err
	}
	result["default"] = parseLinkOutput(string(defaultNS))

	// 自定义网络命名空间
	nsList, err := exec.Command("ip", "netns", "list").Output()
	if err != nil {
		// 若命令失败，可能没有任何自定义网络命名空间
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
			// 忽略该命名空间的错误
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
