package common

import (
	"bufio"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

var ifIdxToName map[int]string = make(map[int]string)
var lock *sync.Mutex = &sync.Mutex{}

func init() {
	ifs, err := net.Interfaces()
	if err == nil {
		for _, each := range ifs {
			ifIdxToName[each.Index] = each.Name
		}
	}
}

func DeleteIfIdxToNameEntry(pid int) {
	delete(ifIdxToName, pid)
}

func GetInterfaceNameByIndex(index int, pid int) (string, error) {
	exist, found := ifIdxToName[index]
	if found {
		return exist, nil
	}

	netNs := GetNetworkNamespaceFromPid(pid)
	var result string

	lock.Lock()
	defer lock.Unlock()
	if netNs == hostNetNs {
		exist, found := ifIdxToName[index]
		if found {
			return exist, nil
		}
		interfc, err := net.InterfaceByIndex(index)
		if err != nil {
			result = ""
			// return "", fmt.Errorf("GetInterfaceNameByIndex(%d) err: %v ", index, err)
		} else {
			result = interfc.Name
			// ifIdxToName[interfc.Index] = interfc.Name
			// return interfc.Name, nil
		}
	} else {
		config := NsEnterConfig{
			Net:    true,
			Target: pid,
		}
		stdout, _, _ := config.Execute("sh", "-c", "ip a")
		scanner := bufio.NewScanner(strings.NewReader(stdout))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.TrimSpace(line) == "" || !strings.Contains(line, ":") {
				continue
			}

			parsedIndex, parsedName, ok := parseIpCmdLine(line)
			if ok && index == parsedIndex {
				result = parsedName
				break
			}
		}
	}
	ifIdxToName[index] = result
	return result, nil
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
	hostNetNs = GetNetworkNamespaceFromPid(1)
}
