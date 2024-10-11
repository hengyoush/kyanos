package common

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/shirou/gopsutil/process"
)

func GetMapPaths(pid int) []string {
	const kProcMapNumFields int = 6

	mapsFilePath := fmt.Sprintf("/proc/%d/maps", pid)
	file, err := os.Open(mapsFilePath)
	if err != nil {
		return nil
	}
	defer file.Close()
	result := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) == kProcMapNumFields {
			pathName := fields[len(fields)-1]
			pathName = strings.Trim(pathName, " ")
			result = append(result, pathName)
		}
	}
	return result
}

func ProcPidRootPath(pid int, paths ...string) string {
	basePath := fmt.Sprintf("/proc/%d", pid)
	for _, path := range paths {
		path = strings.TrimPrefix(path, "/")
		basePath = basePath + "/" + path
	}
	return basePath
}

func GetAllPids() ([]int32, error) {
	return process.Pids()
}

func GetPidCmdString(pid int32) string {
	proc, err := process.NewProcess(pid)
	if err != nil {
		return fmt.Sprintf("%d<%s>", pid, "unknwon")
	} else {
		name, err := proc.Name()
		if err != nil {
			return fmt.Sprintf("%d<%s>", pid, "unknwon")
		}
		return fmt.Sprintf("%d<%s>", pid, name)
	}
}
