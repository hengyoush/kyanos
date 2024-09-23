package common

import (
	"bufio"
	"fmt"
	"os"
	"strings"
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
		fields := strings.Split(line, " ")
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
		if strings.HasPrefix(path, "/") {
			path = path[1:]
		}
		basePath = basePath + "/" + path
	}
	return basePath
}
