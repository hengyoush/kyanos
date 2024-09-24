package uprobe

import (
	"kyanos/common"
	"strings"
)

func findHostPathForPidLibs(libnames []string, pid int, searchType HostPathForPIDPathSearchType) map[string]string {
	paths := common.GetMapPaths(pid)
	result := make(map[string]string)
	for _, libname := range libnames {
		if _, ok := result[libname]; ok {
			continue
		}

		for _, path := range paths {
			if searchType == kSearchTypeContains && !strings.Contains(path, libname) {
				continue
			}
			if searchType == kSearchTypeEndsWith && !strings.HasSuffix(path, libname) {
				continue
			}

			libPath := common.ProcPidRootPath(pid, "root", path)
			result[libname] = libPath
			break
		}
	}
	return result
}

func detectOpenSsl(pid int) {
	for _, matcher := range kLibSSLMatchers {

	}
}
