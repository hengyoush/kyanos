package common

import (
	"fmt"
	"net"
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

func GetInterfaceNameByIndex(index int) (string, error) {
	exist, found := ifIdxToName[index]
	if found {
		return exist, nil
	}
	lock.Lock()
	defer lock.Unlock()
	interfc, err := net.InterfaceByIndex(index)
	if err != nil {
		return "", fmt.Errorf("GetInterfaceNameByIndex(%d) err: %v ", index, err)
	} else {
		ifIdxToName[interfc.Index] = interfc.Name
		return interfc.Name, nil
	}
}
