package bpf

import (
	"embed"

	"github.com/cilium/ebpf/btf"
)

//go:embed custom-archive/*
var BtfFiles embed.FS

func IsKernelSupportHasBTF() bool {
	_, err := btf.LoadKernelSpec()
	if err == nil {
		return true
	} else {
		return false
	}
}
