package common

import (
	"golang.org/x/sys/unix"
)

func HasPermission() (bool, error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return false, err
	}
	return data[0].Permitted&unix.CAP_BPF != 0, nil
}
