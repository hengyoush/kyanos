package common

import (
	"golang.org/x/sys/unix"
)

const (
	// capBpf 0000 0000 0000 0000 0000 0000 1000 0000
	capBpf = 1 << (unix.CAP_BPF - 32)
	// capSysAdmin 0000 0000 0010 0000 0000 0000 0000 0000
	capSysAdmin = 1 << unix.CAP_SYS_ADMIN
)

// HasPermission reference: https://man7.org/linux/man-pages/man2/capset.2.html
func HasPermission() (bool, error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return false, err
	}
	// Note that the CAP_* values are bit indexes and need to be bit-shifted before ORing into the bit fields.
	// Note that 64-bit capabilities use datap[0] and datap[1], whereas 32-bit capabilities use only datap[0].
	return data[1].Permitted&capBpf != 0 || data[0].Permitted&capSysAdmin != 0, nil
}
