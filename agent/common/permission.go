package common

import (
	"os"
	"slices"

	"github.com/containerd/containerd/pkg/cap"
)

func HasPermission() (bool, error) {
	// root is considered as having CAP_BPF capability.
	if os.Geteuid() == 0 {
		return true, nil
	}
	current, err := cap.Current()
	if err != nil {
		return false, err
	}
	return slices.Contains(current, "CAP_BPF"), nil
}
