package common

import (
	"slices"

	"github.com/containerd/containerd/pkg/cap"
)

func HasPermission() (bool, error) {
	current, err := cap.Current()
	if err != nil {
		return false, err
	}
	return slices.Contains(current, "CAP_BPF"), nil
}
