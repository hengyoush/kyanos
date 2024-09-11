package compatible_test

import (
	"kyanos/agent/compatible"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersion(t *testing.T) {
	v := compatible.GetCurrentKernelVersion()
	assert.True(t, v.Version != "")
}
