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

func TestFind(t *testing.T) {
	v := compatible.GetBestMatchedKernelVersion("4.15.0")
	assert.True(t, v.Version != "")
	assert.False(t, v.SupportCapability(compatible.SupportRingBuffer))

}
