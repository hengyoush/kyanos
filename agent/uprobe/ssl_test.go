package uprobe

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectOpenSsl(t *testing.T) {
	key, err := detectOpenSsl(1262837)
	assert.Nil(t, err)
	assert.NotEmpty(t, key)

}

func TestFindLibSslPath(t *testing.T) {
	matcher, path, err := findLibSslPath(1262837)
	assert.Nil(t, err)
	assert.NotEmpty(t, path)
	assert.NotNil(t, matcher)
}

func TestFindHostPathForPidLibs(t *testing.T) {
	path := findHostPathForPidLibs([]string{kLibSSLMatchers[0].Libssl}, 1262837, kLibSSLMatchers[0].SearchType)
	fmt.Println(path)
}

func TestGetOpenSslVersionKey(t *testing.T) {
	path, err := getOpenSslVersionKey("/root/workspace/pktlatency/libssl.so.1.0.2k")
	assert.Nil(t, err)
	fmt.Println(path)
}
