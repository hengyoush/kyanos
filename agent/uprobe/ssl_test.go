package uprobe

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetOpenSslVersionKey(t *testing.T) {
	path, err := getOpenSslVersionKey("/root/workspace/pktlatency/deps/openssl/libssl.so.3")
	assert.Nil(t, err)
	fmt.Println(path)
}
