package uprobe

const (
	kLibSSL_1_1             = "libssl.so.1.1"
	kLibSSL_3               = "libssl.so.3"
	kLibPython              = "libpython"
	kLibNettyTcnativePrefix = "libnetty_tcnative_linux_x86"
)

type HostPathForPIDPathSearchType int

const (
	kSearchTypeEndsWith HostPathForPIDPathSearchType = iota
	kSearchTypeContains
	// 可以根据需要添加更多
)

type SSLSocketFDAccess int

const (
	kNestedSyscall SSLSocketFDAccess = iota
	kUserSpaceOffsets
	// 可以根据需要添加更多
)

type SSLLibMatcher struct {
	Libssl         string
	Libcrypto      string
	SearchType     HostPathForPIDPathSearchType
	SocketFDAccess SSLSocketFDAccess
}

var kLibSSLMatchers = []SSLLibMatcher{
	{
		Libssl:         kLibSSL_1_1,
		Libcrypto:      "libcrypto.so.1.1",
		SearchType:     kSearchTypeEndsWith,
		SocketFDAccess: kNestedSyscall,
	},
	{
		Libssl:         kLibSSL_3,
		Libcrypto:      "libcrypto.so.3",
		SearchType:     kSearchTypeEndsWith,
		SocketFDAccess: kNestedSyscall,
	},
	{
		Libssl:         kLibPython,
		Libcrypto:      kLibPython,
		SearchType:     kSearchTypeContains,
		SocketFDAccess: kNestedSyscall,
	},
	{
		Libssl:         kLibNettyTcnativePrefix,
		Libcrypto:      kLibNettyTcnativePrefix,
		SearchType:     kSearchTypeContains,
		SocketFDAccess: kUserSpaceOffsets,
	},
}
