package uprobe

import "fmt"

const (
	kLibSSL_1_0             = "libssl.so.1.0"
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
		Libssl:         kLibSSL_1_0,
		Libcrypto:      "libcrypto.so.1.0",
		SearchType:     kSearchTypeContains,
		SocketFDAccess: kNestedSyscall,
	},
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

const (
	MaxSupportedOpenSSL102Version = 'u'
	MaxSupportedOpenSSL110Version = 'l'
	MaxSupportedOpenSSL111Version = 'w'
	MaxSupportedOpenSSL30Version  = 15
	MaxSupportedOpenSSL31Version  = 7
	SupportedOpenSSL32Version2    = 2 // openssl 3.2.0 ~ 3.2.2
	MaxSupportedOpenSSL32Version  = 3 // openssl 3.2.3 ~ newer
	MaxSupportedOpenSSL33Version  = 2
)
const (
	Linuxdefaulefilename102 = "linux_default_1_0_2"
	Linuxdefaulefilename110 = "linux_default_1_1_0"
	Linuxdefaulefilename111 = "linux_default_1_1_1"
	Linuxdefaulefilename30  = "linux_default_3_0"
	Linuxdefaulefilename31  = "linux_default_3_0"
	Linuxdefaulefilename320 = "linux_default_3_2"
	Linuxdefaulefilename330 = "linux_default_3_3"
	AndroidDefauleFilename  = "android_default"

	OpenSslVersionLen = 30 // openssl version string length
)

var sslVersionBpfMap map[string]string

func init() {
	initOpensslOffset()
}

// initOpensslOffset initial BpfMap
func initOpensslOffset() {
	sslVersionBpfMap = map[string]string{
		// openssl 1.0.2*
		Linuxdefaulefilename102: "openssl_1_0_2a_kern.o",

		// openssl 1.1.0*
		Linuxdefaulefilename110: "openssl_1_1_0a_kern.o",

		// openssl 1.1.1*
		Linuxdefaulefilename111: "openssl_1_1_1j_kern.o",

		// openssl 3.0.* and openssl 3.1.*
		Linuxdefaulefilename30: "openssl_3_0_0_kern.o",

		// openssl 3.2.*
		Linuxdefaulefilename320: "openssl_3_2_0_kern.o",

		// boringssl
		// git repo: https://android.googlesource.com/platform/external/boringssl/+/refs/heads/android12-release
		"boringssl 1.1.1":      "boringssl_a_13_kern.o",
		"boringssl_a_13":       "boringssl_a_13_kern.o",
		"boringssl_a_14":       "boringssl_a_14_kern.o",
		AndroidDefauleFilename: "boringssl_a_13_kern.o",

		// non-Android boringssl
		// "boringssl na" is a special version for non-android
		// git repo: https://github.com/google/boringssl
		"boringssl na": "boringssl_na_kern.o",
	}

	// in openssl source files, there are 4 offset groups for all 1.1.1* version.
	// group a : 1.1.1a
	sslVersionBpfMap["openssl 1.1.1a"] = "openssl_1_1_1a_kern.o"

	// group b : 1.1.1b-1.1.1c
	sslVersionBpfMap["openssl 1.1.1b"] = "openssl_1_1_1b_kern.o"
	sslVersionBpfMap["openssl 1.1.1c"] = "openssl_1_1_1b_kern.o"

	// group c : 1.1.1d-1.1.1i
	for ch := 'd'; ch <= 'i'; ch++ {
		sslVersionBpfMap["openssl 1.1.1"+string(ch)] = "openssl_1_1_1d_kern.o"
	}

	// group e : 1.1.1j-1.1.1s
	for ch := 'j'; ch <= MaxSupportedOpenSSL111Version; ch++ {
		sslVersionBpfMap["openssl 1.1.1"+string(ch)] = "openssl_1_1_1j_kern.o"
	}

	// openssl 3.0.0 - 3.0.15
	for ch := 0; ch <= MaxSupportedOpenSSL30Version; ch++ {
		sslVersionBpfMap[fmt.Sprintf("openssl 3.0.%d", ch)] = "openssl_3_0_0_kern.o"
	}

	// openssl 3.1.0 - 3.1.4
	for ch := 0; ch <= MaxSupportedOpenSSL31Version; ch++ {
		// The OpenSSL 3.0 series is the same as the 3.1 series of offsets
		sslVersionBpfMap[fmt.Sprintf("openssl 3.1.%d", ch)] = "openssl_3_1_0_kern.o"
	}

	// openssl 3.2.0
	for ch := 0; ch <= SupportedOpenSSL32Version2; ch++ {
		sslVersionBpfMap[fmt.Sprintf("openssl 3.2.%d", ch)] = "openssl_3_2_0_kern.o"
	}

	// openssl 3.2.3 - newer
	for ch := 3; ch <= MaxSupportedOpenSSL32Version; ch++ {
		sslVersionBpfMap[fmt.Sprintf("openssl 3.2.%d", ch)] = "openssl_3_2_3_kern.o"
	}

	// openssl 3.3.0 - newer
	for ch := 0; ch <= MaxSupportedOpenSSL33Version; ch++ {
		// The OpenSSL 3.3.* series is the same as the 3.2.* series of offsets
		sslVersionBpfMap[fmt.Sprintf("openssl 3.3.%d", ch)] = "openssl_3_3_0_kern.o"
	}

	// openssl 1.1.0a - 1.1.0l
	for ch := 'a'; ch <= MaxSupportedOpenSSL110Version; ch++ {
		sslVersionBpfMap["openssl 1.1.0"+string(ch)] = "openssl_1_1_0a_kern.o"
	}

	// openssl 1.0.2a - 1.0.2u
	for ch := 'a'; ch <= MaxSupportedOpenSSL102Version; ch++ {
		sslVersionBpfMap["openssl 1.0.2"+string(ch)] = "openssl_1_0_2a_kern.o"
	}

}
