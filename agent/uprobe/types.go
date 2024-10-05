package uprobe

import (
	"fmt"
	"kyanos/bpf"
	"kyanos/common"

	"github.com/cilium/ebpf"
)

const (
	LibSslReadFuncName    = "SSL_read"
	LibSslReadExFuncName  = "SSL_read_ex"
	LibSslWriteFuncName   = "SSL_write"
	LibSslWriteExFuncName = "SSL_write_ex"
)

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

type OpensslObjectsFunc func() (*ebpf.CollectionSpec, any, error)

var sslVersionBpfMap map[string]OpensslObjectsFunc

func init() {
	initOpensslOffset()
}

// initOpensslOffset initial BpfMap
func initOpensslOffset() {
	sslVersionBpfMap = map[string]OpensslObjectsFunc{
		// openssl 1.0.2*
		Linuxdefaulefilename102: func() (*ebpf.CollectionSpec, any, error) {
			r, err := bpf.LoadOpenssl102a()
			if err != nil {
				common.UprobeLog.Errorln(err)
				return nil, nil, err
			}
			return r, &bpf.Openssl102aObjects{}, nil
		},

		// openssl 1.1.0*
		Linuxdefaulefilename110: func() (*ebpf.CollectionSpec, any, error) {
			r, err := bpf.LoadOpenssl110a()
			if err != nil {
				common.UprobeLog.Errorln(err)
				return nil, nil, err
			}
			return r, &bpf.Openssl110aObjects{}, nil
		},

		// openssl 1.1.1*
		Linuxdefaulefilename111: func() (*ebpf.CollectionSpec, any, error) {
			r, err := bpf.LoadOpenssl111j()
			if err != nil {
				common.UprobeLog.Errorln(err)
				return nil, nil, err
			}
			return r, &bpf.Openssl111jObjects{}, nil
		},

		// openssl 3.0.* and openssl 3.1.*
		Linuxdefaulefilename30: func() (*ebpf.CollectionSpec, any, error) {
			r, err := bpf.LoadOpenssl300()
			if err != nil {
				common.UprobeLog.Errorln(err)
				return nil, nil, err
			}
			return r, &bpf.Openssl300Objects{}, nil
		},

		// openssl 3.2.*
		Linuxdefaulefilename320: func() (*ebpf.CollectionSpec, any, error) {
			r, err := bpf.LoadOpenssl320()
			if err != nil {
				common.UprobeLog.Errorln(err)
				return nil, nil, err
			}
			return r, &bpf.Openssl320Objects{}, nil
		},

		// boringssl
		// git repo: https://android.googlesource.com/platform/external/boringssl/+/refs/heads/android12-release
		"boringssl 1.1.1":      nil,
		"boringssl_a_13":       nil,
		"boringssl_a_14":       nil,
		AndroidDefauleFilename: nil,

		// non-Android boringssl
		// "boringssl na" is a special version for non-android
		// git repo: https://github.com/google/boringssl
		"boringssl na": nil,
	}

	sslVersionBpfMap["openssl 1.1.1"] = sslVersionBpfMap[Linuxdefaulefilename111]

	// in openssl source files, there are 4 offset groups for all 1.1.1* version.
	// group a : 1.1.1a
	sslVersionBpfMap["openssl 1.1.1a"] = func() (*ebpf.CollectionSpec, any, error) {
		r, err := bpf.LoadOpenssl111a()
		if err != nil {
			common.UprobeLog.Errorln(err)
			return nil, nil, err
		}
		return r, &bpf.Openssl111aObjects{}, nil
	}

	// group b : 1.1.1b-1.1.1c
	sslVersionBpfMap["openssl 1.1.1b"] = func() (*ebpf.CollectionSpec, any, error) {
		r, err := bpf.LoadOpenssl111b()
		if err != nil {
			common.UprobeLog.Errorln(err)
			return nil, nil, err
		}
		return r, &bpf.Openssl111bObjects{}, nil
	}

	sslVersionBpfMap["openssl 1.1.1c"] = func() (*ebpf.CollectionSpec, any, error) {
		r, err := bpf.LoadOpenssl111b()
		if err != nil {
			common.UprobeLog.Errorln(err)
			return nil, nil, err
		}
		return r, &bpf.Openssl111bObjects{}, nil
	}
	// group c : 1.1.1d-1.1.1i
	for ch := 'd'; ch <= 'i'; ch++ {
		sslVersionBpfMap["openssl 1.1.1"+string(ch)] = func() (*ebpf.CollectionSpec, any, error) {
			r, err := bpf.LoadOpenssl111d()
			if err != nil {
				common.UprobeLog.Errorln(err)
				return nil, nil, err
			}
			return r, &bpf.Openssl111dObjects{}, nil
		}
	}

	// group e : 1.1.1j-1.1.1s
	for ch := 'j'; ch <= MaxSupportedOpenSSL111Version; ch++ {
		sslVersionBpfMap["openssl 1.1.1"+string(ch)] = func() (*ebpf.CollectionSpec, any, error) {
			r, err := bpf.LoadOpenssl111j()
			if err != nil {
				common.UprobeLog.Errorln(err)
				return nil, nil, err
			}
			return r, &bpf.Openssl111jObjects{}, nil
		}
	}

	// openssl 3.0.0 - 3.0.15
	for ch := 0; ch <= MaxSupportedOpenSSL30Version; ch++ {
		sslVersionBpfMap[fmt.Sprintf("openssl 3.0.%d", ch)] = func() (*ebpf.CollectionSpec, any, error) {
			r, err := bpf.LoadOpenssl300()
			if err != nil {
				common.UprobeLog.Errorln(err)
				return nil, nil, err
			}
			return r, &bpf.Openssl300Objects{}, nil
		}
	}

	// openssl 3.1.0 - 3.1.4
	for ch := 0; ch <= MaxSupportedOpenSSL31Version; ch++ {
		// The OpenSSL 3.0 series is the same as the 3.1 series of offsets
		sslVersionBpfMap[fmt.Sprintf("openssl 3.1.%d", ch)] = func() (*ebpf.CollectionSpec, any, error) {
			r, err := bpf.LoadOpenssl310()
			if err != nil {
				common.UprobeLog.Errorln(err)
				return nil, nil, err
			}
			return r, &bpf.Openssl310Objects{}, nil
		}
	}

	// openssl 3.2.0
	for ch := 0; ch <= SupportedOpenSSL32Version2; ch++ {
		sslVersionBpfMap[fmt.Sprintf("openssl 3.2.%d", ch)] = func() (*ebpf.CollectionSpec, any, error) {
			r, err := bpf.LoadOpenssl320()
			if err != nil {
				common.UprobeLog.Errorln(err)
				return nil, nil, err
			}
			return r, &bpf.Openssl320Objects{}, nil
		}
	}

	// openssl 3.2.3 - newer
	for ch := 3; ch <= MaxSupportedOpenSSL32Version; ch++ {
		sslVersionBpfMap[fmt.Sprintf("openssl 3.2.%d", ch)] = func() (*ebpf.CollectionSpec, any, error) {
			r, err := bpf.LoadOpenssl323()
			if err != nil {
				common.UprobeLog.Errorln(err)
				return nil, nil, err
			}
			return r, &bpf.Openssl323Objects{}, nil
		}
	}

	// openssl 3.3.0 - newer
	for ch := 0; ch <= MaxSupportedOpenSSL33Version; ch++ {
		// The OpenSSL 3.3.* series is the same as the 3.2.* series of offsets
		sslVersionBpfMap[fmt.Sprintf("openssl 3.3.%d", ch)] = func() (*ebpf.CollectionSpec, any, error) {
			r, err := bpf.LoadOpenssl330()
			if err != nil {
				common.UprobeLog.Errorln(err)
				return nil, nil, err
			}
			return r, &bpf.Openssl330Objects{}, nil
		}
	}

	// openssl 1.1.0a - 1.1.0l
	for ch := 'a'; ch <= MaxSupportedOpenSSL110Version; ch++ {
		sslVersionBpfMap["openssl 1.1.0"+string(ch)] = func() (*ebpf.CollectionSpec, any, error) {
			r, err := bpf.LoadOpenssl110a()
			if err != nil {
				common.UprobeLog.Errorln(err)
				return nil, nil, err
			}
			return r, &bpf.Openssl110aObjects{}, nil
		}
	}

	// openssl 1.0.2a - 1.0.2u
	for ch := 'a'; ch <= MaxSupportedOpenSSL102Version; ch++ {
		sslVersionBpfMap["openssl 1.0.2"+string(ch)] = func() (*ebpf.CollectionSpec, any, error) {
			r, err := bpf.LoadOpenssl102a()
			if err != nil {
				common.UprobeLog.Errorln(err)
				return nil, nil, err
			}
			return r, &bpf.Openssl102aObjects{}, nil
		}
	}

}
