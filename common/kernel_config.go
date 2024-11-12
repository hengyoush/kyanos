package common

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"os"
	"regexp"
	"strings"
)

const (
	SysKernelBtfVmlinux = "/sys/kernel/btf/vmlinux"
	ConfigDebugInfoBtf  = "CONFIG_DEBUG_INFO_BTF"
)

// CONFIG CHECK ITEMS
var (
	configCheckItems = []string{
		"CONFIG_BPF",
		// "CONFIG_UPROBES",
		// "CONFIG_ARCH_SUPPORTS_UPROBES",
	}

	configPaths = []string{
		"/proc/config.gz",
		"/boot/config",
		"/boot/config-%s",
		"/lib/modules/%s/build/.config",
	}
)

var (
	// use same list of locations as libbpf
	// https://github.com/libbpf/libbpf/blob/9a3a42608dbe3731256a5682a125ac1e23bced8f/src/btf.c#L3114-L3122

	locations = []string{
		"/boot/vmlinux-%s",
		"/lib/modules/%s/vmlinux-%[1]s",
		"/lib/modules/%s/build/vmlinux",
		"/usr/lib/modules/%s/kernel/vmlinux",
		"/usr/lib/debug/boot/vmlinux-%s",
		"/usr/lib/debug/boot/vmlinux-%s.debug",
		"/usr/lib/debug/lib/modules/%s/vmlinux",
	}
)

func GetSystemConfig() (map[string]string, error) {
	var KernelConfig = make(map[string]string)
	var found bool
	release, e := UnameRelease()
	if e != nil {
		return KernelConfig, e
	}

	var err error
	for _, system_config_path := range configPaths {
		var bootConf = system_config_path
		if strings.Index(system_config_path, "%s") != -1 {
			bootConf = fmt.Sprintf(system_config_path, release)
		}

		KernelConfig, e = getLinuxConfig(bootConf)
		if e != nil {
			err = e
			// 没有找到配置文件，继续找下一个
			continue
		}

		if len(KernelConfig) > 0 {
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("KernelConfig not found. with error: %v", err)
	}
	return KernelConfig, nil
}

func getLinuxConfig(filename string) (map[string]string, error) {
	var KernelConfig = make(map[string]string)

	// Open file bootConf.
	f, err := os.Open(filename)
	if err != nil {
		return KernelConfig, err
	}
	defer f.Close()

	// check if the file is gzipped
	var magic []byte
	var i int
	magic = make([]byte, 2)
	i, err = f.Read(magic)
	if err != nil {
		return KernelConfig, err
	}
	if i != 2 {
		return KernelConfig, fmt.Errorf("read %d bytes, expected 2", i)
	}

	var s *bufio.Scanner
	_, err = f.Seek(0, 0)
	if err != nil {
		return KernelConfig, err
	}

	var reader *gzip.Reader
	//magic number for gzip is 0x1f8b
	if magic[0] == 0x1f && magic[1] == 0x8b {
		// gzip file
		reader, err = gzip.NewReader(f)
		if err != nil {
			return KernelConfig, err
		}
		s = bufio.NewScanner(reader)
	} else {
		// not gzip file
		s = bufio.NewScanner(f)
	}

	if err = parse(s, KernelConfig); err != nil {
		return KernelConfig, err
	}
	return KernelConfig, nil
}

func parse(s *bufio.Scanner, p map[string]string) error {
	r, _ := regexp.Compile("^(?:# *)?(CONFIG_\\w*)(?:=| )(y|n|m|is not set|\\d+|0x.+|\".*\")$")

	for s.Scan() {

		t := s.Text()

		// Skip line if empty.
		if t == "" {
			continue
		}

		// 0 is the match of the entire expression,
		// 1 is the key, 2 is the value.
		m := r.FindStringSubmatch(t)
		if m == nil {
			continue
		}

		if len(m) != 3 {
			return fmt.Errorf("match is not 3 chars long: %v", m)
		}
		// Remove all leading and trailing double quotes from the value.
		if len(m[2]) > 1 {
			m[2] = strings.Trim(m[2], "\"")
		}

		// Insert entry into map.
		p[m[1]] = m[2]
	}

	if err := s.Err(); err != nil {
		return err
	}

	return nil
}

// IsEnableBPF check BPF CONFIG
func IsEnableBPF() (bool, error) {
	var e error
	var KernelConfig = make(map[string]string)

	KernelConfig, e = GetSystemConfig()
	if e != nil {
		return false, e
	}

	for _, item := range configCheckItems {
		bc, found := KernelConfig[item]
		if !found {
			// 没有这个配置项
			return false, fmt.Errorf("Config not found,  item:%s.", item)
		}

		//如果有，在判断配置项的值
		if bc != "y" {
			// 没有开启
			return false, fmt.Errorf("Config disabled, item :%s.", item)
		}
	}

	return true, nil
}
