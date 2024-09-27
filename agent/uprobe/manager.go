package uprobe

import (
	"debug/elf"
	"fmt"
	"kyanos/bpf"
	"kyanos/common"
	"os"
	"regexp"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func AttachSslUprobe(pid int) ([]link.Link, error) {
	versionKey, err := detectOpenSsl(pid)
	if err != nil {
		return nil, err
	}
	bpfFunc := sslVersionBpfMap[versionKey]
	spec, objs, err := bpfFunc()
	if err != nil {
		return nil, err
	}
	collectionOptions := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
			LogSize:  10 * 1024 * 1024,
		},
		MapReplacements: map[string]*ebpf.Map{
			"active_ssl_read_args_map":  bpf.GetMapFromObjs(bpf.Objs, "ActiveSslReadArgsMap"),
			"active_ssl_write_args_map": bpf.GetMapFromObjs(bpf.Objs, "ActiveSslWriteArgsMap"),
			"conn_evt_rb":               bpf.GetMapFromObjs(bpf.Objs, "ConnEvtRb"),
			"conn_info_map":             bpf.GetMapFromObjs(bpf.Objs, "ConnInfoMap"),
			"rb":                        bpf.GetMapFromObjs(bpf.Objs, "Rb"),
			"ssl_data_map":              bpf.GetMapFromObjs(bpf.Objs, "SslDataMap"),
			"ssl_rb":                    bpf.GetMapFromObjs(bpf.Objs, "SslRb"),
			"ssl_user_space_call_map":   bpf.GetMapFromObjs(bpf.Objs, "SslUserSpaceCallMap"),
			"syscall_data_map":          bpf.GetMapFromObjs(bpf.Objs, "SyscallDataMap"),
			"syscall_rb":                bpf.GetMapFromObjs(bpf.Objs, "SyscallRb"),
		},
	}
	err = spec.LoadAndAssign(objs, collectionOptions)
	if err != nil {
		common.UprobeLog.Errorln(err)
		return nil, err
	}

	matcher, libSslPath, err := findLibSslPath(pid)
	if err != nil {
		return nil, err
	}

	sslEx, err := link.OpenExecutable(libSslPath)
	if err != nil {
		return nil, err
	}

	var l link.Link
	var links []link.Link
	// SSL_read
	l, err = sslEx.Uprobe(LibSslReadFuncName, bpf.GetProgramFromObjs(objs, buildBPFFuncName(LibSslReadFuncName, false, false, matcher.SocketFDAccess)), nil)
	links = handleAttachOpenSslUprobeResult(l, err, links)
	l, err = sslEx.Uretprobe(LibSslReadFuncName, bpf.GetProgramFromObjs(objs, buildBPFFuncName(LibSslReadFuncName, false, true, matcher.SocketFDAccess)), nil)
	links = handleAttachOpenSslUprobeResult(l, err, links)
	// SSL_read_ex
	l, err = sslEx.Uprobe(LibSslReadExFuncName, bpf.GetProgramFromObjs(objs, buildBPFFuncName(LibSslReadFuncName, true, false, matcher.SocketFDAccess)), nil)
	links = handleAttachOpenSslUprobeResult(l, err, links)
	l, err = sslEx.Uretprobe(LibSslReadExFuncName, bpf.GetProgramFromObjs(objs, buildBPFFuncName(LibSslReadFuncName, true, true, matcher.SocketFDAccess)), nil)
	links = handleAttachOpenSslUprobeResult(l, err, links)
	// SSL_write
	l, err = sslEx.Uprobe(LibSslWriteFuncName, bpf.GetProgramFromObjs(objs, buildBPFFuncName(LibSslWriteFuncName, false, false, matcher.SocketFDAccess)), nil)
	links = handleAttachOpenSslUprobeResult(l, err, links)
	l, err = sslEx.Uretprobe(LibSslWriteFuncName, bpf.GetProgramFromObjs(objs, buildBPFFuncName(LibSslWriteFuncName, false, true, matcher.SocketFDAccess)), nil)
	links = handleAttachOpenSslUprobeResult(l, err, links)
	// SSL_write_ex
	l, err = sslEx.Uprobe(LibSslWriteExFuncName, bpf.GetProgramFromObjs(objs, buildBPFFuncName(LibSslWriteFuncName, true, false, matcher.SocketFDAccess)), nil)
	links = handleAttachOpenSslUprobeResult(l, err, links)
	l, err = sslEx.Uretprobe(LibSslWriteExFuncName, bpf.GetProgramFromObjs(objs, buildBPFFuncName(LibSslWriteFuncName, true, true, matcher.SocketFDAccess)), nil)
	links = handleAttachOpenSslUprobeResult(l, err, links)

	return links, nil
}

func handleAttachOpenSslUprobeResult(l link.Link, err error, links []link.Link) []link.Link {
	if err != nil {
		common.UprobeLog.Warnf("attach openssl probe failed: %v", err)
	} else {
		links = append(links, l)
	}
	return links
}

func buildBPFFuncName(baseName string, isEx bool, isRet bool, socketFDAccess SSLSocketFDAccess) string {
	result := baseName
	if isEx {
		result += "Ex"
	}
	if isRet {
		result += "Ret"
	} else {
		result += "Entry"
	}
	if socketFDAccess == kNestedSyscall {
		result += "NestedSyscall"
	} else {
		result += "Offset"
	}
	return result
}

func detectOpenSsl(pid int) (string, error) {
	_, libSslPath, err := findLibSslPath(pid)
	if err != nil {
		return "", err
	}
	if result, err := getOpenSslVersionKey(libSslPath); err == nil {
		return result, nil
	}
	libSslLibName := libSslPath[strings.LastIndex(libSslPath, "/")+1:]
	if libSslLibName == "libssl.so.3" {
		return Linuxdefaulefilename30, nil
	} else {
		return Linuxdefaulefilename111, nil
	}
}

func findLibSslPath(pid int) (SSLLibMatcher, string, error) {
	for _, matcher := range kLibSSLMatchers {
		libnames := []string{matcher.Libssl}
		libnameToPath := findHostPathForPidLibs(libnames, pid, matcher.SearchType)
		path, found := libnameToPath[matcher.Libssl]
		if found {
			return matcher, path, nil
		}
	}
	return SSLLibMatcher{}, "", fmt.Errorf("no dynamic link openssl found")
}

func findHostPathForPidLibs(libnames []string, pid int, searchType HostPathForPIDPathSearchType) map[string]string {
	paths := common.GetMapPaths(pid)
	result := make(map[string]string)
	for _, libname := range libnames {
		if _, ok := result[libname]; ok {
			continue
		}

		for _, path := range paths {
			if searchType == kSearchTypeContains && !strings.Contains(path, libname) {
				continue
			}
			if searchType == kSearchTypeEndsWith && !strings.HasSuffix(path, libname) {
				continue
			}

			libPath := common.ProcPidRootPath(pid, "root", path)
			result[libname] = libPath
			break
		}
	}
	return result
}

func getOpenSslVersionKey(libSslPath string) (string, error) {
	f, err := os.OpenFile(libSslPath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return "", fmt.Errorf("can not open %s, with error:%v", libSslPath, err)
	}
	r, e := elf.NewFile(f)
	if e != nil {
		return "", fmt.Errorf("parse the ELF file  %s failed, with error:%v", libSslPath, err)
	}

	switch r.FileHeader.Machine {
	case elf.EM_X86_64:
	case elf.EM_AARCH64:
	default:
		return "", fmt.Errorf("unsupported arch library ,ELF Header Machine is :%s, must be one of EM_X86_64 and EM_AARCH64", r.FileHeader.Machine.String())
	}

	s := r.Section(".rodata")
	if s == nil {
		// not found
		return "", fmt.Errorf("detect openssl version failed, cant read .rodata section from %s", libSslPath)
	}

	sectionOffset := int64(s.Offset)
	sectionSize := s.Size

	r.Close()

	_, err = f.Seek(0, 0)
	if err != nil {
		return "", err
	}

	ret, err := f.Seek(sectionOffset, 0)
	if ret != sectionOffset || err != nil {
		return "", err
	}

	versionKey := ""

	// e.g : OpenSSL 1.1.1j  16 Feb 2021
	// OpenSSL 3.2.0 23 Nov 2023
	rex, err := regexp.Compile(`(OpenSSL\s\d\.\d\.[0-9a-z]+)`)
	if err != nil {
		return "", err
	}

	buf := make([]byte, 1024*1024) // 1Mb
	totalReadCount := 0
	for totalReadCount < int(sectionSize) {
		var readCount int
		readCount, err = f.Read(buf)

		if err != nil {
			common.DefaultLog.Errorf("read openssl version failed: %v", err)
			break
		}

		if readCount == 0 {
			break
		}

		match := rex.Find(buf)
		if match != nil {
			versionKey = string(match)
			break
		}

		// Subtracting OpenSslVersionLen from totalReadCount,
		// to cover the edge-case in which openssl version string
		// could be split into two buffers. Subtraction will,
		// makes sure that last 30 bytes of previous buffer are considered.
		totalReadCount += readCount - OpenSslVersionLen

		_, err = f.Seek(sectionOffset+int64(totalReadCount), 0)
		if err != nil {
			break
		}

		clear(buf)
	}
	_ = f.Close()
	//buf = buf[:0]

	if versionKey != "" {
		versionKeyLower := strings.ToLower(versionKey)
		return versionKeyLower, nil
	} else {
		return "", fmt.Errorf("no openssl version found in openssl so path: %s", libSslPath)
	}
}
