package uprobe

import (
	"debug/elf"
	"fmt"
	ac "kyanos/agent/common"
	"kyanos/bpf"
	"kyanos/common"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/shirou/gopsutil/process"
)

var attachedLibPaths map[string]bool = make(map[string]bool)
var uprobeLinks []link.Link = make([]link.Link, 0)

func StartHandleSchedExecEvent() chan *bpf.AgentProcessExecEvent {
	ch := make(chan *bpf.AgentProcessExecEvent)
	go func() {
		for event := range ch {
			go func(e *bpf.AgentProcessExecEvent) {
				// Delay some time to give the process time to map the SSL library
				// but there is still a chance that the process doesn't map the SSL library
				// at the start time.
				// TODO: There may be a better way to handle this.
				time.Sleep(1000 * time.Millisecond)
				handleSchedExecEvent(e)
			}(event)
		}
	}()
	return ch
}

func handleSchedExecEvent(event *bpf.AgentProcessExecEvent) {
	links, err := AttachSslUprobe(int(event.Pid))
	var procName string
	if proc, err := process.NewProcess(event.Pid); err == nil {
		procName, _ = proc.Name()
	}
	if err == nil {
		if len(links) > 0 {
			uprobeLinks = append(uprobeLinks, links...)
		} else {
			common.UprobeLog.Debugf("Attach OpenSsl uprobes success for pid: %d (%s) use previous libssl path", event.Pid, procName)
		}
	} else {
		common.UprobeLog.Debugf("AttachSslUprobe failed for exec event(pid: %d %s): %v", event.Pid, procName, err)
	}
	links, err = AttachGoTlsProbes(int(event.Pid))
	if err == nil {
		if len(links) > 0 {
			uprobeLinks = append(uprobeLinks, links...)
		} else {
			common.UprobeLog.Debugf("Attach GoTls uprobes success for pid: %d (%s) use previous libssl path", event.Pid, procName)
		}
	} else {
		common.UprobeLog.Debugf("Attach GoTls Uprobe failed for exec event(pid: %d %s): %v", event.Pid, procName, err)
	}
}

func AttachSslUprobe(pid int) ([]link.Link, error) {
	versionKey, err := detectOpenSsl(pid)
	if err != nil || versionKey == "" {
		return []link.Link{}, err
	}
	bpfFunc, ok := sslVersionBpfMap[versionKey]
	if !ok {
		common.UprobeLog.Warnf("versionKey %s found but bpfFunc not found", versionKey)
		return []link.Link{}, nil
	}

	matcher, libSslPath, _, err := findLibSslPath(pid)
	if err != nil || libSslPath == "" {
		return nil, err
	}

	if _, found := attachedLibPaths[libSslPath]; found {
		return []link.Link{}, nil
	} else {
		attachedLibPaths[libSslPath] = true
	}

	sslEx, err := link.OpenExecutable(libSslPath)
	if err != nil {
		return nil, err
	}

	spec, objs, err := bpfFunc()
	if err != nil {
		return nil, err
	}
	collectionOptions := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			// LogLevel: ebpf.LogLevelInstruction,
			LogSize:     10 * 1024,
			KernelTypes: ac.CollectionOpts.Programs.KernelTypes,
		},
		MapReplacements: getMapReplacementsForOpenssl(),
	}
	err = spec.LoadAndAssign(objs, collectionOptions)
	if err != nil {
		common.UprobeLog.Warnf("load openssl uprobe failed for pid %d lib path %s : %v", pid, libSslPath, err)
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
	if err == nil {
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
	_, libSslPath, libcryptopath, err := findLibSslPath(pid)
	if err != nil || libSslPath == "" {
		return "", err
	}
	if result, err := getOpenSslVersionKey(libSslPath); err == nil {
		common.UprobeLog.Debugf("getOpenSslVersionKey return libSslPath: %s", result)
		return result, nil
	}
	if result, err := getOpenSslVersionKey(libcryptopath); err == nil {
		common.UprobeLog.Debugf("getOpenSslVersionKey return libcryptopath: %s", result)
		return result, nil
	}
	libSslLibName := libSslPath[strings.LastIndex(libSslPath, "/")+1:]
	if libSslLibName == "libssl.so.3" {
		return Linuxdefaulefilename30, nil
	} else {
		return Linuxdefaulefilename111, nil
	}
}

func findLibSslPath(pid int) (SSLLibMatcher, string, string, error) {
	for _, matcher := range kLibSSLMatchers {
		libnames := []string{matcher.Libssl, matcher.Libcrypto}
		libnameToPath := findHostPathForPidLibs(libnames, pid, matcher.SearchType)
		libsslpath, sslfound := libnameToPath[matcher.Libssl]
		libcryptopath, cryptofound := libnameToPath[matcher.Libcrypto]
		if sslfound && cryptofound {
			common.UprobeLog.Debugf("[findLibSslPath] matcher: %s  matched for pid: %d", matcher.Libssl, pid)
			return matcher, libsslpath, libcryptopath, nil
		} else {
			common.UprobeLog.Debugf("[findLibSslPath] matcher: %s doesn't match for pid: %d", matcher.Libssl, pid)
		}
	}
	return SSLLibMatcher{}, "", "", nil
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
