package loader

import (
	"context"
	"debug/elf"
	"fmt"
	"io"
	ac "kyanos/agent/common"
	"kyanos/bpf"
	"kyanos/common"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

const (
	DefaultPath   = "/sys/kernel/btf/vmlinux"
	candidatePath = "/var/lib/kyanos/btf/vmlinux"

	// https://github.com/aquasecurity/btfhub-archive/raw/main/centos/7/x86_64/4.19.113-300.el7.x86_64.btf.tar.xz
	btfHubURL = "https://github.com/aquasecurity/btfhub-archive/raw/main/%s/%s/%s/%s.btf.tar.xz"

	// https://mirrors.openanolis.cn/coolbpf/btf/x86_64/vmlinux-4.19.91-21.al7.x86_64
	openAnolisURL = "https://mirrors.openanolis.cn/coolbpf/btf/%s/vmlinux-%s"
)

const (
	MirrorBTFHub = iota
	MirrorOpenAnolis
)

func loadBTFSpec(options ac.AgentOptions) *btf.Spec {
	if bpf.IsKernelSupportHasBTF() {
		return nil
	}

	options.LoadPorgressChannel <- "starting load BTF file"
	var spec *btf.Spec
	if options.BTFFilePath != "" {
		btfPath, err := btf.LoadSpec(options.BTFFilePath)
		if err != nil {
			common.AgentLog.Fatalf("can't load btf spec: %v", err)
		}
		spec = btfPath
		options.LoadPorgressChannel <- "starting load BTF file: success!"
	} else {
		fileBytes, err := getBestMatchedBTFFile()
		if err == nil {
			needGenerateBTF := fileBytes != nil
			if needGenerateBTF {
				btfFilePath, err := writeToFile(fileBytes, ".kyanos.btf")
				if err == nil {
					defer os.Remove(btfFilePath)
					btfPath, err := btf.LoadSpec(btfFilePath)
					if err != nil {
						common.AgentLog.Warnf("can't load btf spec: %v (embedded in kyanos)", err)
					}
					spec = btfPath
				} else {
					common.AgentLog.Warnf("failed write embeded btf file to disk: %+v", err)
				}
			}
		} else {
			common.AgentLog.Warnf("failed to load embeded btf file: %+v", err)
		}
	}

	if spec == nil {
		// try download
		options.LoadPorgressChannel <- "starting load BTF from network..."
		btfSpec, _, err := loadBTFSpecFallback("")
		if err != nil {
			common.AgentLog.Warnf("failed to get btf file from network: %+v", err)
		}
		spec = btfSpec
	}

	if spec == nil {
		common.AgentLog.Fatalf("can't find btf file to load!")
	}
	return spec
}

func loadBTFSpecFallback(path string) (*btf.Spec, string, error) {
	if path != "" {
		spec, path, err := loadSpec(path)
		if err == nil {
			common.AgentLog.Infof("use BTF specs from %s", path)
			return spec, path, nil
		}
		return nil, path, fmt.Errorf("load BTF specs from %s: %w", path, err)
	}

	spec, err := btf.LoadKernelSpec()
	if err == nil {
		common.AgentLog.Info("use BTF specs from default locations")
		return spec, DefaultPath, nil
	}

	spec, path, err = loadSpecFromCandidateLocations()
	if err == nil {
		return spec, path, nil
	}

	common.AgentLog.Warnf("could not load BTF specs from local: %s, try to load from remote", err)
	spec, path, err = loadSpecFromRemote()
	if err != nil {
		common.AgentLog.Warnf("load BTF specs from remote failed: %s", err)
		return nil, path, err
	}
	return spec, path, nil
}

var kernelVersionInfo struct {
	once    sync.Once
	version string
	err     error
}

func getKernelVersion() (string, error) {
	kernelVersionInfo.once.Do(func() {

		var uname unix.Utsname
		err := unix.Uname(&uname)
		if err != nil {
			kernelVersionInfo.err = fmt.Errorf(": %w", err)
		} else {
			kernelVersionInfo.version = strings.TrimSpace(unix.ByteSliceToString(uname.Release[:]))
		}
	})

	return kernelVersionInfo.version, kernelVersionInfo.err
}
func loadSpecFromRemote() (*btf.Spec, string, error) {
	kernelVersion, err := getKernelVersion()
	if err != nil {
		return nil, "", fmt.Errorf("get kernel version: %w", err)
	}
	release, err := common.GetRelease()
	if err != nil {
		return nil, "", fmt.Errorf("get os release: %w", err)
	}
	saveDir := filepath.Dir(candidatePath)
	if err := os.MkdirAll(saveDir, 0755); err != nil {
		return nil, "", fmt.Errorf("mkdir %s: %w", saveDir, err)
	}

	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}

	spec, path, err := loadSpecFromOpenanolis(arch, *release, kernelVersion, saveDir)
	if err != nil {
		common.AgentLog.Errorf("load BTF specs from OpenAnolis failed: %s", err)
	}
	if spec != nil {
		common.AgentLog.Infof("use BTF specs from %s", path)
		return spec, path, nil
	}

	spec, path, err = loadSpecFromBTFHub(arch, *release, kernelVersion, saveDir)
	if err != nil {
		common.AgentLog.Errorf("load BTF specs from BTFHub failed: %s", err)
	}
	return spec, path, err
}

func loadSpecFromBTFHub(arch string, release common.Release, kernelVersion,
	saveDir string) (*btf.Spec, string, error) {
	common.AgentLog.Info("try to load BTF specs from BTFHub")

	path := filepath.Join(saveDir, fmt.Sprintf("%s.btf", kernelVersion))
	if exist, err := fileExist(path); err != nil {
		return nil, path, err
	} else if exist {
		return loadSpec(path)
	}

	downloadUrl := fmt.Sprintf(btfHubURL, release.Id, release.VersionId, arch, kernelVersion)
	common.AgentLog.Infof("try to download BTF specs from %s and uncompress it to %s", downloadUrl, path)

	resp, err := httpGet(context.TODO(), downloadUrl)
	if err != nil {
		return nil, path, fmt.Errorf("download BTF specs from %s: %w", downloadUrl, err)
	}
	defer resp.Body.Close()

	data, err := decompressXzReader(resp.Body)
	if err != nil {
		return nil, path, fmt.Errorf("download BTF specs from %s: %w", downloadUrl, err)
	}
	if err := saveDataToFile(data, path); err != nil {
		return nil, path, err
	}

	return loadSpec(path)
}

func loadSpecFromOpenanolis(arch string, _ common.Release, kernelVersion,
	saveDir string) (*btf.Spec, string, error) {
	common.AgentLog.Info("try to load BTF specs from OpenAnolis mirror")
	if arch == "arm64" {
		arch = "aarch64"
	}
	path := filepath.Join(saveDir, fmt.Sprintf("vmlinux-%s", kernelVersion))
	if exist, err := fileExist(path); err != nil {
		return nil, path, err
	} else if exist {
		return loadSpec(path)
	}

	downloadUrl := fmt.Sprintf(openAnolisURL, arch, kernelVersion)
	common.AgentLog.Infof("try to download BTF specs from %s and save it to %s", downloadUrl, path)

	resp, err := httpGet(context.TODO(), downloadUrl)
	if err != nil {
		return nil, path, fmt.Errorf("download BTF specs from %s: %w", downloadUrl, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, path, fmt.Errorf("download BTF specs from %s: %w", downloadUrl, err)
	}
	if err := saveDataToFile(data, path); err != nil {
		return nil, path, err
	}

	return loadSpec(path)
}

func httpGet(ctx context.Context, url string) (*http.Response, error) {
	// TODO: add timeout
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status code is not 200: %d", resp.StatusCode)
	}
	return resp, err
}

func fileExist(path string) (bool, error) {
	_, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return false, fmt.Errorf("stat file %s: %w", path, err)
		}
		return false, nil
	}
	return true, nil
}

func loadSpecFromCandidateLocations() (*btf.Spec, string, error) {
	path := candidatePath
	common.AgentLog.Infof("try to load BTF specs from %s", path)

	spec, path, err := loadSpec(path)
	if err == nil {
		common.AgentLog.Infof("use BTF specs from %s", path)
		return spec, path, nil
	}
	common.AgentLog.Infof("load BTF specs from %s failed: %s", path, err)

	kernelVersion, err := getKernelVersion()
	if err != nil {
		return nil, path, fmt.Errorf("get kernel version: %w", err)
	}
	path = fmt.Sprintf("%s-%s", candidatePath, kernelVersion)

	return loadSpec(path)
}

func loadSpec(path string) (*btf.Spec, string, error) {
	spec, err := btf.LoadSpec(path)
	if err == nil {
		common.AgentLog.Infof("use BTF specs from %s", path)
		return spec, path, nil
	}
	if spec, err := loadSpecFromELF(path); err == nil {
		return spec, path, nil
	}
	common.AgentLog.Warnf("load BTF specs from %s failed: %s", path, err)
	return nil, path, err
}

func loadSpecFromELF(path string) (spec *btf.Spec, err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		err = fmt.Errorf("reading ELF file panicked: %s", r)
	}()

	file, err := elf.Open(path)
	if err != nil {
		return nil, err
	}

	var (
		btfSection *elf.Section
	)

	for _, sec := range file.Sections {
		switch sec.Name {
		case ".BTF", ".btf":
			btfSection = sec
		default:
		}
	}

	if btfSection == nil {
		return nil, fmt.Errorf("btf: %w", btf.ErrNotFound)
	}

	if btfSection.ReaderAt == nil {
		return nil, fmt.Errorf("compressed BTF is not supported")
	}

	spec, err = btf.LoadSpecFromReader(btfSection.ReaderAt)
	return spec, err
}
