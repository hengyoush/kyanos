package uprobe

import (
	"debug/dwarf"
	"debug/elf"
	"errors"
	"fmt"
	ac "kyanos/agent/common"
	dwarfreader "kyanos/agent/uprobe/dwarf_reader"
	"kyanos/bpf"
	"kyanos/common"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/hashicorp/go-version"
)

var fileAttachedGoTlsProbeMap = make(map[string]bool)
var goTlsObjs any

func LoadGoTlsUprobe() error {
	collectionOptions := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			// LogLevel: ebpf.LogLevelInstruction,
			LogSize:     10 * 1024,
			KernelTypes: ac.CollectionOpts.Programs.KernelTypes,
		},
		MapReplacements: getMapReplacementsForGoTls(),
	}
	var spec *ebpf.CollectionSpec
	var err error
	v4, _ := version.NewVersion("4.0.0")
	var objs any
	if common.GetKernelVersion().LessThan(v4) {
		spec, err = bpf.LoadGoTlsLagacyKernel310()
		if err != nil {
			return err
		}
		common.UprobeLog.Debugf("less than 4.x use legacy objects")
		objs = &bpf.GoTlsLagacyKernel310Objects{}
		err = spec.LoadAndAssign(objs, collectionOptions)
	} else {
		spec, err = bpf.LoadGoTls()
		if err != nil {
			return err
		}
		objs = &bpf.GoTlsObjects{}
		err = spec.LoadAndAssign(objs, collectionOptions)
	}

	if err != nil {
		err = errors.Unwrap(errors.Unwrap(err))
		inner_err, ok := err.(*ebpf.VerifierError)
		if ok {
			common.UprobeLog.Errorf("load gotls uprobe failed: %+v", inner_err)
		} else {
			common.UprobeLog.Errorf("load gotls uprobe failed: %+v", err)
		}
		return err
	}
	goTlsObjs = objs
	return nil
}
func AttachGoTlsProbes(pid int) ([]link.Link, error) {
	elfFile, f, err := GetElfFile(pid)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	defer elfFile.Close()

	execPath, err := common.GetExecutablePathFromPid(pid)
	if err != nil {
		return nil, err
	}
	execLink, err := link.OpenExecutable(execPath)
	if err != nil {
		return nil, err
	}

	pidStr := fmt.Sprintf("%d", pid)
	if _, ok := fileAttachedGoTlsProbeMap[pidStr]; ok {
		return nil, nil
	} else {
		fileAttachedGoTlsProbeMap[pidStr] = true
	}

	err = UpdateCommonSymAddrs(pid, elfFile, goTlsObjs)
	if err != nil {
		return nil, err
	}
	err = UpdateGoTlsSymAddrs(pid, elfFile, goTlsObjs)
	if err != nil {
		return nil, err
	}

	var l link.Link
	var links []link.Link
	l, err = execLink.Uprobe("crypto/tls.(*Conn).Read", bpf.GetProgramFromObjs(goTlsObjs, "ProbeEntryTlsConnRead"), nil)
	links = handleAttachGoTlsUprobeResult(l, err, links)
	if err != nil {
		return links, err
	}
	funcAddr, retOffsets, err := getGoRetOffset(elfFile, execPath, "crypto/tls.(*Conn).Read")
	if err != nil {
		return links, err
	}
	for _, retOffset := range retOffsets {
		l, err = execLink.Uprobe("crypto/tls.(*Conn).Read", bpf.GetProgramFromObjs(goTlsObjs, "ProbeReturnTlsConnRead"), &link.UprobeOptions{
			// PID:     pid,
			Address: funcAddr,
			Offset:  retOffset,
		})
		links = handleAttachGoTlsUprobeResult(l, err, links)
		if err != nil {
			return links, err
		}
	}
	l, err = execLink.Uprobe("crypto/tls.(*Conn).Write", bpf.GetProgramFromObjs(goTlsObjs, "ProbeEntryTlsConnWrite"), nil)
	links = handleAttachGoTlsUprobeResult(l, err, links)

	funcAddr, retOffsets, err = getGoRetOffset(elfFile, execPath, "crypto/tls.(*Conn).Write")
	if err != nil {
		return links, err
	}
	for _, retOffset := range retOffsets {
		l, err = execLink.Uprobe("crypto/tls.(*Conn).Write", bpf.GetProgramFromObjs(goTlsObjs, "ProbeReturnTlsConnWrite"), &link.UprobeOptions{
			// PID:     pid,
			Address: funcAddr,
			Offset:  retOffset,
		})
		links = handleAttachGoTlsUprobeResult(l, err, links)
		if err != nil {
			return links, err
		}
	}

	return links, nil
}

func getGoRetOffset(elfFile *elf.File, execPath string, symbolName string) (uint64, []uint64, error) {

	var symbolOffset uint64
	var retOffsets []uint64
	var err error
	retOffsets, err = common.GetFuncRetOffsetsViaSymbolTable(elfFile, symbolName)
	if err == nil && len(retOffsets) == 0 {
		err = errors.New("not found any RET instruction")
	}
	if err != nil {
		common.UprobeLog.Infof("get offsets via symbol table failed: %+v", err)
		// symbolOffset, retOffsets, err = common.GetFuncRetOffsetsViaPclntab(execPath, elfFile, symbolName)
	}
	if err == nil && len(retOffsets) == 0 {
		err = errors.New("not found any RET instruction")
	}
	if err != nil {
		common.UprobeLog.Debugf("skip go TLS related logics due to parse elf failed: %s", err)
		return 0, []uint64{}, nil
	}

	retOffset := retOffsets[len(retOffsets)-1]
	common.UprobeLog.Debugf("got symbolOffset: %d, got retOffsets: %v, will attach at ret offset: %d",
		symbolOffset, retOffsets, retOffset)
	return symbolOffset, retOffsets, nil
}

func handleAttachGoTlsUprobeResult(l link.Link, err error, links []link.Link) []link.Link {
	if err == nil {
		links = append(links, l)
	}
	return links
}

func getArgOffset(argMap map[string]dwarfreader.ArgInfo, argName string) bpf.GoTlsLocationT {
	const kSpOffset = 8
	var location bpf.GoTlsLocationT
	arg, ok := argMap[argName]
	if !ok {
		location.Type = bpf.GoTlsLocationTypeTKLocationTypeInvalid
		location.Offset = -1
		return location
	}
	switch arg.Location.LocType {
	case dwarfreader.KStack, dwarfreader.KStackBP:
		location.Type = bpf.GoTlsLocationTypeTKLocationTypeStack
		location.Offset = int32(arg.Location.Offset + kSpOffset)
		return location
	case dwarfreader.KRegister, dwarfreader.KRegisterFP:
		location.Type = bpf.GoTlsLocationTypeTKLocationTypeRegisters
		location.Offset = int32(arg.Location.Offset)
		return location
	default:
		location.Type = bpf.GoTlsLocationTypeTKLocationTypeInvalid
		location.Offset = -1
		return location
	}
}

func UpdateGoTlsSymAddrs(pid int, elfFile *elf.File, goTlsObjs any) error {
	executablePath, err := common.GetExecutablePathFromPid(pid)
	if err != nil {
		return err
	}
	goVersion, err := common.ExtraceGoVersion(executablePath)
	if err != nil {
		return err
	}

	dwarfData, err := elfFile.DWARF()
	if err != nil {
		return err
	}
	reader := dwarfData.Reader()
	retVal0Arg := "~r1"
	retVal1Arg := "~r2"

	if goVersion.After(1, 17) {
		retVal0Arg = "~r0"
		retVal1Arg = "~r1"
	}

	tlsSymAddrs := bpf.GoTlsGoTlsSymaddrsT{}

	{
		fn := "crypto/tls.(*Conn).Write"
		argsMap, err := dwarfreader.GetFunctionArgInfo(copyReader(reader), *goVersion, fn)
		if err != nil {
			return err
		}
		tlsSymAddrs.WriteC_loc = getArgOffset(argsMap, "c")
		tlsSymAddrs.WriteB_loc = getArgOffset(argsMap, "b")
		tlsSymAddrs.WriteRetval0Loc = getArgOffset(argsMap, retVal0Arg)
		tlsSymAddrs.WriteRetval1Loc = getArgOffset(argsMap, retVal1Arg)
	}

	{
		fn := "crypto/tls.(*Conn).Read"
		argsMap, err := dwarfreader.GetFunctionArgInfo(copyReader(reader), *goVersion, fn)
		if err != nil {
			return err
		}
		tlsSymAddrs.ReadC_loc = getArgOffset(argsMap, "c")
		tlsSymAddrs.ReadB_loc = getArgOffset(argsMap, "b")
		tlsSymAddrs.ReadRetval0Loc = getArgOffset(argsMap, retVal0Arg)
		tlsSymAddrs.ReadRetval1Loc = getArgOffset(argsMap, retVal1Arg)
	}

	if tlsSymAddrs.WriteB_loc.Type == bpf.GoTlsLocationTypeTKLocationTypeInvalid ||
		tlsSymAddrs.WriteC_loc.Type == bpf.GoTlsLocationTypeTKLocationTypeInvalid {
		return errors.New("Go TLS Read/Write arguments not found.")
	}
	if goTlsObjs != nil {
		var GoTlsSymaddrsMap *ebpf.Map = bpf.GetMapFromObjs(goTlsObjs, "GoTlsSymaddrsMap")
		GoTlsSymaddrsMap.Update(uint32(pid), tlsSymAddrs, ebpf.UpdateAny)
	}
	return nil
}

func copyReader(reader *dwarf.Reader) *dwarf.Reader {
	copy := *reader
	return &copy
}

func UpdateCommonSymAddrs(pid int, elfFile *elf.File, goTlsObjs any) error {
	dwarfData, err := elfFile.DWARF()
	if err != nil {
		return err
	}

	commonSymaddrs := bpf.GoTlsGoCommonSymaddrsT{}
	commonSymaddrs.TlsConn = int64(ResolveSymbolWithEachGoPrefix(elfFile, "itab.*crypto/tls.Conn,net.Conn"))
	commonSymaddrs.NetTCPConn = int64(ResolveSymbolWithEachGoPrefix(elfFile, "itab.*net.TCPConn,net.Conn"))
	commonSymaddrs.G_addrOffset = -8
	commonSymaddrs.FD_SysfdOffset, _ = dwarfreader.GetStructMemberOffset("internal/poll.FD", "Sysfd", dwarfData.Reader())
	commonSymaddrs.TlsConnConnOffset, _ = dwarfreader.GetStructMemberOffset("crypto/tls.Conn", "conn", dwarfData.Reader())
	commonSymaddrs.G_goidOffset, _ = dwarfreader.GetStructMemberOffset("runtime.g", "goid", dwarfData.Reader())
	if commonSymaddrs.FD_SysfdOffset < 0 {
		return errors.New("FD_Sysfd_offset not found")
	}
	if goTlsObjs != nil {
		var GoCommonSymaddrsMap *ebpf.Map = bpf.GetMapFromObjs(goTlsObjs, "GoCommonSymaddrsMap")
		GoCommonSymaddrsMap.Update(uint32(pid), commonSymaddrs, ebpf.UpdateAny)
	}
	return nil
}

func GetElfFile(pid int) (*elf.File, *os.File, error) {
	executablePath, err := common.GetExecutablePathFromPid(pid)
	if isGoFile, err := common.IsGoExecutable(executablePath); err != nil || !isGoFile {
		return nil, nil, errors.New(fmt.Sprintf("Not a Go Program: %d", pid))
	}
	file, err := os.Open(executablePath)
	if err != nil {
		return nil, nil, err
	}
	elfFile, err := elf.NewFile(file)
	if err != nil {
		return nil, nil, err
	} else {
		return elfFile, file, nil
	}
}

func ResolveSymbolWithEachGoPrefix(e *elf.File, symbolName string) uint64 {

	goPrefixies := []string{"go.", "go:"}
	for _, prefix := range goPrefixies {
		targetSymbolName := prefix + symbolName
		// Traverse all symbol tables to find the symbol
		for _, section := range e.Sections {
			if section.Type == elf.SHT_SYMTAB || section.Type == elf.SHT_DYNSYM {
				symbols, err := e.Symbols()
				if err != nil {
					common.UprobeLog.Fatalf("failed to read symbols from section %s: %v", section.Name, err)
				}

				for _, sym := range symbols {
					if sym.Name == targetSymbolName {
						// 打印符号地址
						// fmt.Printf("Symbol %s found at address: %x\n", symbolName, sym.Value)
						return sym.Value
					}
				}
			}
		}
	}
	return 0
}
