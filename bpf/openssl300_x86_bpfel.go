// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package bpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type Openssl300ConnEvtT struct {
	ConnInfo Openssl300ConnInfoT
	ConnType Openssl300ConnTypeT
	_        [4]byte
	Ts       uint64
}

type Openssl300ConnIdS_t struct {
	TgidFd  uint64
	NoTrace bool
	_       [7]byte
}

type Openssl300ConnInfoT struct {
	ConnId struct {
		Upid struct {
			Pid            uint32
			_              [4]byte
			StartTimeTicks uint64
		}
		Fd   int32
		_    [4]byte
		Tsid uint64
	}
	ReadBytes     uint64
	WriteBytes    uint64
	SslReadBytes  uint64
	SslWriteBytes uint64
	Laddr         struct {
		In6 struct {
			Sin6Family   uint16
			Sin6Port     uint16
			Sin6Flowinfo uint32
			Sin6Addr     struct{ In6U struct{ U6Addr8 [16]uint8 } }
			Sin6ScopeId  uint32
		}
	}
	Raddr struct {
		In6 struct {
			Sin6Family   uint16
			Sin6Port     uint16
			Sin6Flowinfo uint32
			Sin6Addr     struct{ In6U struct{ U6Addr8 [16]uint8 } }
			Sin6ScopeId  uint32
		}
	}
	Protocol            Openssl300TrafficProtocolT
	Role                Openssl300EndpointRoleT
	PrevCount           uint64
	PrevBuf             [4]int8
	PrependLengthHeader bool
	NoTrace             bool
	Ssl                 bool
	_                   [1]byte
}

type Openssl300ConnTypeT uint32

const (
	Openssl300ConnTypeTKConnect       Openssl300ConnTypeT = 0
	Openssl300ConnTypeTKClose         Openssl300ConnTypeT = 1
	Openssl300ConnTypeTKProtocolInfer Openssl300ConnTypeT = 2
)

type Openssl300ControlValueIndexT uint32

const (
	Openssl300ControlValueIndexTKTargetTGIDIndex          Openssl300ControlValueIndexT = 0
	Openssl300ControlValueIndexTKStirlingTGIDIndex        Openssl300ControlValueIndexT = 1
	Openssl300ControlValueIndexTKEnabledXdpIndex          Openssl300ControlValueIndexT = 2
	Openssl300ControlValueIndexTKEnableFilterByPid        Openssl300ControlValueIndexT = 3
	Openssl300ControlValueIndexTKEnableFilterByLocalPort  Openssl300ControlValueIndexT = 4
	Openssl300ControlValueIndexTKEnableFilterByRemotePort Openssl300ControlValueIndexT = 5
	Openssl300ControlValueIndexTKEnableFilterByRemoteHost Openssl300ControlValueIndexT = 6
	Openssl300ControlValueIndexTKNumControlValues         Openssl300ControlValueIndexT = 7
)

type Openssl300EndpointRoleT uint32

const (
	Openssl300EndpointRoleTKRoleClient  Openssl300EndpointRoleT = 1
	Openssl300EndpointRoleTKRoleServer  Openssl300EndpointRoleT = 2
	Openssl300EndpointRoleTKRoleUnknown Openssl300EndpointRoleT = 4
)

type Openssl300KernEvt struct {
	FuncName [16]int8
	Ts       uint64
	Seq      uint64
	Len      uint32
	Flags    uint8
	_        [3]byte
	Ifindex  uint32
	_        [4]byte
	ConnIdS  Openssl300ConnIdS_t
	Step     Openssl300StepT
	_        [4]byte
}

type Openssl300KernEvtData struct {
	Ke      Openssl300KernEvt
	BufSize uint32
	Msg     [30720]int8
	_       [4]byte
}

type Openssl300SockKey struct {
	Sip   [2]uint64
	Dip   [2]uint64
	Sport uint16
	Dport uint16
	_     [4]byte
}

type Openssl300StepT uint32

const (
	Openssl300StepTStart       Openssl300StepT = 0
	Openssl300StepTSSL_OUT     Openssl300StepT = 1
	Openssl300StepTSYSCALL_OUT Openssl300StepT = 2
	Openssl300StepTTCP_OUT     Openssl300StepT = 3
	Openssl300StepTIP_OUT      Openssl300StepT = 4
	Openssl300StepTQDISC_OUT   Openssl300StepT = 5
	Openssl300StepTDEV_OUT     Openssl300StepT = 6
	Openssl300StepTNIC_OUT     Openssl300StepT = 7
	Openssl300StepTNIC_IN      Openssl300StepT = 8
	Openssl300StepTDEV_IN      Openssl300StepT = 9
	Openssl300StepTIP_IN       Openssl300StepT = 10
	Openssl300StepTTCP_IN      Openssl300StepT = 11
	Openssl300StepTUSER_COPY   Openssl300StepT = 12
	Openssl300StepTSYSCALL_IN  Openssl300StepT = 13
	Openssl300StepTSSL_IN      Openssl300StepT = 14
	Openssl300StepTEnd         Openssl300StepT = 15
)

type Openssl300TrafficDirectionT uint32

const (
	Openssl300TrafficDirectionTKEgress  Openssl300TrafficDirectionT = 0
	Openssl300TrafficDirectionTKIngress Openssl300TrafficDirectionT = 1
)

type Openssl300TrafficProtocolT uint32

const (
	Openssl300TrafficProtocolTKProtocolUnset   Openssl300TrafficProtocolT = 0
	Openssl300TrafficProtocolTKProtocolUnknown Openssl300TrafficProtocolT = 1
	Openssl300TrafficProtocolTKProtocolHTTP    Openssl300TrafficProtocolT = 2
	Openssl300TrafficProtocolTKProtocolHTTP2   Openssl300TrafficProtocolT = 3
	Openssl300TrafficProtocolTKProtocolMySQL   Openssl300TrafficProtocolT = 4
	Openssl300TrafficProtocolTKProtocolCQL     Openssl300TrafficProtocolT = 5
	Openssl300TrafficProtocolTKProtocolPGSQL   Openssl300TrafficProtocolT = 6
	Openssl300TrafficProtocolTKProtocolDNS     Openssl300TrafficProtocolT = 7
	Openssl300TrafficProtocolTKProtocolRedis   Openssl300TrafficProtocolT = 8
	Openssl300TrafficProtocolTKProtocolNATS    Openssl300TrafficProtocolT = 9
	Openssl300TrafficProtocolTKProtocolMongo   Openssl300TrafficProtocolT = 10
	Openssl300TrafficProtocolTKProtocolKafka   Openssl300TrafficProtocolT = 11
	Openssl300TrafficProtocolTKProtocolMux     Openssl300TrafficProtocolT = 12
	Openssl300TrafficProtocolTKProtocolAMQP    Openssl300TrafficProtocolT = 13
	Openssl300TrafficProtocolTKNumProtocols    Openssl300TrafficProtocolT = 14
)

// LoadOpenssl300 returns the embedded CollectionSpec for Openssl300.
func LoadOpenssl300() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Openssl300Bytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load Openssl300: %w", err)
	}

	return spec, err
}

// LoadOpenssl300Objects loads Openssl300 and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*Openssl300Objects
//	*Openssl300Programs
//	*Openssl300Maps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadOpenssl300Objects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadOpenssl300()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// Openssl300Specs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type Openssl300Specs struct {
	Openssl300ProgramSpecs
	Openssl300MapSpecs
}

// Openssl300Specs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type Openssl300ProgramSpecs struct {
	SSL_readEntryNestedSyscall    *ebpf.ProgramSpec `ebpf:"SSL_read_entry_nested_syscall"`
	SSL_readEntryOffset           *ebpf.ProgramSpec `ebpf:"SSL_read_entry_offset"`
	SSL_readExEntryNestedSyscall  *ebpf.ProgramSpec `ebpf:"SSL_read_ex_entry_nested_syscall"`
	SSL_readExRetNestedSyscall    *ebpf.ProgramSpec `ebpf:"SSL_read_ex_ret_nested_syscall"`
	SSL_readRetNestedSyscall      *ebpf.ProgramSpec `ebpf:"SSL_read_ret_nested_syscall"`
	SSL_readRetOffset             *ebpf.ProgramSpec `ebpf:"SSL_read_ret_offset"`
	SSL_writeEntryNestedSyscall   *ebpf.ProgramSpec `ebpf:"SSL_write_entry_nested_syscall"`
	SSL_writeEntryOffset          *ebpf.ProgramSpec `ebpf:"SSL_write_entry_offset"`
	SSL_writeExEntryNestedSyscall *ebpf.ProgramSpec `ebpf:"SSL_write_ex_entry_nested_syscall"`
	SSL_writeExRetNestedSyscall   *ebpf.ProgramSpec `ebpf:"SSL_write_ex_ret_nested_syscall"`
	SSL_writeRetNestedSyscall     *ebpf.ProgramSpec `ebpf:"SSL_write_ret_nested_syscall"`
	SSL_writeRetOffset            *ebpf.ProgramSpec `ebpf:"SSL_write_ret_offset"`
}

// Openssl300MapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type Openssl300MapSpecs struct {
	ActiveSslReadArgsMap  *ebpf.MapSpec `ebpf:"active_ssl_read_args_map"`
	ActiveSslWriteArgsMap *ebpf.MapSpec `ebpf:"active_ssl_write_args_map"`
	ConnEvtRb             *ebpf.MapSpec `ebpf:"conn_evt_rb"`
	ConnInfoMap           *ebpf.MapSpec `ebpf:"conn_info_map"`
	FilterMntnsMap        *ebpf.MapSpec `ebpf:"filter_mntns_map"`
	FilterNetnsMap        *ebpf.MapSpec `ebpf:"filter_netns_map"`
	FilterPidMap          *ebpf.MapSpec `ebpf:"filter_pid_map"`
	FilterPidnsMap        *ebpf.MapSpec `ebpf:"filter_pidns_map"`
	Rb                    *ebpf.MapSpec `ebpf:"rb"`
	SslDataMap            *ebpf.MapSpec `ebpf:"ssl_data_map"`
	SslRb                 *ebpf.MapSpec `ebpf:"ssl_rb"`
	SslUserSpaceCallMap   *ebpf.MapSpec `ebpf:"ssl_user_space_call_map"`
	SyscallDataMap        *ebpf.MapSpec `ebpf:"syscall_data_map"`
	SyscallRb             *ebpf.MapSpec `ebpf:"syscall_rb"`
}

// Openssl300Objects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadOpenssl300Objects or ebpf.CollectionSpec.LoadAndAssign.
type Openssl300Objects struct {
	Openssl300Programs
	Openssl300Maps
}

func (o *Openssl300Objects) Close() error {
	return _Openssl300Close(
		&o.Openssl300Programs,
		&o.Openssl300Maps,
	)
}

// Openssl300Maps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadOpenssl300Objects or ebpf.CollectionSpec.LoadAndAssign.
type Openssl300Maps struct {
	ActiveSslReadArgsMap  *ebpf.Map `ebpf:"active_ssl_read_args_map"`
	ActiveSslWriteArgsMap *ebpf.Map `ebpf:"active_ssl_write_args_map"`
	ConnEvtRb             *ebpf.Map `ebpf:"conn_evt_rb"`
	ConnInfoMap           *ebpf.Map `ebpf:"conn_info_map"`
	FilterMntnsMap        *ebpf.Map `ebpf:"filter_mntns_map"`
	FilterNetnsMap        *ebpf.Map `ebpf:"filter_netns_map"`
	FilterPidMap          *ebpf.Map `ebpf:"filter_pid_map"`
	FilterPidnsMap        *ebpf.Map `ebpf:"filter_pidns_map"`
	Rb                    *ebpf.Map `ebpf:"rb"`
	SslDataMap            *ebpf.Map `ebpf:"ssl_data_map"`
	SslRb                 *ebpf.Map `ebpf:"ssl_rb"`
	SslUserSpaceCallMap   *ebpf.Map `ebpf:"ssl_user_space_call_map"`
	SyscallDataMap        *ebpf.Map `ebpf:"syscall_data_map"`
	SyscallRb             *ebpf.Map `ebpf:"syscall_rb"`
}

func (m *Openssl300Maps) Close() error {
	return _Openssl300Close(
		m.ActiveSslReadArgsMap,
		m.ActiveSslWriteArgsMap,
		m.ConnEvtRb,
		m.ConnInfoMap,
		m.FilterMntnsMap,
		m.FilterNetnsMap,
		m.FilterPidMap,
		m.FilterPidnsMap,
		m.Rb,
		m.SslDataMap,
		m.SslRb,
		m.SslUserSpaceCallMap,
		m.SyscallDataMap,
		m.SyscallRb,
	)
}

// Openssl300Programs contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadOpenssl300Objects or ebpf.CollectionSpec.LoadAndAssign.
type Openssl300Programs struct {
	SSL_readEntryNestedSyscall    *ebpf.Program `ebpf:"SSL_read_entry_nested_syscall"`
	SSL_readEntryOffset           *ebpf.Program `ebpf:"SSL_read_entry_offset"`
	SSL_readExEntryNestedSyscall  *ebpf.Program `ebpf:"SSL_read_ex_entry_nested_syscall"`
	SSL_readExRetNestedSyscall    *ebpf.Program `ebpf:"SSL_read_ex_ret_nested_syscall"`
	SSL_readRetNestedSyscall      *ebpf.Program `ebpf:"SSL_read_ret_nested_syscall"`
	SSL_readRetOffset             *ebpf.Program `ebpf:"SSL_read_ret_offset"`
	SSL_writeEntryNestedSyscall   *ebpf.Program `ebpf:"SSL_write_entry_nested_syscall"`
	SSL_writeEntryOffset          *ebpf.Program `ebpf:"SSL_write_entry_offset"`
	SSL_writeExEntryNestedSyscall *ebpf.Program `ebpf:"SSL_write_ex_entry_nested_syscall"`
	SSL_writeExRetNestedSyscall   *ebpf.Program `ebpf:"SSL_write_ex_ret_nested_syscall"`
	SSL_writeRetNestedSyscall     *ebpf.Program `ebpf:"SSL_write_ret_nested_syscall"`
	SSL_writeRetOffset            *ebpf.Program `ebpf:"SSL_write_ret_offset"`
}

func (p *Openssl300Programs) Close() error {
	return _Openssl300Close(
		p.SSL_readEntryNestedSyscall,
		p.SSL_readEntryOffset,
		p.SSL_readExEntryNestedSyscall,
		p.SSL_readExRetNestedSyscall,
		p.SSL_readRetNestedSyscall,
		p.SSL_readRetOffset,
		p.SSL_writeEntryNestedSyscall,
		p.SSL_writeEntryOffset,
		p.SSL_writeExEntryNestedSyscall,
		p.SSL_writeExRetNestedSyscall,
		p.SSL_writeRetNestedSyscall,
		p.SSL_writeRetOffset,
	)
}

func _Openssl300Close(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed openssl300_x86_bpfel.o
var _Openssl300Bytes []byte
