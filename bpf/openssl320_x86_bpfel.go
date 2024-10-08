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

type Openssl320ConnEvtT struct {
	ConnInfo Openssl320ConnInfoT
	ConnType Openssl320ConnTypeT
	_        [4]byte
	Ts       uint64
}

type Openssl320ConnIdS_t struct {
	TgidFd  uint64
	NoTrace bool
	_       [7]byte
}

type Openssl320ConnInfoT struct {
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
	Protocol            Openssl320TrafficProtocolT
	Role                Openssl320EndpointRoleT
	PrevCount           uint64
	PrevBuf             [4]int8
	PrependLengthHeader bool
	NoTrace             bool
	Ssl                 bool
	_                   [1]byte
}

type Openssl320ConnTypeT uint32

const (
	Openssl320ConnTypeTKConnect       Openssl320ConnTypeT = 0
	Openssl320ConnTypeTKClose         Openssl320ConnTypeT = 1
	Openssl320ConnTypeTKProtocolInfer Openssl320ConnTypeT = 2
)

type Openssl320ControlValueIndexT uint32

const (
	Openssl320ControlValueIndexTKTargetTGIDIndex          Openssl320ControlValueIndexT = 0
	Openssl320ControlValueIndexTKStirlingTGIDIndex        Openssl320ControlValueIndexT = 1
	Openssl320ControlValueIndexTKEnabledXdpIndex          Openssl320ControlValueIndexT = 2
	Openssl320ControlValueIndexTKEnableFilterByPid        Openssl320ControlValueIndexT = 3
	Openssl320ControlValueIndexTKEnableFilterByLocalPort  Openssl320ControlValueIndexT = 4
	Openssl320ControlValueIndexTKEnableFilterByRemotePort Openssl320ControlValueIndexT = 5
	Openssl320ControlValueIndexTKEnableFilterByRemoteHost Openssl320ControlValueIndexT = 6
	Openssl320ControlValueIndexTKNumControlValues         Openssl320ControlValueIndexT = 7
)

type Openssl320EndpointRoleT uint32

const (
	Openssl320EndpointRoleTKRoleClient  Openssl320EndpointRoleT = 1
	Openssl320EndpointRoleTKRoleServer  Openssl320EndpointRoleT = 2
	Openssl320EndpointRoleTKRoleUnknown Openssl320EndpointRoleT = 4
)

type Openssl320KernEvt struct {
	FuncName [16]int8
	Ts       uint64
	Seq      uint64
	Len      uint32
	Flags    uint8
	_        [3]byte
	Ifindex  uint32
	_        [4]byte
	ConnIdS  Openssl320ConnIdS_t
	Step     Openssl320StepT
	_        [4]byte
}

type Openssl320KernEvtData struct {
	Ke      Openssl320KernEvt
	BufSize uint32
	Msg     [30720]int8
	_       [4]byte
}

type Openssl320SockKey struct {
	Sip   [2]uint64
	Dip   [2]uint64
	Sport uint16
	Dport uint16
	_     [4]byte
}

type Openssl320StepT uint32

const (
	Openssl320StepTStart       Openssl320StepT = 0
	Openssl320StepTSSL_OUT     Openssl320StepT = 1
	Openssl320StepTSYSCALL_OUT Openssl320StepT = 2
	Openssl320StepTTCP_OUT     Openssl320StepT = 3
	Openssl320StepTIP_OUT      Openssl320StepT = 4
	Openssl320StepTQDISC_OUT   Openssl320StepT = 5
	Openssl320StepTDEV_OUT     Openssl320StepT = 6
	Openssl320StepTNIC_OUT     Openssl320StepT = 7
	Openssl320StepTNIC_IN      Openssl320StepT = 8
	Openssl320StepTDEV_IN      Openssl320StepT = 9
	Openssl320StepTIP_IN       Openssl320StepT = 10
	Openssl320StepTTCP_IN      Openssl320StepT = 11
	Openssl320StepTUSER_COPY   Openssl320StepT = 12
	Openssl320StepTSYSCALL_IN  Openssl320StepT = 13
	Openssl320StepTSSL_IN      Openssl320StepT = 14
	Openssl320StepTEnd         Openssl320StepT = 15
)

type Openssl320TrafficDirectionT uint32

const (
	Openssl320TrafficDirectionTKEgress  Openssl320TrafficDirectionT = 0
	Openssl320TrafficDirectionTKIngress Openssl320TrafficDirectionT = 1
)

type Openssl320TrafficProtocolT uint32

const (
	Openssl320TrafficProtocolTKProtocolUnset   Openssl320TrafficProtocolT = 0
	Openssl320TrafficProtocolTKProtocolUnknown Openssl320TrafficProtocolT = 1
	Openssl320TrafficProtocolTKProtocolHTTP    Openssl320TrafficProtocolT = 2
	Openssl320TrafficProtocolTKProtocolHTTP2   Openssl320TrafficProtocolT = 3
	Openssl320TrafficProtocolTKProtocolMySQL   Openssl320TrafficProtocolT = 4
	Openssl320TrafficProtocolTKProtocolCQL     Openssl320TrafficProtocolT = 5
	Openssl320TrafficProtocolTKProtocolPGSQL   Openssl320TrafficProtocolT = 6
	Openssl320TrafficProtocolTKProtocolDNS     Openssl320TrafficProtocolT = 7
	Openssl320TrafficProtocolTKProtocolRedis   Openssl320TrafficProtocolT = 8
	Openssl320TrafficProtocolTKProtocolNATS    Openssl320TrafficProtocolT = 9
	Openssl320TrafficProtocolTKProtocolMongo   Openssl320TrafficProtocolT = 10
	Openssl320TrafficProtocolTKProtocolKafka   Openssl320TrafficProtocolT = 11
	Openssl320TrafficProtocolTKProtocolMux     Openssl320TrafficProtocolT = 12
	Openssl320TrafficProtocolTKProtocolAMQP    Openssl320TrafficProtocolT = 13
	Openssl320TrafficProtocolTKNumProtocols    Openssl320TrafficProtocolT = 14
)

// LoadOpenssl320 returns the embedded CollectionSpec for Openssl320.
func LoadOpenssl320() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Openssl320Bytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load Openssl320: %w", err)
	}

	return spec, err
}

// LoadOpenssl320Objects loads Openssl320 and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*Openssl320Objects
//	*Openssl320Programs
//	*Openssl320Maps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadOpenssl320Objects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadOpenssl320()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// Openssl320Specs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type Openssl320Specs struct {
	Openssl320ProgramSpecs
	Openssl320MapSpecs
}

// Openssl320Specs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type Openssl320ProgramSpecs struct {
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

// Openssl320MapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type Openssl320MapSpecs struct {
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

// Openssl320Objects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadOpenssl320Objects or ebpf.CollectionSpec.LoadAndAssign.
type Openssl320Objects struct {
	Openssl320Programs
	Openssl320Maps
}

func (o *Openssl320Objects) Close() error {
	return _Openssl320Close(
		&o.Openssl320Programs,
		&o.Openssl320Maps,
	)
}

// Openssl320Maps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadOpenssl320Objects or ebpf.CollectionSpec.LoadAndAssign.
type Openssl320Maps struct {
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

func (m *Openssl320Maps) Close() error {
	return _Openssl320Close(
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

// Openssl320Programs contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadOpenssl320Objects or ebpf.CollectionSpec.LoadAndAssign.
type Openssl320Programs struct {
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

func (p *Openssl320Programs) Close() error {
	return _Openssl320Close(
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

func _Openssl320Close(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed openssl320_x86_bpfel.o
var _Openssl320Bytes []byte
