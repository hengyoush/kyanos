package common_test

import (
	"fmt"
	"kyanos/common"
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zcalusic/sysinfo"
)

func TestBytesToInt8(t *testing.T) {
	type args struct {
		byteArray []byte
	}
	tests := []struct {
		name    string
		args    args
		want    int8
		wantErr bool
	}{
		{name: "1", args: args{byteArray: common.IntToBytes[int8](3)}, want: 3, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := common.BytesToInt[int8](tt.args.byteArray)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("BytesToInt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBytesToInt16(t *testing.T) {
	type args struct {
		byteArray []byte
	}
	tests := []struct {
		name    string
		args    args
		want    int16
		wantErr bool
	}{
		{name: "1", args: args{byteArray: common.IntToBytes[int16](3123)}, want: 3123, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := common.BytesToInt[int16](tt.args.byteArray)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("BytesToInt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVersion(t *testing.T) {
	var si sysinfo.SysInfo
	si.GetSysInfo()
	fmt.Println(si)
}

func TestTempDir(t *testing.T) {
	TempDir := os.TempDir()
	fmt.Println(TempDir)
}

func TestSockKeyIpToNetIPv6(t *testing.T) {
	var addr []uint64
	addr = append(addr, 121312)
	addr = append(addr, 12131231232)
	netIp := common.SockKeyIpToNetIP(addr, true)
	assert.Equal(t, 16, len(netIp))
	newAddr := common.BytesToSockKey(netIp)
	assert.True(t, slices.Compare(addr, newAddr) == 0)
}

func TestSockKeyIpToNetIPv4(t *testing.T) {
	var addr []uint64
	addr = append(addr, 121312, 0)
	netIp := common.SockKeyIpToNetIP(addr, false)
	assert.Equal(t, 4, len(netIp))
	newAddr := common.BytesToSockKey(netIp)
	assert.True(t, slices.Compare(addr, newAddr) == 0)
}

func TestBytesToIpv4(t *testing.T) {
	int32_, _ := common.IPv4ToUint32("127.0.0.1")
	addr := common.IntToBytes(int32_)

	ip := common.BytesToNetIP(addr, false)
	assert.Equal(t, "127.0.0.1", ip)
	fmt.Println(ip)
}

func TestBytesToIpv6(t *testing.T) {
	ipv6Addr := "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

	// Convert IPv6 address to []byte
	addr, _ := common.IPv6ToBytes(ipv6Addr)

	ip := common.BytesToNetIP(addr, true)
	addr2, _ := common.IPv6ToBytes(ip.String())
	assert.Equal(t, addr, addr2)
}

func TestIpv4ToBytes(t *testing.T) {
	bytes, _ := common.IPv4ToBytes("127.0.0.1")
	fmt.Println(bytes)
}
