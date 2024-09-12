package common_test

import (
	"fmt"
	"kyanos/common"
	"os"
	"reflect"
	"testing"

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
