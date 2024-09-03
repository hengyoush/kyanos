package mysql

import (
	"math"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_processLengthEncodedInt(t *testing.T) {
	type args struct {
		s      string
		offset int
	}
	tests := []struct {
		name      string
		args      args
		newOffset uint
		result    uint
		ok        bool
	}{
		{
			name: "1", args: args{s: "\x77\x12", offset: 1},
			newOffset: 2, result: 18, ok: true,
		},
		{
			name: "2", args: args{s: "\x77\xfa", offset: 1},
			newOffset: 2, result: 250, ok: true,
		}, {
			name: "2", args: args{s: "\x77\xfc\xfb\x00", offset: 1},
			newOffset: 4, result: 251, ok: true,
		}, {
			name: "2", args: args{s: "\x77\xfd\x01\x23\x45", offset: 1},
			newOffset: 5, result: 0x452301, ok: true,
		}, {
			name: "2", args: args{s: "\x77\xfe\x01\x23\x45\x67\x89\xab\xcd\xef", offset: 1},
			newOffset: 10, result: 0xefcdab8967452301, ok: true,
		},
		{
			name: "NotEnoughBytes", args: args{s: "", offset: 0},
			newOffset: 0, result: math.MaxUint64, ok: false,
		}, {
			name: "NotEnoughBytes", args: args{s: "\xfc\xfb", offset: 0},
			newOffset: 0, result: math.MaxUint64, ok: false,
		}, {
			name: "NotEnoughBytes", args: args{s: "\xfd\x01\x23", offset: 0},
			newOffset: 0, result: math.MaxUint64, ok: false,
		}, {
			name: "NotEnoughBytes", args: args{s: "\xfe\x01\x23\x45\x67\x89\xab\xcd", offset: 0},
			newOffset: 0, result: math.MaxUint64, ok: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got1, got2 := processLengthEncodedInt(tt.args.s, &tt.args.offset)
			if got1 != int64(tt.result) {
				t.Errorf("processLengthEncodedInt() got1 = %v, want %v", got1, tt.result)
			}
			if got2 != tt.ok {
				t.Errorf("processLengthEncodedInt() got2 = %v, want %v", got2, tt.ok)
			}
			if tt.args.offset != int(tt.newOffset) {
				t.Errorf("processLengthEncodedInt() offset = %v, want %v", tt.args.offset, int(tt.newOffset))
			}

		})
	}
}

func Test_readNBytesToInt(t *testing.T) {
	type args struct {
		s      string
		offset int
		nbytes uint
	}
	tests := []struct {
		name         string
		args         args
		result       int32
		newResult    int32
		expectOffset uint
		offset       int
		ok           bool
	}{
		{name: "1", args: args{s: "\x05", offset: 0, nbytes: 1}, expectOffset: 1, result: 5, ok: true},
		{name: "1", args: args{s: "\x01\x23", offset: 0, nbytes: 2}, expectOffset: 2, result: 8961, ok: true},
		{name: "1", args: args{s: "\x01\x23\x45\x67", offset: 0, nbytes: 4}, expectOffset: 4, result: 1732584193, ok: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok := DissectInt[int32](tt.args.s, &tt.args.offset, int(tt.args.nbytes), &tt.newResult)
			if !reflect.DeepEqual(tt.newResult, tt.result) {
				t.Errorf("readNBytesToInt() got = %v, want %v", tt.newResult, tt.result)
			}
			if uint(tt.args.offset) != tt.expectOffset {
				t.Errorf("readNBytesToInt() got1 = %v, want %v", tt.args.offset, tt.expectOffset)
			}
			if ok != tt.ok {
				t.Errorf("readNBytesToInt() got2 = %v, want %v", ok, tt.ok)
			}
		})
	}
}

func TestDissectStringParam(t *testing.T) {
	type args struct {
		s      string
		offset *int
		param  *string
	}
	offset := 0
	value := ""
	tests := []struct {
		name string
		args args
		ok   bool
	}{
		{
			name: "1", args: args{s: "\x05" + "mysql", offset: &offset, param: &value}, ok: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DissectStringParam(tt.args.s, tt.args.offset, tt.args.param); got != tt.ok {
				t.Errorf("DissectStringParam() = %v, want %v", got, tt.ok)
			}
			assert.Equal(t, 6, offset)
			assert.Equal(t, "mysql", value)
		})
	}
}
