package common

import (
	"testing"
)

func TestLEndianBytesToKInt(t *testing.T) {
	type args struct {
		buf    []byte
		nBytes int
	}
	tests := []struct {
		name   string
		args   args
		result int16
		ok     bool
	}{
		{
			name: "1", args: args{buf: []byte("\x78\x56"), nBytes: 2},
			result: 0x5678, ok: true,
		}, {
			name: "1", args: args{buf: []byte("\x78\x56"), nBytes: 1},
			result: 0x78, ok: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := LEndianBytesToKInt[int16](tt.args.buf, tt.args.nBytes)
			if got != tt.result {
				t.Errorf("LEndianBytesToKInt() got = %v, want %v", got, tt.result)
			}
			if got1 != tt.ok {
				t.Errorf("LEndianBytesToKInt() got1 = %v, want %v", got1, tt.ok)
			}
		})
	}
}
