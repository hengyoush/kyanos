package common

import (
	"fmt"
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

type I1 interface {
	A()
}

type I2 interface {
	B()
}

type M struct {
}

func (m *M) A() {

}

func (m *M) B() {

}

func TestAmsa(t *testing.T) {
	var m I1 = &M{}
	I2 := m.(I2)
	I2.B()
	fmt.Print(1)
}

type I3 interface {
	kk() string
}
type Inner struct {
	B string
}

func (I *Inner) kk() string {
	return "1"
}

type Outer struct {
	Inner
	CM string
}

func TestAa(t *testing.T) {
	var outer I3 = &Outer{}
	_, ok := outer.(*Outer)
	if !ok {
		t.FailNow()
	}
}
