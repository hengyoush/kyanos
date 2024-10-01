package bpf_test

import (
	"fmt"
	"kyanos/bpf"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
)

func TestGetProg(t *testing.T) {
	var objs any
	objs = &bpf.Openssl102aObjects{
		Openssl102aPrograms: bpf.Openssl102aPrograms{
			SSL_readEntryNestedSyscall: &ebpf.Program{},
		},
	}
	val := reflect.ValueOf(objs)

	// Check if it is a struct and get its "Programs" field
	programField := val.Elem().Field(0)
	if !programField.IsValid() {
		fmt.Println("Field 'Programs' not found in Openssl102aObjects")
		return
	}
	// Find the field in Openssl102aProgramSpecs by its name using reflection
	programSpecsVal := programField
	// Name of the field in Openssl102aProgramSpecs that we want to access
	fieldName := "SSL_readEntryNestedSyscall"
	fieldVal := programSpecsVal.FieldByName(fieldName)
	if fieldVal.IsValid() && fieldVal.Kind() == reflect.Ptr && !fieldVal.IsNil() {
		programSpec := fieldVal.Interface().(*ebpf.Program)
		fmt.Printf("Program Spec found: %s\n", programSpec.String())
	} else {
		fmt.Printf("Field '%s' not found or is nil\n", fieldName)
	}
}
