package bpf

import (
	"reflect"

	"github.com/cilium/ebpf"
)

// TODO remove me
// func GetMap(mapName string) *ebpf.Map {
// 	oldObjs, isOld := Objs.(*AgentOldObjects)
// 	if isOld {
// 		maps := oldObjs.AgentOldMaps
// 		v := reflect.ValueOf(maps)
// 		f := v.FieldByName(mapName).Interface()
// 		return f.(*ebpf.Map)
// 	} else {
// 		newobjs := Objs.(*AgentObjects)
// 		maps := newobjs.AgentMaps
// 		v := reflect.ValueOf(maps)
// 		f := v.FieldByName(mapName).Interface()
// 		return f.(*ebpf.Map)
// 	}
// }

// // TODO remove me
// func GetMapByObjs(mapName string, objs any) *ebpf.Map {
// 	oldObjs, isOld := objs.(*AgentOldObjects)
// 	if isOld {
// 		maps := oldObjs.AgentOldMaps
// 		v := reflect.ValueOf(maps)
// 		f := v.FieldByName(mapName).Interface()
// 		return f.(*ebpf.Map)
// 	} else {
// 		newobjs := objs.(*AgentObjects)
// 		maps := newobjs.AgentMaps
// 		v := reflect.ValueOf(maps)
// 		f := v.FieldByName(mapName).Interface()
// 		return f.(*ebpf.Map)
// 	}
// }

func GetMapFromObjs(objs any, mapName string) *ebpf.Map {
	val := reflect.ValueOf(objs)

	mapsField := val.Elem().Field(1)
	if !mapsField.IsValid() {
		return nil
	}
	mapSpecsVal := mapsField
	fieldName := mapName
	fieldVal := mapSpecsVal.FieldByName(fieldName)
	if fieldVal.IsValid() && fieldVal.Kind() == reflect.Ptr && !fieldVal.IsNil() {
		m := fieldVal.Interface().(*ebpf.Map)
		return m
	} else {
		return nil
	}
}
