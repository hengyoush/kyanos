package dwarfreader

import (
	"debug/dwarf"
	"errors"
	"fmt"
	"kyanos/common"
	"strings"
	"unsafe"
)

type DwarfReader struct {
	*dwarf.Reader
}

type StructMemberInfo struct {
	offset   int64
	typeInfo TypeInfo
}

// String 方法返回 TypeInfo 的字符串表示
func (si StructMemberInfo) String() string {
	return fmt.Sprintf("offset=%d type_info=[%s]", si.offset, si.typeInfo.String())
}

func GetFunctionArgInfo(reader *dwarf.Reader, goVersion common.GoVersion, funcSymbolName string) (map[string]ArgInfo, error) {
	argInfoMap := make(map[string]ArgInfo)
	useRegister := goVersion.After(1, 17)
	regModel := NewGolangRegABIModel()
	stackModel := GolangStackABIModel{}

	dies := GetMatchingDies(reader, funcSymbolName, dwarf.TagSubprogram)
	if len(dies) == 0 {
		return nil, errors.New(fmt.Sprintf("Can't find %s in dwarf data", funcSymbolName))
	}
	die := dies[0]
	argNames := make(map[string]bool)
	paramDies := GetParamDies(die, reader)
	for _, param := range paramDies {
		name := GetDieName(param)
		if name == "" {
			continue
		}
		if _, ok := argNames[name]; ok {
			continue
		}
		argNames[name] = true

		arg := ArgInfo{}
		arg.Retarg = IsGolangRetArg(param)

		typeDie, err := GetTypeAttribute(param, copyReader(reader))
		if err != nil {
			return nil, err
		}
		typeClass, err := GetTypeClass(&typeDie, copyReader(reader))
		if err != nil {
			return nil, err
		}
		typeSize, err := GetTypeByteSize(&typeDie, copyReader(reader))
		if err != nil {
			return nil, err
		}
		align, err := GetAlignmentByteSize(&typeDie, copyReader(reader))
		if err != nil {
			return nil, err
		}
		numPrimitives, err := GetNumPrimitives(&typeDie, copyReader(reader))
		if err != nil {
			return nil, err
		}

		var loc *VarLocation
		if useRegister {
			loc, err = resolveLocationForReg(typeClass, uint64(typeSize), uint64(align), numPrimitives, arg.Retarg, regModel)
		} else {
			loc, err = resolveLocationForStack(typeClass, uint64(typeSize), uint64(align), numPrimitives, arg.Retarg, &stackModel)
		}
		if err != nil {
			return nil, err
		}
		arg.Location = *loc
		argInfoMap[name] = arg
	}
	return argInfoMap, nil

}
func copyReader(reader *dwarf.Reader) *dwarf.Reader {
	copy := *reader
	return &copy
}
func IsGolangRetArg(die *dwarf.Entry) bool {
	attr := die.AttrField(dwarf.AttrVarParam)
	if attr == nil {
		return false
	}
	val, ok := attr.Val.(bool)
	if !ok {
		return false
	}
	return val
}

func GetParamDies(die *dwarf.Entry, reader *dwarf.Reader) []*dwarf.Entry {
	result := make([]*dwarf.Entry, 0)
	for _, each := range getChildren(die, copyReader(reader)) {
		if each.Tag == dwarf.TagFormalParameter {
			result = append(result, each)
		}
	}
	return result
}

func GetDieName(die *dwarf.Entry) string {
	funcName, ok := die.Val(dwarf.AttrName).(string)
	if !ok {
		return ""
	}
	return funcName
}

func GetMatchingDies(reader *dwarf.Reader, name string, tag dwarf.Tag) []*dwarf.Entry {
	reader.Seek(0)
	result := make([]*dwarf.Entry, 0)
	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			break // 处理错误或结束遍历
		}
		funcName, ok := entry.Val(dwarf.AttrName).(string)
		if !ok {
			continue
		}
		if entry.Tag == tag && funcName == name {
			result = append(result, entry)
		}
	}
	return result
}

func IsDeclaration(die *dwarf.Entry) bool {
	decl := die.AttrField(dwarf.AttrDeclaration)
	if decl != nil {
		return decl.Val.(bool)
	} else {
		return false
	}
}

func GetStructMemberOffset(structName string, memberName string, reader *dwarf.Reader) (int32, error) {
	memberInfo, err := GetStructMemberInfo(structName, dwarf.TagStructType, memberName, dwarf.TagMember, reader)
	if err != nil {
		return -1, err
	}
	return int32(memberInfo.offset), nil
}

func GetStructMemberInfo(structName string, tag dwarf.Tag, memberName string, memberTag dwarf.Tag, reader *dwarf.Reader) (*StructMemberInfo, error) {
	var memberInfo StructMemberInfo
	memberInfo.offset = -1
	dies := GetMatchingDies(reader, structName, tag)
	var structDie *dwarf.Entry
	for _, die := range dies {
		// Declaration DIE does not include the member DIEs.
		if IsDeclaration(die) {
			continue
		}
		structDie = die
	}
	if structDie == nil {
		return nil, errors.New(fmt.Sprintf("no strcut: %s found", structName))
	}

	copiedReader := *reader
	var err error
	for _, child := range getChildren(structDie, &copiedReader) {
		if child.Tag != memberTag {
			continue
		}
		dieName, ok := child.Val(dwarf.AttrName).(string)
		if !ok {
			continue
		}
		if dieName != memberName {
			continue
		}
		memberInfo.offset, err = GetMemberOffset(child)
		if err != nil {
			continue
		}
		return &memberInfo, nil
	}
	return nil, errors.New(fmt.Sprintf("Could not find member %s in struct %s.", memberName, structName))
}

func GetMemberOffset(die *dwarf.Entry) (int64, error) {
	if die.Tag != dwarf.TagMember {
		panic("not a member")
	}
	attr := die.AttrField(dwarf.AttrDataMemberLoc)
	if attr == nil {
		return 0, errors.New(fmt.Sprintf("can't find DW_AT_data_member_location"))
	}
	return attr.Val.(int64), nil
}

func GetNumPrimitives(die *dwarf.Entry, reader *dwarf.Reader) (int, error) {
	switch die.Tag {
	case dwarf.TagPointerType:
		fallthrough
	case dwarf.TagSubroutineType:
		fallthrough
	case dwarf.TagBaseType:
		return 1, nil
	case dwarf.TagStructType:
		copyReader := *reader
		num_primitives := 0
		for _, child := range getChildren(die, &copyReader) {
			if child.Tag == dwarf.TagMember {
				copyReader := *reader
				typeDie, err := GetTypeAttribute(child, &copyReader)
				if err != nil {
					return -1, err
				}
				copyReader = *reader
				memberNumPrimitives, err := GetNumPrimitives(&typeDie, &copyReader)
				if err != nil {
					return -1, err
				}
				num_primitives += memberNumPrimitives
			}
		}
		return num_primitives, nil
	default:
		panic("not implemented!")
	}
}

func GetAlignmentByteSize(die *dwarf.Entry, reader *dwarf.Reader) (int64, error) {
	const kAddressSize = unsafe.Sizeof(die)
	switch die.Tag {
	case dwarf.TagPointerType:
		fallthrough
	case dwarf.TagSubroutineType:
		return int64(kAddressSize), nil

	case dwarf.TagBaseType:
		return GetBaseOrStructTypeByteSize(die), nil
	case dwarf.TagStructType:
		copyReader := *reader
		maxSize := int64(1)
		for _, child := range getChildren(die, &copyReader) {
			if child.Tag == dwarf.TagMember {
				copyReader := *reader
				typeDie, err := GetTypeAttribute(child, &copyReader)
				if err != nil {
					return -1, err
				}
				copyReader = *reader
				memberAlign, err := GetAlignmentByteSize(&typeDie, &copyReader)
				if err != nil {
					return -1, err
				}
				maxSize = max(maxSize, memberAlign)
			}
		}
		return maxSize, nil
	default:
		panic("not implemented!")

	}
}

func GetBaseOrStructTypeByteSize(die *dwarf.Entry) int64 {
	byteSizeAttr := die.AttrField(dwarf.AttrByteSize)
	return byteSizeAttr.Val.(int64)
}

func GetTypeByteSize(die *dwarf.Entry, reader *dwarf.Reader) (int64, error) {
	const kAddressSize = unsafe.Sizeof(die)
	switch die.Tag {
	case dwarf.TagPointerType:
		fallthrough
	case dwarf.TagSubroutineType:
		return int64(kAddressSize), nil
	case dwarf.TagBaseType:
		fallthrough
	case dwarf.TagStructType:
		return GetBaseOrStructTypeByteSize(die), nil
	default:
		return 0, errors.New(fmt.Sprintf("not supported tag: %d", die.Tag))
	}
}

func getChildren(entry *dwarf.Entry, reader *dwarf.Reader) []*dwarf.Entry {
	if !entry.Children {
		return []*dwarf.Entry{}
	}
	reader.Seek(entry.Offset)
	reader.Next()
	result := make([]*dwarf.Entry, 0)
	for {
		child, err := reader.Next()
		if err != nil || child.Tag == 0 {
			break
		}
		result = append(result, child)
	}
	return result
}

func GetTypeClass(typeDie *dwarf.Entry, reader *dwarf.Reader) (TypeClass, error) {
	switch typeDie.Tag {
	case dwarf.TagPointerType:
		fallthrough
	case dwarf.TagSubroutineType:
		return kInteger, nil
	case dwarf.TagBaseType:
		encodingAttr := typeDie.AttrField(dwarf.AttrEncoding)
		encoding, ok := encodingAttr.Val.(int64)
		if !ok {
			return kNone, errors.New(fmt.Sprintf("Could not extract encoding from die (%v)", *typeDie))
		}
		if encoding == 4 {
			return kFloat, nil
		}
		return kInteger, nil
	case dwarf.TagStructType:
		typeClass := kNone
		for _, memberDie := range getChildren(typeDie, copyReader(reader)) {
			if memberDie.Tag == dwarf.TagMember {
				memberTypeDie, err := GetTypeAttribute(memberDie, copyReader(reader))
				if err != nil {
					return kNone, nil
				}
				childType, err := GetTypeClass(&memberTypeDie, copyReader(reader))
				if err != nil {
					return kNone, nil
				}
				typeClass = Combine(typeClass, childType)
			}
		}
		return typeClass, nil
	default:
		panic("not implemented!")
	}
}

func Combine(a, b TypeClass) TypeClass {
	if a == kMixed || b == kMixed {
		return kMixed
	}
	if a == kNone {
		return b
	}

	if a != b {
		return kMixed
	}
	return a
}

func GetTypeAttribute(die *dwarf.Entry, reader *dwarf.Reader) (dwarf.Entry, error) {
	attrType := die.AttrField(dwarf.AttrType)
	if attrType == nil {
		return *die, nil
	}
	typeOffset := attrType.Val.(dwarf.Offset)
	reader.Seek(typeOffset)
	typeEntry, err := reader.Next()
	if typeEntry.Tag != dwarf.TagTypedef {
		return *typeEntry, nil
	}
	if err != nil {
		return dwarf.Entry{}, err
	} else {
		return GetTypeAttribute(typeEntry, reader)
	}
}

func resolveLocationForStack(tc TypeClass,
	typeSize uint64, align uint64, numVars int, isRetArg bool, model *GolangStackABIModel) (*VarLocation, error) {
	var varLoc VarLocation
	model.current_stack_offset_ = SnapUpToMultiple(model.current_stack_offset_, int(align))
	varLoc.LocType = KStack
	varLoc.Offset = int64(model.current_stack_offset_)
	model.current_stack_offset_ += int(typeSize)
	return &varLoc, nil
}

func resolveLocationForReg(tc TypeClass,
	typeSize uint64, align uint64, numVars int, isRetArg bool, model *GolangRegABIModel) (*VarLocation, error) {
	var regOffset *int
	var registers *[]RegisterName

	if tc == kInteger {
		if isRetArg {
			regOffset = &model.current_int_retval_reg_offset_
			registers = &model.int_retval_registers_
		} else {
			regOffset = &model.current_int_arg_reg_offset_
			registers = &model.int_arg_registers_
		}
	} else if tc == kFloat {
		if isRetArg {
			regOffset = &model.current_fp_retval_reg_offset_
			registers = &model.fp_retval_registers_
		} else {
			regOffset = &model.current_fp_arg_reg_offset_
			registers = &model.int_arg_registers_
		}
	} else {
		return nil, errors.New("not implented")
	}

	var varLoc VarLocation
	if numVars <= len(*registers) {
		// register
		if tc == kInteger {
			varLoc.LocType = KRegister
		} else {
			varLoc.LocType = KRegisterFP
		}
		varLoc.Offset = int64(*regOffset)
		for i := 0; i < numVars; i++ {
			reg := (*registers)[0]
			*registers = (*registers)[1:]
			varLoc.Registers = append(varLoc.Registers, reg)
		}
		*regOffset += numVars * int(model.regSize)
	} else {
		// stack
		model.current_stack_offset_ = SnapUpToMultiple(model.current_stack_offset_, int(align))
		varLoc.LocType = KStack
		varLoc.Offset = int64(model.current_stack_offset_)
		model.current_stack_offset_ += int(typeSize)
	}
	return &varLoc, nil
}

type GolangStackABIModel struct {
	current_stack_offset_ int
}
type GolangRegABIModel struct {
	regSize                        uint64
	current_stack_offset_          int
	current_int_arg_reg_offset_    int
	current_fp_arg_reg_offset_     int
	current_int_retval_reg_offset_ int
	current_fp_retval_reg_offset_  int

	int_arg_registers_    []RegisterName
	fp_arg_registers_     []RegisterName
	int_retval_registers_ []RegisterName
	fp_retval_registers_  []RegisterName
}

func NewGolangRegABIModel() *GolangRegABIModel {
	model := GolangRegABIModel{}
	model.regSize = 8
	model.int_arg_registers_ = []RegisterName{kRAX, kRBX, kRCX, kRDI, kRSI, kR8, kR9, kR10, kR11}
	model.fp_arg_registers_ = []RegisterName{kXMM0, kXMM1, kXMM2, kXMM3, kXMM4, kXMM5, kXMM6, kXMM7, kXMM8, kXMM9, kXMM10, kXMM11, kXMM12, kXMM13, kXMM14}
	model.int_retval_registers_ = []RegisterName{kRAX, kRBX, kRCX, kRDI, kRSI, kR8, kR9, kR10, kR11}
	model.fp_retval_registers_ = []RegisterName{kXMM0, kXMM1, kXMM2, kXMM3, kXMM4, kXMM5, kXMM6, kXMM7, kXMM8, kXMM9, kXMM10, kXMM11, kXMM12, kXMM13, kXMM14}
	return &model
}

type RegisterName int

const (
	kRAX RegisterName = iota
	kRBX
	kRCX
	kRDX
	kRDI
	kRSI
	kR8
	kR9
	kR10
	kR11

	kXMM0
	kXMM1
	kXMM2
	kXMM3
	kXMM4
	kXMM5
	kXMM6
	kXMM7
	kXMM8
	kXMM9
	kXMM10
	kXMM11
	kXMM12
	kXMM13
	kXMM14
)

// String 方法返回 RegisterName 的字符串表示
func (rn RegisterName) String() string {
	switch rn {
	case kRAX:
		return "RAX"
	case kRBX:
		return "RBX"
	case kRCX:
		return "RCX"
	case kRDX:
		return "RDX"
	case kRDI:
		return "RDI"
	case kRSI:
		return "RSI"
	case kR8:
		return "R8"
	case kR9:
		return "R9"
	case kR10:
		return "R10"
	case kR11:
		return "R11"
	case kXMM0:
		return "XMM0"
	case kXMM1:
		return "XMM1"
	case kXMM2:
		return "XMM2"
	case kXMM3:
		return "XMM3"
	case kXMM4:
		return "XMM4"
	case kXMM5:
		return "XMM5"
	case kXMM6:
		return "XMM6"
	case kXMM7:
		return "XMM7"
	case kXMM8:
		return "XMM8"
	case kXMM9:
		return "XMM9"
	case kXMM10:
		return "XMM10"
	case kXMM11:
		return "XMM11"
	case kXMM12:
		return "XMM12"
	case kXMM13:
		return "XMM13"
	case kXMM14:
		return "XMM14"
	default:
		return "UnknownRegister"
	}
}

type TypeClass int

const (
	kNone TypeClass = iota
	kInteger
	kFloat
	kMixed
)

type LocationType int

// Identifies where a variable is located.
const (
	KUnknown LocationType = iota
	// Stack address relative to the frame stack pointer (SP)
	KStack
	// Stack address relative to the frame base pointer (BP)
	KStackBP
	// Integer register.
	KRegister
	// Floating-point register.
	KRegisterFP
)

// String 方法返回 LocationType 的友好字符串表示
func (lt LocationType) String() string {
	switch lt {
	case KUnknown:
		return "Unknown"
	case KStack:
		return "Stack"
	case KStackBP:
		return "StackBP"
	case KRegister:
		return "Register"
	case KRegisterFP:
		return "RegisterFP"
	default:
		return "Invalid"
	}
}

// intArgRegisters 定义了整数参数寄存器
var intArgRegisters = []RegisterName{
	kRAX, kRBX, kRCX,
	kRDI, kRSI, kR8,
	kR9, kR10, kR11,
}

// fpArgRegisters 定义了浮点参数寄存器
var fpArgRegisters = []RegisterName{
	kXMM0, kXMM1, kXMM2, kXMM3, kXMM4, kXMM5,
	kXMM6, kXMM7, kXMM8, kXMM9, kXMM10, kXMM11,
	kXMM12, kXMM13, kXMM14,
}

// intRetvalRegisters 定义了整数返回值寄存器
var intRetvalRegisters = []RegisterName{
	kRAX, kRBX, kRCX,
	kRDI, kRSI, kR8,
	kR9, kR10, kR11,
}

// fpRetvalRegisters 定义了浮点返回值寄存器
var fpRetvalRegisters = []RegisterName{
	kXMM0, kXMM1, kXMM2, kXMM3, kXMM4, kXMM5,
	kXMM6, kXMM7, kXMM8, kXMM9, kXMM10, kXMM11,
	kXMM12, kXMM13, kXMM14,
}

type VarLocation struct {
	LocType   LocationType
	Offset    int64
	Registers []RegisterName
}

func (v VarLocation) String() string {
	registersStr := "[" + strings.Join(v.formatRegisters(), ",") + "]"
	return fmt.Sprintf("type=%s offset=%d registers=%s", v.LocType.String(), v.Offset, registersStr)
}

// formatRegisters 将寄存器切片转换为字符串切片
func (v VarLocation) formatRegisters() []string {
	var registerNames []string
	for _, reg := range v.Registers {
		registerNames = append(registerNames, reg.String())
	}
	return registerNames
}

// SnapUpToMultiple rounds x up to the nearest multiple of size
func SnapUpToMultiple(x, size int) int {
	return IntRoundUpDivide(x, size) * size
}

// IntRoundUpDivide performs integer division that rounds up if there is any fractional portion
func IntRoundUpDivide(x, y int) int {
	return (x + y - 1) / y
}

// VarType 是一个枚举，用来表示不同的变量类型
type VarType int

const (
	kUnspecified VarType = iota
	kVoid
	kBaseType
	kPointer
	kClass
	kStruct
	kSubroutine
)

// VarTypeToString 将 VarType 转换为字符串
func VarTypeToString(t VarType) string {
	switch t {
	case kUnspecified:
		return "Unspecified"
	case kVoid:
		return "Void"
	case kBaseType:
		return "BaseType"
	case kPointer:
		return "Pointer"
	case kClass:
		return "Class"
	case kStruct:
		return "Struct"
	case kSubroutine:
		return "Subroutine"
	default:
		return "Unknown"
	}
}

type ArgInfo struct {
	TypeInfo TypeInfo
	Location VarLocation

	// If true, this argument is really a return value.
	// Used by golang return values which are really function arguments from a DWARF perspective.
	Retarg bool
}

func (ArgInfo ArgInfo) String() string {
	return fmt.Sprintf("type_info=[%s] location=[%s] retarg=%v", ArgInfo.TypeInfo, ArgInfo.Location, ArgInfo.Retarg)
}

// TypeInfo 表示类型信息
type TypeInfo struct {
	Type     VarType
	TypeName string
	DeclType string
}

// String 方法返回 TypeInfo 的字符串表示
func (ti TypeInfo) String() string {
	return fmt.Sprintf("type=%s decl_type=%s type_name=%s", VarTypeToString(ti.Type), ti.DeclType, ti.TypeName)
}

// GetType 获取DWARFDie的类型
func GetType(die *dwarf.Entry) VarType {
	// 实现获取类型的逻辑
	switch die.Tag {
	case 0: // 假设的标签值
		return kPointer
	case 1: // 假设的标签值
		return kSubroutine
	case 2: // 假设的标签值
		return kBaseType
	case 3: // 假设的标签值
		return kClass
	case 4: // 假设的标签值
		return kStruct
	default:
		return kUnspecified
	}
}
