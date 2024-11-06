package common

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/go-version"
	"github.com/jefurry/logrus"
	"github.com/zcalusic/sysinfo"
)

func IntToIP(ipInt uint32) string {
	// 将32位整数转换为4字节的切片
	ipBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ipBytes, ipInt)

	// 将字节切片转换为net.IP类型
	ip := net.IP(ipBytes)

	// 将net.IP类型转换为字符串
	return ip.String()
}

func IntToBytes[T KInt](n T) []byte {
	// 假设我们的int是非负的，并且我们工作在64位系统上
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, n)
	return buf.Bytes()
}

func BytesToInt[T KInt](byteArray []byte) T {
	// 假设bytes是以LittleEndian方式编码的64位整数
	var n T
	buf := bytes.NewReader(byteArray)
	err := binary.Read(buf, binary.LittleEndian, &n)
	if err != nil {
		return 0
	}
	// 转换回int，注意可能的溢出
	return T(n)
}

func BytesToNetIP(addr []uint8, isIpv6 bool) net.IP {
	result := make([]byte, 0)
	if isIpv6 {
		for _, a := range addr {
			result = append(result, byte(a))
		}
	} else {
		for idx := 0; idx < 4; idx++ {
			result = append(result, byte(addr[idx]))
		}
	}

	return net.IP(result)
}

func NetIPToBytes(ip net.IP, isIpv6 bool) []byte {
	bytes := [16]byte{}
	if isIpv6 {
		return []byte(ip)
	} else {
		ipv4 := ip.To4()
		for i, a := range ipv4 {
			bytes[i] = a
		}
		return bytes[:]
	}
}

func SockKeyIpToNetIP(addr []uint64, isIpv6 bool) net.IP {
	if isIpv6 {
		result := make([]byte, 0)
		for _, a := range addr {
			result = append(result, IntToBytes(a)...)
		}
		return net.IP(result)
	} else {
		a := uint32(addr[0])
		return IntToBytes(a)
	}
}

func BytesToSockKey(ip net.IP) []uint64 {
	result := make([]uint64, 0)
	if len(ip) == 16 {
		result = append(result, BytesToInt[uint64](ip[0:8]))
		result = append(result, BytesToInt[uint64](ip[8:]))
	} else {
		newIp := make([]uint32, 0)
		newIp = append(newIp, BytesToInt[uint32](ip))
		result = append(result, uint64(newIp[0]))
		result = append(result, 0)
	}
	return result
}

func Int8ToStr(arr []int8) string {
	str := ""
	for _, v := range arr {
		if v >= 0 && v <= 127 { // 确保int8值在有效的ASCII范围内
			str += string(byte(v)) // 将int8转换为byte并转换为字符串片段
		} else {
			// 处理可能的负数或其他非ASCII值，例如转换为rune并打印其Unicode编码
			str += fmt.Sprintf("\\u%04x", rune(v))
		}
	}
	return str
}

func B2S(bs []int8) string {
	ba := make([]byte, 0, len(bs))
	for _, b := range bs {
		ba = append(ba, byte(b))
	}
	return string(ba)
}

func DisplayTcpFlags(flags uint8) string {
	return ConvertTcpFlagAck(flags) + ConvertTcpFlagPsh(flags) +
		ConvertTcpFlagRst(flags) + ConvertTcpFlagSyn(flags)
}

func ConvertTcpFlagAck(flags uint8) string {
	if (flags & uint8(TCP_FLAGS_ACK)) != 0 {
		return "A"
	}
	return ""
}

func ConvertTcpFlagPsh(flags uint8) string {
	if (flags & uint8(TCP_FLAGS_PSH)) != 0 {
		return "P"
	}
	return ""
}

func ConvertTcpFlagRst(flags uint8) string {
	if (flags & uint8(TCP_FLAGS_RST)) != 0 {
		return "R"
	}
	return ""
}

func ConvertTcpFlagSyn(flags uint8) string {
	if (flags & uint8(TCP_FLAGS_SYN)) != 0 {
		return "S"
	}
	return ""
}

func GetIPAddrByInterfaceName(filter string) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	nameIPS := map[string]string{}
	names := []string{}
	for _, i := range interfaces {
		name := i.Name
		addrs, err := i.Addrs()
		if err != nil {
			panic(err)
		}
		// handle err
		for _, addr := range addrs {
			var (
				ip net.IP
			)
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if filter == "" || strings.Contains(name, filter) {
				names = append(names, name)
				nameIPS[name] = ip.String()
			}
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "", errors.New("can not find the client ip address ")
	}
	logrus.Infof("GetClientIP ips:%v", nameIPS)
	return nameIPS[names[0]], nil

}

func IPv4ToUint32(ipStr string) (uint32, error) {
	// 解析IPv4地址
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	// 检查是否为IPv4地址
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("not an IPv4 address: %s", ipStr)
	}

	// 将IPv4地址的四个字节组合成一个uint32
	var result uint32
	for i := 3; i >= 0; i-- {
		byteValue := uint32(ip4[i])
		result = (result << 8) | byteValue
	}

	return result, nil
}

func IPv4ToBytes(ipStr string) ([]byte, error) {
	// 解析IPv4地址
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	// 检查是否为IPv4地址
	ip16 := ip.To16()
	if ip16 == nil {
		return nil, fmt.Errorf("not an IPv4 address: %s", ipStr)
	}
	return ip16, nil
}

// ipv6ToBytes converts an IPv6 address string to a []byte.
func IPv6ToBytes(ipv6Addr string) ([]byte, error) {
	// Parse the IPv6 address
	ip := net.ParseIP(ipv6Addr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IPv6 address: %s", ipv6Addr)
	}

	// Extract the 16-byte representation of the IPv6 address
	ipv6 := ip.To16()
	if ipv6 == nil {
		return nil, fmt.Errorf("not a valid IPv6 address: %s", ipv6Addr)
	}

	return ipv6, nil
}

func GetBufioReaderReadIndex(r *bufio.Reader) int {
	_type := reflect.ValueOf(*r)
	f := _type.FieldByName("r")
	return int(f.Int())
}

func FormatTimestampWithPrecision(timestamp uint64, nano bool) string {
	t := time.Unix(int64(timestamp/1000000000), int64(timestamp%1000000000))
	if nano {
		return t.Format("2006-01-02 15:04:05.000000000")
	} else {
		return t.Format("2006-01-02 15:04:05.000")
	}
}

func ConvertDurationToMillisecondsIfNeeded(duration float64, nano bool) float64 {
	if nano {
		return duration
	} else {
		return duration / 1000000
	}
}

// "5.15.0-72-generic"
func GetKernelVersion() *version.Version {
	var si sysinfo.SysInfo
	si.GetSysInfo()
	release := si.Kernel.Release
	v, err := version.NewVersion(release)
	if err != nil {
		DefaultLog.Debugf("Parse kernel version failed: %v, may be centos version, adjust and retry", err)
		release = release[:strings.Index(release, "-")]
		v, err = version.NewVersion(release)
		if err != nil {
			DefaultLog.Fatalf("Can't parse kernel version: %v, may be a bug, please submit a issue on http://github.com/hengyoush/kyanos", err)
		} else {
			return v
		}
	}
	return v
}

var osReleaseFiles = []string{
	"/etc/os-release",
	"/usr/lib/os-release",
}

type Release struct {
	Id        string
	VersionId string
}

func GetRelease() (*Release, error) {
	var errors []error
	for _, path := range osReleaseFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			errors = append(errors, err)
			continue
		}

		var release Release
		for _, line := range strings.Split(string(data), "\n") {
			line := strings.TrimSpace(line)
			parts := strings.Split(line, "=")
			if len(parts) < 2 {
				continue
			}
			key, value := parts[0], parts[1]
			key = strings.TrimSpace(key)
			switch key {
			case "ID":
				release.Id = strings.TrimSpace(value)
				break
			case "VERSION_ID":
				release.VersionId = strings.TrimSpace(value)
				break
			}
		}
		if release.Id != "" {
			return &release, nil
		}
	}

	if len(errors) != 0 {
		return nil, fmt.Errorf("%v", errors)
	}

	return nil, fmt.Errorf("can't get release info from %v", osReleaseFiles)
}

func NanoToMills[T KInt](x T) float64 {
	return float64(x) / 1000000
}

func TruncateString(s string, maxBytes int) string {
	if len(s) < maxBytes {
		return s
	} else {
		return fmt.Sprintf("%s...(truncated, total: %dbytes)", s[:maxBytes], len(s))
	}
}

// 计算两个字符串的公共前缀长度
func CommonPrefix(str1, str2 string) string {
	minLen := len(str1)
	if len(str2) < minLen {
		minLen = len(str2)
	}

	i := 0
	for i < minLen && str1[i] == str2[i] {
		i++
	}

	return str1[:i]
}

func UnwrapErr(err error) error {
	for {
		if v := errors.Unwrap(err); v != nil {
			err = v
		} else {
			return err
		}
	}
}
