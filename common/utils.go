package common

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/jefurry/logrus"
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
