package common

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unicode"
)

func checkEnvPath(env string) (string, error) {
	filePath, _ := os.LookupEnv(env)
	if filePath != "" {
		_, err := os.Stat(filePath)
		if err != nil {
			return "", fmt.Errorf("could not open %s %s", env, filePath)
		}
		return filePath, nil
	}
	return "", nil
}

// UnameRelease gets the version string of the current running kernel
func UnameRelease() (string, error) {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return "", fmt.Errorf("could not get utsname")
	}

	var buf [65]byte
	for i, b := range uname.Release {
		buf[i] = byte(b)
	}

	ver := string(buf[:])
	ver = strings.Trim(ver, "\x00")

	return ver, nil
}

// UnameMachine gets the version string of host's architecture
func UnameMachine() (string, error) {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return "", fmt.Errorf("could not get utsname")
	}

	var buf [65]byte
	for i, b := range uname.Machine {
		buf[i] = byte(b)
	}

	arch := string(buf[:])
	arch = strings.Trim(arch, "\x00")

	if strings.Contains(arch, "aarch64") {
		arch = "arm64"
	}

	return arch, nil
}

type KernelVersionComparison int

const (
	KernelVersionInvalid KernelVersionComparison = iota - 1
	KernelVersionEqual
	KernelVersionOlder
	KernelVersionNewer
)

// CompareKernelRelease will compare two given kernel version/release
// strings and returns a KernelVersionComparison constant that shows
// the relationship of the given kernel version to the base.
// For example CompareKernelRelease("5.8.1", "4.12.3") == KernelVersionOlder
// because 4.12.3 is older than 5.8.1
//
// It also returns an error incase of a malformed kernel version.
//
// Consumers should use the constants defined in this package for checking
// the results: KernelVersionOlder, KernelVersionEqual, KernelVersionNewer
//
// Examples of $(uname -r):
//
// 5.11.0-31-generic (ubuntu)
// 4.18.0-305.12.1.el8_4.x86_64 (alma)
// 4.18.0-338.el8.x86_64 (stream8)
// 4.18.0-305.7.1.el8_4.centos.x86_64 (centos)
// 4.18.0-305.7.1.el8_4.centos.plus.x86_64 (centos + plus repo)
// 5.13.13-arch1-1 (archlinux)
// 5.4.228+ (ubuntu-gke 5.4)
func CompareKernelRelease(base, given string) (KernelVersionComparison, error) {
	b := strings.Split(base, "-") // [base]-xxx
	b = strings.Split(b[0], ".")  // [major][minor][patch]
	for len(b) < 3 {
		b = append(b, "0")
	}
	if len(b) != 3 {
		return KernelVersionInvalid, fmt.Errorf("invalid base kernel version format: %s", base)
	}

	g := strings.Split(given, "-")
	g = strings.Split(g[0], ".")
	for len(g) < 3 {
		g = append(g, "0")
	}
	if len(g) != 3 {
		return KernelVersionInvalid, fmt.Errorf("invalid given kernel version format: %s", given)
	}

	for n := 0; n <= 2; n++ {
		givenValue, err := strconv.Atoi(cleanVersionNumber(g[n]))
		if err != nil {
			return KernelVersionInvalid, fmt.Errorf("invalid given kernel version value: %s issue with: %s", given, g[n])
		}
		baseValue, err := strconv.Atoi(cleanVersionNumber(b[n]))
		if err != nil {
			return KernelVersionInvalid, fmt.Errorf("invalid base kernel version value: %s issue with: %s", base, b[n])
		}

		switch {
		case givenValue > baseValue:
			return KernelVersionNewer, nil
		case givenValue < baseValue:
			return KernelVersionOlder, nil
		}
	}
	return KernelVersionEqual, nil
}

func cleanVersionNumber(number string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsDigit(r) {
			return r
		}
		return -1
	}, number)
}
