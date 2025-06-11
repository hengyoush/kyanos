package version

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var (
	ErrAheadLatest  = fmt.Errorf("local version is ahead of the latest release")
	ErrBehindLatest = fmt.Errorf("local version is out of date.")
)

func UpgradeDetect() error {
	localVersion, err := ParseVersion(Version)
	if err != nil {
		return fmt.Errorf("Failed to parse local version: %s err: %v", Version, err)
	}
	os.Setenv("GODEBUG", "netdns=go")

	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()
	releaseTagName, downloadUrl, err := ReleaseVersion(ctx)
	if err != nil {
		return fmt.Errorf("Failed to get latest release: %v", err)
	}
	remoteVersion, err := ParseVersion(strings.TrimPrefix(releaseTagName, "v"))
	if err != nil {
		return err
	}

	compare := CompareVersions(localVersion, remoteVersion)
	switch {
	case compare < 0:
		return fmt.Errorf("%w Current verion: %q.\n  🎉 New verion: %q from %q", ErrBehindLatest, Version, releaseTagName, downloadUrl)
	case compare > 0:
		return ErrAheadLatest
	default:
		return nil
	}
}

// SemanticVersion represents a semantic version in the format "major.minor.patch".
type SemanticVersion struct {
	Major int
	Minor int
	Patch int
}

// ParseVersion parses a version string in the format "major.minor.patch" into a SemVer struct.
func ParseVersion(versionStr string) (SemanticVersion, error) {
	parts := strings.Split(versionStr, ".")
	if len(parts) != 3 {
		return SemanticVersion{}, fmt.Errorf("invalid version format")
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return SemanticVersion{}, fmt.Errorf("invalid verision.major format")
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return SemanticVersion{}, fmt.Errorf("invalid version.minor format")
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return SemanticVersion{}, fmt.Errorf("invalid version.patch format")
	}

	return SemanticVersion{Major: major, Minor: minor, Patch: patch}, nil
}

// CompareVersions compares two semantic versions.
func CompareVersions(v1, v2 SemanticVersion) int {
	if v1.Major != v2.Major {
		return v1.Major - v2.Major
	}
	if v1.Minor != v2.Minor {
		return v1.Minor - v2.Minor
	}
	return v1.Patch - v2.Patch
}
