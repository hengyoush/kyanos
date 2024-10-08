package common

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
)

// NsEnterConfig is the nsenter configuration used to generate
// nsenter command
type NsEnterConfig struct {
	Cgroup              bool   // Enter cgroup namespace
	CgroupFile          string // Cgroup namespace location, default to /proc/PID/ns/cgroup
	FollowContext       bool   // Set SELinux security context
	GID                 int    // GID to use to execute given program
	IPC                 bool   // Enter IPC namespace
	IPCFile             string // IPC namespace location, default to /proc/PID/ns/ipc
	Mount               bool   // Enter mount namespace
	MountFile           string // Mount namespace location, default to /proc/PID/ns/mnt
	Net                 bool   // Enter network namespace
	NetFile             string // Network namespace location, default to /proc/PID/ns/net
	NoFork              bool   // Do not fork before executing the specified program
	PID                 bool   // Enter PID namespace
	PIDFile             string // PID namespace location, default to /proc/PID/ns/pid
	PreserveCredentials bool   // Preserve current UID/GID when entering namespaces
	RootDirectory       string // Set the root directory, default to target process root directory
	Target              int    // Target PID (required)
	UID                 int    // UID to use to execute given program
	User                bool   // Enter user namespace
	UserFile            string // User namespace location, default to /proc/PID/ns/user
	UTS                 bool   // Enter UTS namespace
	UTSFile             string // UTS namespace location, default to /proc/PID/ns/uts
	WorkingDirectory    string // Set the working directory, default to target process working directory
}

// Execute executs the givne command with a default background context
func (c *NsEnterConfig) Execute(program string, args ...string) (string, string, error) {
	return c.ExecuteContext(context.Background(), program, args...)
}

// ExecuteContext the given program using the given nsenter configuration and given context
// and return stdout/stderr or an error if command has failed
func (c *NsEnterConfig) ExecuteContext(ctx context.Context, program string, args ...string) (string, string, error) {
	cmd, err := c.buildCommand(ctx)
	if err != nil {
		return "", "", fmt.Errorf("Error while building command: %v", err)
	}

	// Prepare command
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Args = append(cmd.Args, program)
	cmd.Args = append(cmd.Args, args...)

	err = cmd.Run()
	if err != nil {
		return stdout.String(), stderr.String(), fmt.Errorf("Error while executing command: %v", err)
	}

	return stdout.String(), stderr.String(), nil
}

func (c *NsEnterConfig) buildCommand(ctx context.Context) (*exec.Cmd, error) {
	if c.Target == 0 {
		return nil, fmt.Errorf("Target must be specified")
	}

	var args []string
	args = append(args, "--target", strconv.Itoa(c.Target))

	if c.Cgroup {
		if c.CgroupFile != "" {
			args = append(args, fmt.Sprintf("--cgroup=%s", c.CgroupFile))
		} else {
			args = append(args, "--cgroup")
		}
	}

	if c.FollowContext {
		args = append(args, "--follow-context")
	}

	if c.GID != 0 {
		args = append(args, "--setgid", strconv.Itoa(c.GID))
	}

	if c.IPC {
		if c.IPCFile != "" {
			args = append(args, fmt.Sprintf("--ip=%s", c.IPCFile))
		} else {
			args = append(args, "--ipc")
		}
	}

	if c.Mount {
		if c.MountFile != "" {
			args = append(args, fmt.Sprintf("--mount=%s", c.MountFile))
		} else {
			args = append(args, "--mount")
		}
	}

	if c.Net {
		if c.NetFile != "" {
			args = append(args, fmt.Sprintf("--net=%s", c.NetFile))
		} else {
			args = append(args, "--net")
		}
	}

	if c.NoFork {
		args = append(args, "--no-fork")
	}

	if c.PID {
		if c.PIDFile != "" {
			args = append(args, fmt.Sprintf("--pid=%s", c.PIDFile))
		} else {
			args = append(args, "--pid")
		}
	}

	if c.PreserveCredentials {
		args = append(args, "--preserve-credentials")
	}

	if c.RootDirectory != "" {
		args = append(args, "--root", c.RootDirectory)
	}

	if c.UID != 0 {
		args = append(args, "--setuid", strconv.Itoa(c.UID))
	}

	if c.User {
		if c.UserFile != "" {
			args = append(args, fmt.Sprintf("--user=%s", c.UserFile))
		} else {
			args = append(args, "--user")
		}
	}

	if c.UTS {
		if c.UTSFile != "" {
			args = append(args, fmt.Sprintf("--uts=%s", c.UTSFile))
		} else {
			args = append(args, "--uts")
		}
	}

	if c.WorkingDirectory != "" {
		args = append(args, "--wd", c.WorkingDirectory)
	}

	cmd := exec.CommandContext(ctx, "nsenter", args...)

	return cmd, nil
}
