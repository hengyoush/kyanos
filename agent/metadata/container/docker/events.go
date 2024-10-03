package docker

type Action string

const (
	ActionCreate Action = "create"
	ActionStart  Action = "start"

	// ActionExecCreate is the prefix used for exec_create events. These
	// event-actions are commonly followed by a colon and space (": "),
	// and the command that's defined for the exec, for example:
	//
	//	exec_create: /bin/sh -c 'echo hello'
	//
	// This is far from ideal; it's a compromise to allow filtering and
	// to preserve backward-compatibility.
	ActionExecCreate Action = "exec_create"
	// ActionExecStart is the prefix used for exec_create events. These
	// event-actions are commonly followed by a colon and space (": "),
	// and the command that's defined for the exec, for example:
	//
	//	exec_start: /bin/sh -c 'echo hello'
	//
	// This is far from ideal; it's a compromise to allow filtering and
	// to preserve backward-compatibility.
	ActionExecStart Action = "exec_start"
)
