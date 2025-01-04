# Debug Tips

## Build Related

Note that every time you modify the eBPF-related code, you need to use
`make build-bpf` to regenerate some bpf-related code, and then use `make` to
build or debug in the IDE.

Use `kyanos-debug` to build binary files with debug information for better
debugging.

```sh
make kyanos-debug
```

## Log Related

Start kyanos with logging enabled. Logs are divided into several modules that
can be enabled separately. Level 5 is the debug level, and the default is the
warn level. The following are the log options for each module:

| Parameter             | Meaning                                                                                |
| --------------------- | -------------------------------------------------------------------------------------- |
| --agent-log-level     | Specify the log level for the agent module, mainly related to Agent startup logs       |
| --bpf-event-log-level | Specify the log level for bpf events, logs related to kernel and syscall layer events  |
| --conntrack-log-level | Specify the log level for the conntrack module, logs related to connection events      |
| --protocol-log-level  | Specify the log level for the protocol module, mainly related to protocol parsing logs |
| --uprobe-log-level    | Specify the log level for the uprobe module, mainly related to ssl probe logs          |

For example, if you are debugging the protocol parsing part of the code, it is
recommended to add:
`--bpf-event-log-level 5 --conntrack-log-level 5 --protocol-log-level 5`.

If you encounter a situation where the eBPF code fails to load, you can add
`--agent-log-level 5` to print some logs during Agent startup.

Logs are output to /tmp by default. Adding the `--debug-output` option allows
logs to be output to standard output, and the tables displayed by the TUI will
not be shown. All captured requests will be directly output to the console:

```
WARN[0023] [ Request ]
GET /health HTTP/1.1
Host: :8080
User-Agent: Go-http-client/1.1
Accept-Encoding: gzip

[ Response ]
HTTP/1.1 200 OK
Date: Wed, 01 Jan 2025 16:20:20 GMT
Content-Length: 2
Content-Type: text/plain; charset=utf-8

OK

[conn] [pid=2252][local addr]=127.0.0.1:8080 [remote addr]=127.0.0.1:38664 [side]=server [ssl]=false
[total duration] = 0.423(ms)(start=2025-01-02 00:20:20.095, end=2025-01-02 00:20:20.095)
[read from sockbuf]=0.296(ms)
[process internal duration]=0.078(ms)
[syscall] [read count]=1 [read bytes]=92 [write count]=1 [write bytes]=118
```

> [!TIP]
>
> When debugging protocol parsing related code, you can use:
> `--bpf-event-log-level 5 --conntrack-log-level 5 --protocol-log-level 5 --debug-output`
> This option is generally sufficient.

## IDE Related

Open the project directly in VSCODE, and add the following configuration to
.vscode/launch.json:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Launch file",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "program": "${workspaceFolder}",
      "args": ["watch", "--debug-output"]
    }
  ]
}
```

Make sure to add the `--debug-output` parameter.

## Source Code Structure

```
> agent
  > analysis (aggregation analysis module, used by the stat command)
  > conn (connection tracking module)
  > protocol (protocol parsing module)
  > render (TUI rendering module)
  > uprobe (uprobe related, mainly ssl probe)
> bpf
  > loader (bpf program loading logic)
  pktlatency.bpf.go (kernel core code, including syscall and kernel event reporting logic)
  gotls.bpf.go (gotls probe related)
  protocol_inference.h (protocol inference related)
  openssl* (openssl related)
> cmd (command line related)
> common (some utility classes)
> docs (documentation based on vitepress)
```
