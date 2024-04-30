//go:build ignore
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */

#include <sys/types.h>
#include <sys/stat.h>
#include <gelf.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <time.h>
#include <arpa/inet.h>
#include <mysql.h>
#include "pktlatency.skel.h"
#include "pktlatency.h"
// #include "conn_track.h"

#define HOST "rm-bp1y5q3z1gokgd8w27o.mysql.rds.aliyuncs.com" /*MySql服务器地址*/
#define USERNAME "root" /*用户名*/
#define PASSWORD "pAssw0rd" /*数据库连接密码*/
#define DATABASE "pktlatency" /*需要连接的数据库*/

#define warn(...) fprintf(stderr, __VA_ARGS__)


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args); 
}

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}


#define warn(...) fprintf(stderr, __VA_ARGS__)

/*
 * Returns 0 on success; -1 on failure.  On sucess, returns via `path` the full
 * path to the program for pid.
 */
int get_pid_binary_path(pid_t pid, char *path, size_t path_sz)
{
	ssize_t ret;
	char proc_pid_exe[32];

	if (snprintf(proc_pid_exe, sizeof(proc_pid_exe), "/proc/%d/exe", pid)
	    >= sizeof(proc_pid_exe)) {
		warn("snprintf /proc/PID/exe failed");
		return -1;
	}
	ret = readlink(proc_pid_exe, path, path_sz);
	if (ret < 0) {
		warn("No such pid %d\n", pid);
		return -1;
	}
	if (ret >= path_sz) {
		warn("readlink truncation");
		return -1;
	}
	path[ret] = '\0';

	return 0;
}

/*
 * Returns 0 on success; -1 on failure.  On success, returns via `path` the full
 * path to a library matching the name `lib` that is loaded into pid's address
 * space.
 */
int get_pid_lib_path(pid_t pid, const char *lib, char *path, size_t path_sz)
{
	FILE *maps;
	char *p;
	char proc_pid_maps[32];
	char line_buf[1024];
	char path_buf[1024];

	if (snprintf(proc_pid_maps, sizeof(proc_pid_maps), "/proc/%d/maps", pid)
	    >= sizeof(proc_pid_maps)) {
		warn("snprintf /proc/PID/maps failed");
		return -1;
	}
	maps = fopen(proc_pid_maps, "r");
	if (!maps) {
		warn("No such pid %d\n", pid);
		return -1;
	}
	while (fgets(line_buf, sizeof(line_buf), maps)) {
		if (sscanf(line_buf, "%*x-%*x %*s %*x %*s %*u %s", path_buf) != 1)
			continue;
		/* e.g. /usr/lib/x86_64-linux-gnu/libc-2.31.so */
		p = strrchr(path_buf, '/');
		if (!p)
			continue;
		if (strncmp(p, "/lib", 4))
			continue;
		p += 4;
		if (strncmp(lib, p, strlen(lib)))
			continue;
		p += strlen(lib);
		/* libraries can have - or . after the name */
		if (*p != '.' && *p != '-')
			continue;
		if (strnlen(path_buf, 1024) >= path_sz) {
			warn("path size too small\n");
			return -1;
		}
		strcpy(path, path_buf);
		fclose(maps);
		return 0;
	}

	warn("Cannot find library %s\n", lib);
	fclose(maps);
	return -1;
}

/*
 * Returns 0 on success; -1 on failure.  On success, returns via `path` the full
 * path to the program.
 */
static int which_program(const char *prog, char *path, size_t path_sz)
{
	FILE *which;
	char cmd[100];

	if (snprintf(cmd, sizeof(cmd), "which %s", prog) >= sizeof(cmd)) {
		warn("snprintf which prog failed");
		return -1;
	}
	which = popen(cmd, "r");
	if (!which) {
		warn("which failed");
		return -1;
	}
	if (!fgets(path, path_sz, which)) {
		warn("fgets which failed");
		pclose(which);
		return -1;
	}
	/* which has a \n at the end of the string */
	path[strlen(path) - 1] = '\0';
	pclose(which);
	return 0;
}

/*
 * Returns 0 on success; -1 on failure.  On success, returns via `path` the full
 * path to the binary for the given pid.
 * 1) pid == x, binary == ""    : returns the path to x's program
 * 2) pid == x, binary == "foo" : returns the path to libfoo linked in x
 * 3) pid == 0, binary == ""    : failure: need a pid or a binary
 * 4) pid == 0, binary == "bar" : returns the path to `which bar`
 *
 * For case 4), ideally we'd like to search for libbar too, but we don't support
 * that yet.
 */
int resolve_binary_path(const char *binary, pid_t pid, char *path, size_t path_sz)
{
	if (!strcmp(binary, "")) {
		if (!pid) {
			warn("Uprobes need a pid or a binary\n");
			return -1;
		}
		return get_pid_binary_path(pid, path, path_sz);
	}
	if (pid)
		return get_pid_lib_path(pid, binary, path, path_sz);

	if (which_program(binary, path, path_sz)) {
		/*
		 * If the user is tracing a program by name, we can find it.
		 * But we can't find a library by name yet.  We'd need to parse
		 * ld.so.cache or something similar.
		 */
		warn("Can't find %s (Need a PID if this is a library)\n", binary);
		return -1;
	}
	return 0;
}

/*
 * Opens an elf at `path` of kind ELF_K_ELF.  Returns NULL on failure.  On
 * success, close with close_elf(e, fd_close).
 */
Elf *open_elf(const char *path, int *fd_close)
{
	int fd;
	Elf *e;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		warn("elf init failed\n");
		return NULL;
	}
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		warn("Could not open %s\n", path);
		return NULL;
	}
	e = elf_begin(fd, ELF_C_READ, NULL);
	if (!e) {
		warn("elf_begin failed: %s\n", elf_errmsg(-1));
		close(fd);
		return NULL;
	}
	if (elf_kind(e) != ELF_K_ELF) {
		warn("elf kind %d is not ELF_K_ELF\n", elf_kind(e));
		elf_end(e);
		close(fd);
		return NULL;
	}
	*fd_close = fd;
	return e;
}

Elf *open_elf_by_fd(int fd)
{
	Elf *e;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		warn("elf init failed\n");
		return NULL;
	}
	e = elf_begin(fd, ELF_C_READ, NULL);
	if (!e) {
		warn("elf_begin failed: %s\n", elf_errmsg(-1));
		close(fd);
		return NULL;
	}
	if (elf_kind(e) != ELF_K_ELF) {
		warn("elf kind %d is not ELF_K_ELF\n", elf_kind(e));
		elf_end(e);
		close(fd);
		return NULL;
	}
	return e;
}

void close_elf(Elf *e, int fd_close)
{
	elf_end(e);
	close(fd_close);
}

/* Returns the offset of a function in the elf file `path`, or -1 on failure. */
off_t get_elf_func_offset(const char *path, const char *func)
{
	off_t ret = -1;
	int i, fd = -1;
	Elf *e;
	Elf_Scn *scn;
	Elf_Data *data;
	GElf_Ehdr ehdr;
	GElf_Shdr shdr[1];
	GElf_Phdr phdr;
	GElf_Sym sym[1];
	size_t shstrndx, nhdrs;
	char *n;

	e = open_elf(path, &fd);

	if (!gelf_getehdr(e, &ehdr))
		goto out;

	if (elf_getshdrstrndx(e, &shstrndx) != 0)
		goto out;

	scn = NULL;
	while ((scn = elf_nextscn(e, scn))) {
		if (!gelf_getshdr(scn, shdr))
			continue;
		if (!(shdr->sh_type == SHT_SYMTAB || shdr->sh_type == SHT_DYNSYM))
			continue;
		data = NULL;
		while ((data = elf_getdata(scn, data))) {
			for (i = 0; gelf_getsym(data, i, sym); i++) {
				n = elf_strptr(e, shdr->sh_link, sym->st_name);
				if (!n)
					continue;
				if (GELF_ST_TYPE(sym->st_info) != STT_FUNC)
					continue;
				if (!strcmp(n, func)) {
					ret = sym->st_value;
					goto check;
				}
			}
		}
	}

check:
	if (ehdr.e_type == ET_EXEC || ehdr.e_type == ET_DYN) {
		if (elf_getphdrnum(e, &nhdrs) != 0) {
			ret = -1;
			goto out;
		}
		for (i = 0; i < (int)nhdrs; i++) {
			if (!gelf_getphdr(e, i, &phdr))
				continue;
			if (phdr.p_type != PT_LOAD || !(phdr.p_flags & PF_X))
				continue;
			if (phdr.p_vaddr <= ret && ret < (phdr.p_vaddr + phdr.p_memsz)) {
				ret = ret - phdr.p_vaddr + phdr.p_offset;
				goto out;
			}
		}
		ret = -1;
	}
out:
	close_elf(e, fd);
	return ret;
}
static MYSQL *conn;
static int init_mysql() {
	MYSQL *_conn;
	_conn = mysql_init(NULL);
	if (!_conn) {
		fprintf(stderr, "init mysql failed\n");
		return -1;
	}
	_conn = mysql_real_connect(_conn, HOST, USERNAME, PASSWORD, DATABASE, 0, NULL, 0);
	if (!_conn) {
		fprintf(stderr, "connect mysql failed\n");
		return -1;
	}
	conn = _conn;
	mysql_set_character_set(conn,"utf8");
}

#define CHECK_FUNC_OFF(func_name, path) \
	if (func_off < 0) { \
		warn("could not find %s in %s: %d\n", func_name, path, func_off);					\
		return -1; \
	}
#define DISABLE_AUTOLOAD(prog) \
	bpf_program__set_autoload(skel->progs.prog, false); \
	bpf_program__set_autoattach(skel->progs.prog, false); 

#define NR_UPROBE 10

static int attach_uprobes(struct pktlatency_bpf *skel, struct bpf_link *links[]) {
	int err;
	char *redis_server_path = "/usr/local/bin/redis-server";

	off_t func_off = get_elf_func_offset(redis_server_path, "connSocketRead");
	// CHECK_FUNC_OFF("connSocketRead", redis_server_path)
	// links[0] = bpf_program__attach_uprobe(skel->progs.connSocketRead , false, -1, redis_server_path, func_off);
	// DISABLE_AUTOLOAD(connSocketRead)

	func_off = get_elf_func_offset(redis_server_path, "processMultibulkBuffer");
	CHECK_FUNC_OFF("processMultibulkBuffer", redis_server_path)
	links[1] = bpf_program__attach_uprobe(skel->progs.processMultibulkBuffer, false, -1, redis_server_path, func_off);
	links[2] = bpf_program__attach_uprobe(skel->progs.processMultibulkBufferReturn, true, -1, redis_server_path, func_off);
	DISABLE_AUTOLOAD(processMultibulkBuffer)
	DISABLE_AUTOLOAD(processMultibulkBufferReturn)

	func_off = get_elf_func_offset(redis_server_path, "_addReplyToBufferOrList");
	CHECK_FUNC_OFF("_addReplyToBufferOrList", redis_server_path)
	links[3] = bpf_program__attach_uprobe(skel->progs._addReplyToBufferOrList, false, -1, redis_server_path, func_off);
	links[4] = bpf_program__attach_uprobe(skel->progs._addReplyToBufferOrListReturn, true, -1, redis_server_path, func_off);
	DISABLE_AUTOLOAD(_addReplyToBufferOrList)
	DISABLE_AUTOLOAD(_addReplyToBufferOrListReturn)

	return 0;
}

static uint64_t launch_epoch_time;
static void init_time() {
	struct timespec timestamp = { 0, 0 };
	clock_gettime(CLOCK_REALTIME, &timestamp);// 当前时间
	uint64_t now_epoch_time = (uint64_t)timestamp.tv_sec * 1000000000 + timestamp.tv_nsec;
	fprintf(stderr, "real time: %ld, seconds: %ld, nano:  %ld\n", now_epoch_time, timestamp.tv_sec, timestamp.tv_nsec);
	
	clock_gettime(CLOCK_MONOTONIC, &timestamp);
	uint64_t machine_running_duration = (uint64_t)timestamp.tv_sec * 1000000000 + timestamp.tv_nsec;
	fprintf(stderr, "mono time: %ld\n", machine_running_duration);

	launch_epoch_time = now_epoch_time - machine_running_duration;
	fprintf(stderr, "machine start time: %ld\n", launch_epoch_time);
}
// 抽象出来的函数，用于打印当前日期、时间、微秒和纳秒  
size_t print_timestamp_with_nanoseconds(long long nanoseconds, char* buffer) {
	uint64_t current_epoch_nano = launch_epoch_time + nanoseconds;
	uint64_t current_epoch_seconds = current_epoch_nano / 1000000000;
	struct tm *timeinfo = localtime(&current_epoch_seconds);
	char _buf[30] = {0};
	strftime(_buf, sizeof(_buf), "%Y-%m-%d %H:%M:%S", timeinfo);
	sprintf(buffer, "%s.%09ld", _buf, current_epoch_nano % 1000000000);
	printf("Formatted time: %s.%09ld\n", buffer, current_epoch_nano % 1000000000);
	return current_epoch_nano;
} 
void format_nanotime(uint64_t nanoseconds) {
    time_t seconds = nanoseconds / 1000000000;
    long milliseconds = (nanoseconds % 1000000000) / 1000000;

    struct tm *timeinfo;
    char buffer[80];

    timeinfo = localtime(&seconds);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);

    printf("Formatted time: %s.%03ld, origin: %ld\n", buffer, milliseconds, nanoseconds);
}
void intToIp(unsigned int ipInt, char *ipStr) {
	ipInt = ntohl(ipInt);
    sprintf(ipStr, "%u.%u.%u.%u",
            (ipInt >> 24) & 0xFF,
            (ipInt >> 16) & 0xFF,
            (ipInt >> 8) & 0xFF,
            ipInt & 0xFF);
}
static int handle__kern_event(void *ctx, void *data, size_t data_sz)
{
	// const struct kern_evt *e = data;
	
	// char buffer[80] = {0};
	// uint64_t nanos = print_timestamp_with_nanoseconds(e->ts, buffer);
	// // format_nanotime(e->ts);
	// struct sock_key sock = e->sock;
    // char sip_str[INET_ADDRSTRLEN];
    // char dip_str[INET_ADDRSTRLEN];
	// intToIp(sock.sip, sip_str);
	// intToIp(sock.dip, dip_str);
	// fprintf(stderr,"kern evt %s:%d => %s:%d | ", sip_str, sock.sport, dip_str, sock.dport);
	// fprintf(stderr,"func_name:%s|%d, seq: %u, len: %u\n", e->func_name, e->step, e->seq, e->len);

	// if (e->len <= 0) {
	// 	return 0;
	// }

	// char sql[1024];
	// bool isDirectIn = e->step >= kNetDevIn;
	// sprintf(sql, "insert into records (lip,rip,lport,rport,seconds,nanoseconds,direct,seq,len,func_name,format_date) values (%ld,%ld,%ld,%ld,%ld,%ld,%ld,%u,%u,'%s','%s') ",
	// 	e->sock.sip,
	// 	e->sock.dip, e->sock.sport, e->sock.dport, nanos /1000000, nanos, e->step >= kNetDevIn, e->seq, e->len,e->func_name, buffer);
	// int err = mysql_query(conn, sql) ;
	// if (err) {
	// 	fprintf(stderr, "mysql insert err! : %d, sql:%s\n", err,sql);
	// }
	return 0;
}

struct pktlatency_bpf *skel;
static int handle__data_event(void *ctx, void *data, size_t data_sz) {
	// int err;

	// struct data_evt* evt = (struct data_evt*)data;
	// add_data_evt_to_ct(evt);

	// uint64_t conn_key = (uint64_t)evt->attr.conn_id.upid.pid << 32 | (uint32_t)evt->attr.conn_id.fd;
	// struct conn_info_t *conn_info = malloc(sizeof(struct conn_info_t));
	// if (!conn_info) {
	// 	return -1;
	// }
	// err = bpf_map__lookup_elem(skel->maps.conn_info_map, &conn_key, sizeof(uint64_t), conn_info, sizeof(struct conn_info_t), 0);
	// if (err) {
	// 	free(conn_info);
	// 	return -1;
	// }
	// format_nanotime(evt->attr.ts);
	// fprintf(stderr,"data evt %d:%d %s %d:%d | ", conn_info->laddr.in4.sin_addr.s_addr, conn_info->laddr.in4.sin_port, 
	// 	evt->attr.direct == kEgress ? "=>" : "<=",
	// 	conn_info->raddr.in4.sin_addr.s_addr, ntohs(conn_info->raddr.in4.sin_port));
	// fprintf(stderr,"func_name:%u, seq: %u, len: %u, data_len:%u\n", evt->attr.fn, evt->attr.seq, evt->attr.origin_len,
	// evt->attr.data_len);
	
	// free(conn_info);
	return 0;
}

int main(int argc, char **argv)
{
	init_time();
	init_mysql();
	int err;
	unsigned int ifindex;
	struct bpf_link *links[NR_UPROBE] = {}; 

	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	err = setrlimit(RLIMIT_MEMLOCK, &rlim_new);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open load and verify BPF application */
	skel = pktlatency_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
      	goto cleanup;
	}
	// init_conn_tracks();

	struct ring_buffer *rb = NULL, *data_rb = NULL;
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle__kern_event, NULL, NULL);
	data_rb = ring_buffer__new(bpf_map__fd(skel->maps.conn_evt_rb), handle__data_event, NULL, NULL);
	if (!rb || !data_rb) {
      err = -1;
      fprintf(stderr, "Failed to create ring buffer\n");
      goto cleanup;
    }

	// err = attach_uprobes(skel, links);
	// if (err) {
	// 	fprintf(stderr, "Failed to attach BPF uprobes\n");
	// 	goto cleanup;
	// }
	
	/* Attach tracepoint handler */

	err = pktlatency_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	// attache xdp
	ifindex = if_nametoindex("eth0");
	int prog_id = bpf_program__fd(skel->progs.xdp_proxy);
	LIBBPF_OPTS(bpf_xdp_attach_opts, attach_opts);
	unsigned int xdp_flags =  XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
	err = bpf_xdp_attach(ifindex, prog_id, xdp_flags, &attach_opts);
	if (err) {
		fprintf(stderr, "Failed to bpf_xdp_attach: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	while (!stop) {
		// fprintf(stderr, ".");
		// sleep(1);
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
		// err = ring_buffer__poll(data_rb, 100 /* timeout, ms */);
		// if (err < 0) {
		// 	printf("Error polling ring buffer: %d\n", err);
		// 	break;
		// }
	}

cleanup:
	for (int idx = 0; idx < NR_UPROBE; idx++) {
		err = bpf_link__destroy(links[idx]);
		if (err ) {
			fprintf(stderr, "link destroy err: %d\n", err);
		}
	}
	pktlatency_bpf__destroy(skel);
	bpf_xdp_detach(ifindex, xdp_flags, &attach_opts);
	// destroy_conn_tracks();
	mysql_close(conn);
	return -err;
}
