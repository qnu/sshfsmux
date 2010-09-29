/****************************************************************************
 * SSHFS Mutiplex Filesystem
 * Copyright (C) 2008,2009,2010  Nan Dun <dunnan@yl.is.s.u-tokyo.ac.jp>
 * Department of Computer Science, The University of Tokyo
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 ***************************************************************************/

/*
 * sshfsm.c
 * Mount multiple remote hosts via SSH channel to local directory
 */

#define _GNU_SOURCE /* avoid implicit declaration of *pt* functions */
#include "config.h"

#ifdef linux
#define _XOPEN_SOURCE 500 /* for pread()/pwrite() */
#endif

#include <fuse.h>
#include <fuse_opt.h>
#include <fuse_lowlevel.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <semaphore.h>
#include <pthread.h>
#include <netdb.h>
#include <signal.h>
#include <pwd.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <glib.h>

#include "cache.h"

#if GLIB_CHECK_VERSION(2, 16, 0)
#define G_HASH_TABLE_HAS_ITER
#endif

#ifndef MAP_LOCKED
#define MAP_LOCKED 0
#endif

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif

#define SSH_FXP_INIT                1
#define SSH_FXP_VERSION             2
#define SSH_FXP_OPEN                3
#define SSH_FXP_CLOSE               4
#define SSH_FXP_READ                5
#define SSH_FXP_WRITE               6
#define SSH_FXP_LSTAT               7
#define SSH_FXP_FSTAT               8
#define SSH_FXP_SETSTAT             9
#define SSH_FXP_FSETSTAT           10
#define SSH_FXP_OPENDIR            11
#define SSH_FXP_READDIR            12
#define SSH_FXP_REMOVE             13
#define SSH_FXP_MKDIR              14
#define SSH_FXP_RMDIR              15
#define SSH_FXP_REALPATH           16
#define SSH_FXP_STAT               17
#define SSH_FXP_RENAME             18
#define SSH_FXP_READLINK           19
#define SSH_FXP_SYMLINK            20
#define SSH_FXP_STATUS            101
#define SSH_FXP_HANDLE            102
#define SSH_FXP_DATA              103
#define SSH_FXP_NAME              104
#define SSH_FXP_ATTRS             105
#define SSH_FXP_EXTENDED          200
#define SSH_FXP_EXTENDED_REPLY    201

#define SSH_FILEXFER_ATTR_SIZE          0x00000001
#define SSH_FILEXFER_ATTR_UIDGID        0x00000002
#define SSH_FILEXFER_ATTR_PERMISSIONS   0x00000004
#define SSH_FILEXFER_ATTR_ACMODTIME     0x00000008
#define SSH_FILEXFER_ATTR_EXTENDED      0x80000000

#define SSH_FX_OK                       0
#define SSH_FX_EOF                      1
#define SSH_FX_NO_SUCH_FILE             2
#define SSH_FX_PERMISSION_DENIED        3
#define SSH_FX_FAILURE                  4
#define SSH_FX_BAD_MESSAGE              5
#define SSH_FX_NO_CONNECTION            6
#define SSH_FX_CONNECTION_LOST          7
#define SSH_FX_OP_UNSUPPORTED           8

#define SSH_FXF_READ            0x00000001
#define SSH_FXF_WRITE           0x00000002
#define SSH_FXF_APPEND          0x00000004
#define SSH_FXF_CREAT           0x00000008
#define SSH_FXF_TRUNC           0x00000010
#define SSH_FXF_EXCL            0x00000020

/* statvfs@openssh.com f_flag flags */
#define SSH2_FXE_STATVFS_ST_RDONLY	0x00000001
#define SSH2_FXE_STATVFS_ST_NOSUID	0x00000002

#define SFTP_EXT_POSIX_RENAME "posix-rename@openssh.com"
#define SFTP_EXT_STATVFS "statvfs@openssh.com"

/* 
 * inaddr piggybacking flags
 * 0x5285------------LLU: in_addr flag
 * 0x----XXXX--------LLU: hops of in_addr piggybacking
 * 0x--------XXXXXXXXLLU: in_addr (ip address)
 */
#define INADDR_FLAG 0x5285000000000000LLU
#define INADDR_MASK 0xffff000000000000LLU
#define INADDR_HOPS 0x0000ffff00000000LLU
#define INADDR_ADDR 0x00000000ffffffffLLU

#define PROTO_VERSION 3

#define MY_EOF 1

#define MAX_REPLY_LEN (1 << 17)

#define RENAME_TEMP_CHARS 8

#define SFTP_SERVER_PATH "/usr/lib/sftp-server"

#define SSHNODELAY_SO "sshnodelay.so"

#define MAX_PATH    1024
#define MAX_BUF_LEN 1024

#define MAX_REQ_SIZE 65536


struct buffer {
	uint8_t *p;
	size_t len;
	size_t size;
};

struct list_head {
	struct list_head *prev;
	struct list_head *next;
};

struct request;
typedef void (*request_func)(struct request *);

struct request {
	unsigned int want_reply;
	sem_t ready;
	uint8_t reply_type;
	int replied;
	int error;
	struct buffer reply;
	struct timeval start;
	void *data;
	request_func end_func;
	size_t len;
	struct list_head list;
};

struct read_chunk {
	sem_t ready;
	off_t offset;
	size_t size;
	struct buffer data;
	int refs;
	int res;
	long modifver;
};

struct tree_node_data {
	char *dirname;
	GPtrArray *servarr;
};
typedef struct tree_node_data * ndata_t;

struct serv {
	char *hostname;
	struct in_addr inaddr;
	char *basepath;
	int local;
	int rank;
	int version;
	int connver;
	int modifver;
	int fd;
	int ptyfd;
	int ptyslavefd;
	unsigned remote_uid;
	int remote_uid_detected;
	GHashTable *reqtab;
	pthread_t thread_id;
	pthread_mutex_t lock;
	pthread_mutex_t	lock_write;
	int processing_thread_started;
	unsigned outstanding_len;
	pthread_cond_t outstanding_cond;
	uint32_t idctr;
	int is_forward;
	int forward_refs;
	time_t forward_valid;
	
	/* statistics */
	uint64_t bytes_sent;
	uint64_t bytes_received;
	uint64_t num_sent;
	uint64_t num_received;
	unsigned int min_rtt;
	unsigned int max_rtt;
	uint64_t total_rtt;
	unsigned int num_connect;
};
typedef struct serv * serv_t;

struct sshfsm_file {
	struct buffer handle;
	struct list_head write_reqs;
	pthread_cond_t write_finished;
	int write_error;
	struct read_chunk *readahead;
	off_t next_pos;
	int is_seq;
	int connver;
	int modifver;
	int refs;
	serv_t serv;
	int local_fd;
};

struct sshfsm {
	char *directport;
	char *ssh_command;
	char *sftp_server;
	struct fuse_args ssh_args;
	char *workarounds;
	int rename_workaround;
	int nodelay_workaround;
	int nodelayserv_workaround;
	int truncate_workaround;
	int buflimit_workaround;
	int transform_symlinks;
	int follow_symlinks;
	int no_check_root;
	int detect_uid;
	unsigned max_read;
	unsigned max_write;
	unsigned ssh_ver;
	int sync_write;
	int sync_read;
	int debug;
	int foreground;
	int reconnect;
	int delay_connect;
	unsigned int randseed;
	unsigned local_uid;
	unsigned blksize;
	char *progname;
	unsigned max_outstanding_len;
	int password_stdin;
	char *password;
	int ext_posix_rename;
	int ext_statvfs;
	mode_t mnt_mode;
	int sftp_proxy;
	int sftp_proxy_lockfd;
	int port;
	int backlog;
	int sndbuf;
	int rcvbuf;
	char *psk_path;
	char *sftp_local_server;
	int inaddr_ino;
	unsigned int inaddr_nth;
	char *forward_io;
	unsigned forward_timeout;
	GPtrArray *serv_arr;
	GPtrArray *fwd_serv_arr;
	time_t fwd_serv_arr_last_cleaned;
	GNode *tree;
	pthread_mutex_t lock_serv_arr;

	/* statistics */
	uint64_t bytes_sent;
	uint64_t bytes_received;
	uint64_t num_sent;
	uint64_t num_received;
	unsigned int min_rtt;
	unsigned int max_rtt;
	uint64_t total_rtt;
	unsigned int num_connect;

	/* runtime and debug */
	pid_t pid;
	uid_t uid;
	gid_t gid;
	char *username;
	char *userhome;
	char *config_dir;
	char *session_dir;
	char *mountpoint;
	FILE *errlog;
	int dump;
};

static struct sshfsm sshfsm;

static const char *ssh_opts[] = {
	"AddressFamily",
	"BatchMode",
	"BindAddress",
	"ChallengeResponseAuthentication",
	"CheckHostIP",
	"Cipher",
	"Ciphers",
	"Compression",
	"CompressionLevel",
	"ConnectionAttempts",
	"ConnectTimeout",
	"ControlMaster",
	"ControlPath",
	"GlobalKnownHostsFile",
	"GSSAPIAuthentication",
	"GSSAPIDelegateCredentials",
	"HostbasedAuthentication",
	"HostKeyAlgorithms",
	"HostKeyAlias",
	"HostName",
	"IdentitiesOnly",
	"IdentityFile",
	"KbdInteractiveAuthentication",
	"KbdInteractiveDevices",
	"LocalCommand",
	"LogLevel",
	"MACs",
	"NoHostAuthenticationForLocalhost",
	"NumberOfPasswordPrompts",
	"PasswordAuthentication",
	"Port",
	"PreferredAuthentications",
	"ProxyCommand",
	"PubkeyAuthentication",
	"RekeyLimit",
	"RhostsRSAAuthentication",
	"RSAAuthentication",
	"ServerAliveCountMax",
	"ServerAliveInterval",
	"SmartcardDevice",
	"StrictHostKeyChecking",
	"TCPKeepAlive",
	"UsePrivilegedPort",
	"UserKnownHostsFile",
	"VerifyHostKeyDNS",
	NULL,
};

enum {
	KEY_PORT,
	KEY_COMPRESS,
	KEY_HELP,
	KEY_VERSION,
	KEY_FOREGROUND,
	KEY_CONFIGFILE,
	KEY_DAEMON,
	KEY_LOCALSRV,
};

#define SSHFSM_OPT(t, p, v) { t, offsetof(struct sshfsm, p), v }

static struct fuse_opt sshfsm_opts[] = {
	SSHFSM_OPT("directport=%s",     directport, 0),
	SSHFSM_OPT("ssh_command=%s",    ssh_command, 0),
	SSHFSM_OPT("sftp_server=%s",    sftp_server, 0),
	SSHFSM_OPT("backlog=%u",        backlog, 0),
	SSHFSM_OPT("psk=%s",            psk_path, 0),
	SSHFSM_OPT("sndbuf=%u",         sndbuf, 0),
	SSHFSM_OPT("rcvbuf=%u",         rcvbuf, 0),
	SSHFSM_OPT("max_read=%u",       max_read, 0),
	SSHFSM_OPT("max_write=%u",      max_write, 0),
	SSHFSM_OPT("ssh_protocol=%u",   ssh_ver, 0),
	SSHFSM_OPT("-1",                ssh_ver, 1),
	SSHFSM_OPT("workaround=%s",     workarounds, 0),
	SSHFSM_OPT("idmap=none",        detect_uid, 0),
	SSHFSM_OPT("idmap=user",        detect_uid, 1),
	SSHFSM_OPT("sshfsm_sync",       sync_write, 1),
	SSHFSM_OPT("no_readahead",      sync_read, 1),
	SSHFSM_OPT("sshfsm_debug",      debug, 1),
	SSHFSM_OPT("reconnect",         reconnect, 1),
	SSHFSM_OPT("transform_symlinks", transform_symlinks, 1),
	SSHFSM_OPT("follow_symlinks",   follow_symlinks, 1),
	SSHFSM_OPT("no_check_root",     no_check_root, 1),
	SSHFSM_OPT("password_stdin",    password_stdin, 1),
	SSHFSM_OPT("delay_connect",     delay_connect, 1),
	SSHFSM_OPT("session_dir=%s",    session_dir, 0),
	SSHFSM_OPT("dump",              dump, 1),
	SSHFSM_OPT("inaddr_ino",        inaddr_ino, 1),
	SSHFSM_OPT("inaddr_nth=%u",     inaddr_nth, 0),
	SSHFSM_OPT("forward_io=%s",   	forward_io, 0),
	SSHFSM_OPT("forward_timeout=%u",forward_timeout, 0),
	
	/* Append a space if the option takes an argument */
	FUSE_OPT_KEY("-p ",             KEY_PORT),
	FUSE_OPT_KEY("-C",              KEY_COMPRESS),
	FUSE_OPT_KEY("-V",              KEY_VERSION),
	FUSE_OPT_KEY("--version",       KEY_VERSION),
	FUSE_OPT_KEY("-h",              KEY_HELP),
	FUSE_OPT_KEY("--help",          KEY_HELP),
	FUSE_OPT_KEY("debug",           KEY_FOREGROUND),
	FUSE_OPT_KEY("-d",              KEY_FOREGROUND),
	FUSE_OPT_KEY("-f",              KEY_FOREGROUND),
	FUSE_OPT_KEY("-F ",             KEY_CONFIGFILE),
	FUSE_OPT_KEY("-D",              KEY_DAEMON),
	FUSE_OPT_KEY("-P ",             KEY_LOCALSRV),
	FUSE_OPT_END
};

static struct fuse_opt workaround_opts[] = {
	SSHFSM_OPT("none",       rename_workaround, 0),
	SSHFSM_OPT("none",       nodelay_workaround, 0),
	SSHFSM_OPT("none",       nodelayserv_workaround, 0),
	SSHFSM_OPT("none",       truncate_workaround, 0),
	SSHFSM_OPT("none",       buflimit_workaround, 0),
	SSHFSM_OPT("all",        rename_workaround, 1),
	SSHFSM_OPT("all",        nodelay_workaround, 1),
	SSHFSM_OPT("all",        nodelayserv_workaround, 1),
	SSHFSM_OPT("all",        truncate_workaround, 1),
	SSHFSM_OPT("all",        buflimit_workaround, 1),
	SSHFSM_OPT("rename",     rename_workaround, 1),
	SSHFSM_OPT("norename",   rename_workaround, 0),
	SSHFSM_OPT("nodelay",    nodelay_workaround, 1),
	SSHFSM_OPT("nonodelay",  nodelay_workaround, 0),
	SSHFSM_OPT("nodelayserv", nodelayserv_workaround, 1),
	SSHFSM_OPT("nonodelayserv", nodelayserv_workaround, 0),
	SSHFSM_OPT("truncate",   truncate_workaround, 1),
	SSHFSM_OPT("notruncate", truncate_workaround, 0),
	SSHFSM_OPT("buflimit",   buflimit_workaround, 1),
	SSHFSM_OPT("nobuflimit", buflimit_workaround, 0),
	FUSE_OPT_END
};

static void error2(int errnum, const char *format, ...)
{
	va_list argv;
	fflush(stdout);
	fprintf(stderr, "error: ");
	va_start(argv, format);
	vfprintf(stderr, format, argv);
	va_end(argv);
	fprintf(stderr, ": %s\n", strerror(errnum));
}

static void perror2(const char *format, ...)
{
	va_list argv;
	fflush(stdout);
	fprintf(stderr, "error: ");
	va_start(argv, format);
	vfprintf(stderr, format, argv);
	va_end(argv);
	fprintf(stderr, ": %s\n", strerror(errno));
}

/* forward all function declarations here */
static int sftp_local_connect(serv_t);
static int sftp_proxy_connect(serv_t, char *);

static int serv_arr_init(void);
static void serv_arr_destroy(void);
static int tree_init(void);
static void tree_destroy(void);
static inline void tree_print(void);
static void fwd_serv_arr_cleanup(time_t timeout);

static char * find_base_path(char *);

#define error3(format, ...) \
	fprintf(stderr, "error: "format"\n", ## __VA_ARGS__)
#define message(format, ...) \
	fprintf(stderr, "sshfsm: "format"\n", ## __VA_ARGS__)
#define warning(format, ...) \
	fprintf(stderr, "warning: "format"\n", ## __VA_ARGS__)
#define fatal(status, format, ...) \
	{perror2(format, ## __VA_ARGS__); exit(status);}
#define log(format, ...) \
	fprintf(stderr, "log: "format"\n", ## __VA_ARGS__)
#define debug(format, ...) \
	if (sshfsm.debug) {fprintf(stderr, "debug: "format"\n", ## __VA_ARGS__);}
#define get_ino_hops(ino) ((ino & INADDR_HOPS) >> 32)

#define serv_num sshfsm.serv_arr->len
#define serv_0 g_ptr_array_index(sshfsm.serv_arr, 0)
#define serv_i(idx) g_ptr_array_index(sshfsm.serv_arr, idx)
#define serv_add_path(serv, path) \
	g_strdup_printf("%s%s", serv->basepath, path[1] ? path+1 : ".")

static inline char * g_strdup_and_free(char *s)
{
	char *t = g_strdup(s);
	free(s);
	return t;
}

static int get_currtime_str(char *buf, size_t buflen, const char *format)
{
	time_t t;
	struct tm *tm;

	t = time(NULL);
	tm = localtime(&t);
	if (tm == NULL) {
		perror2("failed to get localtime");
		return 0;
	}

	return strftime(buf, buflen, format, tm);
}

static char * get_file(const char *path, size_t *len, int escape)
{
	FILE *fp;
	char *buf;
	size_t i, buflen;
	int c;
	
	fp = fopen(path, "rb");
	if (fp == NULL) {
		perror2("failed to open file \"%s\"", path);
		return NULL;
	}
	
	i = 0; 
	buflen = MAX_BUF_LEN;
	buf = g_malloc0(MAX_BUF_LEN);
	while ((c = getc(fp)) != EOF) {
		buf[i++] = c;
		if (i >= buflen) {
			buflen += MAX_BUF_LEN;
			buf = g_realloc(buf, buflen);
		}
	}
	fclose(fp);

	buf[i] = '\0';
	*len = i;

	if (escape) {
		for (i = 0; i < *len; i++) {
			if (buf[i] == '\0' || buf[i] == '\n')
				buf[i] = ' ';
		}
		buf[*len - 1] = '\0';
	}
	
	return buf;
}

#if 0
static int get_cmd_output(const char *cmd, char *buf, size_t buflen)
{
	FILE *fp;
	fp = popen(cmd, "r");
	if (fp == NULL) {
		error3("failed to popen");
		return -1;
	}
	while (fgets(buf, buflen - 1, fp) != NULL);
	pclose(fp);
	return 0;
}
#endif

static void set_nodelay(int sockfd)
{
	int opt;
	socklen_t optlen;

	optlen = sizeof(opt);
	if (getsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		perror("warning: failed to get TCP_NODELAY");
		return;
	}

	if (opt == 1)
		return;

	opt = 1;
	if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &opt, 
		sizeof(opt)) == -1) {
		perror("warning: failed to get TCP_NODELAY");
	}
}

static const char *type_name(uint8_t type)
{
	switch(type) {
	case SSH_FXP_INIT:           return "INIT";
	case SSH_FXP_VERSION:        return "VERSION";
	case SSH_FXP_OPEN:           return "OPEN";
	case SSH_FXP_CLOSE:          return "CLOSE";
	case SSH_FXP_READ:           return "READ";
	case SSH_FXP_WRITE:          return "WRITE";
	case SSH_FXP_LSTAT:          return "LSTAT";
	case SSH_FXP_FSTAT:          return "FSTAT";
	case SSH_FXP_SETSTAT:        return "SETSTAT";
	case SSH_FXP_FSETSTAT:       return "FSETSTAT";
	case SSH_FXP_OPENDIR:        return "OPENDIR";
	case SSH_FXP_READDIR:        return "READDIR";
	case SSH_FXP_REMOVE:         return "REMOVE";
	case SSH_FXP_MKDIR:          return "MKDIR";
	case SSH_FXP_RMDIR:          return "RMDIR";
	case SSH_FXP_REALPATH:       return "REALPATH";
	case SSH_FXP_STAT:           return "STAT";
	case SSH_FXP_RENAME:         return "RENAME";
	case SSH_FXP_READLINK:       return "READLINK";
	case SSH_FXP_SYMLINK:        return "SYMLINK";
	case SSH_FXP_STATUS:         return "STATUS";
	case SSH_FXP_HANDLE:         return "HANDLE";
	case SSH_FXP_DATA:           return "DATA";
	case SSH_FXP_NAME:           return "NAME";
	case SSH_FXP_ATTRS:          return "ATTRS";
	case SSH_FXP_EXTENDED:       return "EXTENDED";
	case SSH_FXP_EXTENDED_REPLY: return "EXTENDED_REPLY";
	default:                     return "???";
	}
}

#define container_of(ptr, type, member) ({				\
			const typeof( ((type *)0)->member ) *__mptr = (ptr); \
			(type *)( (char *)__mptr - offsetof(type,member) );})

#define list_entry(ptr, type, member)		\
	container_of(ptr, type, member)

static void list_init(struct list_head *head)
{
	head->next = head;
	head->prev = head;
}

static void list_add(struct list_head *new, struct list_head *head)
{
	struct list_head *prev = head;
	struct list_head *next = head->next;
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static void list_del(struct list_head *entry)
{
	struct list_head *prev = entry->prev;
	struct list_head *next = entry->next;
	next->prev = prev;
	prev->next = next;

}

static int list_empty(const struct list_head *head)
{
	return head->next == head;
}

/*
 * SFTP Stuff
 */
static inline void buf_init(struct buffer *buf, size_t size)
{
	if (size) {
		buf->p = (uint8_t *) malloc(size);
		if (!buf->p) {
			perror2("memory allocation failed");
			abort();
		}
	} else
		buf->p = NULL;
	buf->len = 0;
	buf->size = size;
}

static inline void buf_free(struct buffer *buf)
{
	free(buf->p);
}

static inline void buf_finish(struct buffer *buf)
{
	buf->len = buf->size;
}

static inline void buf_clear(struct buffer *buf)
{
	buf_free(buf);
	buf_init(buf, 0);
}

static void buf_resize(struct buffer *buf, size_t len)
{
	buf->size = (buf->len + len + 63) & ~31;
	buf->p = (uint8_t *) realloc(buf->p, buf->size);
	if (!buf->p) {
		perror2("memory allocation failed");
		abort();
	}
}

static inline void buf_check_add(struct buffer *buf, size_t len)
{
	if (buf->len + len > buf->size)
		buf_resize(buf, len);
}

#define _buf_add_mem(b, d, l)			\
	buf_check_add(b, l);			\
	memcpy(b->p + b->len, d, l);		\
	b->len += l;

static inline void buf_add_mem(struct buffer *buf, const void *data,
                               size_t len)
{
	_buf_add_mem(buf, data, len);
}

static inline void buf_add_buf(struct buffer *buf, const struct buffer *bufa)
{
	_buf_add_mem(buf, bufa->p, bufa->len);
}

static inline void buf_add_uint8(struct buffer *buf, uint8_t val)
{
	_buf_add_mem(buf, &val, 1);
}

static inline void buf_add_uint32(struct buffer *buf, uint32_t val)
{
	uint32_t nval = htonl(val);
	_buf_add_mem(buf, &nval, 4);
}

static inline void buf_add_uint64(struct buffer *buf, uint64_t val)
{
	buf_add_uint32(buf, val >> 32);
	buf_add_uint32(buf, val & 0xffffffff);
}

static inline void buf_add_data(struct buffer *buf, const struct buffer *data)
{
	buf_add_uint32(buf, data->len);
	buf_add_mem(buf, data->p, data->len);
}

static inline void buf_add_string(struct buffer *buf, const char *str)
{
	struct buffer data;
	data.p = (uint8_t *) str;
	data.len = strlen(str);
	buf_add_data(buf, &data);
}

static inline void buf_add_path(serv_t serv, struct buffer *buf, 
	const char *path)
{
	char *realpath;

	if (serv->basepath[0]) {
		if (path[1]) {
			if (serv->basepath[strlen(serv->basepath)-1] != '/')
				realpath = g_strdup_printf("%s/%s", serv->basepath, path + 1);
			else
				realpath = g_strdup_printf("%s%s", serv->basepath, path + 1);
		} else
			realpath = g_strdup(serv->basepath);
	} else {
		if (path[1])
			realpath = g_strdup(path + 1);
		else
			realpath = g_strdup(".");
	}
	buf_add_string(buf, realpath);
	g_free(realpath);
}

static int buf_check_get(struct buffer *buf, size_t len)
{
	if (buf->len + len > buf->size) {
		error3("buffer too short");
		return -1;
	} else
		return 0;
}

static inline int buf_get_mem(struct buffer *buf, void *data, size_t len)
{
	if (buf_check_get(buf, len) == -1)
		return -1;
	memcpy(data, buf->p + buf->len, len);
	buf->len += len;
	return 0;
}

static inline int buf_get_uint8(struct buffer *buf, uint8_t *val)
{
	return buf_get_mem(buf, val, 1);
}

static inline int buf_get_uint32(struct buffer *buf, uint32_t *val)
{
	uint32_t nval;
	if (buf_get_mem(buf, &nval, 4) == -1)
		return -1;
	*val = ntohl(nval);
	return 0;
}

static inline int buf_get_uint64(struct buffer *buf, uint64_t *val)
{
	uint32_t val1;
	uint32_t val2;
	if (buf_get_uint32(buf, &val1) == -1 ||
	    buf_get_uint32(buf, &val2) == -1) {
		return -1;
	}
	*val = ((uint64_t) val1 << 32) + val2;
	return 0;
}

static inline int buf_get_data(struct buffer *buf, struct buffer *data)
{
	uint32_t len;
	if (buf_get_uint32(buf, &len) == -1 || len > buf->size - buf->len)
		return -1;
	buf_init(data, len + 1);
	data->size = len;
	if (buf_get_mem(buf, data->p, data->size) == -1) {
		buf_free(data);
		return -1;
	}
	return 0;
}

static inline int buf_get_string(struct buffer *buf, char **str)
{
	struct buffer data;
	if (buf_get_data(buf, &data) == -1)
		return -1;
	data.p[data.size] = '\0';
	*str = (char *) data.p;
	return 0;
}

static int buf_get_attrs(serv_t serv, struct buffer *buf, struct stat *stbuf, 
	int *flagsp)
{
	uint32_t flags;
	uint64_t size = 0;
	uint32_t uid = 0;
	uint32_t gid = 0;
	uint32_t atime = 0;
	uint32_t mtime = 0;
	uint32_t mode = S_IFREG | 0777;
	uint64_t ino = 64;

	if (buf_get_uint32(buf, &flags) == -1)
		return -1;
	if (flagsp)
		*flagsp = flags;
	if ((flags & SSH_FILEXFER_ATTR_SIZE) &&
	    buf_get_uint64(buf, &size) == -1)
		return -1;
	if ((flags & SSH_FILEXFER_ATTR_UIDGID) &&
	    (buf_get_uint32(buf, &uid) == -1 ||
	     buf_get_uint32(buf, &gid) == -1))
		return -1;
	if ((flags & SSH_FILEXFER_ATTR_PERMISSIONS) &&
	    buf_get_uint32(buf, &mode) == -1)
		return -1;
	if ((flags & SSH_FILEXFER_ATTR_ACMODTIME)) {
		if (buf_get_uint32(buf, &atime) == -1 ||
		    buf_get_uint32(buf, &mtime) == -1)
			return -1;
	}
	if ((flags & SSH_FILEXFER_ATTR_EXTENDED)) {
		uint32_t extcount;
		unsigned i;
		if (buf_get_uint32(buf, &extcount) == -1)
			return -1;
		for (i = 0; i < extcount; i++) {
			char *type;
			if (buf_get_string(buf, &type) == -1)
				return -1;
			if (strcmp(type, "ino") == 0) {
				if (buf_get_uint64(buf, &ino) == -1)
					return -1;
			}
			free(type);
		}
	}

	/* TODO: Set local uid properly */
	if (serv->remote_uid_detected && uid == serv->remote_uid)
		uid = sshfsm.local_uid;

	memset(stbuf, 0, sizeof(struct stat));
	stbuf->st_mode = mode;
	stbuf->st_nlink = 1;
	stbuf->st_size = size;
	if (sshfsm.blksize) {
		stbuf->st_blksize = sshfsm.blksize;
		stbuf->st_blocks = ((size + sshfsm.blksize - 1) &
			~((unsigned long long) sshfsm.blksize - 1)) >> 9;
	}
	stbuf->st_uid = uid;
	stbuf->st_gid = gid;
	stbuf->st_atime = atime;
	stbuf->st_ctime = stbuf->st_mtime = mtime;
	if (sshfsm.inaddr_ino) { 
		if ((ino & INADDR_MASK) != INADDR_FLAG)
			ino = INADDR_FLAG + serv->inaddr.s_addr;
		else if (get_ino_hops(ino) <= sshfsm.inaddr_nth)
			ino = (ino & 0xffffffff00000000LLU) + serv->inaddr.s_addr;
		ino += 0x0000000100000000LLU;
	}
	stbuf->st_ino = ino;
	return 0;
}

static int buf_get_statvfs(struct buffer *buf, struct statvfs *stbuf)
{
	uint64_t bsize;
	uint64_t frsize;
	uint64_t blocks;
	uint64_t bfree;
	uint64_t bavail;
	uint64_t files;
	uint64_t ffree;
	uint64_t favail;
	uint64_t fsid;
	uint64_t flag;
	uint64_t namemax;

	if (buf_get_uint64(buf, &bsize) == -1 ||
	    buf_get_uint64(buf, &frsize) == -1 ||
	    buf_get_uint64(buf, &blocks) == -1 ||
	    buf_get_uint64(buf, &bfree) == -1 ||
	    buf_get_uint64(buf, &bavail) == -1 ||
	    buf_get_uint64(buf, &files) == -1 ||
	    buf_get_uint64(buf, &ffree) == -1 ||
	    buf_get_uint64(buf, &favail) == -1 ||
	    buf_get_uint64(buf, &fsid) == -1 ||
	    buf_get_uint64(buf, &flag) == -1 ||
	    buf_get_uint64(buf, &namemax) == -1) {
		return -1;
	}

	memset(stbuf, 0, sizeof(struct statvfs));
	stbuf->f_bsize = bsize;
	stbuf->f_frsize = frsize;
	stbuf->f_blocks = blocks;
	stbuf->f_bfree = bfree;
	stbuf->f_bavail = bavail;
	stbuf->f_files = files;
	stbuf->f_ffree = ffree;
	stbuf->f_favail = favail;
	stbuf->f_namemax = namemax;

	return 0;
}

static int buf_get_entries(serv_t serv, struct buffer *buf, 
	fuse_cache_dirh_t h, fuse_cache_dirfil_t filler)
{
	uint32_t count;
	unsigned i;

	if (buf_get_uint32(buf, &count) == -1)
		return -1;

	for (i = 0; i < count; i++) {
		int err = -1;
		char *name;
		char *longname;
		struct stat stbuf;
		if (buf_get_string(buf, &name) == -1)
			return -1;
		if (buf_get_string(buf, &longname) != -1) {
			free(longname);
			if (buf_get_attrs(serv, buf, &stbuf, NULL) != -1) {
				if (sshfsm.follow_symlinks && S_ISLNK(stbuf.st_mode))
					stbuf.st_mode = 0;
				filler(h, name, &stbuf);
				err = 0;
			}
		}
		free(name);
		if (err)
			return err;
	}
	return 0;
}

static int buf_get_entries_set(serv_t serv, struct buffer *buf,
	GHashTable *set)
{
	uint32_t count;
	unsigned i;
	struct stat *st;

	if (buf_get_uint32(buf, &count) == -1)
		return -1;

	for (i = 0; i < count; i++) {
		int err = -1;
		char *name;
		char *longname;
		struct stat stbuf;
		if (buf_get_string(buf, &name) == -1)
			return -1;
		if (buf_get_string(buf, &longname) != -1) {
			free(longname);
			if (buf_get_attrs(serv, buf, &stbuf, NULL) != -1) {
				if (sshfsm.follow_symlinks && S_ISLNK(stbuf.st_mode))
					stbuf.st_mode = 0;
				st = g_new(struct stat, 1);
				*st = stbuf;
				g_hash_table_insert(set, g_strdup(name), (gpointer) st);
				err = 0;
			}
		}
		free(name);
		if (err)
			return err;
	}
	return 0;
}

static void ssh_add_arg(const char *arg)
{
	if (fuse_opt_add_arg(&sshfsm.ssh_args, arg) == -1)
		_exit(1);
}

#ifdef SSH_NODELAY_WORKAROUND
static int do_ssh_nodelay_workaround(void)
{
	char *oldpreload = getenv("LD_PRELOAD");
	char *newpreload;
	char sopath[PATH_MAX];
	int res;

	snprintf(sopath, sizeof(sopath), "%s/%s", LIBDIR, SSHNODELAY_SO);
	res = access(sopath, R_OK);
	if (res == -1) {
		char *s;
		if (!realpath(sshfsm.progname, sopath))
			return -1;

		s = strrchr(sopath, '/');
		if (!s)
			s = sopath;
		else
			s++;

		if (s + strlen(SSHNODELAY_SO) >= sopath + sizeof(sopath))
			return -1;

		strcpy(s, SSHNODELAY_SO);
		res = access(sopath, R_OK);
		if (res == -1) {
			perror2("cannot find %s", SSHNODELAY_SO);
			return -1;
		}
	}

	newpreload = g_strdup_printf("%s%s%s",
				     oldpreload ? oldpreload : "",
				     oldpreload ? " " : "",
				     sopath);

	if (!newpreload || setenv("LD_PRELOAD", newpreload, 1) == -1) 
		warning("failed set LD_PRELOAD for ssh nodelay workaround");
	
	g_free(newpreload);
	return 0;
}
#endif

static int pty_expect_loop(serv_t serv)
{
	int res;
	char buf[256];
	const char *passwd_str = "assword:";
	int timeout = 60 * 1000; /* 1min timeout for the prompt to appear */
	int passwd_len = strlen(passwd_str);
	int len = 0;
	char c;

	while (1) {
		struct pollfd fds[2];

		fds[0].fd = serv->fd;
		fds[0].events = POLLIN;
		fds[1].fd = serv->ptyfd;
		fds[1].events = POLLIN;
		res = poll(fds, 2, timeout);
		if (res == -1) {
			perror2("faild to poll");
			return -1;
		}
		if (res == 0) {
			error3("poll: timeout waiting for prompt");
			return -1;
		}
		if (fds[0].revents) {
			/*
			 * Something happened on stdout of ssh, this
			 * either means, that we are connected, or
			 * that we are disconnected.  In any case the
			 * password doesn't matter any more.
			 */
			break;
		}

		res = read(serv->ptyfd, &c, 1);
		if (res == -1) {
			perror2("failed to read");
			return -1;
		}
		if (res == 0) {
			error3("EOF while waiting for prompt");
			return -1;
		}
		buf[len] = c;
		len++;
		if (len == passwd_len) {
			if (memcmp(buf, passwd_str, passwd_len) == 0) {
				res = write(serv->ptyfd, sshfsm.password,
				      strlen(sshfsm.password));
			}
			memmove(buf, buf + 1, passwd_len - 1);
			len--;
		}
	}

	if (!sshfsm.reconnect) {
		size_t size = getpagesize();

		memset(sshfsm.password, 0, size);
		munmap(sshfsm.password, size);
		sshfsm.password = NULL;
	}

	return 0;
}

static int pty_master(char **name)
{
	int mfd;

	mfd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
	if (mfd == -1) {
		perror2("failed to open pty");
		return -1;
	}
	if (grantpt(mfd) != 0) {
		perror2("grantpt");
		return -1;
	}
	if (unlockpt(mfd) != 0) {
		perror2("failed to unlockpt");
		return -1;
	}
	*name = ptsname(mfd);

	return mfd;
}

static void replace_arg(char **argp, const char *newarg)
{
	free(*argp);
	*argp = strdup(newarg);
	if (*argp == NULL) {
		perror2("failed to strdup");
		abort();
	}
}

static int start_ssh(serv_t serv)
{
	char *ptyname = NULL;
	int sockpair[2];
	int pid, i, res;
	struct fuse_args ssh_args = FUSE_ARGS_INIT(0, NULL);
	
	/* since we threading start_ssh, we must make ssh_args local */
	for (i = 0; i < sshfsm.ssh_args.argc; i++) {
		if (fuse_opt_add_arg(&ssh_args, sshfsm.ssh_args.argv[i]) == -1)
			return -1;
	}
	if (fuse_opt_insert_arg(&ssh_args, 1, serv->hostname) == -1)
		return -1;

	if (sshfsm.password_stdin) {
		serv->ptyfd = pty_master(&ptyname);
		if (serv->ptyfd == -1)
			return -1;

		serv->ptyslavefd = open(ptyname, O_RDWR | O_NOCTTY);
		if (serv->ptyslavefd == -1)
			return -1;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockpair) == -1) {
		perror2("failed to create socket pair");
		return -1;
	}
	serv->fd = sockpair[0];

	pid = fork();
	if (pid == -1) {
		perror2("failed to fork");
		close(sockpair[1]);
		return -1;
	} else if (pid == 0) {
		int devnull;

#ifdef SSH_NODELAY_WORKAROUND
		if (sshfsm.nodelay_workaround &&
		    do_ssh_nodelay_workaround() == -1) {
			warning("warning: ssh nodelay workaround disabled");
		}
#endif

		if (sshfsm.nodelayserv_workaround) {
			int i;
			/*
			 * Hack to work around missing TCP_NODELAY
			 * setting in sshd
			 */
			for (i = 1; i < sshfsm.ssh_args.argc; i++) {
				if (strcmp(sshfsm.ssh_args.argv[i], "-x") == 0) {
					replace_arg(&sshfsm.ssh_args.argv[i], "-X");
					break;
				}
			}
		}

		devnull = open("/dev/null", O_WRONLY);

		if (dup2(sockpair[1], 0) == -1 || dup2(sockpair[1], 1) == -1) {
			perror2("failed to redirect input/output");
			_exit(1);
		}
		if (!sshfsm.foreground && devnull != -1)
			dup2(devnull, 2);

		close(devnull);
		close(sockpair[0]);
		close(sockpair[1]);

		switch (fork()) {
			case -1:
				perror2("failed to fork");
				_exit(1);
			case 0:
				break;
			default:
				_exit(0);
		}
		res = chdir("/");

		if (sshfsm.password_stdin) {
			int sfd;

			setsid();
			sfd = open(ptyname, O_RDWR);
			if (sfd == -1) {
				perror2("failed to open \"%s\"", ptyname);
				_exit(1);
			}
			close(sfd);
			close(serv->ptyslavefd);
			close(serv->ptyfd);
		}

		if (sshfsm.debug) {
			int i;

			fprintf(stderr, "executing");
			for (i = 0; i < sshfsm.ssh_args.argc; i++)
				fprintf(stderr, " <%s>",
					sshfsm.ssh_args.argv[i]);
			fprintf(stderr, "\n");
		}

		execvp(ssh_args.argv[0], ssh_args.argv);
		perror2("failed to execute \"%s\"", sshfsm.ssh_args.argv[0]);
		_exit(1);
	}
	waitpid(pid, NULL, 0);
	close(sockpair[1]);
	fuse_opt_free_args(&ssh_args);
	return 0;
}

static int do_write(serv_t serv, struct iovec *iov, size_t count)
{
	int res;
	while (count) {
		res = writev(serv->fd, iov, count);
		if (res == -1) {
			perror2("failed to writev");
			return -1;
		} else if (res == 0) {
			error3("zero writev");
			return -1;
		}
		do {
			if ((unsigned) res < iov->iov_len) {
				iov->iov_len -= res;
				iov->iov_base += res;
				break;
			} else {
				res -= iov->iov_len;
				count --;
				iov ++;
			}
		} while(count);
	}
	return 0;
}

static uint32_t sftp_get_id(void)
{
	static uint32_t idctr;
	return idctr++;
}

static void buf_to_iov(const struct buffer *buf, struct iovec *iov)
{
	iov->iov_base = buf->p;
	iov->iov_len = buf->len;
}

static size_t iov_length(const struct iovec *iov, unsigned long nr_segs)
{
	unsigned long seg;
	size_t ret = 0;

	for (seg = 0; seg < nr_segs; seg++)
		ret += iov[seg].iov_len;
	return ret;
}

#define SFTP_MAX_IOV 3

static int sftp_send_iov(serv_t serv, uint8_t type, uint32_t id, 
	struct iovec iov[], size_t count)
{
	int res;
	struct buffer buf;
	struct iovec iovout[SFTP_MAX_IOV];
	unsigned i;
	unsigned nout = 0;

	assert(count <= SFTP_MAX_IOV - 1);
	buf_init(&buf, 9);
	buf_add_uint32(&buf, iov_length(iov, count) + 5);
	buf_add_uint8(&buf, type);
	buf_add_uint32(&buf, id);
	buf_to_iov(&buf, &iovout[nout++]);
	for (i = 0; i < count; i++)
		iovout[nout++] = iov[i];
	pthread_mutex_lock(&serv->lock_write);
	res = do_write(serv, iovout, nout);
	pthread_mutex_unlock(&serv->lock_write);
	buf_free(&buf);
	return res;
}

static int do_read(serv_t serv, struct buffer *buf)
{
	int res;
	uint8_t *p = buf->p;
	size_t size = buf->size;
	while (size) {
		res = read(serv->fd, p, size);
		if (res == -1) {
			perror2("failed to read");
			return -1;
		} else if (res == 0) {
			error3("remote host %s has disconnected", serv->hostname);
			return -1;
		}
		size -= res;
		p += res;
	}
	return 0;
}

static int sftp_read(serv_t serv, uint8_t *type, struct buffer *buf)
{
	int res;
	struct buffer buf2;
	uint32_t len;
	buf_init(&buf2, 5);
	res = do_read(serv, &buf2);
	if (res != -1) {
		if (buf_get_uint32(&buf2, &len) == -1)
			return -1;
		if (len > MAX_REPLY_LEN) {
			error3("reply len too large: %u", len);
			return -1;
		}
		if (buf_get_uint8(&buf2, type) == -1)
			return -1;
		buf_init(buf, len - 1);
		res = do_read(serv, buf);
	}
	buf_free(&buf2);
	return res;
}

static void request_free(struct request *req)
{
	buf_free(&req->reply);
	sem_destroy(&req->ready);
	g_free(req);
}

static void chunk_free(struct read_chunk *chunk)
{
	buf_free(&chunk->data);
	sem_destroy(&chunk->ready);
	g_free(chunk);
}

static void chunk_put(struct read_chunk *chunk)
{
	if (chunk) {
		chunk->refs--;
		if (!chunk->refs)
			chunk_free(chunk);
	}
}

static void chunk_put_locked(serv_t serv, struct read_chunk *chunk)
{
	pthread_mutex_lock(&serv->lock);
	chunk_put(chunk);
	pthread_mutex_unlock(&serv->lock);
}

static int clean_req(void *key_, struct request *req)
{
	(void) key_;

	req->error = -EIO;
	if (req->want_reply)
		sem_post(&req->ready);
	else {
		if (req->end_func)
			req->end_func(req);
		request_free(req);
	}
	return TRUE;
}

static int process_one_request(serv_t serv)
{
	int res;
	struct buffer buf;
	uint8_t type;
	struct request *req;
	uint32_t id;

	buf_init(&buf, 0);
	res = sftp_read(serv, &type, &buf);
	if (res == -1)
		return -1;
	if (buf_get_uint32(&buf, &id) == -1)
		return -1;

	pthread_mutex_lock(&serv->lock);
	req = (struct request *)
		g_hash_table_lookup(serv->reqtab, GUINT_TO_POINTER(id));
	if (req == NULL)
		error3("request %i not found", id);
	else {
		int was_over;

		was_over = serv->outstanding_len > sshfsm.max_outstanding_len;
		serv->outstanding_len -= req->len;
		if (was_over &&
		    serv->outstanding_len <= sshfsm.max_outstanding_len) {
			pthread_cond_broadcast(&serv->outstanding_cond);
		}
		g_hash_table_remove(serv->reqtab, GUINT_TO_POINTER(id));
	}
	pthread_mutex_unlock(&serv->lock);
	if (req != NULL) {
		if (sshfsm.debug) {
			struct timeval now;
			unsigned int difftime;
			unsigned msgsize = buf.size + 5;

			gettimeofday(&now, NULL);
			difftime = (now.tv_sec - req->start.tv_sec) * 1000;
			difftime += (now.tv_usec - req->start.tv_usec) / 1000;
			debug("  [%05i] %14s %8ubytes (%ims)", id,
			      type_name(type), msgsize, difftime);

			if (difftime < serv->min_rtt || !serv->num_received)
				serv->min_rtt = difftime;
			if (difftime > serv->max_rtt)
				serv->max_rtt = difftime;
			serv->total_rtt += difftime;
			serv->num_received++;
			serv->bytes_received += msgsize;
		}
		req->reply = buf;
		req->reply_type = type;
		req->replied = 1;
		if (req->want_reply)
			sem_post(&req->ready);
		else {
			if (req->end_func) {
				pthread_mutex_lock(&serv->lock);
				req->end_func(req);
				pthread_mutex_unlock(&serv->lock);
			}
			request_free(req);
		}
	} else
		buf_free(&buf);

	return 0;
}

static void close_conn(serv_t serv)
{
	close(serv->fd);
	serv->fd = -1;
	if (serv->ptyfd != -1) {
		close(serv->ptyfd);
		serv->ptyfd = -1;
	}
	if (serv->ptyslavefd != -1) {
		close(serv->ptyslavefd);
		serv->ptyslavefd = -1;
	}
}

static void *process_requests(void *data)
{
	serv_t *servp = (serv_t *) data;
	serv_t serv = *servp;

	while (1) {
		if (process_one_request(serv) == -1)
			break;
	}

	if (!sshfsm.reconnect) {
		/* harakiri */
		kill(getpid(), SIGTERM);
	} else {
		pthread_mutex_lock(&serv->lock);
		serv->processing_thread_started = 0;
		close_conn(serv);
		g_hash_table_foreach_remove(serv->reqtab, (GHRFunc) clean_req, NULL);
		serv->connver ++;
		pthread_mutex_unlock(&serv->lock);
	}
	g_free(data);
	return NULL;
}

static int sftp_init_reply_ok(serv_t serv, struct buffer *buf, 
	uint32_t *version)
{
	uint32_t len;
	uint8_t type;

	if (buf_get_uint32(buf, &len) == -1)
		return -1;

	if (len < 5 || len > MAX_REPLY_LEN)
		return 1;

	if (buf_get_uint8(buf, &type) == -1)
		return -1;

	if (type != SSH_FXP_VERSION)
		return 1;

	if (buf_get_uint32(buf, version) == -1)
		return -1;

	debug("Server version: %u", *version);

	if (len > 5) {
		struct buffer buf2;

		buf_init(&buf2, len - 5);
		if (do_read(serv, &buf2) == -1)
			return -1;

		do {
			char *ext;
			char *extdata;

			if (buf_get_string(&buf2, &ext) == -1 ||
			    buf_get_string(&buf2, &extdata) == -1)
				return -1;

			debug("Extension: %s <%s>", ext, extdata);

			if (strcmp(ext, SFTP_EXT_POSIX_RENAME) == 0 &&
			    strcmp(extdata, "1") == 0) {
				sshfsm.ext_posix_rename = 1;
				sshfsm.rename_workaround = 0;
			}
			if (strcmp(ext, SFTP_EXT_STATVFS) == 0 &&
			    strcmp(extdata, "2") == 0)
				sshfsm.ext_statvfs = 1;
		} while (buf2.len < buf2.size);
	}
	return 0;
}

static int sftp_find_init_reply(serv_t serv, uint32_t *version)
{
	int res;
	struct buffer buf;

	buf_init(&buf, 9);
	res = do_read(serv, &buf);
	while (res != -1) {
		struct buffer buf2;

		res = sftp_init_reply_ok(serv, &buf, version);
		if (res <= 0)
			break;

		/* Iterate over any rubbish until the version reply is found */
		debug("%c", *buf.p);
		memmove(buf.p, buf.p + 1, buf.size - 1);
		buf.len = 0;
		buf2.p = buf.p + buf.size - 1;
		buf2.size = 1;
		res = do_read(serv, &buf2);
	}
	buf_free(&buf);
	return res;
}

static int sftp_init(serv_t serv)
{
	int res = -1;
	uint32_t version = 0;
	struct buffer buf;
	buf_init(&buf, 0);
	if (sftp_send_iov(serv, SSH_FXP_INIT, PROTO_VERSION, NULL, 0) == -1)
		goto out;

	if (sshfsm.password_stdin && pty_expect_loop(serv) == -1)
		goto out;

	if (sftp_find_init_reply(serv, &version) == -1)
		goto out;

	serv->version = version;
	if (version > PROTO_VERSION)
		warning("server uses version: %i, we support: %i",
			version, PROTO_VERSION);
	res = 0;

out:
	buf_free(&buf);
	return res;
}

static int sftp_error_to_errno(uint32_t error)
{
	switch (error) {
	case SSH_FX_OK:                return 0;
	case SSH_FX_NO_SUCH_FILE:      return ENOENT;
	case SSH_FX_PERMISSION_DENIED: return EACCES;
	case SSH_FX_FAILURE:           return EPERM;
	case SSH_FX_BAD_MESSAGE:       return EBADMSG;
	case SSH_FX_NO_CONNECTION:     return ENOTCONN;
	case SSH_FX_CONNECTION_LOST:   return ECONNABORTED;
	case SSH_FX_OP_UNSUPPORTED:    return EOPNOTSUPP;
	default:                       return EIO;
	}
}

static void sftp_detect_uid(serv_t serv)
{
	if (serv->local) {
		serv->remote_uid = sshfsm.local_uid = getuid();
		serv->remote_uid_detected = 1;
		return;
	}

	int flags;
	uint32_t id = sftp_get_id();
	uint32_t replid;
	uint8_t type;
	struct buffer buf;
	struct stat stbuf;
	struct iovec iov[1];

	buf_init(&buf, 5);
	buf_add_string(&buf, ".");
	buf_to_iov(&buf, &iov[0]);
	if (sftp_send_iov(serv, SSH_FXP_STAT, id, iov, 1) == -1)
		goto out;
	buf_clear(&buf);
	if (sftp_read(serv, &type, &buf) == -1)
		goto out;
	if (type != SSH_FXP_ATTRS && type != SSH_FXP_STATUS) {
		error3("protocol perror2");
		goto out;
	}
	if (buf_get_uint32(&buf, &replid) == -1)
		goto out;
	if (replid != id) {
		error3("bad reply ID");
		goto out;
	}
	if (type == SSH_FXP_STATUS) {
		uint32_t serr;
		if (buf_get_uint32(&buf, &serr) == -1)
			goto out;

		error3("failed to stat home directory (%i)", serr);
		goto out;
	}
	if (buf_get_attrs(serv, &buf, &stbuf, &flags) == -1)
		goto out;

	if (!(flags & SSH_FILEXFER_ATTR_UIDGID))
		goto out;

	serv->remote_uid = stbuf.st_uid;
	sshfsm.local_uid = getuid();
	serv->remote_uid_detected = 1;
	debug("remote_uid = %i", serv->remote_uid);

out:
	if (!serv->remote_uid_detected)
		error3("failed to detect remote user ID for %s\n", serv->hostname);

	buf_free(&buf);
}

static int serv_check_root(serv_t serv)
{
	struct stat stbuf;
	if (serv->local) {
		int res = lstat(serv->basepath, &stbuf);
		if (res == -1)
			error2(errno, "failed to check local root: %s", serv->basepath);
		if (S_ISDIR(sshfsm.mnt_mode) && !S_ISDIR(stbuf.st_mode))
			error3("%s:%s: Not a directory", serv->hostname, serv->basepath);
		return res;
	}

	int flags;
	uint32_t id = sftp_get_id();
	uint32_t replid;
	uint8_t type;
	struct buffer buf;
	struct iovec iov[1];
	int err = -1;
	const char *remote_dir = serv->basepath[0] ? serv->basepath : ".";

	buf_init(&buf, 0);
	buf_add_string(&buf, remote_dir);
	buf_to_iov(&buf, &iov[0]);
	if (sftp_send_iov(serv, SSH_FXP_STAT, id, iov, 1) == -1)
		goto out;
	buf_clear(&buf);
	if (sftp_read(serv, &type, &buf) == -1)
		goto out;
	if (type != SSH_FXP_ATTRS && type != SSH_FXP_STATUS) {
		perror2("protocol error");
		goto out;
	}
	if (buf_get_uint32(&buf, &replid) == -1)
		goto out;
	if (replid != id) {
		error3("bad reply ID");
		goto out;
	}
	if (type == SSH_FXP_STATUS) {
		uint32_t serr;
		if (buf_get_uint32(&buf, &serr) == -1)
			goto out;

		error3("%s:%s: %s", serv->hostname, remote_dir,
			strerror(sftp_error_to_errno(serr)));

		goto out;
	}
	if (buf_get_attrs(serv, &buf, &stbuf, &flags) == -1)
		goto out;

	if (!(flags & SSH_FILEXFER_ATTR_PERMISSIONS))
		goto out;

	if (S_ISDIR(sshfsm.mnt_mode) && !S_ISDIR(stbuf.st_mode)) {
		error3("%s:%s: Not a directory", serv->hostname, remote_dir);
		goto out;
	}
	if ((sshfsm.mnt_mode ^ stbuf.st_mode) & S_IFMT) {
		error3("%s:%s: type of file differs from mountpoint",
			serv->hostname, remote_dir);
		goto out;
	}

	err = 0;

out:
	buf_free(&buf);
	return err;
}

static int get_hostinfo(char *host, char *port, struct in_addr *addr, 
	char *fqdnbuf)
{
	int err;
	struct addrinfo *ai;
	struct addrinfo hint;
	(void) fqdnbuf;
	
	memset(&hint, 0, sizeof(hint));
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;
	err = getaddrinfo(host, port, &hint, &ai);
	if (err) {
		debug("failed to resolve %s: %s", host, gai_strerror(err));
		addr->s_addr = 0;
		return -1;
	}
	addr->s_addr = ((struct sockaddr_in *) (ai->ai_addr))->sin_addr.s_addr;

	freeaddrinfo(ai);
	return 0;
}

#if 0
static int get_hostinfo2(char *host, char *port, struct in_addr *addr, 
	char *fqdnbuf)
{	
	int err;
	struct addrinfo *ai;
	struct addrinfo hint;
	struct hostent *hostent;

	memset(&hint, 0, sizeof(hint));
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;
	err = getaddrinfo(host, port, &hint, &ai);
	if (!err) {
		hostent = gethostbyaddr(ai, sizeof(struct addrinfo), AF_INET);
		if (hostent == NULL) {
			debug("failed to get host entry: %s", gai_strerror(h_errno))
		} else {
			g_snprintf(fqdnbuf, 128, "%s", hostent->h_name);
			goto out;
		}
	}
	debug("failed to resolve %s: %s", host, gai_strerror(err));
	
	/* Get FQDN and try again */
	char *cmd, fqdn[128];
	memset(fqdn, 0x0, 128);
	cmd = g_strdup_printf("ssh %s 'hostname -f'", host);
	err = get_cmd_output(cmd, fqdn, 128);
	fqdn[strlen(fqdn)-1] = '\0';
	g_free(cmd);
	if (err) {
		debug("failed to get fqdn via ssh");
		addr->s_addr = 0;
		return -1;
	}
	g_snprintf(fqdnbuf, 128, "%s", fqdn);
	err = getaddrinfo(fqdn, port, &hint, &ai);
	if (err) {
		debug("failed to resolve fqdn %s (%lu)", fqdn, strlen(fqdn));
		addr->s_addr = 0;
		return -1;
	}

out:
	addr->s_addr = ((struct sockaddr_in *) (ai->ai_addr))->sin_addr.s_addr;
	freeaddrinfo(ai);
	return 0;
}
#endif

static int get_inaddr(uint64_t ino, struct in_addr *inaddr)
{
	if ((ino & INADDR_MASK) != INADDR_FLAG)
		return -1;

	inaddr->s_addr = ino & INADDR_ADDR;
	return 0;
}

static int connect_remote(serv_t serv)
{
	if (serv->local)
		return 0;

	int err;
	
	if (sshfsm.sftp_local_server)
		err = sftp_local_connect(serv);
	else if (sshfsm.directport)
		err = sftp_proxy_connect(serv, sshfsm.directport);
	else
		err = start_ssh(serv);
	
	if (!err)
		err = sftp_init(serv);

	if (err)
		close_conn(serv);
	else
		serv->num_connect++;
	
	return err;
}

static int start_processing_thread(serv_t serv)
{
	if (serv->local)
		return 0;

	int err;
	pthread_t thread_id;
	sigset_t oldset;
	sigset_t newset;

	if (serv->processing_thread_started)
		return 0;

	if (serv->fd == -1) {
		err = connect_remote(serv);
		if (err)
			return -EIO;
	}

	serv_t *data = g_new(serv_t, 1);
	*data = serv;
	sigemptyset(&newset);
	sigaddset(&newset, SIGTERM);
	sigaddset(&newset, SIGINT);
	sigaddset(&newset, SIGHUP);
	sigaddset(&newset, SIGQUIT);
	pthread_sigmask(SIG_BLOCK, &newset, &oldset);
	err = pthread_create(&thread_id, NULL, process_requests, (void *) data);
	if (err) {
		error2(err, "create thread");
		return -EIO;
	}
	pthread_detach(thread_id);
	pthread_sigmask(SIG_SETMASK, &oldset, NULL);
	serv->thread_id = thread_id;
	serv->processing_thread_started = 1;
	return 0;
}

static int start_processing_thread_all(void)
{
	int err;
	unsigned int i;
	serv_t serv;
	for (i = 0; i < serv_num; i++) {
		serv = serv_i(i);
		if ((err = start_processing_thread(serv)) != 0) {
			error2(err, "%s: starting processing thread failed: %s", 
					serv->hostname);
			return -EIO;
		}
	}
	return 0;
}

static void runtime_init(void)
{	
	char path[PATH_MAX];
	int res;
	
	sshfsm.pid = getpid();
	if (sshfsm.session_dir) {
		char *tmp = sshfsm.session_dir;
		sshfsm.session_dir = g_strdup(tmp);
		free(tmp);
	} else
		sshfsm.session_dir = g_strdup_printf("/tmp/sshfsm-%s-%u",
			sshfsm.username, g_str_hash(sshfsm.mountpoint));

	res = mkdir(sshfsm.session_dir, S_IRUSR | S_IWUSR | S_IXUSR);
	if (res == -1 && errno != EEXIST) 
		fatal(1, "create directory \"%s\"\n", sshfsm.session_dir);

	if (sshfsm.dump) {
		memset(path, 0, PATH_MAX);
		snprintf(path, PATH_MAX, "%s/error.log", sshfsm.session_dir);
		sshfsm.errlog = fopen(path, "wb");
		if (sshfsm.errlog == NULL)
			fatal(1, "open file \"%s\"", path);
		if (dup2(fileno(sshfsm.errlog), 1) == -1 || 
			dup2(fileno(sshfsm.errlog), 2) == -1) 
			fatal(1, "failed to redirect stdout and stderr to \"%s\"", path);
	}

	debug("initial\n"
		  " user:       %s\n"
		  " mountpoint: %s",
		  sshfsm.username, sshfsm.mountpoint);
}

static void runtime_destroy(void)
{
	unsigned int avg_rtt = 0;

	if (sshfsm.num_sent)
		avg_rtt = sshfsm.total_rtt / sshfsm.num_sent;

	debug("runtime statistics\n"
		  "  sent:               %llu messages, %llu bytes\n"
		  "  received:           %llu messages, %llu bytes\n"
		  "  rtt min/max/avg:    %ums/%ums/%ums\n"
		  "  num connect:        %u",
		  (unsigned long long) sshfsm.num_sent,
		  (unsigned long long) sshfsm.bytes_sent,
		  (unsigned long long) sshfsm.num_received,
		  (unsigned long long) sshfsm.bytes_received,
		  sshfsm.min_rtt, sshfsm.max_rtt, avg_rtt,
		  sshfsm.num_connect);

	if (sshfsm.dump)
		fclose(sshfsm.errlog);
		
	g_free(sshfsm.mountpoint);
	g_free(sshfsm.username);
	g_free(sshfsm.userhome);
	g_free(sshfsm.session_dir);
	if (sshfsm.sftp_local_server)
		g_free(sshfsm.sftp_local_server);
	if (sshfsm.forward_io)
		g_free(sshfsm.forward_io);
}

#if FUSE_VERSION >= 26
static void *sshfsm_init(struct fuse_conn_info *conn)
#else
static void *sshfsm_init(void)
#endif
{
	runtime_init();

#if FUSE_VERSION >= 26
	/* Readahead should be done by kernel or sshfs but not both */
	if (conn->async_read)
		sshfsm.sync_read = 1;
#endif

	if (!sshfsm.delay_connect)
		start_processing_thread_all();

	return NULL;
}

static void sshfsm_destroy(void *data_)
{
	(void) data_;

	if (sshfsm.debug)
		tree_print();
	
	cache_destroy();
	serv_arr_destroy();
	tree_destroy();
	runtime_destroy();
}

static int sftp_request_wait(serv_t serv, struct request *req, 
	uint8_t type, uint8_t expect_type, struct buffer *outbuf)
{
	int err;

	if (req->error) {
		err = req->error;
		goto out;
	}
	while (sem_wait(&req->ready));
	if (req->error) {
		err = req->error;
		goto out;
	}
	err = -EIO;
	if (req->reply_type != expect_type &&
	    req->reply_type != SSH_FXP_STATUS) {
		fprintf(stderr, "protocol perror2\n");
		goto out;
	}
	if (req->reply_type == SSH_FXP_STATUS) {
		uint32_t serr;
		if (buf_get_uint32(&req->reply, &serr) == -1)
			goto out;

		switch (serr) {
		case SSH_FX_OK:
			if (expect_type == SSH_FXP_STATUS)
				err = 0;
			else
				err = -EIO;
			break;

		case SSH_FX_EOF:
			if (type == SSH_FXP_READ || type == SSH_FXP_READDIR)
				err = MY_EOF;
			else
				err = -EIO;
			break;

		default:
			err = -sftp_error_to_errno(serr);
		}
	} else {
		buf_init(outbuf, req->reply.size - req->reply.len);
		buf_get_mem(&req->reply, outbuf->p, outbuf->size);
		err = 0;
	}

out:
	if (req->end_func) {
		pthread_mutex_lock(&serv->lock);
		req->end_func(req);
		pthread_mutex_unlock(&serv->lock);
	}
	request_free(req);
	return err;
}

static int sftp_request_send(serv_t serv,
	uint8_t type, struct iovec *iov, size_t count,
	request_func begin_func, request_func end_func,
    int want_reply, void *data, struct request **reqp)
{
	int err;
	uint32_t id;
	struct request *req = g_new0(struct request, 1);

	req->want_reply = want_reply;
	req->end_func = end_func;
	req->data = data;
	sem_init(&req->ready, 0, 0);
	buf_init(&req->reply, 0);
	pthread_mutex_lock(&serv->lock);
	if (begin_func)
		begin_func(req);
	id = sftp_get_id();
	err = start_processing_thread(serv);
	if (err) {
		pthread_mutex_unlock(&serv->lock);
		goto out;
	}
	req->len = iov_length(iov, count) + 9;
	serv->outstanding_len += req->len;
	while (serv->outstanding_len > sshfsm.max_outstanding_len)
		pthread_cond_wait(&serv->outstanding_cond, &serv->lock);

	g_hash_table_insert(serv->reqtab, GUINT_TO_POINTER(id), req);
	if (sshfsm.debug) {
		gettimeofday(&req->start, NULL);
		serv->num_sent++;
		serv->bytes_sent += req->len;
	}
	debug("[%05i] %s", id, type_name(type));
	pthread_mutex_unlock(&serv->lock);

	err = -EIO;
	if (sftp_send_iov(serv, type, id, iov, count) == -1) {
		pthread_mutex_lock(&serv->lock);
		g_hash_table_remove(serv->reqtab, GUINT_TO_POINTER(id));
		pthread_mutex_unlock(&serv->lock);
		goto out;
	}
	if (want_reply)
		*reqp = req;
	return 0;

out:
	req->error = err;
	if (!want_reply)
		sftp_request_wait(serv, req, type, 0, NULL);
	else
		*reqp = req;

	return err;
}


static int sftp_request_iov(serv_t serv,
							uint8_t type, struct iovec *iov, size_t count,
                            uint8_t expect_type, struct buffer *outbuf)
{
	struct request *req;

	sftp_request_send(serv, type, iov, count, NULL, NULL, expect_type, NULL,
			  &req);
	if (expect_type == 0)
		return 0;

	return sftp_request_wait(serv, req, type, expect_type, outbuf);
}

static int sftp_request(serv_t serv, uint8_t type, const struct buffer *buf,
	uint8_t expect_type, struct buffer *outbuf)
{
	struct iovec iov;

	buf_to_iov(buf, &iov);
	return sftp_request_iov(serv, type, &iov, 1, expect_type, outbuf);
}

/*
 * Server Array and Directory Tree
 */
static int serv_arr_init(void)
{
	unsigned int i;
	serv_t serv;
	for (i = 0; i < serv_num; i++) {
		serv = serv_i(i);
		serv->fd = -1;
		serv->ptyfd = -1;
		serv->ptyslavefd = -1;
		serv->is_forward = 0;
		if (serv->local)
			continue;
		pthread_mutex_init(&serv->lock, NULL);
		pthread_mutex_init(&serv->lock_write, NULL);
		pthread_cond_init(&serv->outstanding_cond, NULL);
		serv->reqtab = g_hash_table_new(NULL, NULL);
		if (!serv->reqtab) {
			error3("failed to create hash table");
			return -1;
		}
		serv->connver = 0;
		serv->processing_thread_started = 0;
	}
	pthread_mutex_init(&sshfsm.lock_serv_arr, NULL);
	return 0;
}

static void serv_arr_destroy(void)
{
	unsigned int i;
	serv_t serv;
	
	for (i = 0; i < serv_num; i++) {
		serv = serv_i(i);
		g_free(serv->hostname);
		g_free(serv->basepath);
		if (serv->local)
			continue;
		pthread_mutex_destroy(&serv->lock);
		pthread_mutex_destroy(&serv->lock_write);
		pthread_cond_destroy(&serv->outstanding_cond);
		g_hash_table_destroy(serv->reqtab);
	}
	pthread_mutex_destroy(&sshfsm.lock_serv_arr);
}

static int serv_arr_find(GPtrArray *arr, serv_t serv)
{
	unsigned int i;
	serv_t serv2;
	for (i = 0; i < arr->len; i++) {
		serv2 = g_ptr_array_index(arr, i);
		if (serv == serv2)
			return i;
	}
	return -1;
}

static inline void serv_arr_insert(GPtrArray *arr, serv_t serv)
{
	if (serv_arr_find(arr, serv) == -1)
		g_ptr_array_add(arr, serv);
}

static serv_t serv_arr_lookup(struct in_addr *inaddr)
{
	unsigned int i;
	serv_t serv;
	GPtrArray *arr;
	
	arr = sshfsm.serv_arr;
	for (i = 0; i < arr->len; i++) {
		serv = (serv_t) g_ptr_array_index(arr, i);
		if (serv->inaddr.s_addr == inaddr->s_addr)
			return serv;
	}
	return NULL;
}

static int tree_init(void)
{
	ndata_t data = g_new0(struct tree_node_data, 1);
	sshfsm.serv_arr = g_ptr_array_new();
	data->dirname = g_strdup("/");
	data->servarr = sshfsm.serv_arr;
	sshfsm.tree = g_node_new((gpointer) data);
	sshfsm.fwd_serv_arr = g_ptr_array_new();
	return 0;
}

static int tree_node_free(GNode *node, gpointer data)
{
	(void) data;
	ndata_t p = (ndata_t) node->data;
	/* sshfsm.serv_arr has been handled in serv_arr_destroy() */
	if (strcmp(p->dirname, "/") != 0)
		g_ptr_array_free(p->servarr, TRUE);
	g_free(p->dirname);
	
	/* Don't stop traversal */
	return 1;	
}

static void tree_destroy(void)
{	
	g_node_traverse(sshfsm.tree, G_POST_ORDER, G_TRAVERSE_ALL, -1,
		(GNodeTraverseFunc) tree_node_free, NULL);
	g_node_destroy(sshfsm.tree);
	g_ptr_array_free(sshfsm.serv_arr, TRUE);
	fwd_serv_arr_cleanup(0);
	g_ptr_array_free(sshfsm.fwd_serv_arr, TRUE);
}

static void tree_node_destroy(GNode *node)
{
	g_node_traverse(node, G_POST_ORDER, G_TRAVERSE_ALL, -1,
		(GNodeTraverseFunc) tree_node_free, NULL);
	g_node_destroy(node);
}

static inline GNode * tree_find_child(GNode *node, const char *dirname)
{
	ndata_t curr_node;
	GNode *curr = g_node_first_child(node);
	while (curr != NULL) {
		curr_node = (ndata_t) curr->data;
		if (strcmp(curr_node->dirname, dirname) == 0)
			return curr;
		curr = curr->next;
	}
	return NULL;
}

static GNode * tree_lookup(const char *path)
{
	char **strv, **curr;
	GNode *curr_node, *curr_child;

	curr = strv = g_strsplit(path, "/", -1);
	curr_node = sshfsm.tree;

	for (curr = strv; *curr; curr++) {
		if (strlen(*curr) == 0)
			continue;
		curr_child = tree_find_child(curr_node, *curr);
		if (curr_child == NULL)
			break;
		curr_node = curr_child;
	}
	
	g_strfreev(strv);
	return curr_node;
}

static GNode * tree_exact_lookup(const char *path)
{
	char **strv, **curr;
	GNode *curr_node, *curr_child;
	
	curr = strv = g_strsplit(path, "/", -1);
	curr_node = sshfsm.tree;

	for (curr = strv; *curr; curr++) {
		if (strlen(*curr) == 0)
			continue;
		curr_child = tree_find_child(curr_node, *curr);
		if (curr_child == NULL) {
			g_strfreev(strv);
			return NULL;
		}
		curr_node = curr_child;
	}
	
	g_strfreev(strv);
	return curr_node;
}

static void tree_insert(const char *path, serv_t serv)
{
	char **strv, **curr;
	GNode *curr_node, *curr_child;
	ndata_t curr_data;
	GPtrArray *curr_arr;

	curr = strv = g_strsplit(path, "/", -1);
	curr_node = sshfsm.tree;
	curr_data = (ndata_t) curr_node->data;
	
	for (curr = strv; *curr; curr++) {
		if (strlen(*curr) == 0)
			continue;
		curr_child = tree_find_child(curr_node, *curr);
		if (curr_child) {
			curr_data = (ndata_t) curr_child->data;
			curr_arr = curr_data->servarr;
			serv_arr_insert(curr_arr, serv);
		} else {
			ndata_t new_data = g_new0(struct tree_node_data, 1);
			new_data->dirname = g_strdup(*curr);
			new_data->servarr = g_ptr_array_new();
			g_ptr_array_add(new_data->servarr, (gpointer) serv);
			curr_child = g_node_new(new_data);
			g_node_prepend(curr_node, curr_child);
		}
		curr_node = curr_child;
	}
}

static void tree_remove_serv(const char *path, serv_t serv)
{
	GNode *node = tree_exact_lookup(path);
	if (node) {
		ndata_t data = node->data;
		g_ptr_array_remove(data->servarr, serv);
		if (data->servarr->len == 0)
			tree_node_destroy(node);
	}
}

static void tree_remove_path(const char *path)
{
	GNode *node = tree_exact_lookup(path);
	if (node)
		tree_node_destroy(node);
}

static int tree_node_print(GNode *node, gpointer data)
{
	unsigned int i;
	serv_t serv;
	(void) data;
	ndata_t p = (ndata_t) node->data;
	fprintf(stderr, "[%02d:%10s]", g_node_depth(node), p->dirname);
	for (i = 0; i < p->servarr->len; i++) {
		serv = (serv_t) g_ptr_array_index(p->servarr, i);
		fprintf(stderr, "%s ",serv->hostname);
	}
	fprintf(stderr, "\n");
	return 0;
}

static inline void tree_print(void)
{
	static int ver = 0;
	fprintf(stderr, "BEGIN: Tree %02d:\n", ver);
	g_node_traverse(sshfsm.tree, G_PRE_ORDER, G_TRAVERSE_ALL, -1,
		(GNodeTraverseFunc) tree_node_print, NULL);
	fprintf(stderr, "END:   Tree %02d:\n", ver);
	ver++;
	fflush(stderr);
	fflush(stdout);
}

/* 
 * FUSE APIs
 */

static inline GPtrArray * get_serv_arr(GNode *node)
{
	struct tree_node_data *data = (struct tree_node_data *) node->data;
	return data->servarr;
}

/* getattr */
static int getattr_local(serv_t serv, const char *path, struct stat *stbuf)
{
	int res;
	char *realpath = serv_add_path(serv, path);
	if (sshfsm.follow_symlinks)
		res = stat(realpath, stbuf);
	else
		res = lstat(realpath, stbuf);
	g_free(realpath);
	if (res == -1)
		return -errno;
	
	return res;
}

static int getattr_remote(serv_t serv,
	const char *path, struct stat *stbuf)
{
	int err;
	struct buffer buf;
	struct buffer outbuf;
	buf_init(&buf, 0);
	buf_add_path(serv, &buf, path);
	err = sftp_request(serv, 
			sshfsm.follow_symlinks ? SSH_FXP_STAT : SSH_FXP_LSTAT,
			&buf, SSH_FXP_ATTRS, &outbuf);
	if (!err) {
		if (buf_get_attrs(serv, &outbuf, stbuf, NULL) == -1)
			err = -EIO;
		buf_free(&outbuf);
	}
	buf_free(&buf);
	return err;
}

static int serv_getattr(serv_t serv, const char *path,
	struct stat *stbuf)
{
	return serv->local ? 
		getattr_local(serv, path, stbuf) : getattr_remote(serv, path, stbuf);
}

static int sshfsm_getattr(const char *path, struct stat *stbuf)
{
	if (serv_num == 1)
		return serv_getattr(serv_0, path, stbuf);
	
	int err = 0, err2 = 1, firsterr = 0;
	unsigned int i;
	serv_t serv;
	GPtrArray *serv_arr = get_serv_arr(tree_lookup(path));
	
	for (i = 0; i < serv_arr->len; i++) {
		serv = g_ptr_array_index(serv_arr, i);
		err = serv_getattr(serv, path, stbuf);
		if (!err) {
			if (strcmp(path, "/") != 0 && S_ISDIR(stbuf->st_mode)) {
				/* For directory, check every possible branches */
				tree_insert(path, serv);
			} else {
				/* For regular file, return the file found in branch
				   with highest rank */
				return 0;
			}
		}
		if (!firsterr)
			firsterr = err;
		err2 *= err;
	}
	return err2 ? firsterr : 0;;
}

/* readlink */
static int count_components(const char *p)
{
	int ctr;

	for (; *p == '/'; p++);
	for (ctr = 0; *p; ctr++) {
		for (; *p && *p != '/'; p++);
		for (; *p == '/'; p++);
	}
	return ctr;
}

static void strip_common(const char **sp, const char **tp)
{
	const char *s = *sp;
	const char *t = *tp;
	do {
		for (; *s == '/'; s++);
		for (; *t == '/'; t++);
		*tp = t;
		*sp = s;
		for (; *s == *t && *s && *s != '/'; s++, t++);
	} while ((*s == *t && *s) || (!*s && *t == '/') || (*s == '/' && !*t));
}

static void transform_symlink(serv_t serv, const char *path, char **linkp)
{
	const char *l = *linkp;
	const char *b = serv->basepath;
	char *newlink;
	char *s;
	int dotdots;
	int i;

	if (l[0] != '/' || b[0] != '/')
		return;

	strip_common(&l, &b);
	if (*b)
		return;

	strip_common(&l, &path);
	dotdots = count_components(path);
	if (!dotdots)
		return;
	dotdots--;

	newlink = malloc(dotdots * 3 + strlen(l) + 2);
	if (!newlink) {
		perror2("memory allocation failed");
		abort();
	}
	for (s = newlink, i = 0; i < dotdots; i++, s += 3)
		strcpy(s, "../");

	if (l[0])
		strcpy(s, l);
	else if (!dotdots)
		strcpy(s, ".");
	else
		s[0] = '\0';

	free(*linkp);
	*linkp = newlink;
}

static int readlink_local(serv_t serv, const char *path, char *linkbuf, 
	size_t size)
{
	char *realpath = serv_add_path(serv, path);
	int res = readlink(realpath, linkbuf, size - 1);
	g_free(realpath);
	if (res == -1)
		return -errno;
	linkbuf[size - 1] = '\0';
	return res;
}

static int readlink_remote(serv_t serv, const char *path, 
	char *linkbuf, size_t size)
{
	int err;
	struct buffer buf;
	struct buffer name;

	if (serv->version < 3)
		return -EPERM;

	buf_init(&buf, 0);
	buf_add_path(serv, &buf, path);
	err = sftp_request(serv, SSH_FXP_READLINK, &buf, SSH_FXP_NAME, &name);
	if (!err) {
		uint32_t count;
		char *link;
		err = -EIO;
		if(buf_get_uint32(&name, &count) != -1 && count == 1 &&
		   buf_get_string(&name, &link) != -1) {
			if (sshfsm.transform_symlinks)
				transform_symlink(serv, path, &link);
			strncpy(linkbuf, link, size - 1);
			linkbuf[size - 1] = '\0';
			free(link);
			err = 0;
		}
		buf_free(&name);
	}
	buf_free(&buf);
	return err;
}

static int serv_readlink(serv_t serv, const char *path,
						 char *linkbuf, size_t size)
{
	assert(size > 0);
	return serv->local ? readlink_local(serv, path, linkbuf, size) : 
		readlink_remote(serv, path, linkbuf, size);
}

static int sshfsm_readlink(const char *path, char *linkbuf, size_t size)
{
	if (serv_num == 1)
		return serv_readlink(serv_0, path, linkbuf, size);
	
	int err = 0, firsterr = 0;
	unsigned int i;
	serv_t serv;
	GPtrArray *serv_arr = get_serv_arr(tree_lookup(path));
	for (i = 0; i < serv_arr->len; i++) {
		serv = g_ptr_array_index(serv_arr, i);
		err = serv_readlink(serv, path, linkbuf, size);
		if (!err)
			return err;
		if (!firsterr)
			firsterr = err;
	}
	return firsterr;
}

/* getdir */
/* getdir() when there is only one server */
static int getdir_local_0(serv_t serv, const char *path, fuse_cache_dirh_t h,
	fuse_cache_dirfil_t filler)
{
	char *realpath = serv_add_path(serv, path);
	DIR *dp = opendir(realpath);
	if (dp == NULL) {
		g_free(realpath);
		return -errno;
	}

	union {
		struct dirent de;
		char buf[offsetof(struct dirent, d_name) + NAME_MAX + 1];
	} u;
	struct dirent *dep;
	struct stat stbuf;
	char *filename;
	int res = 0;
	while ((readdir_r(dp, &u.de, &dep) == 0) && dep) {
		memset(&stbuf, 0, sizeof(stbuf));
		filename = g_strdup_printf("%s/%s", realpath, u.de.d_name);
		if (sshfsm.follow_symlinks)
			res = stat(filename, &stbuf);
		else
			res = lstat(filename, &stbuf);
		g_free(filename);
		if (res == -1) {
			res = -errno;
			break;
		}
		if (filler(h, u.de.d_name, &stbuf)) {
			res = -EIO;
			break;
		}
	}
	closedir(dp);
	g_free(realpath);
	return res;
}

static int getdir_remote_0(serv_t serv, const char *path,
	fuse_cache_dirh_t h, fuse_cache_dirfil_t filler)
{
	int err;
	struct buffer buf;
	struct buffer handle;
	buf_init(&buf, 0);
	buf_add_path(serv, &buf, path);
	err = sftp_request(serv, SSH_FXP_OPENDIR, &buf, SSH_FXP_HANDLE, &handle);
	if (!err) {
		int err2;
		buf_finish(&handle);
		do {
			struct buffer name;
			err = sftp_request(serv, SSH_FXP_READDIR, &handle, 
				SSH_FXP_NAME, &name);
			if (!err) {
				if (buf_get_entries(serv, &name, h, filler) == -1)
					err = -EIO;
				buf_free(&name);
			}
		} while (!err);
		if (err == MY_EOF)
			err = 0;

		err2 = sftp_request(serv, SSH_FXP_CLOSE, &handle, 0, NULL);
		if (!err)
			err = err2;
		buf_free(&handle);
	}
	buf_free(&buf);
	return err;
}

static int serv_getdir_0(serv_t serv, const char *path,
	fuse_cache_dirh_t h, fuse_cache_dirfil_t filler)
{
	return serv->local ? getdir_local_0(serv, path, h, filler) : 
		getdir_remote_0(serv, path, h, filler);
}

static int getdir_local(serv_t serv, const char *path, GHashTable* set)
{
	char *realpath = serv_add_path(serv, path);
	DIR *dp = opendir(realpath);
	if (dp == NULL) {
		g_free(realpath);
		return -errno;
	}
		
	union {
		struct dirent de;
		char buf[offsetof(struct dirent, d_name) + NAME_MAX + 1];
	} u;
	struct dirent *dep;
	struct stat stbuf, *st;
	char *filename;
	int res = 0;
	
	while ((readdir_r(dp, &u.de, &dep) == 0) && dep) {
		memset(&stbuf, 0, sizeof(stbuf));
		filename = g_strdup_printf("%s/%s", realpath, u.de.d_name);
		if (sshfsm.follow_symlinks)
			res = stat(filename, &stbuf);
		else
			res = lstat(filename, &stbuf);
		g_free(filename);
		if (res == -1) {
			res = -errno;
			break;
		}
		st = g_new(struct stat, 1);
		*st = stbuf;
		g_hash_table_insert(set, g_strdup(u.de.d_name), (gpointer) st);
	}
	closedir(dp);
	g_free(realpath);
	return res;
}

static int getdir_remote(serv_t serv, const char *path, GHashTable* set)
{
	int err;
	struct buffer buf;
	struct buffer handle;
	buf_init(&buf, 0);
	buf_add_path(serv, &buf, path);
	err = sftp_request(serv, SSH_FXP_OPENDIR, &buf, SSH_FXP_HANDLE, &handle);
	if (!err) {
		int err2;
		buf_finish(&handle);
		do {
			struct buffer name;
			err = sftp_request(serv, SSH_FXP_READDIR, &handle, 
				SSH_FXP_NAME, &name);
			if (!err) {
				if (buf_get_entries_set(serv, &name, set) == -1)
					err = -EIO;
				buf_free(&name);
			}
		} while (!err);
		if (err == MY_EOF)
			err = 0;

		err2 = sftp_request(serv, SSH_FXP_CLOSE, &handle, 0, NULL);
		if (!err)
			err = err2;
		buf_free(&handle);
	}
	buf_free(&buf);
	return err;
}

static int serv_getdir(serv_t serv, const char *path, GHashTable* set)
{
	return serv->local ? getdir_local(serv, path, set) 
		: getdir_remote(serv, path, set);
}

struct getdir_thread_data {
	serv_t serv;
	const char *path;
	GHashTable *set;
	int err;
};

static void * getdir_thread_func(void *data)
{
	struct getdir_thread_data *p =
		(struct getdir_thread_data *) data;
	p->err = serv_getdir(p->serv, p->path, p->set);
	p->err ? pthread_exit((void *) -1) : pthread_exit((void *) 0);
}

#ifndef G_HASH_TABLE_HAS_ITER
struct getdir_fill_data {
	fuse_cache_dirh_t h;
	fuse_cache_dirfil_t filler;
	int err;
};

static void getdir_fill_func(gpointer key, gpointer value, gpointer data)
{
	char *d_name = (char *) key;
	struct stat *st = (struct stat *) value;
	struct getdir_fill_data *p = (struct getdir_fill_data *) data;
	if (!p->err) {
		if(p->filler(p->h, d_name, st))
			p->err = -EIO;
	}
}

struct getdir_merge_data {
	fuse_cache_dirh_t h;
	fuse_cache_dirfil_t filler;
	GHashTable *table;
	int err;
};

static void getdir_merge_func(gpointer key, gpointer value, gpointer data)
{
	char *d_name = (char *) key;
	struct stat *st = (struct stat *) value;
	struct getdir_merge_data *p = (struct getdir_merge_data *) data;
	if (!p->err) {
		if (g_hash_table_lookup(p->table, d_name))
			return;
		if(p->filler(p->h, d_name, st))
			p->err = -EIO;
	}
}
#endif

static int sshfsm_getdir(const char *path, fuse_cache_dirh_t h,
                        fuse_cache_dirfil_t filler)
{
	if (serv_num == 1)
		return serv_getdir_0(serv_0, path, h, filler);

	int err = 0, err2, err3 = 1, firsterr = 0;
	unsigned int i, nthreads;
	pthread_t *threads;
	pthread_attr_t attr;
	struct getdir_thread_data *thread_dat;
	GPtrArray *serv_arr;
	GHashTable **sets;
	
	serv_arr = get_serv_arr(tree_lookup(path));
	nthreads = serv_arr->len;
	sets = g_new0(GHashTable *, nthreads);
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	thread_dat = g_new0(struct getdir_thread_data, nthreads);
	threads = g_new(pthread_t, nthreads);

	for (i = 0; i < nthreads; i++) {
		sets[i] = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, g_free);
		thread_dat[i].serv = (serv_t) g_ptr_array_index(serv_arr, i);
		thread_dat[i].path = path;
		thread_dat[i].set = sets[i];
		err = pthread_create(&threads[i], &attr,
				getdir_thread_func, &thread_dat[i]);
		if (err) {
			error2(err, "sshfsm_getdir: create thread failed"); 
			err = -EIO;
			goto out;
		}
	}
	
	for (i = 0; i < nthreads; i++) {
		err = pthread_join(threads[i], (void *) &err2);
		if (err) {
			error2(err, "sshfsm_getdir: join thread failed");
			err = -EIO;
			goto out;
		}
		if (!firsterr)
			firsterr = thread_dat[i].err;
		err3 *= err2;
	}
	err = err3 ? firsterr : 0;
	
	/* Aggregte all directory entires */
#ifdef G_HASH_TABLE_HAS_ITER
	GHashTableIter iter;
	gpointer key, value;
	char *d_name;
	struct stat *st;
	
	g_hash_table_iter_init(&iter, sets[0]);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		d_name = (char *) key;
		st = (struct stat *) value;
		if (filler(h, d_name, st)) {
			err = -EIO;
			goto out;
		}
	}
	
	for (i = 1; i < nthreads; i++) {
		g_hash_table_iter_init(&iter, sets[i]);
		while (g_hash_table_iter_next(&iter, &key, &value)) {
			d_name = (char *) key;
			st = (struct stat *) value;
			if (g_hash_table_lookup(sets[0], d_name))
				continue;
			if (filler(h, d_name, st)) {
				err = -EIO;
				goto out;
			}
		}
	}
#else
	struct getdir_fill_data fdata;
	fdata.h = h;
	fdata.filler = filler;
	fdata.err = 0;
	g_hash_table_foreach(sets[0], getdir_fill_func, &fdata);
	if (fdata.err) {
		err = -EIO;
		goto out;
	}
	
	struct getdir_merge_data mdata;
	mdata.h = h;
	mdata.filler = filler;
	mdata.table = sets[0];
	mdata.err = 0;
	for (i = 1; i < nthreads; i++) {
		g_hash_table_foreach(sets[i], getdir_merge_func, &mdata);
		if (mdata.err) {
			err = -EIO;
			goto out;
		}
	}
#endif

out:
	for (i = 0; i < nthreads; i++)
		g_hash_table_destroy(sets[i]);
	pthread_attr_destroy(&attr);
	g_free(sets);
	g_free(thread_dat);
	g_free(threads);
	return err;
}

/* mkdir */
static int mkdir_local(serv_t serv, const char *path, mode_t mode)
{
	char *realpath = serv_add_path(serv, path);
	int res = mkdir(realpath, mode);
	g_free(realpath);
	if (res == -1)
		return -errno;
	return res;
}

static int mkdir_remote(serv_t serv, const char *path, mode_t mode)
{
	int err;
	struct buffer buf;
	buf_init(&buf, 0);
	buf_add_path(serv, &buf, path);
	buf_add_uint32(&buf, SSH_FILEXFER_ATTR_PERMISSIONS);
	buf_add_uint32(&buf, mode);
	err = sftp_request(serv, SSH_FXP_MKDIR, &buf, SSH_FXP_STATUS, NULL);
	buf_free(&buf);
	return err;
}

static int serv_mkdir(serv_t serv, const char *path, mode_t mode)
{
	return serv->local ? mkdir_local(serv, path, mode) 
		: mkdir_remote(serv, path, mode);
}

static int sshfsm_mkdir(const char *path, mode_t mode)
{
	/* Note that the parent directory of current path 
	   has been confirmed existing */

	if (serv_num == 1)
		return serv_mkdir(serv_0, path, mode);
	
	/* TODO: optional makedirs at all branches */

	int err = 0, firsterr = 0;
	unsigned int i;
	serv_t serv;
	GPtrArray *serv_arr = get_serv_arr(tree_lookup(path));
	for (i = 0; i < serv_arr->len; i++) {
		serv = g_ptr_array_index(serv_arr, i);
		err = serv_mkdir(serv, path, mode);
		if (!err) {
			tree_insert(path, serv);
			return err;
		}
		if (!firsterr)
			firsterr = err;
	}
	return firsterr;
}

/* mknod */
static int mknod_local(serv_t serv, const char *path, mode_t mode, dev_t rdev)
{
	int res;
	char *realpath = serv_add_path(serv, path);
	if (S_ISFIFO(mode))
		res = mkfifo(realpath, mode);
	else
		res = mknod(realpath, mode, rdev);
	g_free(realpath);
	if (res == -1)
		return -errno;
	return res;
}

static int mknod_remote(serv_t serv, const char *path,
	mode_t mode, dev_t rdev)
{
	int err;
	struct buffer buf;
	struct buffer handle;
	(void) rdev;

	if ((mode & S_IFMT) != S_IFREG)
		return -EPERM;

	buf_init(&buf, 0);
	buf_add_path(serv, &buf, path);
	buf_add_uint32(&buf, SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_EXCL);
	buf_add_uint32(&buf, SSH_FILEXFER_ATTR_PERMISSIONS);
	buf_add_uint32(&buf, mode);
	err = sftp_request(serv, SSH_FXP_OPEN, &buf, SSH_FXP_HANDLE, &handle);
	if (!err) {
		int err2;
		buf_finish(&handle);
		err2 = sftp_request(serv, SSH_FXP_CLOSE, &handle, 
			SSH_FXP_STATUS, NULL);
		if (!err)
			err = err2;
		buf_free(&handle);
	}
	buf_free(&buf);
	return err;
}

static int serv_mknod(serv_t serv, const char *path,
	mode_t mode, dev_t rdev)
{
	return serv->local ? mknod_local(serv, path, mode, rdev) : 
		mknod_remote(serv, path, mode, rdev);
}

static int sshfsm_mknod(const char *path, mode_t mode, dev_t rdev)
{
	if (serv_num == 1)
		return serv_mknod(serv_0, path, mode, rdev);

	/* TODO: mkdirs for all branches */
	int err = 0, firsterr = 0;
	unsigned int i;
	serv_t serv;
	GPtrArray *serv_arr = get_serv_arr(tree_lookup(path));
	for (i = 0; i < serv_arr->len; i++) {
		serv = g_ptr_array_index(serv_arr, i);
		err = serv_mknod(serv, path, mode, rdev);
		if (!err) {
			if (S_ISDIR(mode))
				tree_insert(path, serv);
			return err;
		}
		if (!firsterr)
			firsterr = err;
	}
	return firsterr;
}

/* symlink */
static int symlink_local(serv_t serv, const char *from, const char *to)
{
	char *realfrom = serv_add_path(serv, from);
	char *realto = serv_add_path(serv, to);
	int res = symlink(realfrom, realto);
	g_free(realfrom);
	g_free(realto);
	if (res == -1)
		return -errno;
	return res;
}

static int symlink_remote(serv_t serv, const char *from,
	const char *to)
{
	int err;
	struct buffer buf;

	if (serv->version < 3)
		return -EPERM;

	/* openssh sftp server doesn't follow standard: link target and
	   link name are mixed up, so we must also be non-standard :( */
	buf_init(&buf, 0);
	buf_add_string(&buf, from);
	buf_add_path(serv, &buf, to);
	err = sftp_request(serv, SSH_FXP_SYMLINK, &buf, SSH_FXP_STATUS, NULL);
	buf_free(&buf);
	return err;
}

static int serv_symlink(serv_t serv, const char *from, 
	const char *to)
{
	return serv->local ? symlink_local(serv, from, to) : 
		symlink_remote(serv, from, to);
}

static int sshfsm_symlink(const char *from, const char *to)
{
	if (serv_num == 1)
		return serv_symlink(serv_0, from, to);
	
	int err = 0, firsterr = 0;
	unsigned int i;
	serv_t serv;
	GPtrArray *serv_arr = get_serv_arr(tree_lookup(from));
	for (i = 0; i < serv_arr->len; i++) {
		serv = g_ptr_array_index(serv_arr, i);
		err = serv_symlink(serv, from, to);
		if (!err) 
			return err;
		if (!firsterr)
			firsterr = err;
	}
	return firsterr;
}

/* unlink */
static int unlink_local(serv_t serv, const char *path)
{
	char *realpath = serv_add_path(serv, path);
	int res = unlink(realpath);
	g_free(realpath);
	if (res == -1)
		return -errno;
	return res;
}

static int unlink_remote(serv_t serv, const char *path)
{
	int err;
	struct buffer buf;
	
	buf_init(&buf, 0);
	buf_add_path(serv, &buf, path);
	err = sftp_request(serv, SSH_FXP_REMOVE, &buf, SSH_FXP_STATUS, NULL);
	buf_free(&buf);
	return err;
}

static int serv_unlink(serv_t serv, const char *path)
{
	return serv->local ? unlink_local(serv, path) : unlink_remote(serv, path);
}

struct unlink_thread_data {
	serv_t serv;
	const char *path;
	int err;
};

static void * unlink_thread_func(void *data)
{
	struct unlink_thread_data *p = (struct unlink_thread_data *) data;
	p->err = serv_unlink(p->serv, p->path);
	p->err ? pthread_exit((void *) -1) : pthread_exit((void *) 0);
}

static int sshfsm_unlink(const char *path)
{
	if (serv_num == 1)
		return serv_unlink(serv_0, path);
	
	int err = 0, err2, err3 = 1, firsterr = 0;
	unsigned int i, nthreads;
	pthread_t *threads;
	pthread_attr_t attr;
	struct unlink_thread_data *thread_dat;
	GPtrArray *serv_arr;
	
	serv_arr = get_serv_arr(tree_lookup(path));
	nthreads = serv_arr->len;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	thread_dat = g_new0(struct unlink_thread_data, serv_arr->len);
	threads = g_new(pthread_t, serv_arr->len);
	
	for (i = 0; i < nthreads; i++) {
		thread_dat[i].serv = g_ptr_array_index(serv_arr, i);
		thread_dat[i].path = path;
		err = pthread_create(&threads[i], &attr,
				unlink_thread_func, &thread_dat[i]);
		if (err) {
			error2(err, "sshfsm_unlink: create thread failed"); 
			err = -EIO;
			goto out;
		}
	}
	
	for (i = 0; i < nthreads; i++) {
		err = pthread_join(threads[i], (void *) &err2);
		if (err) {
			error2(err, "sshfsm_unlink: join thread failed");
			err = -EIO;
			goto out;
		}
		if (!firsterr)
			firsterr = thread_dat[i].err;
		err3 *= err2;
	}
	err = err3 ? firsterr : 0;

out:
	pthread_attr_destroy(&attr);
	g_free(thread_dat);
	g_free(threads);
	return err;
}

/* rmdir */
static int rmdir_local(serv_t serv, const char *path)
{
	char *realpath = serv_add_path(serv, path);
	int res = rmdir(realpath);
	g_free(realpath);
	if (res == -1)
		return -errno;
	return res;
}

static int rmdir_remote(serv_t serv, const char *path)
{
	int err;
	struct buffer buf;
	
	buf_init(&buf, 0);
	buf_add_path(serv, &buf, path);
	err = sftp_request(serv, SSH_FXP_RMDIR, &buf, SSH_FXP_STATUS, NULL);
	buf_free(&buf);
	return err;
}

static int serv_rmdir(serv_t serv, const char *path)
{
	return serv->local ? rmdir_local(serv, path) : rmdir_remote(serv, path);
}

struct rmdir_thread_data {
	serv_t serv;
	const char *path;
	int err;
};

static void * rmdir_thread_func(void *data)
{
	struct rmdir_thread_data *p = (struct rmdir_thread_data *) data;
	p->err = serv_rmdir(p->serv, p->path);
	p->err ? pthread_exit((void *) -1) : pthread_exit((void *) 0);
}

static int sshfsm_rmdir(const char *path)
{
	if (serv_num == 1)
		return serv_rmdir(serv_0, path);
	
	int err = 0, err2, err3 = 0, firsterr = 0;
	GPtrArray *serv_arr;

	serv_arr = get_serv_arr(tree_lookup(path));
	if (serv_arr->len == 1) {
		serv_t serv = g_ptr_array_index(serv_arr, 0);
		err = serv_rmdir(serv, path);
		if (!err)
			tree_remove_path(path);
		return err;
	}
	
	pthread_t *threads;
	pthread_attr_t attr;
	unsigned int i, nthreads;
	struct rmdir_thread_data *thread_dat;
	
	nthreads = serv_arr->len;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	thread_dat = g_new0(struct rmdir_thread_data, nthreads);
	threads = g_new(pthread_t, nthreads);
	
	for (i = 0; i < nthreads; i++) {
		thread_dat[i].serv = g_ptr_array_index(serv_arr, i);
		thread_dat[i].path = path;
		err = pthread_create(&threads[i], &attr,
				rmdir_thread_func, &thread_dat[i]);
		if (err) {
			error2(err, "sshfsm_rmdir: create thread failed"); 
			err = -EIO;
			goto out;
		}
	}
	
	for (i = 0; i < nthreads; i++) {
		err = pthread_join(threads[i], (void *) &err2);
		if (err) {
			error2(err, "sshfsm_rmdir: join thread failed");
			err = -EIO;
			goto out;
		}
		if (!err2)
			tree_remove_serv(path, thread_dat[i].serv);
		if (!firsterr)
			firsterr = thread_dat[i].err;
		err3 += err2;
	}
	err = err3 ? firsterr : 0;

out:
	pthread_attr_destroy(&attr);
	g_free(thread_dat);
	g_free(threads);
	return err;
}

/* rename */
static int rename_local(serv_t serv, const char *from, const char *to)
{
	char *realfrom = serv_add_path(serv, from);
	char *realto = serv_add_path(serv, to);
	int res = rename(realfrom, realto);
	g_free(realfrom);
	g_free(realto);
	if (res == -1)
		return -errno;
	return res;
}

static int rename_remote(serv_t serv, const char *from, const char *to)
{
	int err;
	struct buffer buf;

	buf_init(&buf, 0);
	buf_add_path(serv, &buf, from);
	buf_add_path(serv, &buf, to);
	err = sftp_request(serv, SSH_FXP_RENAME, &buf, SSH_FXP_STATUS, NULL);
	buf_free(&buf);
	return err;
}

static int rename_remote_ext_posix(serv_t serv, const char *from, const char *to)
{
	int err;
	struct buffer buf;

	buf_init(&buf, 0);
	buf_add_string(&buf, SFTP_EXT_POSIX_RENAME);
	buf_add_path(serv, &buf, from);
	buf_add_path(serv, &buf, to);
	err = sftp_request(serv, SSH_FXP_EXTENDED, &buf, SSH_FXP_STATUS, NULL);
	buf_free(&buf);
	return err;
}

static void random_string(char *str, int length)
{
	int i;
	for (i = 0; i < length; i++)
		*str++ = (char)('0' + rand_r(&sshfsm.randseed) % 10);
	*str = '\0';
}

static int serv_rename(serv_t serv, const char *from, const char *to)
{
	if (serv->local)
		return rename_local(serv, from, to);
	
	int err;
	if (sshfsm.ext_posix_rename)
		err = rename_remote_ext_posix(serv, from, to);
	else
		err = rename_remote(serv, from, to);
	if (err == -EPERM && sshfsm.rename_workaround) {
		size_t tolen = strlen(to);
		if (tolen + RENAME_TEMP_CHARS < PATH_MAX) {
			int tmperr;
			char totmp[PATH_MAX];
			strcpy(totmp, to);
			random_string(totmp + tolen, RENAME_TEMP_CHARS);
			tmperr = rename_remote(serv, to, totmp);
			if (!tmperr) {
				err = rename_remote(serv, from, to);
				if (!err)
					err = serv_unlink(serv, totmp);
				else
					rename_remote(serv, totmp, to);
			}
		}
	}
	return err;
}

struct rename_thread_data {
	serv_t serv;
	const char *from;
	const char *to;
	int err;
};

static void * rename_thread_func(void *data)
{
	struct rename_thread_data *p = (struct rename_thread_data *) data;
	p->err = serv_rename(p->serv, p->from, p->to);
	p->err ? pthread_exit((void *) -1) : pthread_exit((void *) 0);
}

static int sshfsm_rename(const char *from, const char *to)
{
	if (serv_num == 1)
		return serv_rename(serv_0, from, to);
	
	int err = 0, err2, err3 = 1, firsterr = 0;
	struct stat stbuf;
	GPtrArray *serv_arr;

	memset(&stbuf, 0, sizeof(struct stat));
	if (cache_get_attr(from, &stbuf)) 
		sshfsm_getattr(from, &stbuf);

	serv_arr = get_serv_arr(tree_lookup(from));
	if (serv_arr->len == 1) {
		serv_t serv = g_ptr_array_index(serv_arr, 0);
		err = serv_rename(serv, from, to);
		if (!err && S_ISDIR(stbuf.st_mode)) {
			tree_remove_path(from);
			tree_insert(to, serv);
		}
		return err;
	}
	
	pthread_t *threads;
	pthread_attr_t attr;
	unsigned int i, nthreads;
	struct rename_thread_data *thread_dat;

	nthreads = serv_arr->len;
	thread_dat = g_new0(struct rename_thread_data, nthreads);
	threads = g_new(pthread_t, nthreads);
	
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
		
	for (i = 0; i < nthreads; i++) {
		thread_dat[i].serv = g_ptr_array_index(serv_arr, i);
		thread_dat[i].from = from;
		thread_dat[i].to = to;
		err = pthread_create(&threads[i], &attr,
				rename_thread_func, &thread_dat[i]);
		if (err) {
			error2(err, "sshfsm_rename: create thread failed"); 
			err = -EIO;
			goto out;
		}
	}
	
	for (i = 0; i < nthreads; i++) {
		err = pthread_join(threads[i], (void *) &err2);
		if (err) {
			error2(err, "sshfsm_rename: join thread failed");
			err = -EIO;
			goto out;
		}
		if (!err2 && S_ISDIR(stbuf.st_mode)) {
			tree_remove_serv(from, thread_dat[i].serv);
			tree_insert(to, thread_dat[i].serv);
			debug("remove %s: insert %s", from, to);
		}
		if (!firsterr)
			firsterr = thread_dat[i].err;
		err3 *= err2;
	}
	err = err3 ? firsterr : 0;

out:
	pthread_attr_destroy(&attr);
	g_free(thread_dat);
	g_free(threads);
	return err;
}

/* chmod */
static int chmod_local(serv_t serv, const char *path, mode_t mode)
{
	char *realpath = serv_add_path(serv, path);
	int res = chmod(realpath, mode);
	g_free(realpath);
	if (res == -1)
		return -errno;
	return res;
}

static int chmod_remote(serv_t serv, const char *path,
	mode_t mode)
{
	int err;
	struct buffer buf;

	buf_init(&buf, 0);
	buf_add_path(serv, &buf, path);
	buf_add_uint32(&buf, SSH_FILEXFER_ATTR_PERMISSIONS);
	buf_add_uint32(&buf, mode);
	err = sftp_request(serv, SSH_FXP_SETSTAT, &buf, SSH_FXP_STATUS, NULL);
	buf_free(&buf);
	return err;
}

static int serv_chmod(serv_t serv, const char *path,
	mode_t mode)
{
	return serv->local ? chmod_local(serv, path, mode) : 
		chmod_remote(serv, path, mode);
}

static int sshfsm_chmod(const char *path, mode_t mode)
{
	if (serv_num == 1)
		return serv_chmod(serv_0, path, mode);
	
	int err = 0, firsterr = 0;
	unsigned int i;
	serv_t serv;
	GPtrArray *serv_arr = get_serv_arr(tree_lookup(path));
	for (i = 0; i < serv_arr->len; i++) {
		serv = g_ptr_array_index(serv_arr, i);
		err = serv_chmod(serv, path, mode);
		if (!err)
			return err;
		if (!firsterr)
			firsterr = err;
	}
	return firsterr;
}

/* chown */
static int chown_local(serv_t serv, const char *path, uid_t uid, gid_t gid)
{
	int res;
	char *realpath = serv_add_path(serv, path);
	if (sshfsm.follow_symlinks)
		res = chown(realpath, uid, gid);
	else
		res = lchown(realpath, uid, gid);
	g_free(realpath);
	if (res == -1)
		return -errno;
	return res;
}

static int chown_remote(serv_t serv, const char *path, 
	uid_t uid, gid_t gid)
{
	int err;
	struct buffer buf;
	
	buf_init(&buf, 0);
	buf_add_path(serv, &buf, path);
	buf_add_uint32(&buf, SSH_FILEXFER_ATTR_UIDGID);
	buf_add_uint32(&buf, uid);
	buf_add_uint32(&buf, gid);
	err = sftp_request(serv, SSH_FXP_SETSTAT, &buf, SSH_FXP_STATUS, NULL);
	buf_free(&buf);
	return err;
}

static int serv_chown(serv_t serv, const char *path, 
	uid_t uid, gid_t gid)
{
	return serv->local ? chown_local(serv, path, uid, gid) : 
		chown_remote(serv, path, uid, gid);
}

static int sshfsm_chown(const char *path, uid_t uid, gid_t gid)
{
	if (serv_num == 1)
		return serv_chown(serv_0, path, uid, gid);
	
	int err = 0, firsterr = 0;
	unsigned int i;
	serv_t serv;
	GPtrArray *serv_arr = get_serv_arr(tree_lookup(path));
	for (i = 0; i < serv_arr->len; i++) {
		serv = g_ptr_array_index(serv_arr, i);
		err = serv_chown(serv, path, uid, gid);
		if (!err)
			return err;
		if (!firsterr)
			firsterr = err;
	}
	return firsterr;
}

/* truncate */
static int truncate_local(serv_t serv, const char *path, off_t size)
{
	char *realpath = serv_add_path(serv, path);
	int res = truncate(realpath, size);
	g_free(realpath);
	if (res == -1)
		return -errno;
	return res;
}

static int truncate_remote_workaround(serv_t serv, 
	const char *path, off_t size, struct fuse_file_info *fi);

static int truncate_remote(serv_t serv, const char *path, 
	off_t size)
{
	int err;
	struct buffer buf;

	serv->modifver ++;
	if (size == 0 || sshfsm.truncate_workaround)
		return truncate_remote_workaround(serv, path, size, NULL);

	buf_init(&buf, 0);
	buf_add_path(serv, &buf, path);
	buf_add_uint32(&buf, SSH_FILEXFER_ATTR_SIZE);
	buf_add_uint64(&buf, size);
	err = sftp_request(serv, SSH_FXP_SETSTAT, &buf, SSH_FXP_STATUS, NULL);
	buf_free(&buf);
	return err;
}

static int serv_truncate(serv_t serv, const char *path, off_t size)
{
	return serv->local ? truncate_local(serv, path, size) : 
		truncate_remote(serv, path, size);
}

static int sshfsm_truncate(const char *path, off_t size)
{
	if (serv_num == 1)
		return serv_truncate(serv_0, path, size);
	
	GPtrArray *serv_arr = get_serv_arr(tree_lookup(path));
	unsigned int i;
	serv_t serv;
	int err = 0, firsterr = 0;

	for (i = 0; i < serv_arr->len; i++) {
		serv = g_ptr_array_index(serv_arr, 0);
		err = serv_truncate(serv, path, size);
		if (!err)
			return err;
		if (!firsterr)
			firsterr = err;
	}
	return firsterr;
}

/* utime */
static int utime_local(serv_t serv, const char *path, struct utimbuf *ubuf)
{
	char *realpath = serv_add_path(serv, path);
	int res = utime(realpath, ubuf);
	g_free(realpath);
	if (res == -1)
		return -errno;
	return res;
}

static int utime_remote(serv_t serv, const char *path, 
	struct utimbuf *ubuf)
{
	int err;
	struct buffer buf;
	buf_init(&buf, 0);
	buf_add_path(serv, &buf, path);
	buf_add_uint32(&buf, SSH_FILEXFER_ATTR_ACMODTIME);
	buf_add_uint32(&buf, ubuf->actime);
	buf_add_uint32(&buf, ubuf->modtime);
	err = sftp_request(serv, SSH_FXP_SETSTAT, &buf, SSH_FXP_STATUS, NULL);
	buf_free(&buf);
	return err;
}

static int serv_utime(serv_t serv, const char *path, 
	struct utimbuf *ubuf)
{
	return serv->local ? utime_local(serv, path, ubuf) : 
		utime_remote(serv, path, ubuf);
}

static int sshfsm_utime(const char *path, struct utimbuf *ubuf)
{
	if (serv_num == 1)
		return serv_utime(serv_0, path, ubuf);
	
	GPtrArray *serv_arr = get_serv_arr(tree_lookup(path));
	unsigned int i;
	serv_t serv;
	int err = 0, firsterr = 0;

	for (i = 0; i < serv_arr->len; i++) {
		serv = g_ptr_array_index(serv_arr, 0);
		err = serv_utime(serv, path, ubuf);
		if (!err)
			return err;
		if (!firsterr)
			firsterr = err;
	}
	return firsterr;
}

/* open */
static inline int serv_file_is_conn(struct sshfsm_file *sf)
{
	return sf->connver == sf->serv->connver;
}

static int open_local(serv_t serv, const char *path, mode_t mode, 
	struct fuse_file_info *fi)
{
	struct stat stbuf;
	struct sshfsm_file *sf;
	uint64_t wrctr = cache_get_write_ctr();
	char *realpath = serv_add_path(serv, path);
	
	if (sshfsm.sync_write)
		fi->flags |= O_SYNC;
	sf = g_new0(struct sshfsm_file, 1);
	sf->serv = serv;
	sf->local_fd = open(realpath, fi->flags, mode);
	if (sf->local_fd == -1) {
		cache_invalidate(path);
		g_free(sf);
		g_free(realpath);
		return -errno;
	}
	int res = lstat(realpath, &stbuf);
	if (res == -1) {
		cache_invalidate(path);
		g_free(sf);
		g_free(realpath);
		return -errno;
	}
	cache_add_attr(path, &stbuf, wrctr);
	fi->fh = (unsigned long) sf;
	g_free(realpath);
	return res;
}

static int open_remote(serv_t serv, const char *path, 
	mode_t mode, struct fuse_file_info *fi)
{
	int err;
	int err2;
	struct buffer buf;
	struct buffer outbuf;
	struct stat stbuf;
	struct sshfsm_file *sf;
	struct request *open_req;
	uint32_t pflags = 0;
	struct iovec iov;
	uint8_t type;
	uint64_t wrctr = cache_get_write_ctr();

	if ((fi->flags & O_ACCMODE) == O_RDONLY)
		pflags = SSH_FXF_READ;
	else if((fi->flags & O_ACCMODE) == O_WRONLY)
		pflags = SSH_FXF_WRITE;
	else if ((fi->flags & O_ACCMODE) == O_RDWR)
		pflags = SSH_FXF_READ | SSH_FXF_WRITE;
	else
		return -EINVAL;

	if (fi->flags & O_CREAT)
		pflags |= SSH_FXF_CREAT;

	if (fi->flags & O_EXCL)
		pflags |= SSH_FXF_EXCL;

	if (fi->flags & O_TRUNC)
		pflags |= SSH_FXF_TRUNC;

	sf = g_new0(struct sshfsm_file, 1);
	list_init(&sf->write_reqs);
	pthread_cond_init(&sf->write_finished, NULL);
	/* Assume random read after open */
	sf->is_seq = 0;
	sf->refs = 1;
	sf->next_pos = 0;
	sf->serv = serv;
	sf->modifver= serv->modifver;
	sf->connver = serv->connver;
	buf_init(&buf, 0);
	buf_add_path(serv, &buf, path);
	buf_add_uint32(&buf, pflags);
	buf_add_uint32(&buf, SSH_FILEXFER_ATTR_PERMISSIONS);
	buf_add_uint32(&buf, mode);
	buf_to_iov(&buf, &iov);
	sftp_request_send(serv, SSH_FXP_OPEN, &iov, 1, NULL, NULL, 1, NULL,
			  &open_req);
	buf_clear(&buf);
	buf_add_path(serv, &buf, path);
	type = sshfsm.follow_symlinks ? SSH_FXP_STAT : SSH_FXP_LSTAT;
	err2 = sftp_request(serv, type, &buf, SSH_FXP_ATTRS, &outbuf);
	if (!err2) {
		if (buf_get_attrs(serv, &outbuf, &stbuf, NULL) == -1)
			err2 = -EIO;
		buf_free(&outbuf);
	}
	err = sftp_request_wait(serv, open_req, SSH_FXP_OPEN, SSH_FXP_HANDLE,
				&sf->handle);
	if (!err && err2) {
		buf_finish(&sf->handle);
		sftp_request(serv, SSH_FXP_CLOSE, &sf->handle, 0, NULL);
		buf_free(&sf->handle);
		err = err2;
	}

	if (!err) {
		cache_add_attr(path, &stbuf, wrctr);
		buf_finish(&sf->handle);
		fi->fh = (unsigned long) sf;
	} else {
		cache_invalidate(path);
		g_free(sf);
	}
	buf_free(&buf);
	return err;
}

static void fwd_serv_arr_cleanup(time_t timeout)
{
	time_t now = time(NULL);
	unsigned int i;
	serv_t serv;
	GPtrArray *arr;
	
	arr = sshfsm.fwd_serv_arr;
	if (now > sshfsm.fwd_serv_arr_last_cleaned + timeout) {
		for (i = 0; i < arr->len; i++) {
			serv = (serv_t) g_ptr_array_index(arr, i);
			if (serv->forward_refs > 0 || 
				now > serv->forward_valid + timeout)
				continue;
			close_conn(serv);
			g_free(serv->hostname);
			g_free(serv->basepath);
			pthread_mutex_destroy(&serv->lock);
			pthread_mutex_destroy(&serv->lock_write);
			pthread_cond_destroy(&serv->outstanding_cond);
			g_hash_table_destroy(serv->reqtab);
			g_ptr_array_remove_fast(arr, serv);
		}
		sshfsm.fwd_serv_arr_last_cleaned = now;
	}
}

static serv_t fwd_serv_arr_lookup(const struct in_addr *inaddr)
{
	
	unsigned int i;
	serv_t serv;
	GPtrArray *arr;
	
	fwd_serv_arr_cleanup(sshfsm.forward_timeout);
	
	arr = sshfsm.fwd_serv_arr;
	for (i = 0; i < arr->len; i++) {
		serv = (serv_t) g_ptr_array_index(arr, i);
		if (serv->inaddr.s_addr == inaddr->s_addr) {
			serv->forward_valid = time(NULL);
			return serv;
		}
	}

	/* Create a new server */
	serv = g_new0(struct serv, 1);
	serv->hostname = g_strdup(inet_ntoa(*inaddr));
	serv->basepath = g_strdup(sshfsm.forward_io);
	serv->inaddr.s_addr = inaddr->s_addr;
	serv->fd = -1;
	serv->ptyfd = -1;
	serv->ptyslavefd = -1;
	serv->local = 0;
	serv->is_forward = 1;
	serv->forward_refs = 0;
	serv->forward_valid = time(NULL);
	pthread_mutex_init(&serv->lock, NULL);
	pthread_mutex_init(&serv->lock_write, NULL);
	pthread_cond_init(&serv->outstanding_cond, NULL);
	serv->reqtab = g_hash_table_new(NULL, NULL);
	if (!serv->reqtab) {
		error3("failed to create hash table");
		return NULL;
	}
	serv->connver = 0;
	serv->processing_thread_started = 0;
	debug("forward I/O: add arr[%d]: %s(%s):%s,local=%d,rank=%d,", arr->len,
		  serv->hostname, inet_ntoa(serv->inaddr), serv->basepath, 
		  serv->local, serv->rank);
	g_ptr_array_add(arr, (gpointer) serv);

	return serv;
}

static int open_forward(serv_t serv, const char *path, mode_t mode,
	struct fuse_file_info *fi)
{
	serv_t fwd_serv;
	struct stat stbuf;
	struct in_addr inaddr;
	int err;
	memset(&stbuf, 0, sizeof(struct stat));
	if (cache_get_attr(path, &stbuf)) {
		err = serv_getattr(serv, path, &stbuf);
		if (err)
			return err;
	}
	
	err = get_inaddr(stbuf.st_ino, &inaddr);
	if (err)
		return -EIO;
	
	/* Already connected to the server */
	if (get_ino_hops(stbuf.st_ino) <= 1)
		return open_remote(serv, path, mode, fi);
	fwd_serv = serv_arr_lookup(&inaddr);
	if (fwd_serv)
		return open_remote(fwd_serv, path, mode, fi);
	fwd_serv = fwd_serv_arr_lookup(&inaddr);
	if (fwd_serv)
		return open_remote(fwd_serv, path, mode, fi);
	
	/* Not yet */
	debug("forward I/O: connecting %s ...", fwd_serv->hostname);
	if (!sshfsm.delay_connect) {
		if (connect_remote(fwd_serv) == -1)
			return -1;

		if (sshfsm.detect_uid)
			sftp_detect_uid(fwd_serv);

		if (!sshfsm.no_check_root && serv_check_root(fwd_serv) == -1)
			return -1;
	}
	
	err = open_remote(fwd_serv, path, mode, fi);
	if (!err)
		fwd_serv->forward_refs ++;
	return err;
}

static int serv_open_common(serv_t serv, const char *path, 
	mode_t mode, struct fuse_file_info *fi)
{
	int err;
	if (sshfsm.forward_io) {
		err = open_forward(serv, path, mode, fi);
		if (!err)
			return 0;
		/* If failed to open_forward(), fall to ordinary routines */
	}
	
	return serv->local ? open_local(serv, path, mode, fi) :
		open_remote(serv, path, mode, fi);
}

static int sshfsm_open(const char *path, struct fuse_file_info *fi)
{
	if (serv_num == 1)
		return serv_open_common(serv_0, path, 0, fi);

	unsigned int i;
	serv_t serv;
	int err = 0, firsterr = 0;
	GPtrArray *serv_arr = get_serv_arr(tree_lookup(path));
	for (i = 0; i < serv_arr->len; i++) {
		serv = g_ptr_array_index(serv_arr, i);
		err = serv_open_common(serv, path, 0, fi);
		if (!err)
			return err;
		if (!firsterr)
			firsterr = err;
	}
	return firsterr;
}

/* flush */
static inline struct sshfsm_file *get_sshfsm_file(struct fuse_file_info *fi)
{
	return (struct sshfsm_file *) (uintptr_t) fi->fh;
}

static int flush_local(int fd)
{
	int res = fsync(fd);
	if (res == -1)
		return -errno;
	return res;
}

static int sshfsm_flush(const char *path, struct fuse_file_info *fi)
{
	struct sshfsm_file *sf = get_sshfsm_file(fi);
	serv_t serv = sf->serv;
	if (serv->local)
		return flush_local(sf->local_fd);
	
	int err;
	struct list_head write_reqs;
	struct list_head *curr_list;
	(void) path;

	if (!serv_file_is_conn(sf))
		return -EIO;

	if (sshfsm.sync_write)
		return 0;

	pthread_mutex_lock(&serv->lock);
	if (!list_empty(&sf->write_reqs)) {
		curr_list = sf->write_reqs.prev;
		list_del(&sf->write_reqs);
		list_init(&sf->write_reqs);
		list_add(&write_reqs, curr_list);
		while (!list_empty(&write_reqs))
			pthread_cond_wait(&sf->write_finished, &serv->lock);
	}
	err = sf->write_error;
	sf->write_error = 0;
	pthread_mutex_unlock(&serv->lock);
	return err;
}

/* fsync */
static int sshfsm_fsync(const char *path, int isdatasync,
                       struct fuse_file_info *fi)
{
	(void) isdatasync;
	return sshfsm_flush(path, fi);
}

/* release */
static void sshfsm_file_put(struct sshfsm_file *sf)
{
	sf->refs--;
	if (!sf->refs)
		g_free(sf);
}

static void sshfsm_file_get(struct sshfsm_file *sf)
{
	sf->refs++;
}

static int sshfsm_release(const char *path, struct fuse_file_info *fi)
{
	struct sshfsm_file *sf = get_sshfsm_file(fi);
	serv_t serv = sf->serv;
	if (serv->local) {
		close(sf->local_fd);
		return 0;
	}

	struct buffer *handle = &sf->handle;
	if (serv_file_is_conn(sf)) {
		sshfsm_flush(path, fi);
		sftp_request(serv, SSH_FXP_CLOSE, handle, 0, NULL);
	}
	buf_free(handle);
	chunk_put_locked(serv, sf->readahead);
	sshfsm_file_put(sf);
	if (serv->is_forward)
		serv->forward_refs --;
	return 0;
}

/* read */
static int read_local(int fd, char *rbuf, size_t size, off_t offset)
{
	int res = pread(fd, rbuf, size, offset);
	if (res == -1)
		return -errno;
	return res;
}

static int serv_sync_read(struct sshfsm_file *sf, char *rbuf, size_t size,
                           off_t offset)
{
	int err;
	struct buffer buf;
	struct buffer data;
	struct buffer *handle = &sf->handle;
	serv_t serv = sf->serv;
	buf_init(&buf, 0);
	buf_add_buf(&buf, handle);
	buf_add_uint64(&buf, offset);
	buf_add_uint32(&buf, size);
	err = sftp_request(serv, SSH_FXP_READ, &buf, SSH_FXP_DATA, &data);
	if (!err) {
		uint32_t retsize;
		err = -EIO;
		if (buf_get_uint32(&data, &retsize) != -1) {
			if (retsize > size)
				fprintf(stderr, "long read\n");
			else {
				buf_get_mem(&data, rbuf, retsize);
				err = retsize;
			}
		}
		buf_free(&data);
	} else if (err == MY_EOF)
		err = 0;
	buf_free(&buf);
	return err;
}

static void serv_read_end(struct request *req)
{
	struct read_chunk *chunk = (struct read_chunk *) req->data;
	if (req->error)
		chunk->res = req->error;
	else if (req->replied) {
		chunk->res = -EIO;

		if (req->reply_type == SSH_FXP_STATUS) {
			uint32_t serr;
			if (buf_get_uint32(&req->reply, &serr) != -1) {
				if (serr == SSH_FX_EOF)
					chunk->res = 0;
			}
		} else if (req->reply_type == SSH_FXP_DATA) {
			uint32_t retsize;
			if (buf_get_uint32(&req->reply, &retsize) != -1) {
				if (retsize > chunk->size)
					fprintf(stderr, "long read\n");
				else {
					chunk->res = retsize;
					chunk->data = req->reply;
					buf_init(&req->reply, 0);
				}
			}
		} else
			error3("protocol error");
	} else
		chunk->res = -EIO;

	sem_post(&chunk->ready);
	chunk_put(chunk);
}

static void serv_read_begin(struct request *req)
{
	struct read_chunk *chunk = (struct read_chunk *) req->data;
	chunk->refs++;
}

static void serv_send_async_read(struct sshfsm_file *sf,
                                  struct read_chunk *chunk)
{
	struct buffer buf;
	struct buffer *handle = &sf->handle;
	struct iovec iov;
	serv_t serv = sf->serv;
	buf_init(&buf, 0);
	buf_add_buf(&buf, handle);
	buf_add_uint64(&buf, chunk->offset);
	buf_add_uint32(&buf, chunk->size);
	buf_to_iov(&buf, &iov);
	sftp_request_send(serv, SSH_FXP_READ, &iov, 1, serv_read_begin,
			  serv_read_end, 0, chunk, NULL);
	buf_free(&buf);
}

static void submit_read(struct sshfsm_file *sf, size_t size, off_t offset,
                        struct read_chunk **chunkp)
{
	struct read_chunk *chunk = g_new0(struct read_chunk, 1);
	serv_t serv = sf->serv;

	sem_init(&chunk->ready, 0, 0);
	buf_init(&chunk->data, 0);
	chunk->offset = offset;
	chunk->size = size;
	chunk->refs = 1;
	chunk->modifver = serv->modifver;
	serv_send_async_read(sf, chunk);
	pthread_mutex_lock(&serv->lock);
	chunk_put(*chunkp);
	*chunkp = chunk;
	pthread_mutex_unlock(&serv->lock);
}

static int wait_chunk(serv_t serv, struct read_chunk *chunk, 
	char *buf, size_t size)
{
	int res;
	while (sem_wait(&chunk->ready));
	res = chunk->res;
	if (res > 0) {
		if ((size_t) res > size)
			res = size;
		buf_get_mem(&chunk->data, buf, res);
		chunk->offset += res;
		chunk->size -= res;
		chunk->res -= res;
	}
	sem_post(&chunk->ready);
	chunk_put_locked(serv, chunk);
	return res;
}

static struct read_chunk *search_read_chunk(struct sshfsm_file *sf, off_t offset)
{
	struct read_chunk *ch = sf->readahead;
	serv_t serv = sf->serv;
	if (ch && ch->offset == offset && ch->modifver == serv->modifver) {
		ch->refs++;
		return ch;
	} else
		return NULL;
}

static int serv_async_read(struct sshfsm_file *sf, char *rbuf, size_t size,
                            off_t offset)
{
	int res = 0;
	size_t total = 0;
	struct read_chunk *chunk;
	struct read_chunk *chunk_prev = NULL;
	size_t origsize = size;
	int curr_is_seq;
	serv_t serv = sf->serv;

	pthread_mutex_lock(&serv->lock);
	curr_is_seq = sf->is_seq;
	sf->is_seq = (sf->next_pos == offset && sf->modifver == serv->modifver);
	sf->next_pos = offset + size;
	sf->modifver = serv->modifver;
	chunk = search_read_chunk(sf, offset);
	pthread_mutex_unlock(&serv->lock);

	if (chunk && chunk->size < size) {
		chunk_prev = chunk;
		size -= chunk->size;
		offset += chunk->size;
		chunk = NULL;
	}

	if (!chunk)
		submit_read(sf, size, offset, &chunk);

	if (curr_is_seq && chunk && chunk->size <= size)
		submit_read(sf, origsize, offset + size, &sf->readahead);

	if (chunk_prev) {
		size_t prev_size = chunk_prev->size;
		res = wait_chunk(serv, chunk_prev, rbuf, prev_size);
		if (res < (int) prev_size) {
			chunk_put_locked(serv, chunk);
			return res;
		}
		rbuf += res;
		total += res;
	}
	res = wait_chunk(serv, chunk, rbuf, size);
	if (res > 0)
		total += res;
	if (res < 0)
		return res;

	return total;
}

static int sshfsm_read(const char *path, char *rbuf, size_t size, off_t offset,
                      struct fuse_file_info *fi)
{
	struct sshfsm_file *sf = get_sshfsm_file(fi);
	(void) path;

	if (sf->serv->local)
		return read_local(sf->local_fd, rbuf, size, offset);

	if (!serv_file_is_conn(sf))
		return -EIO;

	if (sshfsm.sync_read)
		return serv_sync_read(sf, rbuf, size, offset);
	else
		return serv_async_read(sf, rbuf, size, offset);
}

/* write */
static int write_local(int fd, const char *wbuf, size_t size, off_t offset)
{
	int res = pwrite(fd, wbuf, size, offset);
	if (res == -1)
		return -errno;
	return res;
}

static void serv_write_begin(struct request *req)
{
	struct sshfsm_file *sf = (struct sshfsm_file *) req->data;

	sshfsm_file_get(sf);
	list_add(&req->list, &sf->write_reqs);
}

static void serv_write_end(struct request *req)
{
	uint32_t serr;
	struct sshfsm_file *sf = (struct sshfsm_file *) req->data;

	if (req->error)
		sf->write_error = req->error;
	else if (req->replied) {
		if (req->reply_type != SSH_FXP_STATUS) {
			error3("protocol error");
		} else if (buf_get_uint32(&req->reply, &serr) != -1 &&
			 serr != SSH_FX_OK) {
			sf->write_error = -EIO;
		}
	}
	list_del(&req->list);
	pthread_cond_broadcast(&sf->write_finished);
	sshfsm_file_put(sf);
}

static int write_remote(const char* wbuf, size_t size,
	off_t offset, struct fuse_file_info *fi)
{
	struct sshfsm_file *sf = get_sshfsm_file(fi);
	int err;
	struct buffer buf;
	struct buffer *handle = &sf->handle;
	struct iovec iov[2];
	serv_t serv = sf->serv;

	if (!serv_file_is_conn(sf))
		return -EIO;
	
	serv->modifver ++;
	buf_init(&buf, 0);
	buf_add_buf(&buf, handle);
	buf_add_uint64(&buf, offset);
	buf_add_uint32(&buf, size);
	buf_to_iov(&buf, &iov[0]);
	iov[1].iov_base = (void *) wbuf;
	iov[1].iov_len = size;
	if (!sshfsm.sync_write && !sf->write_error) {
		err = sftp_request_send(serv, SSH_FXP_WRITE, iov, 2,
					serv_write_begin, serv_write_end,
					0, sf, NULL);
	} else {
		err = sftp_request_iov(serv, SSH_FXP_WRITE, iov, 2, SSH_FXP_STATUS,
				       NULL);
	}
	buf_free(&buf);
	return err ? err : (int) size;
}

static int sshfsm_write(const char *path, const char *wbuf, size_t size,
	off_t offset, struct fuse_file_info *fi)
{
	(void) path;
	struct sshfsm_file *sf = get_sshfsm_file(fi);
	if (sf->serv->local)
		return write_local(sf->local_fd, wbuf, size, offset);

	return write_remote(wbuf, size, offset, fi);
}

/* statfs & statvfs */
static int statvfs_local(serv_t serv, const char *path, struct statvfs *stbuf)
{
	char *realpath = serv_add_path(serv, path);
	int res = statvfs(realpath, stbuf);
	g_free(realpath);
	if (res == -1)
		return -errno;
	return res;
}

static int statvfs_remote_ext(serv_t serv, const char *path,
	struct statvfs *stbuf)
{
	int err;
	struct buffer buf;
	struct buffer outbuf;
	buf_init(&buf, 0);
	buf_add_string(&buf, SFTP_EXT_STATVFS);
	buf_add_path(serv, &buf, path);
	err = sftp_request(serv, SSH_FXP_EXTENDED, &buf, SSH_FXP_EXTENDED_REPLY,
			   &outbuf);
	if (!err) {
		if (buf_get_statvfs(&outbuf, stbuf) == -1)
			err = -EIO;
		buf_free(&outbuf);
	}
	buf_free(&buf);
	return err;
}

static int serv_ext_statvfs(serv_t serv, const char *path, 
	struct statvfs *stbuf)
{
	return serv->local ? statvfs_local(serv, path, stbuf) : 
		statvfs_remote_ext(serv, path, stbuf);
}

struct ext_statvfs_thread_data {
	serv_t serv;
	const char *path;
	struct statvfs stbuf;
	int err;
};

static void * ext_statvfs_thread_func(void *data)
{
	struct ext_statvfs_thread_data *p = 
		(struct ext_statvfs_thread_data *) data;
	p->err = serv_ext_statvfs(p->serv, p->path, &p->stbuf);
	p->err ? pthread_exit((void *) -1) : pthread_exit((void *) 0);
}

static int sshfsm_ext_statvfs(const char *path, struct statvfs *stbuf)
{
	if (serv_num == 1)
		return serv_ext_statvfs(serv_0, path, stbuf);

	pthread_t *threads;
	pthread_attr_t attr;
	unsigned int i;
	int err = 0, err2, err3 = 1, firsterr = 0;
	struct ext_statvfs_thread_data *thread_dat = 
		g_new0(struct ext_statvfs_thread_data, serv_num);
	threads = g_new(pthread_t, serv_num);
	
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	for (i = 0; i < serv_num; i++) {
		thread_dat[i].serv = serv_i(i);
		thread_dat[i].path = path;
		err = pthread_create(&threads[i], &attr,
				ext_statvfs_thread_func, &thread_dat[i]);
		if (err) {
			error2(err, "sshfsm_ext_statvfs: create thread failed"); 
			err = -EIO;
			goto out;
		}
	}
	
	for (i = 0; i < serv_num; i++) {
		err = pthread_join(threads[i], (void *) &err2);
		if (err) {
			error2(err, "sshfsm_ext_statvfs: join thread failed");
			err = -EIO;
			goto out;
		}
		if (!err2) {
			if (i == 0) {
				*stbuf = thread_dat[i].stbuf;
			} else {
				stbuf->f_blocks += thread_dat[i].stbuf.f_blocks;
				stbuf->f_bfree += thread_dat[i].stbuf.f_bfree;
				stbuf->f_bavail += thread_dat[i].stbuf.f_bavail;
				stbuf->f_files += thread_dat[i].stbuf.f_files;
				stbuf->f_ffree += thread_dat[i].stbuf.f_ffree;
				stbuf->f_favail += thread_dat[i].stbuf.f_favail;
				/* ignore stbuf->f_fsid */
				/* ignore stbuf->f_flag */
				/* Choose the minimum one for overall limit */
				if (stbuf->f_namemax > thread_dat[i].stbuf.f_namemax)
					stbuf->f_namemax = thread_dat[i].stbuf.f_namemax;
			}
		}
		if (!firsterr)
			firsterr = thread_dat[i].err;
		err3 *= err2;
	}
	err = err3 ? firsterr : 0;

out:
	pthread_attr_destroy(&attr);
	g_free(thread_dat);
	g_free(threads);
	return err;
}


#if FUSE_VERSION >= 25
static int sshfsm_statfs(const char *path, struct statvfs *buf)
{
	if (sshfsm.ext_statvfs)
		return sshfsm_ext_statvfs(path, buf);

	buf->f_namemax = 255;
	buf->f_bsize = sshfsm.blksize;
	/*
	 * df seems to use f_bsize instead of f_frsize, so make them
	 * the same
	 */
	buf->f_frsize = buf->f_bsize;
	buf->f_blocks = buf->f_bfree =  buf->f_bavail =
		1000ULL * 1024 * 1024 * 1024 / buf->f_frsize;
	buf->f_files = buf->f_ffree = 1000000000;
	return 0;
}
#else
static int sshfsm_statfs(const char *path, struct statfs *buf)
{
	if (sshfsm.ext_statvfs) {
		int err;
		struct statvfs vbuf;

		err = sshfsm_ext_statvfs(path, &vbuf);
		if (!err) {
			buf->f_bsize = vbuf.f_bsize;
			buf->f_blocks = vbuf.f_blocks;
			buf->f_bfree = vbuf.f_bfree;
			buf->f_bavail = vbuf.f_bavail;
			buf->f_files = vbuf.f_files;
			buf->f_ffree = vbuf.f_ffree;
			buf->f_namelen = vbuf.f_namemax;
		}
		return err;
	}

	buf->f_namelen = 255;
	buf->f_bsize = sshfsm.blksize;
	buf->f_blocks = buf->f_bfree = buf->f_bavail =
		1000ULL * 1024 * 1024 * 1024 / buf->f_bsize;
	buf->f_files = buf->f_ffree = 1000000000;
	return 0;
}
#endif

/* create */
#if FUSE_VERSION >= 25
static int sshfsm_create(const char *path, mode_t mode,
                        struct fuse_file_info *fi)
{
	if (serv_num == 1)
		return serv_open_common(serv_0, path, mode, fi);
	
	int err = 0, firsterr = 0;
	unsigned int i;
	serv_t serv;
	GPtrArray *serv_arr = get_serv_arr(tree_lookup(path));
	for (i = 0; i < serv_arr->len; i++) {
		serv = g_ptr_array_index(serv_arr, i);
		err = serv_open_common(serv, path, mode, fi);
		if (!err)
			return err;
		if (!firsterr)
			firsterr = err;
	}
	return firsterr;
}

/* ftruncate */
static int ftruncate_remote(serv_t serv, const char *path, off_t size,
	struct fuse_file_info *fi)
{
	int err;
	struct buffer buf;
	(void) path;
	struct sshfsm_file *sf = get_sshfsm_file(fi);

	if (!serv_file_is_conn(sf))
		return -EIO;

	serv->modifver ++;
	if (sshfsm.truncate_workaround)
		return truncate_remote_workaround(serv, path, size, fi);

	buf_init(&buf, 0);
	buf_add_buf(&buf, &sf->handle);
	buf_add_uint32(&buf, SSH_FILEXFER_ATTR_SIZE);
	buf_add_uint64(&buf, size);
	err = sftp_request(serv, SSH_FXP_FSETSTAT, &buf, SSH_FXP_STATUS, NULL);
	buf_free(&buf);

	return err;
}

static int sshfsm_ftruncate(const char *path, off_t size,
    struct fuse_file_info *fi)
{
	struct sshfsm_file *sf = get_sshfsm_file(fi);
	serv_t serv = sf->serv;

	if (serv->local)
		return truncate_local(serv, path, size);

	return ftruncate_remote(serv, path, size, fi);
}
#endif

/* fgetattr */
static int fgetattr_local(int fd, struct stat *stbuf)
{
	int res = fstat(fd, stbuf);
	if (res == -1)
		return -errno;
	return 0;
}

static int fgetattr_remote(serv_t serv, struct stat *stbuf,
	struct fuse_file_info *fi)
{
	int err;
	struct buffer buf;
	struct buffer outbuf;
	struct sshfsm_file *sf = get_sshfsm_file(fi);

	if (!serv_file_is_conn(sf))
		return -EIO;

	buf_init(&buf, 0);
	buf_add_buf(&buf, &sf->handle);
	err = sftp_request(serv, SSH_FXP_FSTAT, &buf, SSH_FXP_ATTRS, &outbuf);
	if (!err) {
		if (buf_get_attrs(serv, &outbuf, stbuf, NULL) == -1)
			err = -EIO;
		buf_free(&outbuf);
	}
	buf_free(&buf);
	return err;
}

static int sshfsm_fgetattr(const char *path, struct stat *stbuf,
	struct fuse_file_info *fi)
{
	struct sshfsm_file *sf = get_sshfsm_file(fi);
	serv_t serv = sf->serv;
	(void) path;

	if (serv->local)
		return fgetattr_local(sf->local_fd, stbuf);
	
	return fgetattr_remote(serv, stbuf, fi);
}

/* truncate */
static int serv_truncate_zero(serv_t serv, const char *path)
{
	int err;
	struct fuse_file_info fi;

	fi.flags = O_WRONLY | O_TRUNC;
	err = serv_open_common(serv, path, 0, &fi);
	if (!err)
		sshfsm_release(path, &fi);

	return err;
}

static size_t calc_buf_size(off_t size, off_t offset)
{
	return offset + sshfsm.max_read < size ? sshfsm.max_read : size - offset;
}

static int serv_truncate_shrink(serv_t serv, const char *path, 
	off_t size)
{
	int res;
	char *data;
	off_t offset;
	struct fuse_file_info fi;

	data = calloc(size, 1);
	if (!data)
		return -ENOMEM;

	fi.flags = O_RDONLY;
	res = serv_open_common(serv, path, 0, &fi);
	if (res)
		goto out;

	for (offset = 0; offset < size; offset += res) {
		size_t bufsize = calc_buf_size(size, offset);
		res = sshfsm_read(path, data + offset, bufsize, offset, &fi);
		if (res <= 0)
			break;
	}
	sshfsm_release(path, &fi);
	if (res < 0)
		goto out;

	fi.flags = O_WRONLY | O_TRUNC;
	res = serv_open_common(serv, path, 0, &fi);
	if (res)
		goto out;

	for (offset = 0; offset < size; offset += res) {
		size_t bufsize = calc_buf_size(size, offset);
		res = sshfsm_write(path, data + offset, bufsize, offset, &fi);
		if (res < 0)
			break;
	}
	if (res >= 0)
		res = sshfsm_flush(path, &fi);
	sshfsm_release(path, &fi);

out:
	free(data);
	return res;
}

static int serv_truncate_extend(serv_t serv,
	const char *path, off_t size, struct fuse_file_info *fi)
{
	int res;
	char c = 0;
	struct fuse_file_info tmpfi;
	struct fuse_file_info *openfi = fi;
	if (!fi) {
		openfi = &tmpfi;
		openfi->flags = O_WRONLY;
		res = serv_open_common(serv, path, 0, openfi);
		if (res)
			return res;
	}
	res = sshfsm_write(path, &c, 1, size - 1, openfi);
	if (res == 1)
		res = sshfsm_flush(path, openfi);
	if (!fi)
		sshfsm_release(path, openfi);

	return res;
}

/*
 * Work around broken sftp servers which don't handle
 * SSH_FILEXFER_ATTR_SIZE in SETSTAT request.
 *
 * If new size is zero, just open the file with O_TRUNC.
 *
 * If new size is smaller than current size, then copy file locally,
 * then open/trunc and send it back.
 *
 * If new size is greater than current size, then write a zero byte to
 * the new end of the file.
 */
static int truncate_remote_workaround(serv_t serv, 
	const char *path, off_t size, struct fuse_file_info *fi)
{
	if (size == 0)
		return serv_truncate_zero(serv, path);
	else {
		struct stat stbuf;
		int err;
		if (fi)
			err = sshfsm_fgetattr(path, &stbuf, fi);
		else
			err = serv_getattr(serv, path, &stbuf);
		if (err)
			return err;
		if (stbuf.st_size == size)
			return 0;
		else if (stbuf.st_size > size)
			return serv_truncate_shrink(serv, path, size);
		else
			return serv_truncate_extend(serv, path, size, fi);
	}
}

static int processing_init(void)
{
	signal(SIGPIPE, SIG_IGN);

	if (serv_arr_init() == -1)
		return -1;

	return 0;
}

static int sftp_local_connect(serv_t serv)
{
	pid_t pid;
	int sockpair[2];

	if (access(sshfsm.sftp_local_server, R_OK | X_OK) == -1)
		fatal(1, "access \"%s\"", sshfsm.sftp_local_server);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockpair) == -1)
		fatal(1, "socketpair", NULL);
	
	pid = fork();
	if (pid == -1) {
		perror2("fork failed");
		_exit(1);
	}

	if (pid == 0) {
		if (dup2(sockpair[1], 0) == -1 || dup2(sockpair[1], 1) == -1) {
			perror2("dup2 failed");
			_exit(1);
		}
		close(sockpair[0]);
		close(sockpair[1]);
		signal(SIGINT, SIG_IGN);
		execl(sshfsm.sftp_local_server, "sftp.local.sshfsm", NULL);
		perror2("failed to exec \"%s\"", sshfsm.sftp_local_server);
		_exit(0);
	} else {
		close(sockpair[1]);
		serv->fd = sockpair[0];
	}
	
	return 0;
}

/* 
 * SFTP direct connection bypassing ssh
 * inspired by Kenjiro Taura
 */
enum {
	SFTP_CONN_FAILED = -1,
	SFTP_CONN_OK = 0,
	SFTP_CONN_REQ = 1,
	SFTP_CONN_REFUSE = 2,
};

static char * sftp_proxy_get_psk(size_t *len)
{
	if (sshfsm.psk_path)
		sshfsm.psk_path = g_strdup_and_free(sshfsm.psk_path);
 	else
		sshfsm.psk_path = g_strdup_printf("%s/key",
			sshfsm.config_dir);

	return get_file(sshfsm.psk_path, len, 0);
}

static int sftp_proxy_chk_psk(void)
{
	struct stat stbuf;

	if (sshfsm.psk_path)
		sshfsm.psk_path = g_strdup_and_free(sshfsm.psk_path);
	else
		sshfsm.psk_path = g_strdup_printf("%s/key",
			sshfsm.config_dir);
	
	if (stat(sshfsm.psk_path, &stbuf) == -1) {
		perror2("failed to stat \"%s\"", sshfsm.psk_path);
		return -1;
	}

	if (!S_ISREG(stbuf.st_mode)) {
		error3("psk file \"%s\" is not a regular file",
			sshfsm.psk_path);
		return -1;
	}

	if ((stbuf.st_mode & 0177) != 0 || 
		(stbuf.st_mode & 0600) != 0600) {
		error3("mode of psk file \"%s\" should be 0600", 
			sshfsm.psk_path);
		return -1;
	}

	return 0;
}

static int sftp_proxy_auth_challenge(int sockfd, const char *key)
{
	char *ptr, *msg, buf[MAX_BUF_LEN];
	int res;
	
	memset(buf, 0x0, MAX_BUF_LEN);
	snprintf(buf, MAX_BUF_LEN, "%d:%s", SFTP_CONN_REQ, key);
	res = write(sockfd, buf, strlen(buf));
	if (res < 0) {
		perror2("failed to write to socket");
		return SFTP_CONN_FAILED;
	}
	debug("sftp auth send %s", buf);
	
	memset(buf, 0x0, MAX_BUF_LEN);
	res = read(sockfd, buf, MAX_BUF_LEN);
	if (res < 0) {
		perror2("failed to read socket");
		return SFTP_CONN_FAILED;
	}
	debug("sftp auth recv %s", buf);
	
	ptr = strchr(buf, ':');
	*ptr = '\0';
	res = atoi(buf);
	msg = ptr + 1;

	if (res != SFTP_CONN_OK)
		error3("authentication: %s", msg);

	return res;
}

static int sftp_proxy_auth_response(int sockfd, const char *key)
{
	char *ptr, *msg, buf[1024];
	int res, code;

	code = SFTP_CONN_REFUSE;
	
	memset(buf, 0x0, MAX_BUF_LEN);
	res = read(sockfd, buf, MAX_BUF_LEN);
	if (res < 0) {
		perror2("failed to read from socket");
		return -1;
	}
		
	ptr = strchr(buf, ':');
	*ptr = '\0';
	res = atoi(buf);
	msg = ptr + 1;
	
	debug("recv authenticate msg %s", msg);

	if (res == SFTP_CONN_REQ) {
		switch (strcmp(msg, key)) {
			case 0:
				code = SFTP_CONN_OK;
				msg = "OK";
				break;
			default:
				code = SFTP_CONN_REFUSE;
				msg = "Connection refused";
		}
	}

	memset(buf, 0x0, MAX_BUF_LEN);
	snprintf(buf, MAX_BUF_LEN, "%d:%s", code, msg);
	res = write(sockfd, buf, MAX_BUF_LEN);
	if (res < 0) {
		perror2("failed to write to socket");
		return -1;
	}

	return code == SFTP_CONN_OK ? 0 : 1;
}

static int sftp_proxy_connect(serv_t serv, char *port)
{
	int err;
	int sock;
	socklen_t len;
	struct addrinfo *ai;
	struct addrinfo hint;
	char *key;
	size_t key_len;
	
	if (sftp_proxy_chk_psk() == -1)
		return -1;
	
	debug("direct connect to %s:%s", serv->hostname, port);

	memset(&hint, 0, sizeof(hint));
	hint.ai_family = PF_INET;
	hint.ai_socktype = SOCK_STREAM;
	
	err = getaddrinfo(serv->hostname, port, &hint, &ai);
	if (err) {
		error3("failed to resolve %s:%s: %s\n", serv->hostname, port,
			gai_strerror(err));
		return -1;
	}
	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (sock == -1) {
		perror2("failed to create socket");
		return -1;
	}
	err = connect(sock, ai->ai_addr, ai->ai_addrlen);
	if (err == -1) {
		perror2("failed to connect");
		return -1;
	}

	set_nodelay(sock);

	if (sshfsm.sndbuf) {
		len = sizeof(sshfsm.sndbuf);
		err = setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sshfsm, len);
		if (err == -1)
			perror("warning: failed to set SO_SNDBUF");
	}
	
	if (sshfsm.rcvbuf) {
		len = sizeof(sshfsm.rcvbuf);
		err = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &sshfsm, len);
		if (err == -1)
			perror("warning: failed to set SO_RCVBUF");
	}

	freeaddrinfo(ai);
	
	key = sftp_proxy_get_psk(&key_len);

	err = sftp_proxy_auth_challenge(sock, key);
	if (err != 0) {
		close(sock);
		return -1;
	}

	serv->fd = sock;
	return 0;
}

static void sftp_proxy_process(void)
{
	int serv_sockfd, clnt_sockfd;
	struct sockaddr_in serv_addr, clnt_addr;
	socklen_t clnt_len = sizeof(clnt_addr);
	pid_t pid;
	char *key;
	size_t key_len;
	int res, flag = 1;
	
	serv_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (serv_sockfd == -1)
		fatal(1, "***failed to create socket", NULL);
	
	res = setsockopt(serv_sockfd, SOL_SOCKET, SO_REUSEADDR, &flag,
		sizeof(flag)); 
	if (res == -1)
	    fatal(1, "failed to set socket", NULL);

	memset(&serv_addr, 0x0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(sshfsm.port);

	res = bind(serv_sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
	if (res == -1)
	    fatal(1, "failed to bind", NULL);
	
	res = listen(serv_sockfd, sshfsm.backlog);
	if (res == -1)
	    fatal(1, "failed to listen", NULL);

	debug("start listen from %d with backlog=%d", 
		serv_sockfd, sshfsm.backlog);
	
	key = sftp_proxy_get_psk(&key_len);
	
	while (1) {
		clnt_sockfd = accept(serv_sockfd, (struct sockaddr *) &clnt_addr,
			&clnt_len);
		if (clnt_sockfd == -1)
			fatal(1, "failed to accept", NULL);

		debug("accept connection from %d", clnt_sockfd);
		
		res = sftp_proxy_auth_response(clnt_sockfd, key); 
		if (res != 0) {
			close(clnt_sockfd);
			debug("authentication failed from %d", clnt_sockfd);
			continue;
		}
		debug("authentication success from %d", clnt_sockfd);
		fflush(sshfsm.errlog);
		
		set_nodelay(clnt_sockfd);
		
		pid = fork();
		if (pid < 0) {
			perror2("fork failed");
			_exit(1);
		} else if (pid == 0) {
			switch (fork()) {
				case -1:
					perror2("failed to fork");
					_exit(1);
				case 0:
					break;
				default:
					_exit(0);
			}
			setsid();
			res = chdir(sshfsm.userhome);
			umask(0);
			close(serv_sockfd);
			dup2(clnt_sockfd, 0);
			dup2(clnt_sockfd, 1);
			execl(sshfsm.sftp_server, "sftp.sshfsm", NULL);
			perror2("failed to execute \"%s\"", sshfsm.sftp_server);
			_exit(1);
		}
		waitpid(pid, NULL, 0);
		close(clnt_sockfd);
	}

	exit(0);
}

static void sftp_proxy_destroy(void)
{
	close(sshfsm.sftp_proxy_lockfd);
	fclose(sshfsm.errlog);
	g_free(sshfsm.username);
	g_free(sshfsm.userhome);
}

static void sftp_proxy_signal_handler(int sig)
{
	switch (sig) {
		case SIGTERM:
			sftp_proxy_destroy();
			exit(0);
	}
}

static void sftp_proxy_init(void)
{
	char path[PATH_MAX];
	int res;

	if (!sshfsm.sftp_server)
		sshfsm.sftp_server = SFTP_SERVER_PATH;
	
	if (access(sshfsm.sftp_server, R_OK | X_OK) == -1)
		fatal(1, "failed to access \"%s\"", sshfsm.sftp_server);
	
	if (sftp_proxy_chk_psk() == -1)
		exit(1);
	
	if (!sshfsm.session_dir)
		sshfsm.session_dir = g_strdup_printf("/tmp/sshfsmd-%s",
			sshfsm.username);

	res = mkdir(sshfsm.session_dir, S_IRUSR | S_IWUSR | S_IXUSR);
	if (res == -1 && errno != EEXIST)
		fatal(1, "failed to create directory \"%s\"", sshfsm.session_dir);
	
	/* make sure only one server started */
	memset(path, 0, PATH_MAX);
	snprintf(path, PATH_MAX, "%s/lock", sshfsm.session_dir);
	sshfsm.sftp_proxy_lockfd = open(path, O_RDWR | O_CREAT, 0640);
	if (sshfsm.sftp_proxy_lockfd < 0)
		fatal(1, "failed to open file \"%s\"", path);

	if (lockf(sshfsm.sftp_proxy_lockfd, F_TEST, 0) < 0) {
		warning("Another proxy daemon is running?");
		close(sshfsm.sftp_proxy_lockfd);
		exit(0);
	}
	
	switch (fork()) {
		case -1:
			perror2("fork failed");
			_exit(1);
		case 0:
			break;
		default:
			_exit(0);
	}
	
	char tmstr[200];
	memset(tmstr, 0x0, sizeof(tmstr));
	get_currtime_str(tmstr, sizeof(tmstr), "%D %T");
	
	sshfsm.pid = getpid();
	memset(path, 0, PATH_MAX);
	snprintf(path, PATH_MAX, "%s/error.log", sshfsm.session_dir);
	sshfsm.errlog = fopen(path, "w+b");
	if (sshfsm.errlog == NULL)
		fatal(1, "failed to open file \"%s\"", path);
	
	if (dup2(fileno(sshfsm.errlog), 1) == -1 || 
		dup2(fileno(sshfsm.errlog), 2) == -1) 
		fatal(1, "failed to redirect stdout and stderr to \"%s\"", path);
	
	log("sftp proxy init at %s\n", tmstr);
	
	setsid();
	res = chdir("/");
	umask(0);
	signal(SIGTERM, sftp_proxy_signal_handler);
	
	if (lockf(sshfsm.sftp_proxy_lockfd, F_TLOCK, 0) < 0)
		fatal(1, "failed to acquire lock", NULL);
	
	sftp_proxy_process();
}

static struct fuse_cache_operations sshfsm_oper = {
	.oper = {
		.init       = sshfsm_init,
		.destroy	= sshfsm_destroy,
		.getattr    = sshfsm_getattr,
		.readlink   = sshfsm_readlink,
		.mknod      = sshfsm_mknod,
		.mkdir      = sshfsm_mkdir,
		.symlink    = sshfsm_symlink,
		.unlink     = sshfsm_unlink,
		.rmdir      = sshfsm_rmdir,
		.rename     = sshfsm_rename,
		.chmod      = sshfsm_chmod,
		.chown      = sshfsm_chown,
		.truncate   = sshfsm_truncate,
		.utime      = sshfsm_utime,
		.open       = sshfsm_open,
		.flush      = sshfsm_flush,
		.fsync      = sshfsm_fsync,
		.release    = sshfsm_release,
		.read       = sshfsm_read,
		.write      = sshfsm_write,
		.statfs     = sshfsm_statfs,
#if FUSE_VERSION >= 25
		.create     = sshfsm_create,
		.ftruncate  = sshfsm_ftruncate,
		.fgetattr   = sshfsm_fgetattr,
#endif
	},
	.cache_getdir = sshfsm_getdir,
};

static void usage(const char *progname)
{
	printf(
"usage: %s [user@]host:[dir] mountpoint [options]\n"
"\n"
"general options:\n"
"    -o opt,[opt...]        mount options\n"
"    -h   --help            print help\n"
"    -V   --version         print version\n"
"\n"
"SSHFSM options:\n"
"    -p PORT                equivalent to '-o port=PORT'\n"
"    -C                     equivalent to '-o compression=yes'\n"
"    -F ssh_configfile      specifies alternative ssh configuration file\n"
"    -1                     equivalent to '-o ssh_protocol=1'\n"
"    -P sftp_server_path    connect directly to local sftp server\n"
"    -D                     sftp directport proxy daemon (default port: 5285)\n"
"    -o backlog=N           sftp proxy backlog (default: 20)\n"
"    -o psk=PATH            sftp proxy pre-shared key (default: ~/.sshfsm/key)\n"
"    -o sndbuf=N            directport send buffer size (default: auto)\n"
"    -o rcvbuf=N            directport receive buffer size (default: auto)\n"
"    -o reconnect           reconnect to server\n"
"    -o delay_connect       delay connection to server\n"
"    -o sshfsm_sync         synchronous writes\n"
"    -o no_readahead        synchronous reads (no speculative readahead)\n"
"    -o cache=BOOL          enable caching {yes,no} (default: yes)\n"
"    -o cache_timeout=N     sets timeout for caches in seconds (default: 20)\n"
"    -o cache_X_timeout=N   sets timeout for {stat,dir,link} cache\n"
"    -o workaround=LIST     colon separated list of workarounds\n"
"             none             no workarounds enabled\n"
"             all              all workarounds enabled\n"
"             [no]rename       fix renaming to existing file (default: off)\n"
#ifdef SSH_NODELAY_WORKAROUND
"             [no]nodelay      set nodelay tcp flag in ssh (default: on)\n"
#endif
"             [no]nodelayserv   set nodelay tcp flag in sshd (default: off)\n"
"             [no]truncate     fix truncate for old servers (default: off)\n"
"             [no]buflimit     fix buffer fillup bug in server (default: on)\n"
"    -o idmap=TYPE          user/group ID mapping, possible types are:\n"
"             none             no translation of the ID space (default)\n"
"             user             only translate UID of connecting user\n"
"    -o ssh_command=CMD     execute CMD instead of 'ssh'\n"
"    -o ssh_protocol=N      ssh protocol to use (default: 2)\n"
"    -o sftp_server=SERV    path to sftp server or subsystem (default: sftp)\n"
"    -o directport=PORT     directly connect to PORT bypassing ssh\n"
"    -o inaddr_ino          piggyback ip address using inode numbers\n"
"    -o inaddr_nth=N        piggyback the Nth ip address (default: 0)\n"
"    -o forward_io=BASEPATH use ip address to forward direct I/O to server\n"
"    -o forward_timeout=N   sets timeout for connections in seconds (default: 60)\n"
"    -o transform_symlinks  transform absolute symlinks to relative\n"
"    -o follow_symlinks     follow symlinks on the server\n"
"    -o no_check_root       don't check for existence of 'dir' on server\n"
"    -o password_stdin      read password from stdin (only for pam_mount!)\n"
"    -o SSHOPT=VAL          ssh options (see man ssh_config)\n"
"    -o session_dir         session directory\n"
"    -o sshfsm_debug        print some debugging information\n"
"    -o dump                dump error/debug information to log file\n"
"\n", progname);
}

static int is_ssh_opt(const char *arg)
{
	if (arg[0] != '-') {
		unsigned arglen = strlen(arg);
		const char **o;
		for (o = ssh_opts; *o; o++) {
			unsigned olen = strlen(*o);
			if (arglen > olen && arg[olen] == '=' &&
			    strncasecmp(arg, *o, olen) == 0)
				return 1;
		}
	}
	return 0;
}

static int sshfsm_fuse_main(struct fuse_args *args)
{
#if FUSE_VERSION >= 26
	return fuse_main(args->argc, args->argv, cache_init(&sshfsm_oper), NULL);
#else
	return fuse_main(args->argc, args->argv, cache_init(&sshfsm_oper));
#endif
}

static int parse_serv_args(const char *arg)
{
	if (!strchr(arg, ':'))
		return 1;

	char *basepath, *tmp, *cp, *port;
	struct serv *serv = g_new0(struct serv, 1);
	GPtrArray *arr = sshfsm.serv_arr;
	tmp = g_strdup(arg);
	basepath = find_base_path(tmp);
	port = sshfsm.directport ? sshfsm.directport : "22";
	
	/* Get mount option */
	if ((cp = strchr(basepath, '='))) {
		if (strchr(cp+1, 'l'))
			serv->local = 1;
		/* Other options can be appended here */
		*cp = '\0';
	} else
		serv->local = 0;

	if (basepath[0] && basepath[strlen(basepath)-1] != '/') {
		if (serv->local && basepath[0] != '/')
			serv->basepath = g_strdup_printf("%s/%s/", sshfsm.userhome,
				basepath);
		else
			serv->basepath = g_strdup_printf("%s/", basepath);
	} else {
		if (serv->local && basepath[0] != '/')
			serv->basepath = g_strdup_printf("%s/%s", sshfsm.userhome,
				basepath);
		else
			serv->basepath = g_strdup(basepath);
	}
	char fqdn[256];
	memset(fqdn, 0x0, 256);
	if (get_hostinfo(tmp, port, &serv->inaddr, fqdn) == -1)
		warning("failed to resolve %s, try use IP or FQDN if using GMount", 
			serv->hostname);
	serv->hostname = strlen(fqdn) ? g_strdup(fqdn) : g_strdup(tmp);
	serv->rank = 10000 - arr->len * 50;
	debug("add \'/\' arr[%d]: %s (%s):%s:%s,local=%d,rank=%d,", arr->len,
		  serv->hostname, inet_ntoa(serv->inaddr), port, serv->basepath, 
		  serv->local, serv->rank);
	g_ptr_array_add(arr, (gpointer) serv);
	
	g_free(tmp);
	return 0;
}

static int sshfsm_opt_proc(void *data, const char *arg, int key,
                          struct fuse_args *outargs)
{
	char *tmp;
	(void) data;

	switch (key) {
	case FUSE_OPT_KEY_OPT:
		if (is_ssh_opt(arg)) {
			tmp = g_strdup_printf("-o%s", arg);
			ssh_add_arg(tmp);
			g_free(tmp);
			return 0;
		}
		return 1;

	case FUSE_OPT_KEY_NONOPT:
		return parse_serv_args(arg);

	case KEY_PORT:
		tmp = g_strdup_printf("-oPort=%s", arg + 2);
		ssh_add_arg(tmp);
		g_free(tmp);
		sshfsm.port = atoi(arg+2);
		return 0;

	case KEY_COMPRESS:
		ssh_add_arg("-oCompression=yes");
		return 0;

	case KEY_CONFIGFILE:
		tmp = g_strdup_printf("-F%s", arg + 2);
		ssh_add_arg(tmp);
		g_free(tmp);
		return 0;

	case KEY_HELP:
		usage(outargs->argv[0]);
		fuse_opt_add_arg(outargs, "-ho");
		sshfsm_fuse_main(outargs);
		exit(1);

	case KEY_VERSION:
		printf("SSHFSM version %s\n", PACKAGE_VERSION);
#if FUSE_VERSION >= 25
		fuse_opt_add_arg(outargs, "--version");
		sshfsm_fuse_main(outargs);
#endif
		exit(0);

	case KEY_FOREGROUND:
		sshfsm.foreground = 1;
		return 1;
	
	case KEY_DAEMON:
		sshfsm.sftp_proxy = 1;
		return 1;

	case KEY_LOCALSRV:
		sshfsm.sftp_local_server = g_strdup(arg + 2);
		return 0;

	default:
		error3("internal error");
		abort();
	}
}

static int workaround_opt_proc(void *data, const char *arg, int key,
			       struct fuse_args *outargs)
{
	(void) data; (void) key; (void) outargs;
	error3("unknown workaround: \"%s\"", arg);
	return -1;
}

int parse_workarounds(void)
{
	int res;
	char *argv[] = { "", "-o", sshfsm.workarounds, NULL };
	struct fuse_args args = FUSE_ARGS_INIT(3, argv);
	char *s = sshfsm.workarounds;
	if (!s)
		return 0;

	while ((s = strchr(s, ':')))
		*s = ',';

	res = fuse_opt_parse(&args, &sshfsm, workaround_opts,
			     workaround_opt_proc);
	fuse_opt_free_args(&args);

	return res;
}

#if FUSE_VERSION == 25
static int fuse_opt_insert_arg(struct fuse_args *args, int pos,
                               const char *arg)
{
	assert(pos <= args->argc);
	if (fuse_opt_add_arg(args, arg) == -1)
		return -1;

	if (pos != args->argc - 1) {
		char *newarg = args->argv[args->argc - 1];
		memmove(&args->argv[pos + 1], &args->argv[pos],
			sizeof(char *) * (args->argc - pos - 1));
		args->argv[pos] = newarg;
	}
	return 0;
}
#endif

static void check_large_read(struct fuse_args *args)
{
	struct utsname buf;
	int err = uname(&buf);
	if (!err && strcmp(buf.sysname, "Linux") == 0 &&
	    strncmp(buf.release, "2.4.", 4) == 0)
		fuse_opt_insert_arg(args, 1, "-olarge_read");
}

static int read_password(void)
{
	int size = getpagesize();
	int max_password = 64;
	int n;

	sshfsm.password = mmap(NULL, size, PROT_READ | PROT_WRITE,
			      MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED,
			      -1, 0);
	if (sshfsm.password == MAP_FAILED) {
		perror2("failed to allocate locked page for password");
		return -1;
	}

	/* Don't use fgets() because password might stay in memory */
	for (n = 0; n < max_password; n++) {
		int res;

		res = read(0, &sshfsm.password[n], 1);
		if (res == -1) {
			perror2("failed to read password");
			return -1;
		}
		if (res == 0) {
			sshfsm.password[n] = '\n';
			break;
		}
		if (sshfsm.password[n] == '\n')
			break;
	}
	if (n == max_password) {
		error3("Password too long (max: %d)", max_password);
		return -1;
	}
	sshfsm.password[n+1] = '\0';
	ssh_add_arg("-oNumberOfPasswordPrompts=1");
	ssh_add_arg("-oPreferredAuthentications=password,keyboard-interactive");

	return 0;
}

static void set_ssh_command(void)
{
	char *s;
	char *d;
	int i = 0;
	int end = 0;

	d = sshfsm.ssh_command;
	s = sshfsm.ssh_command;
	while (!end) {
		switch (*s) {
		case '\0':
			end = 1;
		case ' ':
			*d = '\0';
			if (i == 0) {
				replace_arg(&sshfsm.ssh_args.argv[0],
					    sshfsm.ssh_command);
			} else {
				if (fuse_opt_insert_arg(&sshfsm.ssh_args, i, 
						sshfsm.ssh_command) == -1)
					_exit(1);
			}
			i++;
			d = sshfsm.ssh_command;
			break;

		case '\\':
			if (s[1])
				s++;
		default:
			*d++ = *s;
		}
		s++;
	}
}

static char *find_base_path(char *s)
{
	char *d = s;

	for (; *s && *s != ':'; s++) {
		if (*s == '[') {
			/*
			 * Handle IPv6 numerical address enclosed in square
			 * brackets
			 */
			s++;
			for (; *s != ']'; s++) {
				if (!*s)
					fatal(1, 0, "missing ']' in hostname \"%s\"", s);
				*d++ = *s;
			}
		} else {
			*d++ = *s;
		}
	}
	*d++ = '\0';
	s++;

	return s;
}

/*
 * Remove commas from fsname, as it confuses the fuse option parser.
 */
static void fsname_remove_commas(char *fsname)
{
	if (strchr(fsname, ',') != NULL) {
		char *s = fsname;
		char *d = s;

		for (; *s; s++) {
			if (*s != ',')
				*d++ = *s;
		}
		*d = *s;
	}
}

#if FUSE_VERSION >= 27
static char *fsname_escape_commas(char *fsnameold)
{
	char *fsname = g_malloc(strlen(fsnameold) * 2 + 1);
	char *d = fsname;
	char *s;

	for (s = fsnameold; *s; s++) {
		if (*s == '\\' || *s == ',')
			*d++ = '\\';
		*d++ = *s;
	}
	*d = '\0';
	g_free(fsnameold);

	return fsname;
}
#endif

static void * connect_thread_func(void *data)
{
	serv_t serv = (serv_t) data;
	if (connect_remote(serv) == -1)
		pthread_exit((void *) -1);
	if (sshfsm.detect_uid)
		sftp_detect_uid(serv);
	if (!sshfsm.no_check_root && serv_check_root(serv_0) == -1)
		pthread_exit((void *) -1);
	pthread_exit((void *) 0);
}

static int connect_all(void)
{
	if (processing_init() == -1)
		return -1;
	
	if (serv_num == 1) {
		if (!sshfsm.delay_connect) {
			if (connect_remote(serv_0) == -1)
				return -1;

			if (sshfsm.detect_uid)
				sftp_detect_uid(serv_0);

			if (!sshfsm.no_check_root && serv_check_root(serv_0) == -1)
				return -1;
		}
		return 0;
	}
	
	pthread_t *threads;
	pthread_attr_t attr;
	serv_t serv;
	int err, err2, err3 = 0;
	unsigned int i;

	threads = g_new(pthread_t, serv_num);
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	
	for (i = 0; i < serv_num; i++) {
		serv = serv_i(i);
		err = pthread_create(&threads[i], &attr, connect_thread_func, serv);
		if (err) {
			error2(err, "connect_all: create thread failed");
			err = -1;
			goto out;
		}
	}

	for (i = 0; i < serv_num; i++) {
		err = pthread_join(threads[i], (void *) &err2);
		if (err) {
			error2(err, "connect_all: join thread failed");
			err = -1;
			goto out;
		}
		if (err2) {
			serv = serv_i(i);
			debug("failed to connect to %s", serv->hostname);
		}
		err3 += err2;
	}
	err = err3 ? -1 : 0;
	debug("connect: %d", err);

out:
	pthread_attr_destroy(&attr);
	g_free(threads);
	return err;
}

int main(int argc, char *argv[])
{
	int res;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	char *tmp;
	char *fsname;
	const char *sftp_server;
	int libver;
	struct passwd *pwd;

	g_thread_init(NULL);

	sshfsm.blksize = 4096;
	sshfsm.max_read = MAX_REQ_SIZE;
	sshfsm.max_write = MAX_REQ_SIZE;
	sshfsm.nodelay_workaround = 1;
	sshfsm.nodelayserv_workaround = 0;
	sshfsm.rename_workaround = 0;
	sshfsm.truncate_workaround = 0;
	sshfsm.buflimit_workaround = 1;
	sshfsm.ssh_ver = 2;
	sshfsm.progname = argv[0];
	sshfsm.delay_connect = 0;
	sshfsm.port = 5285;
	sshfsm.backlog = 20;
	sshfsm.sndbuf = 0;
	sshfsm.rcvbuf = 0;
	sshfsm.inaddr_nth = 0;
	sshfsm.forward_timeout = 0;
	sshfsm.errlog = stderr;
	ssh_add_arg("ssh");
	ssh_add_arg("-x");
	ssh_add_arg("-a");
	ssh_add_arg("-oClearAllForwardings=yes");

	sshfsm.uid = getuid();
	sshfsm.pid = getpid();
	pwd = getpwuid(sshfsm.uid);
	if (!pwd)
		fatal(1, "failed to get pwd for uid %d\n", sshfsm.uid);
	
	sshfsm.gid = pwd->pw_gid;
	sshfsm.username = g_strdup(pwd->pw_name);
	sshfsm.userhome = g_strdup(pwd->pw_dir);

	if (tree_init() == -1)
		exit(1);

	if (fuse_opt_parse(&args, &sshfsm, sshfsm_opts, sshfsm_opt_proc) == -1 ||
	    parse_workarounds() == -1)
		exit(1);

	debug("SSHFSM version %s", PACKAGE_VERSION);

	sshfsm.config_dir = g_strdup_printf("%s/.sshfsm", sshfsm.userhome);
	res = mkdir(sshfsm.config_dir, S_IRUSR | S_IWUSR | S_IXUSR);
	if (res == -1 && errno != EEXIST)
		fatal(1, "failed to create directory \"%s\"", sshfsm.config_dir);

	if (sshfsm.sftp_proxy == 1) {
		sftp_proxy_init();
		exit(0);
	}
	
	/* extrace mount point, and need to insert it back */
	if (fuse_parse_cmdline(&args, &sshfsm.mountpoint, NULL, NULL) == -1) {
		fuse_opt_free_args(&args);
		exit(1);
	}
	if (!sshfsm.mountpoint) {
		fprintf(stderr, 
			"%s: missing mount point\n"
			"see `%s -h' for usage\n", 
			sshfsm.progname, sshfsm.progname);
		fuse_opt_free_args(&args);
		exit(1);
	}
	fuse_opt_insert_arg(&args, 1, sshfsm.mountpoint);

	if (sshfsm.password_stdin) {
		res = read_password();
		if (res == -1)
			exit(1);
	}

	if (sshfsm.buflimit_workaround)
		/* Work around buggy sftp-server in OpenSSH.  Without this on
		   a slow server a 10Mbyte buffer would fill up and the server
		   would abort */
		sshfsm.max_outstanding_len = 8388608;
	else
		sshfsm.max_outstanding_len = ~0;
	
	if (!sshfsm.serv_arr->len) {
		fprintf(stderr, 
			"%s: missing host\n"
		    "see `%s -h' for usage\n", 
			sshfsm.progname, sshfsm.progname);
		fuse_opt_free_args(&args);
		exit(1);
	}

	fsname = serv_num == 1 ? g_strdup("sshfsm") : 
		g_strdup_printf("sshfsm_%dhosts", serv_num);

	if (sshfsm.ssh_command)
		set_ssh_command();

	tmp = g_strdup_printf("-%i", sshfsm.ssh_ver);
	ssh_add_arg(tmp);
	g_free(tmp);
	
	if (sshfsm.sftp_server)
		sftp_server = sshfsm.sftp_server;
	else if (sshfsm.ssh_ver == 1)
		sftp_server = SFTP_SERVER_PATH;
	else
		sftp_server = "sftp";

	if (sshfsm.ssh_ver != 1 && strchr(sftp_server, '/') == NULL)
		ssh_add_arg("-s");

	ssh_add_arg(sftp_server);
	free(sshfsm.sftp_server);

	res = cache_parse_options(&args);
	if (res == -1)
		exit(1);

	sshfsm.randseed = time(0);

	if (sshfsm.max_read > MAX_REQ_SIZE)
		sshfsm.max_read = MAX_REQ_SIZE;
	if (sshfsm.max_write > MAX_REQ_SIZE)
		sshfsm.max_write = MAX_REQ_SIZE;

	if (fuse_is_lib_option("ac_attr_timeout="))
		fuse_opt_insert_arg(&args, 1, "-oauto_cache,ac_attr_timeout=0");
	tmp = g_strdup_printf("-omax_read=%u", sshfsm.max_read);
	fuse_opt_insert_arg(&args, 1, tmp);
	g_free(tmp);
	tmp = g_strdup_printf("-omax_write=%u", sshfsm.max_write);
	fuse_opt_insert_arg(&args, 1, tmp);
	g_free(tmp);
	
	if (sshfsm.forward_io)
		sshfsm.inaddr_ino = 1;
		
	if (sshfsm.inaddr_ino)
		fuse_opt_insert_arg(&args, 1, "-ouse_ino");

#if FUSE_VERSION >= 27
	libver = fuse_version();
	assert(libver >= 27);
	if (libver >= 28)
		fsname = fsname_escape_commas(fsname);
	else
		fsname_remove_commas(fsname);
	tmp = g_strdup_printf("-osubtype=sshfsm,fsname=%s", fsname);
#else
	fsname_remove_commas(fsname);
	tmp = g_strdup_printf("-ofsname=sshfsm#%s", fsname);
#endif
	fuse_opt_insert_arg(&args, 1, tmp);
	g_free(tmp);
	g_free(fsname);

	check_large_read(&args);

#if FUSE_VERSION >= 26
	{
		struct fuse *fuse;
		struct fuse_chan *ch;
		char *mountpoint;
		int multithreaded;
		int foreground;
		struct stat st;

		res = fuse_parse_cmdline(&args, &mountpoint, &multithreaded, 
					 &foreground);
		if (res == -1)
			exit(1);

		res = stat(mountpoint, &st);
		if (res == -1)
			fatal(1, "failed to stat mountpoint \"%s\"", mountpoint);
	
		sshfsm.mnt_mode = st.st_mode;

		ch = fuse_mount(mountpoint, &args);
		if (!ch)
			exit(1);

		res = fcntl(fuse_chan_fd(ch), F_SETFD, FD_CLOEXEC);
		if (res == -1)
			perror("warning: failed to set FD_CLOESEC on fuse device");

		fuse = fuse_new(ch, &args, cache_init(&sshfsm_oper),
				sizeof(struct fuse_operations), NULL);
		if (fuse == NULL) {
			fuse_unmount(mountpoint, ch);
			exit(1);
		}
	
		res = connect_all();
		if (res == -1) {
			fuse_unmount(mountpoint, ch);
			fuse_destroy(fuse);
			exit(1);
		}

		res = fuse_daemonize(foreground);
		if (res != -1)
			res = fuse_set_signal_handlers(fuse_get_session(fuse));

		if (res == -1) {
			fuse_unmount(mountpoint, ch);
			fuse_destroy(fuse);
			exit(1);
		}

		if (multithreaded)
			res = fuse_loop_mt(fuse);
		else
			res = fuse_loop(fuse);

		if (res == -1)
			res = 1;
		else
			res = 0;

		fuse_remove_signal_handlers(fuse_get_session(fuse));
		fuse_unmount(mountpoint, ch);
		fuse_destroy(fuse);
		free(mountpoint);
	}
#else
	res = connect_all();
	if (res == -1)
		exit(1);

	res = sshfsm_fuse_main(&args);
#endif

	fuse_opt_free_args(&args);
	fuse_opt_free_args(&sshfsm.ssh_args);
	free(sshfsm.directport);

	return res;
}

/* EOF */
