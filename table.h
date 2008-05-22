/*
    Directory Table
    Copyright (C) 2008  Nan Dun <sshfsm@gmail.com>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#ifndef	_SSHFSM_TABLE_H_
#define	_SSHFSM_TABLE_H_

#include <pthread.h>
#include <glib.h>
#include <fuse.h>
#include <fuse_opt.h>

struct host {
	char *host_name;
	char *base_path;
	int rank;
	int server_version;
	int connver;
	int modifver;
	int	fd;
	unsigned uid;
	GHashTable *reqtab;
	pthread_mutex_t lock;
	pthread_mutex_t	lock_write;
	int processing_thread_started;
	uint32_t idctr;
};

struct table_entry {
	int size;
	int *idx_arr;
	time_t atime;
	unsigned long checksum;
};

struct table_entry * table_entry_new(int size);
void table_entry_free(struct table_entry *entry);
unsigned long table_entry_hash(struct table_entry *entry);

int table_create(struct host **host_arr, int host_num);
void table_destroy(void);
int table_size(void);
void table_insert(const char *key, struct table_entry *entry);
struct table_entry * table_lookup(const char *key);
struct table_entry * table_lookup_r(const char *key);
void table_update(const char *key, GSList *idx_lst);
void table_remove(const char *key);
void table_remove_all(void);

int table_host_map_lookup(const char *key);
void table_host_map_insert(const char *key, int idx);
void table_host_map_remove(const char *key);

int table_tlb_lookup(const char *path);
void table_tlb_purge(const char *path);
void table_tlb_purge_all();
void table_tlb_update(const char *path, int idx);
void table_tlb_clean(void);

int table_parse_options(struct fuse_args *args);

#endif	/* _SSHFSM_TABLE_H_ */
