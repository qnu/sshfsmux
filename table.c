/*
    Directory Table Management Subsystem
    Copyright (C) 2008  Nan Dun <dunnan@yl.is.s.u-tokyoa.ac.jp>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "table.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <time.h>

#define DEFAULT_TABLE_MAX_SIZE	256
#define DEFAULT_TLB_TIMEOUT	20

#define DEBUG(format, args...)						\
	do { if (sshfsm.debug) fprintf(stderr, format, args); } while(0)

typedef struct table_tlb_data {
	int idx;
	time_t valid;
} *table_tlb_data_t;

struct table {
	GHashTable *table;
	size_t max_size;
	pthread_mutex_t lock;
	GHashTable *host_map;
	pthread_mutex_t lock_host_map;
	GHashTable *tlb;
	pthread_mutex_t lock_tlb;
	int tlb_on;
	unsigned tlb_timeout;
};

static struct table table;

struct table_entry * table_entry_new(int size)
{
	struct table_entry *p;
	p = (struct table_entry *) malloc(sizeof(struct table_entry));
	if (!p) {
		fprintf(stderr, "sshfsm: memory allocation failed\n");
		abort();
	}
	
	p->idx_arr = (int *) malloc((sizeof(int) * size));
	if (!p->idx_arr) {
		fprintf(stderr, "sshfsm: memory allocation failed\n");
		abort();
	}
	p->size = size;
	return p;
}

void table_entry_free(struct table_entry *entry)
{
	if (entry == NULL)
		return;
	
	free(entry->idx_arr);
	free(entry);
}

unsigned long table_entry_hash(struct table_entry *entry)
{
	unsigned long value;
	int i;
	
	value = 0;
	for (i = 0; i < entry->size; i++)
		value = value + g_int_hash(entry->idx_arr + i);
	
	return value;
}

int table_create(struct host **host_arr, int host_num)
{	
	struct table_entry *entry;
	char *hoststr;
	struct host *hostp;
	int	i;
	
	table.table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, 
									 (GDestroyNotify) table_entry_free);
	table.host_map = g_hash_table_new_full(g_str_hash, g_str_equal,
											g_free, g_free);
	table.tlb = g_hash_table_new_full(g_str_hash, g_str_equal,
											g_free, g_free);
	if (!table.table || !table.host_map || !table.tlb) {
		fprintf(stderr, "failed to create hash table\n");
		return -1;
	}
	pthread_mutex_init(&table.lock, NULL);
	pthread_mutex_init(&table.lock_host_map, NULL);
	pthread_mutex_init(&table.lock_tlb, NULL);

	entry = table_entry_new(host_num);
	for (i = 0; i < host_num; i++) {
		hostp = host_arr[i];
		/* Fill idx_arr for "/" */
		entry->idx_arr[i] = i;
		/* Fill host map */
		hoststr = g_strdup_printf("%s:%s", hostp->host_name, 
										   hostp->base_path);
		table_host_map_insert(hoststr, i);
		g_free(hoststr);
	}
	entry->size = host_num;
	entry->atime = time(NULL);
	entry->checksum = table_entry_hash(entry);
	table_insert("/", entry);
	return 0;
}

int table_size(void)
{
	return g_hash_table_size(table.table);
}

void table_destroy(void)
{
	table_remove_all();
	g_hash_table_destroy(table.table);
	g_hash_table_destroy(table.host_map);
	g_hash_table_destroy(table.tlb);
	pthread_mutex_destroy(&table.lock);
	pthread_mutex_destroy(&table.lock_host_map);
	pthread_mutex_destroy(&table.lock_tlb);
}

void table_insert(const char *key, struct table_entry *entry)
{
	pthread_mutex_lock(&table.lock);
	g_hash_table_insert(table.table, g_strdup(key), entry);
	pthread_mutex_unlock(&table.lock);
}

struct table_entry * table_lookup(const char *key)
{
	return g_hash_table_lookup(table.table, key);
}

static char * get_parent_dir(const char *path)
{
	int len, i;

	if (strcmp(path, "/") == 0)
		return g_strdup(path);
	
	len = strlen(path);
	i = path[len - 1] == '/' ? 2 : 1;
	while (path[len - i] != '/' && i < len)
		i++;
	
	if (len == i)
		return g_strdup("/");
	
	return g_strndup(path, len - i);
}

struct table_entry * table_lookup_r(const char *key)
{
	struct table_entry *entry = NULL;
	if ((entry = g_hash_table_lookup(table.table, key)))
		return entry;
	
	char *parent_dir = get_parent_dir(key);
	entry = g_hash_table_lookup(table.table, parent_dir);
	g_free(parent_dir);
	return entry;

}

static void idx_lst_hash(void *data, void *hash)
{
	int *datap = (int *) data;
	unsigned long *hashp = (unsigned long *) hash;
	*hashp = *hashp + g_int_hash(datap);
}

void table_update(const char *key, GSList *idx_lst)
{
	unsigned long checksum = 0;
	struct table_entry *entry = table_lookup(key);
	unsigned int lst_length = g_slist_length(idx_lst);
	GSList *lst_entry = NULL;
	int i;
	
	if (lst_length == 0) {
		table_remove(key);
		return;
	}
	if (entry != NULL && entry->size == lst_length) {
		g_slist_foreach(idx_lst, idx_lst_hash, &checksum);
		if (checksum == entry->checksum)
			return;
	}
	entry = table_entry_new(lst_length);
	lst_entry = idx_lst;
	i = 0;
	while (lst_entry) {
		entry->idx_arr[i++] = *((int *) lst_entry->data);
		lst_entry = lst_entry->next;
	}
	entry->checksum = table_entry_hash(entry);
	entry->atime = time(NULL);
	table_insert(key, entry);
	return;
}

void table_remove(const char *key)
{	
	pthread_mutex_lock(&table.lock);
	g_hash_table_remove(table.table, key);
	pthread_mutex_unlock(&table.lock);
}

#if GLIB_CHECK_VERSION(2, 12, 0)
void table_remove_all(void)
{
	pthread_mutex_lock(&table.lock);
	g_hash_table_remove_all(table.table);
	pthread_mutex_unlock(&table.lock);
}
#else
static int true_func(void *key, void *value, void *data)
{
	(void) key;
	(void) value;
	(void) data;
	return TRUE;
}

void table_remove_all(void)
{
	pthread_mutex_lock(&table.lock);
	g_hash_table_foreach_remove(table.table, true_func, NULL);
	pthread_mutex_unlock(&table.lock);
}
#endif


int table_host_map_lookup(const char *key)
{
	int *idxp =
		(int *) g_hash_table_lookup(table.host_map, (const char *) key);
	return idxp ? *idxp : -1;
}

void table_host_map_insert(const char *key, int idx)
{
	char *keycp = g_strdup(key);
	int *idxp = g_new(int, 1);
	*idxp = idx;
	pthread_mutex_lock(&table.lock_host_map);
	g_hash_table_insert(table.host_map, keycp, idxp);	
	pthread_mutex_unlock(&table.lock_host_map);
}

void table_host_map_remove(const char *key)
{
	pthread_mutex_lock(&table.lock_host_map);
	g_hash_table_remove(table.host_map, key);	
	pthread_mutex_unlock(&table.lock_host_map);
}

int table_tlb_lookup(const char *path)
{	
	if (table.tlb_on)
		return -1;
	struct table_tlb_data *data;
	if (!(data = g_hash_table_lookup(table.tlb, path)))
		return -1;
	
	return data->idx;
}

void table_tlb_purge(const char *path)
{
	pthread_mutex_lock(&table.lock_tlb);
	g_hash_table_remove(table.tlb, path);
	pthread_mutex_unlock(&table.lock_tlb);
}

#if GLIB_CHECK_VERSION(2, 12, 0)
void table_tlb_purge_all()
{
	pthread_mutex_lock(&table.lock_tlb);
	g_hash_table_remove_all(table.tlb);
	pthread_mutex_unlock(&table.lock_tlb);
}
#else
static int remove_all_entry(void *key, void *value, void *data)
{
	(void) key;
	(void) value;
	(void) data;
	return TRUE;
}
void table_tlb_purge_all()
{
	pthread_mutex_lock(&table.lock_tlb);
	g_hash_table_foreach_remove(table.tlb, (GHRFunc) remove_all_entry, NULL);
	pthread_mutex_unlock(&table.lock_tlb);
}
#endif

static int table_tlb_clean_entry(void *key, struct table_tlb_data *data,
								   time_t *now)
{
	(void) key;
	if (*now > data->valid)
		return TRUE;
	else
		return FALSE;
}

void table_tlb_clean(void)
{
	time_t now = time(NULL);
	pthread_mutex_lock(&table.lock_tlb);
	g_hash_table_foreach_remove(table.tlb,
								(GHRFunc) table_tlb_clean_entry, &now);
	pthread_mutex_unlock(&table.lock_tlb);
}

void table_tlb_update(const char *path, int idx)
{
	struct table_tlb_data *data;
	time_t now;

	pthread_mutex_lock(&table.lock_tlb);
	data = (table_tlb_data_t) g_hash_table_lookup(table.tlb, path);
	if (!data) {
		char *pathcopy = g_strdup(path);
		data = g_new0(struct table_tlb_data, 1);
		g_hash_table_insert(table.tlb, pathcopy, data);
	}
	data->idx = idx;
	time(&now);
	data->valid = now + table.tlb_timeout;
	pthread_mutex_unlock(&table.lock_tlb);
}

static const struct fuse_opt table_opts[] = {
	{"table_size=%u",	  		offsetof(struct table, max_size), 0},
	{"table_tlb=yes", 			offsetof(struct table, tlb_on), 1},
	{"table_tlb=no",			offsetof(struct table, tlb_on), 0},
	{"table_tlb_timeout=%u",	offsetof(struct table, tlb_timeout), 0},
	FUSE_OPT_END
};

int table_parse_options(struct fuse_args *args)
{
	table.max_size = DEFAULT_TABLE_MAX_SIZE;
	table.tlb_timeout = DEFAULT_TLB_TIMEOUT;
	table.tlb_on = 1;
	return fuse_opt_parse(args, &table, table_opts, NULL);
}

/****************************
 * TODO:
 * 1. Error handling
 ***************************/
