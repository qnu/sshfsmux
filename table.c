/*
    Directory Table
    Copyright (C) 2008  Nan Dun <sshfsm@gmail.com>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "table.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <pthread.h>
#include <assert.h>

struct table {
	GHashTable *table;
	pthread_mutex_t lock;
	int debug;
};

static struct table table;

#define DEBUG(format, args...)						\
	do { if (table.debug) fprintf(stderr, format, args); } while(0)

static inline void item_free(void *data, void *data_)
{
	(void) data_;
	g_free(data);
}

static inline void table_entry_free(void *entry)
{
	GSList *list = (GSList *) entry;
	g_slist_foreach(list, item_free, NULL);
	g_slist_free(list);
}

int table_create(int debug)
{
	table.debug = debug;
	table.table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, 
						table_entry_free);
	if (!table.table) {
		fprintf(stderr, "failed to create diretory hash table\n");
		return -1;
	}
	pthread_mutex_init(&table.lock, NULL);
	return 0;
}

void table_destroy()
{
	g_hash_table_destroy(table.table);
	pthread_mutex_destroy(&table.lock);
}

unsigned table_size()
{
	return g_hash_table_size(table.table);
}

static inline int item_compare_by_idx(const void *a, const void *b)
{
	struct idx_item *item_a = (struct idx_item *) a;
	struct idx_item *item_b = (struct idx_item *) b;
	return item_a->idx - item_b->idx;
}

static inline int item_compare_by_rank(const void *a, const void *b)
{
	struct idx_item *item_a = (struct idx_item *) a;
	struct idx_item *item_b = (struct idx_item *) b;
	/* higher rank comes first */
	return item_b->rank - item_a->rank;
}

static inline GSList* insert_item(GSList *list, struct idx_item *item)
{
	return g_slist_insert_sorted(list, item, item_compare_by_rank);
}

static inline GSList* find_item(GSList *list, struct idx_item *item)
{
	return g_slist_find_custom(list, item, item_compare_by_idx);
}

static inline GSList* remove_item(GSList *list, GSList *itemp)
{
	GSList *newlist = g_slist_remove_link(list, itemp);
	g_free(itemp->data);
	g_slist_free(itemp);
	return newlist;
}

void table_insert(const char *path, const int idx, const int rank)
{
	struct idx_item *item = g_new(struct idx_item, 1);
	item->idx = idx;
	item->rank = rank;
	
	gpointer orig_key, orig_value;
	gboolean exist = g_hash_table_lookup_extended(table.table, path,
						&orig_key, &orig_value);
	if (exist == FALSE) {	
		/* no entry for path, create one */
		pthread_mutex_lock(&table.lock);
		GSList* idx_list = insert_item(NULL, item);
		g_hash_table_insert(table.table, g_strdup(path), idx_list);
		pthread_mutex_unlock(&table.lock);
		DEBUG("  table: insert(path: %s, idx: %d, rank: %d)\n",
			  path, item->idx, item->rank);
		return;
	}

	GSList* found = find_item(orig_value, item);
	if (found) {
		/* no duplicate indices */
		free(item);
		return;
	}
	/* insert if idx does not exist */
	pthread_mutex_lock(&table.lock);
	orig_value = insert_item(orig_value, item);
	g_hash_table_steal(table.table, (const void *) orig_key);
	g_hash_table_insert(table.table, orig_key, orig_value);
	pthread_mutex_unlock(&table.lock);
	DEBUG("  table: insert(path: %s, idx: %d, rank: %d)\n",
		  path, item->idx, item->rank);
}

void table_remove(const char *path)
{
	g_hash_table_remove(table.table, path);
}

void table_delete_idx(const char *path, const int idx)
{
	gpointer orig_key, orig_value;
	gboolean exist = g_hash_table_lookup_extended(table.table, path,
						&orig_key, &orig_value);
	if (exist == FALSE)
		return;
	
	struct idx_item *item = g_new(struct idx_item, 1);
	item->idx = idx;
	item->rank = 0;
	GSList* found = find_item(orig_value, item);
	if (found) {
		pthread_mutex_lock(&table.lock);
		orig_value = remove_item(orig_value, found);
		g_hash_table_steal(table.table, (const void *) orig_key);
		g_hash_table_insert(table.table, orig_key, orig_value);
		pthread_mutex_unlock(&table.lock);
	}
	free(item);
}

void table_empty(void)
{
	g_hash_table_remove_all(table.table);
}

idx_list_t table_lookup(const char *path)
{
	return g_hash_table_lookup(table.table, path);
}

/* Get parent directory of path
 * strip from behind in place
 * so use a copy of path */
static inline char * get_parent_dir(char *path)
{
	if (strcmp(path, "/") == 0)
		return path;
	
	int i = strlen(path) - 1;
	do {
		path[i--] = '\0';
	} while (i != 0 && path[i] != '/');
	return path;
}

idx_list_t table_lookup_r(const char *path, int *r_flag)
{
	GSList *idx_list = NULL;
	if (*r_flag == 0) {
		idx_list = g_hash_table_lookup(table.table, path);
		if (idx_list)
			return idx_list;
	}
	*r_flag = 0;	/* clear flag and do recursive */
	char *parent_dir = g_strdup(path);
	while (idx_list == NULL) {
		*r_flag = *r_flag + 1;
		parent_dir = get_parent_dir(parent_dir);
		DEBUG("debug: table lookup recusively for %s\n", parent_dir);
		idx_list = g_hash_table_lookup(table.table, parent_dir);
		if (idx_list)
			break;
	}
	g_free(parent_dir);
	return idx_list;
}

#ifdef TEST_TABLE
/* Debug utilities */
void table_print_idx_list(const char *path)
{
	int r_flag;
	GSList *list = table_lookup_r(path, &r_flag);
	printf("%s: ", path);
	while (list != NULL) {
		struct idx_item *item = (struct idx_item *) list->data;
		printf("(%d, %d) ", item->idx, item->rank);
		list = list->next;
	}
	printf("\n");
}

int main(void)
{
	int res;
	res = table_create(1);
	table_insert("/", 0, 0);
	table_insert("/", 1, 10);
	table_insert("/", 1, 20);
	table_insert("/", 2, 30);
	table_insert("/", 2, 40);
	table_insert("/", 3, 40);
	table_print_idx_list("/usr");
	table_destroy();
	return 0;
}
#endif
