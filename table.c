/*
    Directory Table
    Copyright (C) 2008  Nan Dun <sshfsm@gmail.com>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "table.h"
#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <pthread.h>

struct table {
	GHashTable *table;
	pthread_mutex_t lock;
};

static struct table table;

void item_free(void *data, void *data_)
{
	(void) data_;
	free(data);
}

void table_entry_free(void *entry)
{
	GSList *list = (GSList *) entry;
	g_slist_foreach(list, item_free, NULL);
	g_slist_free(list);
}

int table_init()
{
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

void table_insert(const char *path, const int idx, const int rank)
{
	struct idx_item *item = malloc(sizeof(struct idx_item));
	if (!item) {
		fprintf(stderr, "sshfsm: memory alloation failed\n");
		abort();
	}
	item->idx = idx;
	item->rank = rank;

	idx_list_t idx_list = g_hash_table_lookup(table.table, path);
	if (idx_list == NULL) {	
		/* no entry for path, create one */
		idx_list = insert_item(idx_list, item);
		g_hash_table_insert(table.table, g_strdup(path), idx_list);
	} else {
		/* insert if idx does not exist */
		GSList* found = find_item(idx_list, item);
		if (found) {
			free(item);
			return;
		} else {
			return;		
		}
	}
}
