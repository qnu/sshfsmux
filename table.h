/*
    Directory Table
    Copyright (C) 2008  Nan Dun <sshfsm@gmail.com>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#ifndef	_SSHFSM_TABLE_H_
#define	_SSHFSM_TABLE_H_

#include <glib.h>
#include <fuse.h>
#include <fuse_opt.h>

struct idx_item {
	int idx;
	int rank;
};
typedef struct idx_item * idx_item_t;

typedef GSList* idx_list_t;

/* Initial directory table */
int table_create(int debug);

/* Destroy directory table */
void table_destroy(void);

/* Get size of diretory table */
unsigned table_size(void);

/* Insert path with its host_idx to table */
void table_insert(const char *path, const int idx, const int rank);

/* Remove one entry from table */
void table_remove(const char *path);

/* Delete the idx from entry */
void table_delete_idx(const char *path, const int idx);

/* Clear all entries in table */
void table_empty(void);

/* Lookup a entry for path 
 * r_flag is to indicate if recursive lookup happend */
idx_list_t table_lookup(const char *path);

/* Lookup a entry for recursively 
 * if entry for path not found,
 * return entry for parent directory of path */
idx_list_t table_lookup_r(const char *path, int *r_flag);

/* Option parser */
int table_parse_options(struct fuse_args *args);

#endif	/* _SSHFSM_TABLE_H_ */
