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

typedef GSList* idx_list_t;

/* Initial directory table */
int table_init();

/* Destroy directory table */
void table_destroy(void);

/* Get size of diretory table */
unsigned table_size(void);

/* Insert path with its host_idx to table */
void table_insert(const char *path, const int idx, const int rank);

/* Remove one entry from table */
void table_remove(const char *path);

/* Remove the idx from entry */
void table_remove_idx(const char *path, const int idx);

/* Lookup a entry for path */
idx_list_t table_lookup(const char *path);

/* Clear all entries in table */
void table_empty(void);

/* Option parser */
int table_parse_options(struct fuse_args *args);

#endif	/* _SSHFSM_TABLE_H_ */
