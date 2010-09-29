/****************************************************************************
 * SSHFS Mutiplex Filesystem Cache Subsystem
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

#ifndef	_SSHFSM_CACHE_H_
#define	_SSHFSM_CACHE_H_

#include <fuse.h>
#include <fuse_opt.h>

#ifndef FUSE_VERSION
#define FUSE_VERSION (FUSE_MAJOR_VERSION * 10 + FUSE_MINOR_VERSION)
#endif

typedef struct fuse_cache_dirhandle *fuse_cache_dirh_t;
typedef int (*fuse_cache_dirfil_t) (fuse_cache_dirh_t h, const char *name,
                                    const struct stat *stbuf);

struct fuse_cache_operations {
    struct fuse_operations oper;
    int (*cache_getdir) (const char *, fuse_cache_dirh_t, fuse_cache_dirfil_t);
};

struct fuse_operations *cache_init(struct fuse_cache_operations *oper);
void cache_destroy();
int cache_parse_options(struct fuse_args *args);
void cache_add_attr(const char *path, const struct stat *stbuf, 
					uint64_t wrctr);
int cache_get_attr(const char *path, struct stat *stbuf);
void cache_invalidate(const char *path);
uint64_t cache_get_write_ctr(void);

#endif	/* _SSHFSM_CACHE_H_ */
