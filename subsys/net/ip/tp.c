/*
 * Copyright (c) 2018-2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <net/net_pkt.h>
#include "tp_priv.h"

static sys_slist_t tp_mem = SYS_SLIST_STATIC_INIT(&tp_mem);
static sys_slist_t tp_nbufs = SYS_SLIST_STATIC_INIT(&tp_nbufs);

void *tp_malloc(size_t size, const char *file, int line)
{
	struct tp_mem *mem = k_malloc(sizeof(struct tp_mem) + size);

	mem->size = size;
	mem->file = file;
	mem->line = line;

	sys_slist_append(&tp_mem, (sys_snode_t *) mem);

	return &mem->mem;
}

void tp_free(void *ptr, const char *file, int line, const char *func)
{
	struct tp_mem *mem = (void *)((u8_t *) ptr - sizeof(struct tp_mem));

	if (!sys_slist_find_and_remove(&tp_mem, (sys_snode_t *) mem)) {
		tp_assert(false, "%s:%d %s() Invalid free(%p)",
				file, line, func, ptr);
	}

	memset(ptr, 0, mem->size);
	k_free(mem);
}

void *tp_calloc(size_t nmemb, size_t size, const char *file, int line)
{
	size *= nmemb;

	void *ptr = tp_malloc(size, file, line);

	memset(ptr, 0, size);

	return ptr;
}

void tp_mem_stat(void)
{
	struct tp_mem *mem;

	SYS_SLIST_FOR_EACH_CONTAINER(&tp_mem, mem, next) {
		tp_dbg("len=%zu %s:%d", mem->size, mem->file, mem->line);
	}
}

struct net_buf *tp_nbuf_alloc(struct net_buf_pool *pool, size_t len,
				const char *file, int line, const char *func)
{
	struct net_buf *nbuf = net_buf_alloc_len(pool, len, K_NO_WAIT);
	struct tp_nbuf *tp_nbuf = k_malloc(sizeof(struct tp_nbuf));

	tp_assert(len, "");
	tp_assert(nbuf, "Out of nbufs");

	tp_dbg("size=%d %p %s:%d %s()", nbuf->size, nbuf, file, line, func);

	tp_nbuf->nbuf = nbuf;
	tp_nbuf->file = file;
	tp_nbuf->line = line;

	sys_slist_append(&tp_nbufs, (sys_snode_t *) tp_nbuf);

	return nbuf;
}

void tp_nbuf_unref(struct net_buf *nbuf, const char *file, int line,
			const char *func)
{
	bool found = false;
	struct tp_nbuf *tp_nbuf;

	tp_dbg("len=%d %p %s:%d %s()", nbuf->len, nbuf, file, line, func);

	SYS_SLIST_FOR_EACH_CONTAINER(&tp_nbufs, tp_nbuf, next) {
		if (tp_nbuf->nbuf == nbuf) {
			found = true;
			break;
		}
	}

	tp_assert(found, "Invalid tp_nbuf_unref(%p): %s:%d", nbuf, file, line);

	sys_slist_find_and_remove(&tp_nbufs, (sys_snode_t *) tp_nbuf);

	net_buf_unref(nbuf);

	k_free(tp_nbuf);
}

void tp_nbuf_stat(void)
{
	struct tp_nbuf *tp_nbuf;

	SYS_SLIST_FOR_EACH_CONTAINER(&tp_nbufs, tp_nbuf, next) {
		tp_dbg("%s:%d len=%d", tp_nbuf->file, tp_nbuf->line,
			tp_nbuf->nbuf->len);
	}
}


