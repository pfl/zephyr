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
static sys_slist_t tp_pkts = SYS_SLIST_STATIC_INIT(&tp_pkts);

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

static struct net_pkt *net_pkt_get(size_t len)
{
	struct net_pkt *pkt = net_pkt_alloc(K_NO_WAIT);
	struct net_buf *nbuf = net_pkt_get_frag(pkt, K_NO_WAIT);

	tp_assert(pkt && nbuf, "");

	pkt->family = AF_INET;

	net_buf_add(nbuf, len);
	net_pkt_frag_insert(pkt, nbuf);

	return pkt;
}

struct net_pkt *tp_pkt_alloc(size_t len, const char *file, int line)
{
	struct net_pkt *pkt = net_pkt_get(len);
	struct tp_pkt *tp_pkt = k_malloc(sizeof(struct tp_pkt));

	tp_assert(tp_pkt, "");

	tp_pkt->pkt = pkt;
	tp_pkt->file = file;
	tp_pkt->line = line;

	sys_slist_append(&tp_pkts, (sys_snode_t *) tp_pkt);

	return pkt;
}

struct net_pkt *tp_pkt_clone(struct net_pkt *pkt, const char *file, int line)
{
	struct tp_pkt *tp_pkt = k_malloc(sizeof(struct tp_pkt));

	pkt = net_pkt_clone(pkt, K_NO_WAIT);

	tp_pkt->pkt = pkt;
	tp_pkt->file = file;
	tp_pkt->line = line;

	sys_slist_append(&tp_pkts, (sys_snode_t *) tp_pkt);

	return pkt;
}

void tp_pkt_unref(struct net_pkt *pkt, const char *file, int line)
{
	bool found = false;
	struct tp_pkt *tp_pkt;

	SYS_SLIST_FOR_EACH_CONTAINER(&tp_pkts, tp_pkt, next) {
		if (tp_pkt->pkt == pkt) {
			found = true;
			break;
		}
	}

	tp_assert(found, "Invalid tp_pkt_unref(%p): %s:%d", pkt, file, line);

	sys_slist_find_and_remove(&tp_pkts, (sys_snode_t *) tp_pkt);

	net_pkt_unref(tp_pkt->pkt);

	k_free(tp_pkt);
}

void tp_pkt_stat(void)
{
	struct tp_pkt *pkt;

	SYS_SLIST_FOR_EACH_CONTAINER(&tp_pkts, pkt, next) {
		tp_dbg("%s:%d %p", pkt->file, pkt->line, pkt->pkt);
	}
}
