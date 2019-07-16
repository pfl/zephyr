/*
 * Copyright (c) 2018-2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TP_H
#define TP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <net/net_pkt.h>

#define TP_SEQ 0
#define TP_ACK 1

void tp_input(struct net_pkt *pkt);

void *tp_malloc(size_t size, const char *file, int line);
void tp_free(void *ptr, const char *file, int line, const char *func);
void *tp_calloc(size_t nmemb, size_t size, const char *file, int line);
void tp_mem_stat(void);

struct net_buf *tp_nbuf_alloc(struct net_buf_pool *pool, size_t len,
				const char *file, int line, const char *func);
void tp_nbuf_unref(struct net_buf *nbuf, const char *file, int line,
			const char *func);
void tp_nbuf_stat(void);

struct net_pkt *tp_pkt_alloc(size_t len, const char *file, int line);
struct net_pkt *tp_pkt_clone(struct net_pkt *pkt, const char *file, int line);
void tp_pkt_unref(struct net_pkt *pkt, const char *file, int line);
void tp_pkt_stat(void);

u32_t tp_seq_track(int kind, u32_t *pvalue, int req,
			const char *file, int line, const char *func);
void tp_seq_stat(void);

#ifdef __cplusplus
}
#endif

#endif /* TP_H */
