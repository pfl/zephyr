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

enum tp_type { /* Test protocol message type */
	TP_NONE = 0,
	TP_COMMAND,
	TP_CONFIG_REQUEST,
	TP_CONFIG_REPLY,
	TP_INTROSPECT_REQUEST,
	TP_INTROSPECT_REPLY,
	TP_INTROSPECT_MEMORY_REQUEST,
	TP_INTROSPECT_MEMORY_REPLY,
	TP_INTROSPECT_PACKETS_REQUEST,
	TP_INTROSPECT_PACKETS_REPLY,
	TP_DEBUG_STOP,
	TP_DEBUG_STEP,
	TP_DEBUG_CONTINUE,
	TP_DEBUG_RESPONSE,
	TP_DEBUG_BREAKPOINT_ADD,
	TP_DEBUG_BREAKPOINT_DELETE,
	TP_TRACE_ADD,
	TP_TRACE_DELETE
};

struct tp {
	enum tp_type type;
	const char *msg;
	const char *status;
	const char *state;
	int seq;
	int ack;
	const char *rcv;
	const char *data;
	const char *op;
};

void tp_input(struct net_pkt *pkt);

char *tp_basename(char *path);

void _tp_output(struct net_if *iface, void *data, size_t data_len,
		const char *file, int line);
#define tp_output(_iface, _data, _data_len) \
	_tp_output(_iface, _data, _data_len, tp_basename(__FILE__), __LINE__)

void tp_pkt_adj(struct net_pkt *pkt, int req_len);

enum tp_type tp_msg_to_type(const char *s);

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
